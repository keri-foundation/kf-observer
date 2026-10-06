# -*- encoding: utf-8 -*-
"""
kfobserver.app.httping module

Falcon resources for the wallet/verifier verified-TEL query face.
"""

import json

import falcon
from keri import Vrsn_2_0
from keri.app.httping import CESR_ATTACHMENT_HEADER, CESR_CONTENT_TYPE
from keri.core import Number, Parser, SerderKERI
from keri.kering import MissingAuthAttachmentError, MissingSenderKeyStateError


# Fine-grained wallet/verifier routes (one registry SAID).
QUERY_ROUTES = ("tels", "tels/head")
# Registrar bulk routes are not served here.
BULK_ROUTES = ("tels/bulk", "regs")


def _snFromQuery(qry):
    """Parse an optional sequence number from a query block."""
    sn = qry.get("sn", 0)
    if sn is None or sn == "":
        return 0
    if isinstance(sn, int):
        return sn
    return Number(num=sn).sn


def _registrySaid(qry):
    """Require a single registry SAID in q.i."""
    raw = qry.get("i")
    if raw is None or raw == "":
        return None
    if isinstance(raw, (list, tuple)):
        if len(raw) != 1:
            return None
        return raw[0]
    return raw


def _loadQueryStream(req):
    """Read a signed qry as CESR-over-HTTP JSON+attachment or a raw CESR stream."""
    ctype = (req.content_type or "").split(";")[0].strip().lower()
    if ctype and ctype != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(
            falcon.HTTP_NOT_ACCEPTABLE,
            title="Content type error",
            description="Unacceptable content type.",
        )
    raw = req.bounded_stream.read()
    if not raw:
        raise falcon.HTTPBadRequest(description="empty body")
    atc = req.get_header(CESR_ATTACHMENT_HEADER, default=None)
    if atc and raw.lstrip()[:1] == b"{":
        payload = json.loads(raw)
        serder = SerderKERI(sad=payload)
        ims = bytearray(serder.raw)
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
        return ims
    ims = bytearray(raw)
    if atc and raw.lstrip()[:1] != b"{":
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
    return ims


class HealthEnd:
    """Liveness probe. No TEL material."""

    def on_get(self, _req, rep):
        rep.media = dict(status="ok")
        rep.status = falcon.HTTP_200


class TelQueryEnd:
    """Signed V2 qry POST for verified TEL last / all / since sn."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, _req, _rep):
        raise falcon.HTTPMethodNotAllowed(
            ["POST"], description="use signed CESR qry POST"
        )

    def on_post(self, req, rep):
        try:
            ims = _loadQueryStream(req)
        except falcon.HTTPError:
            raise
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex

        try:
            dom = Parser(version=Vrsn_2_0).parseOne(
                ims=bytearray(ims), framed=True, processive=False
            )
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex
        if not getattr(dom, "serder", None):
            raise falcon.HTTPBadRequest(description="unable to parse signed query")
        serder = dom.serder
        if serder.ilk != "qry":
            raise falcon.HTTPBadRequest(description="observer face accepts qry messages only")

        route = serder.ked.get("r", "")
        qry = serder.ked.get("q") or {}
        if not isinstance(qry, dict):
            qry = {}

        if route in BULK_ROUTES:
            raise falcon.HTTPForbidden(
                description="bulk registrar routes are not served by the observer"
            )
        if route not in QUERY_ROUTES:
            raise falcon.HTTPForbidden(description=f"invalid observer query route {route}")
        if "vcid" in qry:
            raise falcon.HTTPForbidden(
                description="credential SAID queries are not served; use registry SAID"
            )

        kwa = dict(
            sigers=list(dom.sigers),
            cigars=list(dom.cigars),
            lsgs=list(dom.lsgs),
            tsgs=list(dom.tsgs),
            sscs=list(dom.sscs),
            ssts=list(dom.ssts),
        )

        kramer = self.ctx.kvy.kramer
        if kramer is not None:
            kramer.reconcileConfig()
            try:
                result = kramer.intake(serder, kwa)
            except (MissingAuthAttachmentError, MissingSenderKeyStateError) as ex:
                raise falcon.HTTPUnauthorized(description=str(ex)) from ex
            if result is None:
                raise falcon.HTTPUnauthorized(description="KRAM rejected query")

        regk = _registrySaid(qry)
        if not regk:
            raise falcon.HTTPBadRequest(
                description="q.i must be a single registry SAID"
            )
        if not self.ctx.observer.hasRegistry(regk):
            raise falcon.HTTPNotFound(description=f"unknown registry {regk}")

        if route == "tels/head":
            data = self.ctx.observer.lastRaw(regk)
        else:
            sn = _snFromQuery(qry)
            data = self.ctx.observer.clone(regk, sn=sn)

        rep.set_header("Content-Type", CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = data
