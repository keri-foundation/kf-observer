# -*- encoding: utf-8 -*-
"""
kfobserver.app.httping module

Falcon resources for the wallet/verifier verified-TEL query face.
"""

import json

import falcon
from hio.help import helping as hiohelping
from keri import Vrsn_2_0
from keri.app.httping import CESR_ATTACHMENT_HEADER, CESR_CONTENT_TYPE
from keri.core import Number, Parser, SerderKERI
from keri.kering import (
    InvalidValueError,
    ExtractionError,
    MaterialError,
    MissingAuthAttachmentError,
    MissingSenderKeyStateError,
    Ilks,
    TopLevelStreamError,
    ValidationError,
)


# Fine-grained wallet/verifier routes (one registry SAID).
QUERY_ROUTES = ("tels", "tels/head")
# Registrar bulk routes are not served here.
BULK_ROUTES = ("tels/bulk", "regs")
# shortcut: 8 MiB request-data limit, raise after measuring caller histories.
PUT_BODY_LIMIT = 8 * 1024 * 1024
KEL_ILKS = (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt)


class _KELReplayParser(Parser):
    """Track parser failures and skip accepted events during recovery replay."""

    def __init__(self, **kwa):
        super().__init__(**kwa)
        self.events = []
        self.errors = []

    def msgParsator(self, *args, **kwa):
        try:
            exts = yield from super().msgParsator(*args, **kwa)
        except TopLevelStreamError:
            # Native group parsing handles this control-flow signal.
            raise
        except Exception as ex:
            self.errors.append(ex)
            raise
        serder = exts.serder
        if not isinstance(serder, SerderKERI) or serder.ilk not in KEL_ILKS:
            ex = ValidationError("replay contains a non-KEL message")
            self.errors.append(ex)
            raise ex
        self.events.append((serder.pre, serder.sn, serder.said))
        return exts

    def groupParsator(self, *args, **kwa):
        try:
            return (yield from super().groupParsator(*args, **kwa))
        except Exception as ex:
            self.errors.append(ex)
            raise

    def msgProcess(self, exts, kvy, tvy, exc, rvy, vry):
        try:
            serder = exts["serder"]
            if serder.said in kvy.db.kels.get(keys=serder.pre, on=serder.sn):
                return None
            return super().msgProcess(exts, kvy, tvy, exc, rvy, vry)
        except Exception as ex:
            self.errors.append(ex)
            raise


def _parseKELReplay(raw, kvy):
    """Require accepted single-AID KEL events with valid CESR attachments."""
    events = None
    for processive in (False, True):
        parser = _KELReplayParser(version=Vrsn_2_0)
        parser.parse(ims=bytearray(raw), framed=True, kvy=kvy, processive=processive)
        unexpected = next(
            (
                error
                for error in parser.errors
                if not isinstance(
                    error, (ExtractionError, MaterialError, ValidationError)
                )
            ),
            None,
        )
        if unexpected is not None:
            raise unexpected
        if parser.errors or not parser.events:
            raise falcon.HTTPBadRequest(description="invalid or incomplete KEL replay")
        if events is None:
            events = parser.events
            if len({pre for pre, _sn, _said in events}) != 1:
                raise falcon.HTTPBadRequest(description="replay must contain one AID")
        elif parser.events != events:
            raise falcon.HTTPBadRequest(description="incomplete KEL replay")

    db = kvy.db
    if any(said not in db.kels.get(keys=pre, on=sn) for pre, sn, said in events):
        raise falcon.HTTPBadRequest(description="KEL replay was not fully accepted")


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
    """Public KEL introduction and signed V2 qry POST for verified TEL."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, _req, _rep):
        raise falcon.HTTPMethodNotAllowed(
            ["POST", "PUT"], description="use signed CESR qry POST or KEL PUT"
        )

    def on_put(self, req, rep):
        """Accept public KEL data for signed queries.

        The endpoint limits the request data it accepts and processes. Stock HIO
        buffers the HTTP request before Falcon invokes this handler.
        """
        ctype = (req.content_type or "").split(";")[0].strip().lower()
        if ctype and ctype != CESR_CONTENT_TYPE:
            raise falcon.HTTPError(
                falcon.HTTP_NOT_ACCEPTABLE,
                title="Content type error",
                description="Unacceptable content type.",
            )
        if req.content_length is not None and req.content_length > PUT_BODY_LIMIT:
            raise falcon.HTTPError(
                falcon.HTTP_413,
                title="Request body too large",
                description="KEL replay exceeds the 8 MiB limit.",
            )
        raw = req.bounded_stream.read(PUT_BODY_LIMIT + 1)
        if len(raw) > PUT_BODY_LIMIT:
            raise falcon.HTTPError(
                falcon.HTTP_413,
                title="Request body too large",
                description="KEL replay exceeds the 8 MiB limit.",
            )
        if not raw:
            raise falcon.HTTPBadRequest(description="empty body")
        _parseKELReplay(raw, self.ctx.kvy)
        rep.status = falcon.HTTP_204

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
            raise falcon.HTTPBadRequest(
                description="observer face accepts qry messages only"
            )

        route = serder.ked.get("r", "")
        qry = serder.ked.get("q") or {}
        if not isinstance(qry, dict):
            qry = {}

        if route in BULK_ROUTES:
            raise falcon.HTTPForbidden(
                description="bulk registrar routes are not served by the observer"
            )
        if route not in QUERY_ROUTES:
            raise falcon.HTTPForbidden(
                description=f"invalid observer query route {route}"
            )
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
            # KRAM's get() sees only cached Kevers. Reload accepted sender
            # history after a restart before applying normal authentication.
            try:
                self.ctx.kvy.kevers[serder.pre]
            except KeyError:
                pass  # KRAM retains responsibility for unknown-sender rejection.
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
        if not self.ctx.observer.hasRegistry(regk) and self.ctx.registrars:
            # HIO advances the stream cooperatively and defers status until data.
            rep.stream = self.queryDo(regk, route, qry)
            return
        data = self.queryData(regk, route, qry)
        rep.set_header("Content-Type", CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = data

    @hiohelping.attributize
    def queryDo(self, me, regk, route, qry):
        """Defer the TEL response while HIO services the registrar request."""
        yield from self.ctx.pullRegistry(regk)
        try:
            data = self.queryData(regk, route, qry)
        except falcon.HTTPError as ex:
            me._status = ex.status
            me._headers = {"Content-Type": "application/json"}
            yield ex.to_json()
        else:
            me._status = falcon.HTTP_200
            me._headers = {"Content-Type": CESR_CONTENT_TYPE}
            yield data

    def queryData(self, regk, route, qry):
        """Read verified TEL or retain the existing missing/pending response."""
        if not self.ctx.observer.hasRegistry(regk):
            if regk in self.ctx.observer.pending:
                raise falcon.HTTPServiceUnavailable(
                    description=(
                        f"registry {regk} pending issuer KEL anchors; retry later"
                    )
                )
            raise falcon.HTTPNotFound(description=f"unknown registry {regk}")

        if route == "tels/head":
            return self.ctx.observer.lastRaw(regk)
        try:
            sn = _snFromQuery(qry)
        except (InvalidValueError, TypeError) as ex:
            # Keep Falcon's existing 500 response even when rendering is deferred.
            raise falcon.HTTPInternalServerError() from ex
        return self.ctx.observer.clone(regk, sn=sn)
