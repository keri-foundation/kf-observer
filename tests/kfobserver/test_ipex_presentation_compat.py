# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_ipex_presentation_compat module

Presentation-registry path: issuee TEL+KEL → registrar ingest → observer
bulk (KEL+TEL) → verifier query. Separate Haberies; no shared Habery preload.
"""

import sys
from pathlib import Path

import falcon
from falcon import testing

from keri import Vrsn_2_0
from keri.acdc import blindate, regeventing, regcept
from keri.app.habbing import openHab, openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Kevery, SerderACDC, query
from keri.core.signing import Salter
from keri.help import helping

from kfobserver.core.observing import Observer, parseTelStream
from kfobserver.core.serving import makeContext


# Sibling kf-registrar (umbrella checkout).
_REG_SRC = Path(__file__).resolve().parents[3] / "kf-registrar" / "src"
if str(_REG_SRC) not in sys.path:
    sys.path.insert(0, str(_REG_SRC))

from kfregistrar.core.serving import makeContext as makeRegistrarContext  # noqa: E402


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def _kelClone(hab):
    stream = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0):
        stream.extend(msg)
    return stream.decode("utf-8")


def _telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def _postCesr(client, hab, serder, path="/"):
    msg = hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0)
    headers = {"Content-Type": CESR_CONTENT_TYPE}
    return client.simulate_post(path, body=bytes(msg), headers=headers)


def _bulkQuery(hab, regk, route="tels/bulk"):
    return query(
        pre=hab.pre,
        route=route,
        query=dict(i=regk),
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def _telQuery(hab, regk, route="tels", **qextra):
    q = dict(i=regk, **qextra)
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def test_presentation_registry_hosted_pull_query_vet():
    """Issuee presentation TEL reaches verifier via registrar bulk + observer."""
    with openHab(name="ipex-wallet", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        wallet.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        # Presentation registry binding a grant-like ACDC SAID in the blind.
        grantSaid = "E" + "G" * 43
        blinder = Blinder.blind(
            acdc=grantSaid, state="issued", salt=SALT, sn=1
        )
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        wallet.interact(data=[dict(s=bup.sad["n"], d=bup.said)])
        kel = _kelClone(wallet)
        telBytes = _telStream(rip, bup)
        tel = telBytes.decode("utf-8")
        regk = rip.said

    with openHby(name="ipex-reg", base="test", temp=True, version=Vrsn_2_0) as rhby:
        rhby.makeHab(name="registrar")
        observerHab = rhby.makeHab(name="observer")
        rctx = makeRegistrarContext(
            hby=rhby, alias="registrar", observers=[observerHab.pre]
        )
        try:
            inner = testing.TestClient(rctx.internalApp)
            ingested = inner.simulate_post(
                "/ingest",
                json=dict(kel=kel, tel=tel),
            )
            assert ingested.status == falcon.HTTP_200
            assert regk in ingested.json["accepted"]

            outer = testing.TestClient(rctx.externalApp)
            # Observer AID must sign the bulk qry; use the allow-listed hab.
            bulkResp = _postCesr(
                outer, observerHab, _bulkQuery(observerHab, regk)
            )
            assert bulkResp.status == falcon.HTTP_200
            bulk = bulkResp.content
            assert bulk.endswith(telBytes)
            assert len(bulk) > len(telBytes)
        finally:
            rctx.rgy.close()

    with openHby(name="ipex-obs", base="test", temp=True, version=Vrsn_2_0) as ohby:
        ohby.makeHab(name="observer")
        walletQ = ohby.makeHab(name="verifier")
        octx = makeContext(hby=ohby, alias="observer")
        try:
            summary = octx.observer.ingest(bulk, kvy=octx.kvy)
            assert regk in summary["accepted"]

            client = testing.TestClient(octx.app)
            allResp = _postCesr(client, walletQ, _telQuery(walletQ, regk))
            assert allResp.status == falcon.HTTP_200
            assert allResp.content == telBytes

            headResp = _postCesr(
                client, walletQ, _telQuery(walletQ, regk, route="tels/head")
            )
            assert headResp.status == falcon.HTTP_200
            assert headResp.content == bytes(bup.raw)

            events = parseTelStream(allResp.content)
            rec = regeventing.vet(
                rip=events[0],
                updates=events[1:],
                db=octx.hby.db,
                acdc=None,
                blinder=blinder,
            )
            assert rec.state == "issued"
            assert rec.acdc == grantSaid
        finally:
            octx.observer.close()


def test_tampered_presentation_bulk_not_served():
    """Observer rejects a bulk TEL whose bup digests do not verify."""
    with openHab(name="ipex-bad-wallet", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        wallet.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        blinder = Blinder.blind(
            acdc="E" + "B" * 43, state="issued", salt=SALT, sn=1
        )
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        wallet.interact(data=[dict(s=bup.sad["n"], d=bup.said)])
        kel = bytearray()
        for msg in wallet.db.clonePreIter(pre=wallet.pre, gvrsn=Vrsn_2_0):
            kel.extend(msg)
        badSad = dict(bup.sad)
        badSad["p"] = "E" + "A" * 43
        badSad["d"] = ""
        bad = SerderACDC(sad=badSad, makify=True)
        bulk = bytes(kel) + _telStream(rip, bad)
        regk = rip.said

    with openHby(name="ipex-bad-obs", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="observer")
        kvy = Kevery(db=hby.db, lax=True, local=False)
        observer = Observer(hby=hby, kvy=kvy)
        try:
            summary = observer.ingest(bulk)
            assert regk in summary["rejected"] or regk not in summary["accepted"]
            assert not observer.hasRegistry(regk)
        finally:
            observer.close()
