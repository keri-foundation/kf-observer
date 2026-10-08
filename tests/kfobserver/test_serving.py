# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_serving module

HTTP face tests for wallet/verifier verified-TEL queries.
"""

import falcon
from falcon import testing

from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, SerderACDC, query
from keri.core.signing import Salter
from keri.help import helping

from kfobserver.core.serving import makeContext


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def seal(serder):
    return dict(s=serder.sad["n"], d=serder.said)


def anchor(hab, *serders):
    hab.interact(data=[seal(serder) for serder in serders])


def telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def _postCesr(client, hab, serder, path="/"):
    msg = hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0)
    headers = {"Content-Type": CESR_CONTENT_TYPE}
    return client.simulate_post(path, body=bytes(msg), headers=headers)


def _telQuery(hab, regk, route="tels", **qextra):
    q = dict(i=regk, **qextra)
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def _telIlks(raw):
    ims = bytearray(raw)
    ilks = []
    while ims:
        serder = SerderACDC(raw=ims)
        ilks.append(serder.ilk)
        del ims[: serder.size]
    return ilks


def _seedObserverTel(hby, issuer):
    ripper = regcept(israid=issuer.pre, stamp=STAMP0)
    anchor(issuer, ripper)
    acdc = acdcmap(
        israid=issuer.pre,
        regid=ripper.said,
        attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
        iseaid=issuer.pre,
    )
    blinder = Blinder.blind(acdc=acdc.said, state="issued", salt=SALT, sn=1)
    bup = blindate(
        regid=ripper.said,
        prior=ripper.said,
        blid=blinder.said,
        sn=1,
        stamp=STAMP1,
    )
    anchor(issuer, bup)
    return ripper, bup, blinder, acdc, telStream(ripper, bup)


def test_wallet_query_last_all_since_sn():
    """Signed tels / tels/head queries return verified CESR only."""
    with openHby(name="kf-obs-http", base="test", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        observerHab = hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)

        ctx = makeContext(hby=hby, alias="observer")
        try:
            summary = ctx.observer.ingest(stream)
            assert ripper.said in summary["accepted"]

            client = testing.TestClient(ctx.app)

            allQry = _telQuery(wallet, ripper.said, route="tels")
            allResp = _postCesr(client, wallet, allQry)
            assert allResp.status == falcon.HTTP_200
            assert allResp.headers["content-type"] == CESR_CONTENT_TYPE
            assert allResp.content == stream
            assert _telIlks(allResp.content) == ["rip", "bup"]

            sinceQry = _telQuery(wallet, ripper.said, route="tels", sn=1)
            sinceResp = _postCesr(client, wallet, sinceQry)
            assert sinceResp.status == falcon.HTTP_200
            assert sinceResp.content == bytes(bup.raw)

            headQry = _telQuery(wallet, ripper.said, route="tels/head")
            headResp = _postCesr(client, wallet, headQry)
            assert headResp.status == falcon.HTTP_200
            assert headResp.content == bytes(bup.raw)

            missing = _telQuery(wallet, "E" + "B" * 43, route="tels")
            missingResp = _postCesr(client, wallet, missing)
            assert missingResp.status == falcon.HTTP_404

            bulk = _telQuery(wallet, ripper.said, route="tels/bulk")
            bulkResp = _postCesr(client, wallet, bulk)
            assert bulkResp.status == falcon.HTTP_403

            # unused but proves observer hab exists for ops
            assert observerHab.pre == ctx.hab.pre
        finally:
            ctx.observer.close()


def test_health():
    """Liveness probe leaks no TEL."""
    with openHby(name="kf-obs-health", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="observer")
        ctx = makeContext(hby=hby, alias="observer")
        try:
            client = testing.TestClient(ctx.app)
            response = client.simulate_get("/health")
            assert response.status == falcon.HTTP_200
            assert response.json["status"] == "ok"
        finally:
            ctx.observer.close()


def test_ondemand_pull_on_unknown_registry(monkeypatch):
    """Unknown registry triggers registrar pull before 404."""
    with openHby(name="kf-obs-pull", base="test", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)

        # Build KEL+TEL bulk the way a registrar would.
        kel = bytearray()
        for msg in issuer.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0):
            kel.extend(msg)
        bulk = bytes(kel) + stream

        ctx = makeContext(
            hby=hby,
            alias="observer",
            registrars=["http://127.0.0.1:6632/"],
        )
        try:
            pulled = {"n": 0}

            def _fakePull(hab, url, regk=None, sn=0, timeout=5.0):
                pulled["n"] += 1
                assert regk == ripper.said
                return bulk

            monkeypatch.setattr(
                "kfobserver.core.pulling.pullOnce", _fakePull
            )

            client = testing.TestClient(ctx.app)
            assert not ctx.observer.hasRegistry(ripper.said)
            resp = _postCesr(client, wallet, _telQuery(wallet, ripper.said))
            assert resp.status == falcon.HTTP_200
            assert resp.content == stream
            assert pulled["n"] == 1

            # Second query hits local store; no extra pull.
            resp2 = _postCesr(client, wallet, _telQuery(wallet, ripper.said))
            assert resp2.status == falcon.HTTP_200
            assert pulled["n"] == 1
        finally:
            ctx.observer.close()


def test_ondemand_pull_pending_returns_503(monkeypatch):
    """Escrowed registry after pull returns 503, not 404."""
    with openHby(name="kf-obs-503", base="test", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ripper = regcept(israid=issuer.pre, stamp=STAMP0)
        # Not anchored — vet will escrow.
        tel = telStream(ripper)

        ctx = makeContext(
            hby=hby,
            alias="observer",
            registrars=["http://127.0.0.1:6632/"],
        )
        try:
            monkeypatch.setattr(
                "kfobserver.core.pulling.pullOnce",
                lambda *a, **k: tel,
            )
            client = testing.TestClient(ctx.app)
            resp = _postCesr(client, wallet, _telQuery(wallet, ripper.said))
            assert resp.status == falcon.HTTP_503
            assert ripper.said in ctx.observer.pending
        finally:
            ctx.observer.close()
