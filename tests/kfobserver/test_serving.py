# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_serving module

HTTP face tests for wallet/verifier verified-TEL queries.
"""

from contextlib import ExitStack, contextmanager

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from falcon import testing

from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Parser, SerderACDC, SerderKERI, Texter, eventing, query
from keri.core.coring import Diger
from keri.core.counting import Codens, Counter
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


@contextmanager
def _remoteSignerLab(name):
    """Keep registry issuer, query signer, and Observer in separate Haberies."""
    with ExitStack() as stack:
        issuerHby = stack.enter_context(
            openHby(name=f"{name}-issuer", base="test", temp=True, version=Vrsn_2_0)
        )
        signerHby = stack.enter_context(
            openHby(name=f"{name}-signer", base="test", temp=True, version=Vrsn_2_0)
        )
        observerHby = stack.enter_context(
            openHby(name=f"{name}-observer", base="test", temp=True, version=Vrsn_2_0)
        )
        issuer = issuerHby.makeHab(name="issuer")
        signer = signerHby.makeHab(name="wallet")
        observerHby.makeHab(name="observer")
        ripper, bup, _blinder, _acdc, tel = _seedObserverTel(issuerHby, issuer)
        ctx = makeContext(hby=observerHby, alias="observer")
        stack.callback(ctx.observer.close)
        issuerKel = b"".join(issuer.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerKel), kvy=ctx.kvy)
        assert ctx.observer.ingest(tel, kvy=ctx.kvy)["accepted"]
        client = testing.TestClient(ctx.app)
        yield issuer, signer, observerHby, ctx, client, ripper.said, tel


def _signerKel(hab):
    return b"".join(hab.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0))


def _putKel(client, raw, content_type=CESR_CONTENT_TYPE):
    headers = {"Content-Type": content_type} if content_type is not None else {}
    return client.simulate_put("/", body=raw, headers=headers)


def _signedTelQuery(client, hab, regk, endorser=None):
    qry = _telQuery(hab, regk)
    msg = (endorser or hab).endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0)
    return client.simulate_post(
        "/", body=bytes(msg), headers={"Content-Type": CESR_CONTENT_TYPE}
    )


@pytest.mark.parametrize("grouped", [False, True], ids=["messages", "generic-group"])
def test_put_introduces_remote_signer_for_authenticated_tel_query(grouped):
    """PUT makes public history available; KRAM still authenticates POST."""
    with _remoteSignerLab("observer-remote-signer") as (
        issuer,
        signer,
        observerHby,
        _ctx,
        client,
        regk,
        tel,
    ):
        assert issuer.pre != signer.pre
        assert signer.pre not in observerHby.kevers
        assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_401

        replay = _signerKel(signer)
        if grouped:
            gvc = Counter(
                countB64=Counter.verToB64(major=2, minor=0),
                code=Codens.KERIACDCGenusVersion,
                version=Vrsn_2_0,
            ).qb64b
            serder = SerderKERI(raw=replay)
            body = Counter.enclose(
                qb64=Texter(raw=serder.raw).qb64b,
                code=Codens.NonNativeBodyGroup,
                version=Vrsn_2_0,
            )
            message = Counter.enclose(
                qb64=gvc + body + replay[serder.size:],
                code=Codens.BodyWithAttachmentGroup,
                version=Vrsn_2_0,
            )
            replay = gvc + Counter.enclose(
                qb64=gvc + message, code=Codens.GenericGroup, version=Vrsn_2_0
            )
        response = _putKel(client, replay, f"{CESR_CONTENT_TYPE}; charset=utf-8")
        assert response.status == falcon.HTTP_204
        assert response.content == b""
        assert signer.pre in observerHby.kevers

        assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_200
        assert _signedTelQuery(client, signer, regk).content == tel
        with openHby(
            name="observer-remote-attacker", base="test", temp=True, version=Vrsn_2_0
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            assert (
                _signedTelQuery(client, signer, regk, endorser=attacker).status
                == falcon.HTTP_401
            )
        unsigned = _telQuery(signer, regk)
        assert (
            client.simulate_post(
                "/", body=unsigned.raw, headers={"Content-Type": CESR_CONTENT_TYPE}
            ).status
            == falcon.HTTP_400
        )


def test_unused_outbound_cues_do_not_accumulate():
    """Introductions and unknown signers leave no unused outbound cue backlog."""
    with _remoteSignerLab("observer-unused-cues") as (
        _issuer,
        signer,
        _observerHby,
        ctx,
        client,
        regk,
        _tel,
    ):
        for _ in range(3):
            assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_401
            assert not ctx.kvy.cues

        assert _putKel(client, _signerKel(signer)).status == falcon.HTTP_204
        assert not ctx.kvy.cues
        assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_200


def test_put_replay_is_idempotent_and_accepts_older_history_after_rotation():
    with _remoteSignerLab("observer-replay") as (
        issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        assert _putKel(client, inception).status == falcon.HTTP_204
        signer.rotate()
        current = _signerKel(signer)
        assert _putKel(client, current).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1
        assert _putKel(client, current).status == falcon.HTTP_204
        assert _putKel(client, inception).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1


def test_put_accepts_native_recovery_replay_and_repeat():
    with _remoteSignerLab("observer-native-recovery") as (
        _issuer,
        _signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        with openHby(
            name="observer-native-recovery-source",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as sourceHby:
            signers = Salter(raw=b"recovery-test-salt").signers(count=3)
            pre = eventing.incept(
                keys=[signers[0].verfer.qb64],
                ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64],
                version=Vrsn_2_0,
            )
            ixn1 = eventing.interact(pre=pre.pre, dig=pre.said, sn=1, version=Vrsn_2_0)
            ixn2 = eventing.interact(pre=pre.pre, dig=ixn1.said, sn=2, version=Vrsn_2_0)
            recovery = eventing.rotate(
                pre=pre.pre,
                keys=[signers[1].verfer.qb64],
                dig=pre.said,
                sn=1,
                ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                version=Vrsn_2_0,
            )
            messages = [
                bytes(
                    eventing.messagize(
                        serder,
                        sigers=[signer.sign(serder.raw, index=0)],
                        framed=False,
                        gvrsn=Vrsn_2_0,
                    )
                )
                for serder, signer in (
                    (pre, signers[0]),
                    (ixn1, signers[0]),
                    (ixn2, signers[0]),
                    (recovery, signers[1]),
                )
            ]
            Parser(version=Vrsn_2_0).parse(
                ims=bytearray(b"".join(messages)), kvy=sourceHby.kvy
            )
            replay = b"".join(sourceHby.db.clonePreIter(pre=pre.pre, gvrsn=Vrsn_2_0))
            assert sourceHby.kevers[pre.pre].sn == 1
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert observerHby.kevers[pre.pre].sn == 1
            assert observerHby.kevers[pre.pre].serder.said == recovery.said
            for serder in (pre, ixn1, ixn2, recovery):
                assert serder.said in observerHby.db.kels.get(
                    keys=serder.pre, on=serder.sn
                )
            assert _putKel(client, b"".join(messages[:3])).status == falcon.HTTP_204
            assert observerHby.kevers[pre.pre].serder.said == recovery.said


def test_put_uses_genus_framing_without_requiring_v2_event_bodies():
    with _remoteSignerLab("observer-put-v1-body") as (
        _issuer,
        _signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        with openHby(
            name="observer-put-v1-signer", base="test", temp=True, version=Vrsn_2_0
        ) as legacyHby:
            legacy = legacyHby.makeHab(name="legacy", version=Vrsn_1_0)
            replay = _signerKel(legacy)
            assert legacy.kever.serder.pvrsn == Vrsn_1_0
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert observerHby.kevers[legacy.pre].serder.pvrsn == Vrsn_1_0


@pytest.mark.parametrize(
    "material",
    [
        "empty",
        "malformed",
        "truncated",
        "missing-signature",
        "bad-signature",
        "non-kel",
    ],
)
def test_put_rejects_invalid_or_non_kel_input(material):
    with _remoteSignerLab(f"observer-put-{material}") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        regk,
        _tel,
    ):
        replay = _signerKel(signer)
        if material == "empty":
            replay = b""
        elif material == "malformed":
            replay = b"not CESR"
        elif material == "truncated":
            replay = replay[:-1]
        elif material == "missing-signature":
            replay = signer.kever.serder.raw
        elif material == "bad-signature":
            with openHby(
                name=f"observer-put-attacker-{material}",
                base="test",
                temp=True,
                version=Vrsn_2_0,
            ) as attackerHby:
                attacker = attackerHby.makeHab(name="attacker")
                replay = bytes(
                    attacker.endorse(
                        signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                    )
                )
        elif material == "non-kel":
            qry = _telQuery(signer, regk)
            replay = bytes(signer.endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0))
        assert _putKel(client, replay).status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers


@pytest.mark.parametrize("tail", [b"not CESR", b"-"])
def test_put_rejects_malformed_tail_before_processing_valid_prefix(tail):
    with _remoteSignerLab(f"observer-put-tail-{tail!r}") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        serder = SerderKERI(raw=bytearray(replay))
        enclosedReplay = serder.raw + Counter.enclose(
            qb64=replay[serder.size :], code=Codens.AttachmentGroup
        )
        response = _putKel(client, enclosedReplay + tail)
        assert response.status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers
        assert _putKel(client, replay).status == falcon.HTTP_204


def test_put_rejects_unaccepted_rotation_but_allows_complete_retry():
    with _remoteSignerLab("observer-put-retry") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        signer.rotate()
        with openHby(
            name="observer-put-rotation-attacker",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            invalidRotation = bytes(
                attacker.endorse(
                    signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                )
            )
        assert _putKel(client, inception + invalidRotation).status == falcon.HTTP_400
        assert observerHby.kevers[signer.pre].sn == 0
        assert not observerHby.db.kels.get(keys=signer.pre, on=1)
        assert _putKel(client, _signerKel(signer)).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1


def test_put_checks_every_event_not_only_the_final_rotation():
    with _remoteSignerLab("observer-put-intermediate") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        signer.rotate()
        with openHby(
            name="observer-put-intermediate-attacker",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            invalidRotation = bytes(
                attacker.endorse(
                    signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                )
            )
        signer.rotate()
        finalRotation = bytes(
            signer.endorse(signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
        )
        assert _putKel(client, inception + invalidRotation + finalRotation).status == (
            falcon.HTTP_400
        )
        assert not observerHby.db.kels.get(keys=signer.pre, on=1)
        assert not observerHby.db.kels.get(keys=signer.pre, on=2)


def test_put_rejects_modified_body_with_previously_accepted_said():
    with _remoteSignerLab("observer-put-said") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        assert _putKel(client, replay).status == falcon.HTTP_204
        changed = replay.replace(signer.pre.encode(), ("E" + "A" * 43).encode(), 1)
        assert changed != replay
        assert _putKel(client, changed).status == falcon.HTTP_400
        assert observerHby.kevers[signer.pre].serder.said == signer.kever.serder.said


def test_put_does_not_hide_one_shot_storage_errors(monkeypatch):
    with _remoteSignerLab("observer-put-storage-error") as (
        issuer,
        signer,
        _observerHby,
        ctx,
        client,
        _regk,
        _tel,
    ):
        originalGet = ctx.kvy.db.kels.get
        calls = 0

        def fail_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("storage unavailable")
            return originalGet(*args, **kwargs)

        monkeypatch.setattr(ctx.kvy.db.kels, "get", fail_once)
        assert _putKel(client, _signerKel(signer)).status == falcon.HTTP_500
        assert calls == 1
        assert originalGet(keys=issuer.pre, on=0)


def test_put_rejects_oversized_attachment_group_before_processing():
    with _remoteSignerLab("observer-put-attachment-group") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        serder = SerderKERI(raw=bytearray(replay))
        attachments = replay[serder.size :]
        group = Counter.enclose(qb64=attachments, code=Codens.AttachmentGroup)
        counter = Counter(qb64b=group[:4])
        malformedGroup = (
            Counter(
                code=Codens.AttachmentGroup,
                count=counter.count + 1,
            ).qb64b
            + attachments
        )
        assert _putKel(client, serder.raw + malformedGroup).status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers


def test_put_size_limit_content_type_and_allow_header(monkeypatch):
    with _remoteSignerLab("observer-put-limits") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        assert _putKel(client, replay, "application/json").status == falcon.HTTP_406
        atLimit = (b"not CESR" + b" " * (8 * 1024 * 1024))[: 8 * 1024 * 1024]
        assert len(atLimit) == 8 * 1024 * 1024
        assert _putKel(client, atLimit).status == falcon.HTTP_400
        assert _putKel(client, replay + b"x" * (8 * 1024 * 1024 + 1)).status == (
            falcon.HTTP_413
        )
        declaredLarge = client.simulate_request(
            method="PUT",
            path="/",
            body=replay,
            headers={"Content-Type": CESR_CONTENT_TYPE},
            extras={"CONTENT_LENGTH": str(8 * 1024 * 1024 + 1)},
        )
        assert declaredLarge.status == falcon.HTTP_413
        assert signer.pre not in observerHby.kevers
        method = client.simulate_get("/")
        assert method.status == falcon.HTTP_405
        assert "PUT" in method.headers["allow"]

    from types import SimpleNamespace

    from kfobserver.app import httping

    class BoundedRead:
        sizes = []

        def read(self, size):
            self.sizes.append(size)
            return b"x" * size

    stream = BoundedRead()
    req = SimpleNamespace(
        content_type=CESR_CONTENT_TYPE,
        content_length=None,
        bounded_stream=stream,
    )
    rep = SimpleNamespace()
    monkeypatch.setattr(httping, "PUT_BODY_LIMIT", 8)
    with pytest.raises(falcon.HTTPError) as error:
        httping.TelQueryEnd(None).on_put(req, rep)
    assert error.value.status == falcon.HTTP_413
    assert stream.sizes == [9]


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


@pytest.mark.parametrize(
    ("outcome", "route", "qextra", "status"),
    [
        ("success", "tels", {}, 200),
        ("success", "tels", {"sn": 1}, 200),
        ("success", "tels/head", {}, 200),
        ("pending", "tels", {}, 503),
        ("missing", "tels", {}, 404),
        ("http-failure", "tels", {}, 404),
        ("malformed", "tels", {}, 404),
        ("timeout", "tels", {}, 404),
        ("success", "tels", {"sn": "bad-number"}, 500),
        ("success", "tels", {"sn": []}, 500),
        ("success", "tels", {"sn": {}}, 500),
        ("missing", "tels", {"sn": "bad-number"}, 404),
        ("pending", "tels", {"sn": "bad-number"}, 503),
        ("missing", "tels", {"sn": []}, 404),
        ("pending", "tels", {"sn": {}}, 503),
        ("cancel", "tels", {}, None),
    ],
)
def test_ondemand_query_returns_same_request_without_stalling_scheduler(
    monkeypatch, outcome, route, qextra, status
):
    """Real signed query, backend HTTP, scheduler progress and deferred status."""
    doist = doing.Doist(tock=0.03125, real=False)
    progress = []
    backendTurns = []
    pulled = []
    closed = []
    malformed = []
    originalService = http.clienting.Client.service
    originalClose = http.clienting.Client.close

    def independentDo(tymth=None, tock=0.0, **kwa):
        while True:
            progress.append(tymth())
            yield tock

    def service(client):
        if client.connector.port == registrar.servant.ha[1]:
            backendTurns.append(len(progress))
            if outcome == "malformed" and not malformed:
                malformed.append(client)
                client.connector.serviceReceives = lambda: None
                client.connector.rxbs.extend(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\n"
                )
        originalService(client)

    def close(client):
        if client.connector.port == registrar.servant.ha[1]:
            closed.append(client)
        originalClose(client)

    monkeypatch.setattr(http.clienting.Client, "service", service)
    monkeypatch.setattr(http.clienting.Client, "close", close)

    with openHby(
        name="kf-obs-query-coop", base="test", temp=True, version=Vrsn_2_0
    ) as hby:
        issuer = hby.makeHab(name="issuer")
        hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        if outcome == "pending":
            ripper = regcept(israid=issuer.pre, stamp=STAMP0)
            stream = telStream(ripper)
            bulk = stream  # Deliberately unanchored.
        else:
            ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)
            kel = b"".join(issuer.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0))
            bulk = kel + stream

        class RegistrarEnd:
            def on_post(self, req, rep):
                raw = req.bounded_stream.read()
                dom = Parser(version=Vrsn_2_0).parseOne(
                    ims=bytearray(raw), framed=True, processive=False
                )
                assert dom.serder.ked["r"] == "tels/bulk"
                assert dom.serder.ked["i"] == ctx.hab.pre
                assert dom.serder.ked["q"] == {"i": ripper.said}
                assert dom.serder.pvrsn == Vrsn_2_0
                assert raw == bytes(
                    ctx.hab.endorse(dom.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
                )
                assert req.content_type == CESR_CONTENT_TYPE
                pulled.append(doist.tyme)
                if outcome == "http-failure":
                    rep.status = falcon.HTTP_503

                def delayed():
                    if outcome == "timeout":
                        while True:
                            yield b""
                    for _ in range(4):
                        yield b""
                    yield bulk if outcome not in ("missing", "http-failure") else b""

                rep.stream = delayed()

        peer = falcon.App()
        peer.add_route("/", RegistrarEnd())
        with http.serving.openServer(
            servant=tcp.Server(ha=("127.0.0.1", 0)), app=peer
        ) as registrar:
            registrar.servant.eha = registrar.servant.ha
            ctx = makeContext(
                hby=hby,
                alias="observer",
                registrars=[f"http://127.0.0.1:{registrar.servant.ha[1]}/"],
            )
            try:
                with http.serving.openServer(
                    servant=tcp.Server(ha=("127.0.0.1", 0)), app=ctx.app
                ) as observerServer:
                    observerServer.servant.eha = observerServer.servant.ha
                    client = http.clienting.Client(
                        hostname="127.0.0.1", port=observerServer.servant.ha[1]
                    )
                    qry = _telQuery(wallet, ripper.said, route=route, **qextra)
                    body = bytes(
                        wallet.endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0)
                    )
                    client.request(
                        method="POST",
                        path="/",
                        body=body,
                        headers={"Content-Type": CESR_CONTENT_TYPE},
                    )
                    doist.deeds = doist.enter(
                        doers=[
                            ctx,
                            http.ServerDoer(registrar),
                            http.ServerDoer(observerServer),
                            http.ClientDoer(client),
                            doing.doify(independentDo),
                        ]
                    )
                    try:
                        assert not ctx.observer.hasRegistry(ripper.said)
                        for _ in range(400):
                            doist.recur()
                            if outcome == "cancel" and len(set(backendTurns)) >= 2:
                                responder = next(iter(observerServer.reps.values()))
                                assert not responder.headed
                                responder.iterator.close()
                                assert len(closed) == 1
                                assert closed[0].connector.cs is None
                                return
                            if client.responses:
                                break
                        response = client.respond()
                        assert response is not None
                        assert response.status == status
                        assert len(pulled) == (0 if outcome == "malformed" else 1)
                        assert len(set(backendTurns)) >= (
                            1 if outcome == "malformed" else 4
                        )
                        assert len(closed) == 1
                        assert closed[0].connector.cs is None
                        if outcome == "malformed":
                            assert len(malformed) == 1
                        if outcome == "success" and status == 200:
                            assert response.headers["content-type"] == CESR_CONTENT_TYPE
                            assert bytes(response.body) == (
                                bytes(bup.raw)
                                if qextra or route == "tels/head"
                                else stream
                            )
                            fresh = _telQuery(
                                wallet, ripper.said, route=route, **qextra
                            )
                            body = bytes(
                                wallet.endorse(
                                    fresh, last=True, framed=False, gvrsn=Vrsn_2_0
                                )
                            )
                            client.request(
                                method="POST",
                                path="/",
                                body=body,
                                headers={"Content-Type": CESR_CONTENT_TYPE},
                            )
                            for _ in range(100):
                                doist.recur()
                                if client.responses:
                                    break
                            assert client.respond().status == 200
                            assert len(pulled) == 1  # Now served from the local store.
                        else:
                            assert (
                                response.headers["content-type"] == "application/json"
                            )
                            assert (ripper.said in ctx.observer.pending) == (
                                outcome == "pending"
                            )
                            if outcome == "success":
                                fresh = _telQuery(wallet, ripper.said, **qextra)
                                body = bytes(
                                    wallet.endorse(
                                        fresh, last=True, framed=False, gvrsn=Vrsn_2_0
                                    )
                                )
                                client.request(
                                    method="POST",
                                    path="/",
                                    body=body,
                                    headers={"Content-Type": CESR_CONTENT_TYPE},
                                )
                                for _ in range(100):
                                    doist.recur()
                                    if client.responses:
                                        break
                                assert client.respond().status == 500
                                assert len(pulled) == 1
                    finally:
                        doist.exit()
            finally:
                ctx.observer.close()


@pytest.mark.parametrize("replay_after_restart", [False, True])
def test_persisted_remote_signer_authenticates_after_database_reopen(replay_after_restart):
    """Accepted history survives restart without weakening query authentication."""
    with _remoteSignerLab("observer-restarted-signer") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        regk,
        tel,
    ):
        signer.rotate()
        replay = _signerKel(signer)
        assert _putKel(client, replay).status == falcon.HTTP_204
        db = observerHby.db
        path = db.path
        db.kevers.clear()
        db.reopen(reuse=True)
        assert db.path == path
        assert db.states.get(signer.pre) is not None
        assert not dict.__contains__(db.kevers, signer.pre)
        if replay_after_restart:
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert not dict.__contains__(db.kevers, signer.pre)
        response = _signedTelQuery(client, signer, regk)
        assert response.status == falcon.HTTP_200
        assert response.content == tel
        with openHby(
            name="restart-attacker", base="test", temp=True, version=Vrsn_2_0
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            assert _signedTelQuery(client, attacker, regk).status == falcon.HTTP_401
            assert db.states.get(attacker.pre) is None
            assert _putKel(client, _signerKel(attacker)).status == falcon.HTTP_204
            assert (
                _signedTelQuery(client, signer, regk, endorser=attacker).status
                == falcon.HTTP_401
            )
