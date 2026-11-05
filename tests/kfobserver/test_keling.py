# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_keling module

KEL/TEL split, KEL ingest, and witness fallback helpers.
"""

from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHab, openHby
from keri.core import Blinder, Kevery, Number, Parser, Saider, SealSource, messagize
from keri.core.signing import Salter
from keri.kering import ValidationError
import ssl
from types import SimpleNamespace

import falcon
from hio.base import doing
from hio.base.doing import Doist
from hio.core import http, tcp
import pytest

from kfobserver.core import keling, pulling
from kfobserver.core.keling import WitnessKelFetcher
from kfobserver.core.pulling import RegistrarPuller
from kfobserver.core.observing import Observer, ingestKel, splitKelTel


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def _kelClone(hab):
    stream = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0):
        stream.extend(msg)
    return bytes(stream)


def _telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def test_split_kel_tel_and_ingest_across_haberies():
    """Leading KEL from a foreign Habery lets observer vet without shared Hab."""
    with openHab(name="kel-issuer", temp=True, version=Vrsn_2_0) as (_ihby, issuer):
        rip = regcept(israid=issuer.pre, stamp=STAMP0)
        issuer.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        acdc = acdcmap(
            israid=issuer.pre,
            regid=rip.said,
            attribute=dict(d="", name="presentation"),
        )
        blinder = Blinder.blind(acdc=acdc.said, state="issued", salt=SALT, sn=1)
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        issuer.interact(data=[dict(s=bup.sad["n"], d=bup.said)])
        kel = _kelClone(issuer)
        tel = _telStream(rip, bup)
        bulk = kel + tel
        regk = rip.said
        issuerPre = issuer.pre

    kelPart, telPart = splitKelTel(bulk)
    assert kelPart == kel
    assert telPart == tel

    with openHby(name="kel-obs", base="test", temp=True, version=Vrsn_2_0) as hby:
        kvy = Kevery(db=hby.db, lax=True, local=False)
        observer = Observer(hby=hby, kvy=kvy)
        try:
            assert issuerPre not in hby.kevers
            summary = observer.ingest(bulk)
            assert regk in summary["accepted"]
            assert issuerPre in hby.kevers
            assert observer.clone(regk) == tel
        finally:
            observer.close()


def test_tel_only_bulk_still_works_when_kel_preloaded():
    """TEL-only streams remain valid when the issuer KEL is already local."""
    with openHab(name="kel-local", temp=True, version=Vrsn_2_0) as (hby, hab):
        rip = regcept(israid=hab.pre, stamp=STAMP0)
        hab.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        kvy = Kevery(db=hby.db, lax=True, local=False)
        observer = Observer(hby=hby, kvy=kvy)
        try:
            summary = observer.ingest(_telStream(rip))
            assert rip.said in summary["accepted"]
        finally:
            observer.close()


def test_ingest_kel_bytes_into_observer_baser():
    """Witness fallback body path: ingestKel loads a foreign KEL for vet."""
    with openHab(name="kel-wit", temp=True, version=Vrsn_2_0) as (_hby, hab):
        kel = _kelClone(hab)
        issuer = hab.pre

    with openHby(name="kel-fetch-obs", base="test", temp=True, version=Vrsn_2_0) as hby:
        kvy = Kevery(db=hby.db, lax=True, local=False)
        ingestKel(kvy, kel)
        assert issuer in hby.kevers


@pytest.mark.parametrize("invalid", ["signature", "truncated", "trailing"])
def test_bulk_rejects_invalid_issuer_history(invalid):
    """Malformed input and a wrong signature cannot introduce issuer state."""
    with openHab(name="invalid-bulk", temp=True, version=Vrsn_2_0) as (remote, issuer), \
            openHby(name="invalid-verifier", temp=True, version=Vrsn_2_0) as hby:
        raw = _kelClone(issuer)
        if invalid == "signature":
            attacker = remote.makeHab(name="attacker")
            serder = issuer.kever.serder
            raw = messagize(serder, sigers=attacker.sign(ser=serder.raw, indexed=True),
                            gvrsn=Vrsn_2_0)
        elif invalid == "truncated":
            raw = raw[:-1]
        else:
            raw += b"invalid trailing bytes"
        with pytest.raises(ValidationError):
            ingestKel(Kevery(db=hby.db, lax=True, local=False), raw)
        assert issuer.pre not in hby.kevers


def test_bulk_waits_for_required_witness_receipts():
    """A later complete replay resolves native escrow without weakening toad."""
    with openHab(name="bulk-witness", temp=True, transferable=False,
                 version=Vrsn_2_0) as (remote, witness), \
            openHby(name="receipt-verifier", temp=True, version=Vrsn_2_0) as hby:
        issuer = remote.makeHab(name="issuer", wits=[witness.pre], toad=1)
        inception = issuer.kever.serder
        rip = regcept(israid=issuer.pre)
        issuer.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        observer = Observer(hby=hby, kvy=Kevery(db=hby.db, lax=True, local=False))
        try:
            pending = observer.ingest(_kelClone(issuer) + rip.raw)
            assert rip.said in pending["pending"]
            assert issuer.pre not in hby.kevers
            kel = bytearray()
            for serder in (inception, issuer.kever.serder):
                kel.extend(messagize(
                    serder, sigers=issuer.sign(ser=serder.raw, indexed=True),
                    wigers=witness.sign(ser=serder.raw, indexed=True), gvrsn=Vrsn_2_0,
                ))
            accepted = observer.ingest(bytes(kel) + rip.raw)
            assert rip.said in accepted["accepted"]
            assert observer.clone(rip.said) == rip.raw
        finally:
            observer.close()


def test_bulk_waits_for_delegator_history():
    """A delegate cannot anchor TELs until its delegation is verified."""
    with openHab(name="bulk-delegator", temp=True, version=Vrsn_2_0) as (remote, delegator), \
            openHby(name="delegation-verifier", temp=True, version=Vrsn_2_0) as hby:
        issuer = remote.makeHab(name="issuer", delpre=delegator.pre)
        inception = issuer.kever.serder
        rip = regcept(israid=issuer.pre)
        issuer.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        observer = Observer(hby=hby, kvy=Kevery(db=hby.db, lax=True, local=False))
        try:
            pending = observer.ingest(_kelClone(issuer) + rip.raw)
            assert rip.said in pending["pending"]
            assert issuer.pre not in hby.kevers
            delegator.interact(data=[dict(i=issuer.pre, s="0", d=inception.said)],
                               gvrsn=Vrsn_2_0)
            bond = SealSource(s=Number(num=delegator.kever.sn),
                              d=Saider(qb64=delegator.kever.serder.said))
            dip = messagize(inception, sigers=issuer.sign(ser=inception.raw, indexed=True),
                            bonds=[bond], gvrsn=Vrsn_2_0)
            anchor = issuer.kever.serder
            ixn = messagize(anchor, sigers=issuer.sign(ser=anchor.raw, indexed=True),
                            gvrsn=Vrsn_2_0)
            accepted = observer.ingest(_kelClone(delegator) + dip + ixn + rip.raw)
            assert rip.said in accepted["accepted"]
            assert observer.clone(rip.said) == rip.raw
        finally:
            observer.close()


def test_stale_witness_response_falls_through_to_witness_with_anchor(monkeypatch):
    """A stale 200 response does not stop the configured witness search."""
    issuer = "issuer-aid"

    class PendingObserver:
        def __init__(self):
            self.pending = True
            self.received = []

        def pendingIssuers(self):
            return [issuer] if self.pending else []

        def retryPending(self):
            if self.received and self.received[-1] == b"required-kel":
                self.pending = False
                return {"accepted": {"registry": 2}, "pending": {}, "rejected": {}}
            return {"accepted": {}, "pending": {"registry": 2}, "rejected": {}}

    observer = PendingObserver()
    requested = []

    def fakeFetchDo(owner, issuer_aid, url, aid=None, **kwa):
        requested.append(url)
        yield 0.1
        return b"stale-kel" if len(requested) == 1 else b"required-kel"

    def fakeIngest(_kvy, raw):
        observer.received.append(raw)

    monkeypatch.setattr(keling, "fetchKelDo", fakeFetchDo)
    monkeypatch.setattr(keling, "ingestKel", fakeIngest)
    fetcher = WitnessKelFetcher(
        observer=observer,
        kvy=object(),
        witnesses=[{"url": "http://stale/"}, {"url": "http://current/"}],
        tock=0.1,
    )
    assert observer.pendingIssuers() == [issuer]
    assert len(fetcher.witnesses) == 2
    fetchDo = fetcher.fetchDo(tymth=lambda: 0.0, tock=0.1)
    next(fetchDo)  # initial poll interval
    assert requested == []
    next(fetchDo)  # stale witness request yields
    assert requested == ["http://stale/"]
    next(fetchDo)  # stale result advances to the next witness
    next(fetchDo)  # required-state witness returns

    assert requested == ["http://stale/", "http://current/"]
    assert observer.received == [b"stale-kel", b"required-kel"]
    assert observer.pending is False


@pytest.mark.parametrize(
    ("responses", "expected_urls", "pending_after_pass"),
    [
        ((b"required-kel", b"unused"), ["http://first/"], False),
        ((b"stale-kel", b"stale-kel"), ["http://first/", "http://second/"], True),
        ((b"", b""), ["http://first/", "http://second/"], True),
    ],
)
def test_witness_search_stops_on_state_or_after_all_witnesses(
    monkeypatch, responses, expected_urls, pending_after_pass
):
    """A satisfying first witness stops; stale results visit each witness once."""
    issuer = "issuer-aid"

    class PendingObserver:
        pending = True
        received = []

        def pendingIssuers(self):
            return [issuer] if self.pending else []

        def retryPending(self):
            if self.received and self.received[-1] == b"required-kel":
                self.pending = False
            return {"accepted": {}, "pending": {}, "rejected": {}}

    observer = PendingObserver()
    requested = []

    def fakeFetchDo(owner, issuer_aid, url, aid=None, **kwa):
        requested.append(url)
        yield 0.1
        return responses[len(requested) - 1]

    monkeypatch.setattr(keling, "fetchKelDo", fakeFetchDo)
    monkeypatch.setattr(
        keling, "ingestKel", lambda _kvy, raw: observer.received.append(raw)
    )
    fetcher = WitnessKelFetcher(
        observer=observer,
        kvy=object(),
        witnesses=[{"url": "http://first/"}, {"url": "http://second/"}],
        tock=0.1,
    )
    fetchDo = fetcher.fetchDo(tymth=lambda: 0.0, tock=0.1)

    next(fetchDo)  # initial poll interval
    next(fetchDo)  # first witness request yields
    assert requested == ["http://first/"]
    if len(expected_urls) == 2:
        next(fetchDo)  # stale result starts the second witness request
        assert requested == expected_urls
        next(fetchDo)  # second stale result ends this bounded pass
    else:
        next(fetchDo)  # satisfying result stops this pass

    assert requested == expected_urls
    assert observer.pending is pending_after_pass


@pytest.mark.parametrize("kind", ["registrar", "witness"])
@pytest.mark.parametrize("failure", [None, "construct", "reopen"])
def test_default_poll_services_http_and_delays_between_passes(
    monkeypatch, kind, failure
):
    """Real clients finish at scheduler cadence; the next pass waits five seconds."""
    doist = Doist(tock=0.03125, real=False, limit=10.0)
    requested = []
    completed = []
    progress = []
    closed = []
    failed_at = []
    originalClient = http.clienting.Client
    originalClose = http.clienting.Client.close

    if failure == "construct":
        attempts = []

        def client(*args, **kwa):
            attempts.append(None)
            if len(attempts) == 1:
                failed_at.append(doist.tyme)
                raise OSError("connection setup failed")
            return originalClient(*args, **kwa)

        monkeypatch.setattr(http.clienting, "Client", client)
    elif failure == "reopen":
        originalReopen = originalClient.reopen
        attempts = []

        def reopen(client):
            attempts.append(client)
            if len(attempts) == 1:
                failed_at.append(doist.tyme)
                raise OSError("connection open failed")
            return originalReopen(client)

        monkeypatch.setattr(originalClient, "reopen", reopen)

    def close(client):
        closed.append(client)
        originalClose(client)

    monkeypatch.setattr(originalClient, "close", close)

    class Peer:
        def on_post(self, req, rep):
            raw = req.bounded_stream.read()
            dom = Parser(version=Vrsn_2_0).parseOne(
                ims=bytearray(raw), framed=True, processive=False
            )
            assert req.content_type == pulling.CESR_CONTENT_TYPE
            assert dom.serder.ked["r"] == "tels/bulk"
            assert dom.serder.ked["i"] == hab.pre
            assert dom.serder.ked["q"] == {}
            assert dom.serder.pvrsn == Vrsn_2_0
            assert dom.lsgs
            assert raw == bytes(
                hab.endorse(dom.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
            )
            self.respond(rep)

        def on_get(self, req, rep):
            assert req.path == "/log"
            assert req.get_param("pre") == "issuer"
            assert req.get_header("Accept") == keling.CESR_CONTENT_TYPE
            assert req.get_header(keling.CESR_DESTINATION_HEADER) == "witness-aid"
            self.respond(rep)

        def respond(self, rep):
            requested.append(doist.tyme)

            def delayed():
                for _ in range(3):
                    yield b""
                yield b"cesr"

            rep.stream = delayed()

    class ObserverStub:
        def pendingIssuers(self):
            return ["issuer"]

        def retryPending(self):
            if kind == "witness":
                completed.append(doist.tyme)
            return {}

        def ingest(self, raw, kvy=None):
            assert raw == b"cesr"
            completed.append(doist.tyme)
            return {}

    def independentDo(tymth=None, tock=0.0, **kwa):
        while True:
            progress.append(tymth())
            yield tock

    app = falcon.App()
    app.add_route("/", Peer())
    app.add_route("/log", Peer())
    with openHab(name="default-poll", temp=True, version=Vrsn_2_0) as (_hby, hab):
        with http.serving.openServer(
            servant=tcp.Server(ha=("127.0.0.1", 0)), app=app
        ) as server:
            server.servant.eha = server.servant.ha
            url = f"http://127.0.0.1:{server.servant.ha[1]}/"
            observer = ObserverStub()
            if kind == "registrar":
                poller = RegistrarPuller(hab, observer, urls=[url])
            else:
                poller = WitnessKelFetcher(
                    observer, object(), witnesses=[{"url": url, "aid": "witness-aid"}]
                )
                # The network request is real; these bytes stand in for a KEL here.
                monkeypatch.setattr(keling, "ingestKel", lambda kvy, raw: None)
            doist.do(
                doers=[http.ServerDoer(server), poller, doing.doify(independentDo)]
            )
    assert len(requested) >= (2 if failure is None else 1)
    assert len(requested) == len(completed)
    assert completed[0] - requested[0] < 1.0
    if failure is None:
        assert requested[1] - completed[0] >= 5.0
    else:
        assert requested[0] - failed_at[0] >= 5.0
        assert len(attempts) >= 2
        assert any(failed_at[0] < t < requested[0] for t in progress)
    assert len([t for t in progress if requested[0] <= t <= completed[0]]) >= 3
    assert poller.interval == 5.0
    assert len(closed) == len(completed) + (failure == "reopen")
    assert all(client.connector.cs is None for client in closed)


@pytest.mark.parametrize("kind", ["registrar", "witness"])
def test_malformed_chunk_uses_fallback_and_closes_request(monkeypatch, kind):
    """A real HIO parse failure closes that source and the next source works."""
    doist = Doist(tock=0.03125, real=False, limit=5.75)
    malformed = []
    attempts = []
    seen = set()
    ingested = []
    closed = []
    progress = []
    originalService = http.clienting.Client.service
    originalClose = http.clienting.Client.close

    def service(client):
        if id(client) not in seen:
            seen.add(id(client))
            source = (
                "first" if client.connector.port == first.servant.ha[1] else "second"
            )
            attempts.append((source, doist.tyme))
        if client.connector.port == first.servant.ha[1] and not malformed:
            malformed.append(client)
            client.connector.serviceReceives = lambda: None
            client.connector.rxbs.extend(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\n"
            )
        originalService(client)

    def close(client):
        closed.append(client)
        originalClose(client)

    monkeypatch.setattr(http.clienting.Client, "service", service)
    monkeypatch.setattr(http.clienting.Client, "close", close)

    class Peer:
        def on_post(self, _req, rep):
            rep.data = b"cesr"

        def on_get(self, _req, rep):
            rep.data = b"cesr"

    class ObserverStub:
        def pendingIssuers(self):
            return ["issuer"]

        def retryPending(self):
            return {}

        def ingest(self, raw, kvy=None):
            assert raw == b"cesr"
            ingested.append(raw)
            return {}

    def independentDo(tymth=None, tock=0.0, **kwa):
        while True:
            progress.append(tymth())
            yield tock

    firstApp = falcon.App()
    firstApp.add_route("/", Peer())
    firstApp.add_route("/log", Peer())
    secondApp = falcon.App()
    secondApp.add_route("/", Peer())
    secondApp.add_route("/log", Peer())
    with openHab(name="malformed-chunk", temp=True, version=Vrsn_2_0) as (
        _hby,
        hab,
    ):
        with (
            http.serving.openServer(
                servant=tcp.Server(ha=("127.0.0.1", 0)), app=firstApp
            ) as first,
            http.serving.openServer(
                servant=tcp.Server(ha=("127.0.0.1", 0)), app=secondApp
            ) as second,
        ):
            first.servant.eha = first.servant.ha
            second.servant.eha = second.servant.ha
            urls = [
                f"http://127.0.0.1:{first.servant.ha[1]}/",
                f"http://127.0.0.1:{second.servant.ha[1]}/",
            ]
            observer = ObserverStub()
            if kind == "registrar":
                poller = RegistrarPuller(hab, observer, urls=urls, regk="registry")
            else:
                poller = WitnessKelFetcher(
                    observer,
                    object(),
                    witnesses=[{"url": url} for url in urls],
                )
                monkeypatch.setattr(
                    keling, "ingestKel", lambda _kvy, raw: ingested.append(raw)
                )
            doist.do(
                doers=[
                    http.ServerDoer(first),
                    http.ServerDoer(second),
                    poller,
                    doing.doify(independentDo),
                ]
            )

    assert len(malformed) == 1
    assert [source for source, _ in attempts[:3]] == ["first", "second", "first"]
    assert attempts[2][1] - attempts[1][1] >= 5.0
    assert ingested
    assert len(progress) >= 3
    assert len(closed) == len(attempts)
    assert malformed[0].connector.cs is None
    assert all(client.connector.cs is None for client in closed)


@pytest.mark.parametrize("kind", ["registrar", "witness"])
@pytest.mark.parametrize("failure", ["timeout", "tls", "socket", "http", "parse"])
def test_request_failure_cleans_up_and_scheduler_continues(monkeypatch, kind, failure):
    """Transport failures stay inside the request and a later poll still runs."""
    doist = Doist(tock=0.03125, real=False, limit=5.75)
    serviced = []
    closed = []
    progress = []
    originalService = http.clienting.Client.service
    originalClose = http.clienting.Client.close

    def service(client):
        serviced.append((client, doist.tyme, len(progress)))
        if failure == "tls":
            raise ssl.SSLCertVerificationError(1, "certificate verify failed")
        if failure == "socket":
            raise ConnectionResetError("connection reset by peer")
        if failure == "http":
            client.responses.append(
                dict(
                    version=(1, 1),
                    status=503,
                    reason="Service Unavailable",
                    headers={},
                    body=b"error",
                    data=None,
                    request={},
                    errored=False,
                    error=None,
                )
            )
        if failure == "parse":
            client.respondent.errored = True
        if failure == "timeout":
            # Exercise the actual service path with no response for this request.
            originalService(client)

    def close(client):
        closed.append((client, doist.tyme))
        originalClose(client)

    monkeypatch.setattr(http.clienting.Client, "service", service)
    monkeypatch.setattr(http.clienting.Client, "close", close)

    class ObserverStub:
        def pendingIssuers(self):
            return ["issuer"]

        def retryPending(self):
            return {}

        def ingest(self, raw, kvy=None):
            raise AssertionError("failed request must not be ingested")

    def independentDo(tymth=None, tock=0.0, **kwa):
        while True:
            progress.append(tymth())
            yield tock

    with openHab(name="failure-poll", temp=True, version=Vrsn_2_0) as (_hby, hab):
        app = falcon.App()  # Keep a listener open without ever servicing responses.
        with http.serving.openServer(
            servant=tcp.Server(ha=("127.0.0.1", 0)), app=app
        ) as server:
            server.servant.eha = server.servant.ha
            url = f"http://127.0.0.1:{server.servant.ha[1]}/"
            if kind == "registrar":
                poller = RegistrarPuller(hab, ObserverStub(), urls=[url])
            else:
                poller = WitnessKelFetcher(
                    ObserverStub(), object(), witnesses=[{"url": url}]
                )
            poller.timeout = 0.25
            doist.do(doers=[poller, doing.doify(independentDo)])
    assert len({id(client) for client, _, _ in serviced}) >= 2
    assert {id(client) for client, _, _ in serviced} == {
        id(client) for client, _ in closed
    }
    assert progress[-1] > closed[0][1]
    if failure == "timeout":
        first = serviced[0][0]
        turns = [turn for client, _, turn in serviced if client is first]
        assert len(set(turns)) >= 3
        assert 0.25 <= closed[0][1] - serviced[0][1] < 0.5


@pytest.mark.parametrize("kind", ["registrar", "witness"])
def test_request_cancellation_closes_client(monkeypatch, kind):
    """Closing a suspended domain coroutine releases its real client."""
    clients = []
    originalClose = http.clienting.Client.close

    def close(client):
        clients.append(client)
        originalClose(client)

    monkeypatch.setattr(http.clienting.Client, "close", close)
    owner = SimpleNamespace(tymth=lambda: 0.0)
    with openHab(name="cancel-pull", temp=True, version=Vrsn_2_0) as (_hby, hab):
        if kind == "registrar":
            request = pulling.pullDo(
                owner, hab, "http://127.0.0.1:1/", regk="registry", sn=2
            )
        else:
            request = keling.fetchKelDo(owner, "issuer", "http://127.0.0.1:1/")
        assert next(request) == b""
        request.close()
        if kind == "registrar":
            raw = bytes(clients[0].requester.body)
            dom = Parser(version=Vrsn_2_0).parseOne(
                ims=bytearray(raw), framed=True, processive=False
            )
            assert dom.serder.ked["q"] == {"i": "registry", "sn": 2}
            assert raw == bytes(
                hab.endorse(dom.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
            )
    assert len(clients) == 1
    assert clients[0].connector.cs is None


def test_complete_history_replay_invalidates_superseded_registry_anchor():
    """A recovery is replayed, and an old accepted TEL is no longer served."""
    from keri.core import rotate
    from keri.kering import MissingAnchorError

    with openHab(name="recovery-source", temp=True, version=Vrsn_2_0) as (source, issuer), \
            openHby(name="recovery-observer", temp=True, version=Vrsn_2_0) as hby:
        inception = issuer.kever.serder
        rip = regcept(israid=issuer.pre)
        issuer.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
        kvy = Kevery(db=hby.db, lax=True, local=False)
        observer = Observer(hby=hby, kvy=kvy)
        try:
            assert rip.said in observer.ingest(_kelClone(issuer) + rip.raw)["accepted"]
            assert observer.clone(rip.said) == rip.raw
            verfers, digers = source.mgr.rotate(pre=issuer.pre, temp=True)
            recovery = rotate(pre=issuer.pre, keys=[v.qb64 for v in verfers],
                              dig=inception.said, sn=1,
                              ndigs=[d.qb64 for d in digers], version=Vrsn_2_0)
            sigers = issuer.sign(ser=recovery.raw, verfers=verfers, rotated=True)
            source.kvy.processEvent(serder=recovery, sigers=sigers)
            stream = _kelClone(issuer) + rip.raw
            for _ in range(2):
                assert rip.said in observer.ingest(stream)["pending"]
                assert hby.kevers[issuer.pre].serder.said == recovery.said
                with pytest.raises(MissingAnchorError):
                    observer.clone(rip.said)
            issuer.interact(data=[dict(s=rip.sad["n"], d=rip.said)])
            assert rip.said in observer.ingest(_kelClone(issuer) + rip.raw)["accepted"]
            assert observer.clone(rip.said) == rip.raw
        finally:
            observer.close()
