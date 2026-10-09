# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_keling module

KEL/TEL split, KEL ingest, and witness fallback helpers.
"""

from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHab, openHby
from keri.core import Blinder, Kevery
from keri.core.signing import Salter
from hio.base import doing
from hio.base.doing import Doist
from hio.core import http
import pytest

from kfobserver.core import keling
from kfobserver.core.cooperative import responseDo
from kfobserver.core.keling import WitnessKelFetcher, fetchKelOnce
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
        blinder = Blinder.blind(
            acdc=acdc.said, state="issued", salt=SALT, sn=1
        )
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

    # Unreachable witness returns empty without raising.
    assert fetchKelOnce(issuer, "http://127.0.0.1:1/", aid=issuer, timeout=0.05) == b""


def test_cooperative_http_wait_allows_other_scheduled_work_to_advance():
    """An unfinished HTTP response yields control to unrelated doers."""

    class NoResponseClient:
        responses = []
        respondent = None

    class Harness(doing.DoDoer):
        def __init__(self):
            self.progress = 0
            self.response = "waiting"
            super().__init__(
                doers=[
                    doing.doify(self.requestDo),
                    doing.doify(self.independentDo),
                ],
                always=True,
            )

        def requestDo(self, tymth=None, tock=0.1, **kwa):
            self.wind(tymth)
            client = NoResponseClient()
            self.response = yield from responseDo(
                self, client, timeout=0.3, clientDoer=doing.Doer(tock=0.1)
            )

        def independentDo(self, tymth=None, tock=0.1, **kwa):
            self.wind(tymth)
            while True:
                self.progress += 1
                yield tock

    harness = Harness()
    Doist(tock=0.1, real=False, limit=0.7).do(doers=[harness])
    assert harness.progress >= 3
    assert harness.response is None


def test_registrar_pull_http_wait_does_not_stall_other_doers(monkeypatch):
    """The scheduled registrar pull services HTTP cooperatively."""
    progress = [0]
    serviceProgress = []

    class NoResponseClient:
        responses = []
        respondent = None

        def __init__(self, **kwa):
            pass

        def request(self, **kwa):
            pass

        def wind(self, tymth):
            pass

        def reopen(self):
            pass

        def service(self):
            serviceProgress.append(progress[0])

        def close(self):
            pass

    class ObserverStub:
        def ingest(self, raw, kvy=None):
            raise AssertionError("an unanswered request has no response body")

        def retryPending(self):
            return {}

    monkeypatch.setattr(http.clienting, "Client", NoResponseClient)

    def independentDo(tymth=None, tock=0.1, **kwa):
        while True:
            progress[0] += 1
            yield tock

    with openHab(name="obs-pull-coop", temp=True, version=Vrsn_2_0) as (_hby, hab):
        puller = RegistrarPuller(
            hab=hab,
            observer=ObserverStub(),
            urls=["http://registrar/"],
            tock=0.1,
        )
        Doist(tock=0.1, real=False, limit=0.8).do(
            doers=[puller, doing.doify(independentDo, tock=0.1)]
        )

    assert serviceProgress
    assert len(set(serviceProgress)) > 1


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
