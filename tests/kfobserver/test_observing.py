# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_observing module

Ingest, query, and reject-unverified tests for the observer TEL store.
"""

from keri import Vrsn_2_0, Ilks
from keri.acdc import acdcmap, blindate, regeventing, regcept
from keri.app import habbing
from keri.core import Blinder, SerderACDC
from keri.core.signing import Salter

from kfobserver.core.observing import Observer, parseTelStream


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def seal(serder):
    return dict(s=serder.sad["n"], d=serder.said)


def anchor(hab, *serders):
    hab.interact(data=[seal(serder) for serder in serders])
    return hab.kever.serder


def makeRegistry(hab, stamp=STAMP0, anchored=True):
    ripper = regcept(israid=hab.pre, stamp=stamp)
    if anchored:
        anchor(hab, ripper)
    return ripper


def makeUpdate(regid, prior, acdc, state, *, sn=1, stamp=None, salt=SALT):
    blinder = Blinder.blind(acdc=acdc, state=state, salt=salt, sn=sn)
    bup = blindate(regid=regid, prior=prior, blid=blinder.said, sn=sn, stamp=stamp)
    return blinder, bup


def makeAcdc(hab, regid=None, name="Sunspot College"):
    return acdcmap(
        israid=hab.pre,
        regid=regid,
        attribute=dict(d="", name=name, level="gold"),
    )


def remake(serder, **changes):
    sad = dict(serder.sad)
    sad.update(changes)
    sad["d"] = ""
    return SerderACDC(sad=sad, makify=True)


def telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def test_ingest_bulk_clone_stores_verified_heads():
    """Ingest a contiguous rip+bup clone; heads match the source TEL."""
    with habbing.openHab(name="obs-ingest", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        anchor(hab, bup)
        stream = telStream(ripper, bup)

        observer = Observer(hby=hby)
        try:
            summary = observer.ingest(stream)
            assert ripper.said in summary["accepted"]
            assert summary["accepted"][ripper.said] == 2
            assert observer.clone(ripper.said) == stream
            assert observer.last(ripper.said).said == bup.said
            assert observer.last(ripper.said).ilk == Ilks.bup
        finally:
            observer.close()


def test_query_last_all_since_sn():
    """last / all / since sn return only the verified TEL."""
    with habbing.openHab(name="obs-query", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        anchor(hab, bup)

        observer = Observer(hby=hby)
        try:
            observer.ingest(telStream(ripper, bup))
            assert observer.lastRaw(ripper.said) == bytes(bup.raw)
            assert observer.clone(ripper.said, sn=0) == telStream(ripper, bup)
            assert observer.clone(ripper.said, sn=1) == bytes(bup.raw)
            assert observer.clone(ripper.said, sn=2) == b""
        finally:
            observer.close()


def test_unanchored_bulk_is_not_served():
    """Missing KEL anchors escrows the batch; head stays empty."""
    with habbing.openHab(name="obs-anchor", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )

        observer = Observer(hby=hby)
        try:
            summary = observer.ingest(telStream(ripper, bup))
            assert ripper.said in summary["pending"]
            assert not observer.hasRegistry(ripper.said)
            assert observer.clone(ripper.said) == b""

            # After anchors land, retry accepts.
            anchor(hab, ripper, bup)
            retried = observer.retryPending()
            assert ripper.said in retried["accepted"]
            assert observer.last(ripper.said).said == bup.said
        finally:
            observer.close()


def test_tampered_bulk_is_rejected():
    """Misdigested bup is not stored or served."""
    with habbing.openHab(name="obs-tamper", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        anchor(hab, bup)
        bad = remake(bup, p="E" + "A" * 43)  # wrong prior SAID shape-ish

        observer = Observer(hby=hby)
        try:
            # First store a good head, then attempt a second registry with tamper
            goodRip = makeRegistry(hab, stamp=STAMP1)
            summary = observer.ingest(telStream(ripper, bad))
            # rip alone may verify; bad bup causes rejection of the batch
            assert ripper.said in summary["rejected"] or ripper.said not in summary["accepted"]
            # Do not advance past a verified rip if bup fails — whole batch rejected
            if ripper.said in summary["rejected"]:
                assert not observer.hasRegistry(ripper.said)

            # Completely foreign prior on an otherwise valid-looking chain
            summary2 = observer.ingest(telStream(goodRip, remake(bup, rd=goodRip.said, p=goodRip.said)))
            # bup from another registry remade into goodRip will fail digests/anchors
            assert goodRip.said in summary2["rejected"] or goodRip.said in summary2["pending"]
            if goodRip.said in summary2["rejected"]:
                assert not observer.hasRegistry(goodRip.said)
        finally:
            observer.close()


def test_verifier_style_unblinded_block_plus_observer_tel():
    """Unblinded block + observer-served TEL succeeds with regeventing.vet."""
    with habbing.openHab(name="obs-vet", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        anchor(hab, bup)

        observer = Observer(hby=hby)
        try:
            observer.ingest(telStream(ripper, bup))
            cloned = observer.clone(ripper.said)
            events = parseTelStream(cloned)
            assert [e.ilk for e in events] == ["rip", "bup"]

            rec = regeventing.vet(
                rip=events[0],
                updates=events[1:],
                db=hby.db,
                acdc=acdc,
                blinder=blinder,
            )
            assert rec.state == "issued"
            assert rec.acdc == acdc.said
            assert rec.said == bup.said
        finally:
            observer.close()
