# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_observing module

Ingest, query, and reject-unverified tests for the observer TEL store.
"""

import pytest

from keri import Vrsn_2_0, Ilks
from keri.acdc import Regery, acdcmap, blindate, regeventing, regcept
from keri.acdc.regbasing import RegBaser
from keri.app import habbing
from keri.core import Blinder, SerderACDC, rotate
from keri.core.signing import Salter
from keri.kering import DuplicitousRegistryError, MissingAnchorError

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


def openObserver(hby, path):
    baser = RegBaser(name=hby.name, temp=False, headDirPath=str(path))
    return Observer(hby=hby, rgy=Regery(hby=hby, baser=baser))


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


def test_unanchored_bulk_is_not_served(tmp_path):
    """A shorter accepted replay and a restart preserve the pending update."""
    with habbing.openHab(name="obs-anchor", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab, anchored=False)
        acdc = makeAcdc(hab, regid=ripper.said)
        blinder, bup = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )

        observer = openObserver(hby, tmp_path)
        try:
            summary = observer.ingest(telStream(ripper, bup))
            assert ripper.said in summary["pending"]
            assert not observer.hasRegistry(ripper.said)
            with pytest.raises(MissingAnchorError):
                observer.clone(ripper.said)

            anchor(hab, ripper)
            assert ripper.said in observer.ingest(ripper.raw)["accepted"]
            observer.close()
            observer = openObserver(hby, tmp_path)
            with pytest.raises(MissingAnchorError):
                observer.last(ripper.said)

            anchor(hab, bup)
            retried = observer.retryPending()
            assert ripper.said in retried["accepted"]
            assert observer.last(ripper.said).said == bup.said
        finally:
            observer.close()


@pytest.mark.parametrize("delivery", ["first", "second", "together", "after-recovery"])
def test_conflicting_anchored_tel_fork_recovers_on_verified_replay(tmp_path, delivery):
    """Either delivery order and a single bulk fork withhold the registry on reopen."""
    with habbing.openHab(name="obs-fork", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said, name="forked-history")
        _blinder, first = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        _other, second = makeUpdate(
            ripper.said,
            ripper.said,
            acdc.said,
            "revoked",
            sn=1,
            stamp=STAMP1,
            salt=Salter(raw=b"fedcba9876543210").qb64,
        )
        prior = anchor(hab, first)
        _, tail = makeUpdate(ripper.said, second.said, acdc.said, "issued", sn=2)
        anchor(hab, second, tail)

        observer = openObserver(hby, tmp_path)
        try:
            if delivery == "after-recovery":
                observer.ingest(telStream(ripper, first))
            elif delivery == "together":
                result = observer.ingest(telStream(ripper, first, second))
            else:
                accepted, other = (first, second) if delivery == "first" else (second, first)
                branch = (second, tail) if delivery == "second" else (first,)
                assert ripper.said in observer.ingest(telStream(ripper, *branch))["accepted"]
                result = observer.ingest(telStream(ripper, other))
                assert observer.store.seqSaider(ripper.said, 1).qb64 == accepted.said
            if delivery != "after-recovery":
                assert ripper.said in result["rejected"]
                observer.close()
                observer = openObserver(hby, tmp_path)
                with pytest.raises(DuplicitousRegistryError):
                    observer.clone(ripper.said)

            # Supersede the second anchor, then restore it without redelivering its TEL.
            verfers, digers = hby.mgr.rotate(pre=hab.pre, temp=True)
            recovery = rotate(pre=hab.pre, keys=[v.qb64 for v in verfers],
                              dig=prior.said, sn=prior.sn + 1,
                              ndigs=[d.qb64 for d in digers], version=Vrsn_2_0)
            sigers = hab.sign(ser=recovery.raw, verfers=verfers, rotated=True)
            hby.kvy.processEvent(serder=recovery, sigers=sigers)
            if delivery in ("second", "together"):
                with pytest.raises(MissingAnchorError):
                    observer.last(ripper.said)
                full = (first, second, tail) if delivery == "together" else (first,)
                replay = observer.ingest(telStream(ripper, *full))
                assert ripper.said in replay["accepted"]
            if delivery in ("second", "after-recovery"):
                stale = observer.ingest(telStream(ripper, second, tail))
                assert ripper.said in stale["rejected"]
                observer.close()
                observer = openObserver(hby, tmp_path)
            assert observer.clone(ripper.said) == telStream(ripper, first)
            assert observer.last(ripper.said).said == first.said
            if delivery == "after-recovery":
                _, nextUpdate = makeUpdate(ripper.said, first.said, acdc.said, "revoked", sn=2)
                mixed = telStream(ripper, first, second, tail, nextUpdate)
                assert ripper.said in observer.ingest(mixed)["pending"]
                anchor(hab, nextUpdate)
                observer.retryPending()
                assert observer.last(ripper.said).said == nextUpdate.said
            anchor(hab, second)
            with pytest.raises(DuplicitousRegistryError):
                observer.last(ripper.said)
        finally:
            observer.close()


@pytest.mark.parametrize("missing_head", [True, False], ids=["missing", "stale"])
def test_replay_repairs_head_preserves_history_and_allows_forward_progress(
    tmp_path, missing_head
):
    """Replay repairs an interrupted head write without replacing accepted history."""
    with habbing.openHab(name="obs-replay", temp=True, version=Vrsn_2_0) as (hby, hab):
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said, name="monotonic-history")
        _one, first = makeUpdate(
            ripper.said, ripper.said, acdc.said, "issued", sn=1, stamp=STAMP1
        )
        _two, second = makeUpdate(
            ripper.said, first.said, acdc.said, "revoked", sn=2, stamp=STAMP1
        )
        _three, third = makeUpdate(
            ripper.said, second.said, acdc.said, "reinstated", sn=3, stamp=STAMP1
        )
        anchor(hab, first, second, third)

        observer = openObserver(hby, tmp_path)
        try:
            assert (
                ripper.said
                in observer.ingest(telStream(ripper, first, second))["accepted"]
            )
            assert observer.last(ripper.said).said == second.said
            slots = [observer.store.seqSaider(ripper.said, sn).qb64 for sn in range(3)]
            if missing_head:
                observer.store.baser.heads.rem(keys=ripper.said)
            else:
                observer.store.baser.heads.pin(
                    keys=ripper.said, val=observer.store.seqSaider(ripper.said, 0)
                )
            observer.close()
            observer = openObserver(hby, tmp_path)
            assert (
                ripper.said
                in observer.ingest(telStream(ripper, first, second))["accepted"]
            )
            assert observer.hasRegistry(ripper.said)
            assert observer.last(ripper.said).said == second.said
            assert [
                observer.store.seqSaider(ripper.said, sn).qb64 for sn in range(3)
            ] == slots
            assert ripper.said in observer.ingest(telStream(ripper, first))["accepted"]
            assert observer.last(ripper.said).said == second.said
            assert observer.clone(ripper.said) == telStream(ripper, first, second)

            assert (
                ripper.said
                in observer.ingest(telStream(ripper, first, second, third))["accepted"]
            )
            assert observer.last(ripper.said).said == third.said
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
