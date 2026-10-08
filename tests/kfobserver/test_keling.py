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

from kfobserver.core.keling import fetchKelOnce
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
