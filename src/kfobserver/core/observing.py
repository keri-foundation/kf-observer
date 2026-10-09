# -*- encoding: utf-8 -*-
"""
kfobserver.core.observing module

Verified TEL ingest and query for other parties' registries.
"""

from collections import defaultdict

from keri import Vrsn_2_0, help
from keri.acdc import Regery, regeventing
from keri.core import Number, Parser, SerderACDC
from keri.core.coring import Saider
from keri.kering import MissingAnchorError, ValidationError


logger = help.ogler.getLogger()


def _acceptTelChain(store, regk, chain):
    """Persist a verified chain without replacing slots or regressing its head."""
    sequenced = [(Number(numh=serder.sad["n"]).num, serder) for serder in chain]
    for sn, serder in sequenced:
        current = store.seqEvent(regk, sn)
        if current is not None and current.said != serder.said:
            return f"conflicting TEL event at registry {regk} sequence {sn}"

    for sn, serder in sequenced:
        if store.seqEvent(regk, sn) is not None:
            continue

        # Keep valid historical gaps queryable while only moving the head
        # forward. RegistryStore.accept pins the head unconditionally.
        store.putEvent(serder)
        store.baser.tels.put(keys=regk, on=sn, val=Saider(qb64=serder.said))
        head = store.headEvent(regk)
        if head is None or sn > Number(numh=head.sad["n"]).num:
            store.baser.heads.pin(keys=regk, val=Saider(qb64=serder.said))
    return None


def _asBytes(value):
    """Coerce CESR text or bytes to bytes."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


def ingestKel(kvy, kel):
    """Parse a CESR KEL stream into the observer Kevery / Habery Baser.

    Parameters:
        kvy (Kevery): key-event processor bound to hby.db.
        kel (bytes | bytearray | str): signed KEL clone for TEL issuer(s).

    Returns:
        None
    """
    ims = bytearray(_asBytes(kel))
    if not ims:
        return
    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
    kvy.processEscrows()


def splitKelTel(stream):
    """Split a registrar bulk body into leading KEL CESR and trailing TEL CESR.

    Registrar bulk prepends issuer KEL clones (event + attachments) before
    ``rip``/``bup`` bodies. TEL starts at the first ACDC ``rip`` or ``bup``.

    Parameters:
        stream (bytes | bytearray | str): mixed or TEL-only CESR.

    Returns:
        tuple[bytes, bytes]: (kel, tel). Either may be empty.
    """
    ims = bytearray(_asBytes(stream))
    kel = bytearray()
    while ims:
        try:
            acdc = SerderACDC(raw=ims)
            if acdc.ilk in ("rip", "bup"):
                break
        except Exception:
            pass
        before = len(ims)
        snap = bytes(ims)
        try:
            Parser(version=Vrsn_2_0).parseOne(
                ims=ims, framed=True, processive=False
            )
        except Exception:
            # Not a framed KERI message; treat remainder as TEL.
            break
        kel.extend(snap[: before - len(ims)])
    return bytes(kel), bytes(ims)


def parseTelStream(stream):
    """Parse concatenated CESR TEL event bodies into SerderACDC instances.

    Parameters:
        stream (bytes | bytearray): concatenated ``rip`` / ``bup`` bodies.

    Returns:
        list[SerderACDC]: parsed events in stream order.
    """
    ims = bytearray(stream or b"")
    events = []
    while ims:
        serder = SerderACDC(raw=ims)
        events.append(serder)
        del ims[: serder.size]
    return events


def groupTelEvents(events):
    """Group parsed TEL events by registry SAID.

    Parameters:
        events (Iterable[SerderACDC]): parsed TEL events in any order.

    Returns:
        dict[str, tuple[SerderACDC | None, list[SerderACDC]]]:
            registry SAID -> (rip or None, list of bup events).
    """
    groups = defaultdict(lambda: [None, []])
    for serder in events:
        if serder.ilk == "rip":
            regk = serder.said
            groups[regk][0] = serder
        elif serder.ilk == "bup":
            regk = serder.sad["rd"]
            groups[regk][1].append(serder)
        else:
            raise ValidationError(
                f"unsupported TEL event ilk {serder.ilk} in observer ingest"
            )
    return {regk: (rip, updates) for regk, (rip, updates) in groups.items()}


class Observer:
    """Ingest registrar bulk TEL, verify with ``regeventing.vet``, serve clones.

    Holds a ``Regery`` / ``RegistryStore`` for other parties' TELs. Does not
    unblind attributes or answer issuance business questions.
    """

    def __init__(self, hby, rgy=None, kvy=None, name=None, base=None, temp=None):
        """
        Parameters:
            hby (Habery): habitat whose Baser holds issuer KELs for ``vet``.
            rgy (Regery | None): optional pre-built registry manager.
            kvy (Kevery | None): optional Kevery for KEL ingest from bulk.
            name, base, temp: forwarded to ``Regery`` when ``rgy`` is None.
        """
        self.hby = hby
        self.kvy = kvy
        self.rgy = rgy if rgy is not None else Regery(
            hby=hby,
            name=name if name is not None else hby.name,
            base=base if base is not None else hby.base,
            temp=temp if temp is not None else hby.temp,
        )
        self.store = self.rgy.store
        # Pending batches awaiting issuer KEL anchors: regk -> (rip, updates)
        self.pending = {}

    def close(self):
        """Close the underlying registry store."""
        self.rgy.close()

    def pendingIssuers(self):
        """Return issuer AIDs for registries waiting on KEL anchors."""
        issuers = []
        seen = set()
        for rip, _updates in self.pending.values():
            issuer = rip.sad.get("i") if rip is not None else None
            if issuer and issuer not in seen:
                seen.add(issuer)
                issuers.append(issuer)
        return issuers

    def ingest(self, stream, kvy=None):
        """Parse, verify, and store a bulk CESR dump (optional leading KEL).

        Parameters:
            stream (bytes | bytearray | str): KEL+TEL or TEL-only CESR.
            kvy (Kevery | None): key-event processor for leading KEL bytes.
                Defaults to ``self.kvy``.

        Returns:
            dict: summary with keys ``accepted``, ``pending``, ``rejected``
                mapping registry SAID to event counts or error strings.
        """
        summary = dict(accepted={}, pending={}, rejected={})
        kel, tel = splitKelTel(stream)
        processor = kvy if kvy is not None else self.kvy
        if kel:
            if processor is None:
                summary["rejected"]["kel"] = "Kevery required to ingest KEL bulk"
                return summary
            try:
                ingestKel(processor, kel)
            except Exception as ex:
                logger.info("observer ingest KEL parse failed: %s", ex)
                summary["rejected"]["kel"] = str(ex)
                return summary

        if not tel:
            if kel:
                # KEL-only stream: retry anything waiting on those anchors.
                moved = self.retryPending()
                for bucket, items in moved.items():
                    summary[bucket].update(items)
            return summary

        try:
            events = parseTelStream(tel)
            groups = groupTelEvents(events)
        except Exception as ex:
            logger.info("observer ingest TEL parse failed: %s", ex)
            summary["rejected"]["*"] = str(ex)
            return summary

        for regk, (rip, updates) in groups.items():
            result = self._ingestRegistry(regk, rip, updates)
            summary[result[0]][regk] = result[1]
        return summary

    def retryPending(self):
        """Re-attempt ``vet`` for batches waiting on missing KEL anchors.

        Returns:
            dict: same shape as ``ingest`` summary for registries that moved.
        """
        summary = dict(accepted={}, pending={}, rejected={})
        for regk in list(self.pending):
            rip, updates = self.pending[regk]
            result = self._ingestRegistry(regk, rip, updates)
            summary[result[0]][regk] = result[1]
        return summary

    def _ingestRegistry(self, regk, rip, updates):
        """Verify one registry batch and accept or escrow it.

        Returns:
            tuple[str, object]: (bucket, detail) where bucket is one of
            ``accepted``, ``pending``, ``rejected``.
        """
        if rip is None:
            msg = f"bulk stream missing rip for registry {regk}"
            logger.info(msg)
            self.pending.pop(regk, None)
            return "rejected", msg

        try:
            regeventing.vet(rip=rip, updates=updates, db=self.hby.db)
        except MissingAnchorError as ex:
            self.pending[regk] = (rip, list(updates))
            said = rip.said
            self.store.escrowMissingAnchor(regk, 0, said)
            for bup in updates:
                sn = Number(numh=bup.sad["n"]).num
                self.store.escrowMissingAnchor(regk, sn, bup.said)
            logger.info(
                "observer escrow registry %s pending KEL anchor: %s", regk, ex
            )
            return "pending", len(updates) + 1
        except ValidationError as ex:
            self.pending.pop(regk, None)
            logger.info("observer rejected registry %s: %s", regk, ex)
            return "rejected", str(ex)

        chain = [rip] + sorted(updates, key=lambda s: Number(numh=s.sad["n"]).num)
        conflict = _acceptTelChain(self.store, regk, chain)
        if conflict is not None:
            self.pending.pop(regk, None)
            logger.info("observer rejected registry %s: %s", regk, conflict)
            return "rejected", conflict
        self.pending.pop(regk, None)
        return "accepted", len(chain)

    def last(self, regk):
        """Return the verified head event for a registry, or None."""
        return self.store.headEvent(regk)

    def lastRaw(self, regk):
        """Return raw CESR bytes of the verified head, or empty bytes."""
        serder = self.last(regk)
        return bytes(serder.raw) if serder is not None else b""

    def cloneTelIter(self, regk, sn=0):
        """Yield accepted TEL event bodies in sequence from sn inclusive."""
        yield from self.store.cloneTelIter(regk, sn=sn)

    def clone(self, regk, sn=0):
        """Return verified TEL CESR for ``regk`` from ``sn`` inclusive."""
        return self.store.cloneTel(regk, sn=sn)

    def hasRegistry(self, regk):
        """True when at least one verified event is stored for ``regk``."""
        return self.store.head(regk) is not None
