# -*- encoding: utf-8 -*-
"""
kfobserver.core.observing module

Verified TEL ingest and query for other parties' registries.
"""

from collections import defaultdict

from keri import help
from keri.acdc import Regery, regeventing
from keri.core import Number, SerderACDC
from keri.kering import MissingAnchorError, ValidationError


logger = help.ogler.getLogger()


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

    def __init__(self, hby, rgy=None, name=None, base=None, temp=None):
        """
        Parameters:
            hby (Habery): habitat whose Baser holds issuer KELs for ``vet``.
            rgy (Regery | None): optional pre-built registry manager.
            name, base, temp: forwarded to ``Regery`` when ``rgy`` is None.
        """
        self.hby = hby
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

    def ingest(self, stream):
        """Parse, verify, and store a bulk CESR TEL dump.

        Parameters:
            stream (bytes | bytearray): concatenated TEL event bodies.

        Returns:
            dict: summary with keys ``accepted``, ``pending``, ``rejected``
                mapping registry SAID to event counts or error strings.
        """
        summary = dict(accepted={}, pending={}, rejected={})
        try:
            events = parseTelStream(stream)
            groups = groupTelEvents(events)
        except Exception as ex:
            logger.info("observer ingest parse failed: %s", ex)
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

        chain = [rip] + sorted(
            updates, key=lambda s: Number(numh=s.sad["n"]).num
        )
        for serder in chain:
            sn = Number(numh=serder.sad["n"]).num
            self.store.accept(regk, sn, serder)
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
        """Yield accepted TEL event bodies in sequence from sn inclusive.

        keripy ``RegistryStore`` does not yet expose ``cloneTel``; this walks
        the same ``tels`` / ``evts`` subdbs the registrar dumps from.
        """
        for _keys, _on, saider in self.store.baser.tels.getAllItemIter(
            keys=regk, on=sn
        ):
            serder = self.store.event(saider.qb64)
            if serder is not None:
                yield bytes(serder.raw)

    def clone(self, regk, sn=0):
        """Return verified TEL CESR for ``regk`` from ``sn`` inclusive."""
        stream = bytearray()
        for raw in self.cloneTelIter(regk, sn=sn):
            stream.extend(raw)
        return bytes(stream)

    def hasRegistry(self, regk):
        """True when at least one verified event is stored for ``regk``."""
        return self.store.head(regk) is not None
