# -*- encoding: utf-8 -*-
"""
kfobserver.core.observing module

Verified TEL ingest and query for other parties' registries.
"""

from collections import defaultdict
from itertools import groupby
from operator import attrgetter

from keri import Vrsn_2_0, help
from keri.acdc import Regery, regeventing
from keri.core import Parser, SerderACDC, SerderKERI
from keri.db import B64IoSetSuber, onKey
from keri.kering import (
    DuplicitousRegistryError, Ilks, MisanchorError, MissingAnchorError, MissingDelegationError,
    MissingWitnessSignatureError, OutOfOrderError, TopLevelStreamError,
    ValidationError,
)


logger = help.ogler.getLogger()


def _anchorSuperseded(db, issuer, event):
    """Distinguish a displaced issuer seal from evidence that has yet to arrive."""
    try:
        regeventing.vetAnchor(event, db=db, issuer=issuer)
        return False
    except (MissingAnchorError, MisanchorError):
        pass

    try:
        kever = db.kevers[issuer]
    except KeyError:
        return False
    for sealing in db.getEvtPreIter(pre=issuer):
        if event.said not in regeventing.sealDigests(sealing):
            continue
        current = db.kels.getLast(keys=issuer, on=sealing.sn)
        if sealing.sn > kever.sn or (current is not None and current != sealing.said):
            return True
    return False


def _acceptTelChain(store, regk, chain, replaceFrom=None):
    """Append a verified chain, or replace its suffix after issuer recovery."""
    baser = store.baser
    key = regk.encode()
    # Use one transaction for the event bodies, accepted slots, and head.
    with baser.env.begin(write=True) as txn:
        cursor = txn.cursor(baser.tels.sdb)
        if replaceFrom is not None and cursor.set_range(onKey(key, replaceFrom)):
            while cursor.key().startswith(key + b"."):
                cursor.delete()
        for event in chain:
            txn.put(event.saidb, event.raw, db=baser.evts.sdb)
            txn.put(onKey(key, event.sn), event.saidb, db=baser.tels.sdb, overwrite=False)

        # Repair the head from accepted slots. A matching shorter replay may
        # end before the last stored update.
        head = chain[-1]
        cursor.set_range(onKey(key, head.sn))
        latest = head.saidb
        for slot, said in cursor:
            if not slot.startswith(key + b"."):
                break
            latest = said
        txn.put(key, latest, db=baser.heads.sdb)


def _asBytes(value):
    """Coerce CESR text or bytes to bytes."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


class KELReplayParser(Parser):
    """Surface framing errors and accept only key events in a KEL replay."""

    def __init__(self, **kwa):
        super().__init__(**kwa)
        self.errors = []

    def msgParsator(self, *args, **kwa):
        try:
            exts = yield from super().msgParsator(*args, **kwa)
            if (not isinstance(exts.serder, SerderKERI)
                    or exts.serder.ilk not in (Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt)):
                raise ValidationError("replay contains a non-KEL message")
            return exts
        except TopLevelStreamError:
            raise
        except Exception as ex:
            self.errors.append(ex)
            raise

    def groupParsator(self, *args, **kwa):
        try:
            return (yield from super().groupParsator(*args, **kwa))
        except Exception as ex:
            self.errors.append(ex)
            raise


class _HistoryParser(KELReplayParser):
    """Allow bulk history to wait for witness receipts and delegation."""

    def msgProcess(self, exts, kvy, tvy, exc, rvy, vry):
        try:
            serder = exts["serder"]
            if kvy.db.fons.get(keys=(serder.pre, serder.said)) is not None:
                return None
            return super().msgProcess(exts, kvy, tvy, exc, rvy, vry)
        except (MissingWitnessSignatureError, MissingDelegationError, OutOfOrderError):
            # Native Kevery escrows these events for a later complete replay.
            raise
        except Exception as ex:
            self.errors.append(ex)
            raise


def ingestKel(kvy, kel):
    """Parse a CESR KEL stream into the observer Kevery / Habery Baser.

    Parameters:
        kvy (Kevery): key-event processor bound to hby.db.
        kel (bytes | bytearray | str): signed KEL clone for TEL issuer(s).

    Returns:
        None
    """
    raw = _asBytes(kel)
    if not raw:
        return
    # Validate all framing before processing any event. The second pass still
    # uses native signature, delegation, receipt and recovery verification.
    for processive in (False, True):
        parser = _HistoryParser(version=Vrsn_2_0)
        parser.parse(ims=bytearray(raw), framed=True, kvy=kvy, processive=processive)
        if parser.errors:
            raise ValidationError("invalid bulk issuer history") from parser.errors[0]
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
    raw = _asBytes(stream)
    ims = bytearray(raw)
    end = 0
    while ims:
        try:
            acdc = SerderACDC(raw=ims)
            if acdc.ilk in ("rip", "bup"):
                break
        except Exception:
            pass
        try:
            Parser(version=Vrsn_2_0).parseOne(
                ims=ims, framed=True, processive=False
            )
        except Exception:
            # Not a framed KERI message; treat remainder as TEL.
            break
        end = len(raw) - len(ims)
    return raw[:end], raw[end:]


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
        # Each entry references event bodies in the registry store. Keep batches
        # separate so a replay from one registrar cannot erase another's evidence.
        self.pending = B64IoSetSuber(db=self.store.baser, subkey="pending.")
        self.forks = B64IoSetSuber(db=self.store.baser, subkey="forks.")

    def close(self):
        """Close the underlying registry store."""
        self.rgy.close()

    def pendingIssuers(self):
        """Return issuer AIDs for registries waiting on KEL anchors."""
        return list(dict.fromkeys(
            self.store.event(regk).israid for (regk,), _ in self.pending.getTopItemIter()
        ))

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
        for (regk,), saids in list(self.pending.getTopItemIter()):
            rip, *updates = (self.store.event(said) for said in saids)
            result = self._ingestRegistry(regk, rip, updates)
            summary[result[0]][regk] = result[1]
        return summary

    def _retain(self, table, regk, events):
        saids = tuple(event.said for event in events)
        if saids not in table.get(keys=regk):
            for event in events:
                self.store.putEvent(event)
            table.add(keys=regk, val=saids)

    def _recordFork(self, rip, candidates):
        """Keep proof of anchored siblings even if another sibling awaits its anchor."""
        prefix = []
        for _, group in groupby(sorted(candidates, key=attrgetter("sn", "said")),
                                key=attrgetter("sn")):
            siblings = list(group)
            if len(siblings) == 1:
                prefix.extend(siblings)
                continue
            anchored = []
            for event in siblings:
                try:
                    regeventing.vet(rip=rip, updates=[*prefix, event], db=self.hby.db)
                except ValidationError:
                    continue
                anchored.append(event)
            if len(anchored) > 1:
                self._retain(self.forks, rip.said, [rip, *prefix, *anchored])
            return

    def _supersededSiblings(self, prefix, siblings):
        """Identify displaced siblings with a verified alternative on the same prefix."""
        rip = prefix[0]
        historical = {said: event for said, event in siblings.items()
                      if _anchorSuperseded(self.hby.db, rip.israid, event)}
        if not historical:
            return set()
        for said, survivor in siblings.items():
            if said in historical:
                continue
            try:
                regeventing.vet(rip=rip, updates=[*prefix[1:], survivor], db=self.hby.db)
            except ValidationError:
                continue
            obsolete = [event for event in historical.values()
                        if event.sad["p"] == survivor.sad["p"]]
            if obsolete:
                self._retain(self.forks, rip.said, [*prefix, survivor, *obsolete])
                return {event.said for event in obsolete}
        return set()

    def _ingestRegistry(self, regk, rip, updates):
        """Vet submitted events together with any competing accepted slots."""
        if rip is None:
            return "rejected", f"bulk stream missing rip for registry {regk}"

        updates = sorted(updates, key=attrgetter("sn", "said"))
        batch = [rip, *updates]
        saids = tuple(event.said for event in batch)
        chain = [rip]
        displaced = set()
        replaced = None
        for sn, group in groupby(updates, key=attrgetter("sn")):
            incoming = {}
            for event in group:
                if event.sad["p"] in displaced:
                    displaced.add(event.said)
                else:
                    incoming[event.said] = event
            if not incoming:
                continue

            siblings = incoming.copy()
            # After divergence, the stored descendants belong to the old branch.
            current = self.store.seqEvent(regk, sn) if replaced is None else None
            if current is not None:
                siblings[current.said] = current

            if len(siblings) > 1:
                obsolete = self._supersededSiblings(chain, siblings)
                displaced.update(obsolete)
                if current is not None and current.said in obsolete:
                    replaced = current
            retained = [event for event in siblings.values() if event.said not in displaced]
            if any(event.said not in displaced for event in incoming.values()):
                chain.extend(retained)

        if displaced and len(chain) == 1:
            self.pending.rem(keys=regk, val=saids)
            return "rejected", "registry branch was superseded"
        try:
            regeventing.vet(rip=rip, updates=chain[1:], db=self.hby.db)
        except MissingAnchorError:
            self._recordFork(rip, chain[1:])
            self._retain(self.pending, regk, batch)
            return "pending", len(batch)
        except DuplicitousRegistryError as ex:
            self._recordFork(rip, chain[1:])
            result = "rejected", str(ex)
        except ValidationError as ex:
            result = "rejected", str(ex)
        else:
            _acceptTelChain(self.store, regk, chain, replaceFrom=replaced.sn if replaced else None)
            result = "accepted", len(chain)
        self.pending.rem(keys=regk, val=saids)
        return result

    def last(self, regk):
        """Return the verified head event for a registry, or None."""
        self.validate(regk)
        return self.store.headEvent(regk)

    def lastRaw(self, regk):
        """Return raw CESR bytes of the verified head, or empty bytes."""
        serder = self.last(regk)
        return bytes(serder.raw) if serder is not None else b""

    def cloneTelIter(self, regk, sn=0):
        """Yield accepted TEL event bodies in sequence from sn inclusive."""
        self.validate(regk)
        yield from self.store.cloneTelIter(regk, sn=sn)

    def clone(self, regk, sn=0):
        """Return verified TEL CESR for ``regk`` from ``sn`` inclusive."""
        self.validate(regk)
        return self.store.cloneTel(regk, sn=sn)

    def validate(self, regk):
        """Recheck retained anchors against the currently accepted issuer KEL.

        A recovery rotation can supersede an anchor after the TEL was stored.
        Retain the historical evidence but never serve it as currently verified.
        This check performs no network requests.
        """
        survivors = {}
        for proof in self.forks.getIter(keys=regk):
            rip, *updates = (self.store.event(said) for said in proof)
            # Ingest verified the links. Recovery can supersede the common
            # prefix or individual siblings, including siblings in other batches.
            fork_sn = updates[-1].sn
            for event in (rip, *updates):
                try:
                    regeventing.vetAnchor(event, db=self.hby.db, issuer=rip.israid)
                except (MissingAnchorError, MisanchorError):
                    if event.sn < fork_sn:
                        break
                    continue
                if event.sn == fork_sn:
                    slot = (fork_sn, event.sad["p"])
                    if survivors.setdefault(slot, event.said) != event.said:
                        raise DuplicitousRegistryError(
                            f"Conflicting anchored updates for registry {regk} at {fork_sn}"
                        )

        for (sn, _), said in survivors.items():
            accepted = self.store.seqSaider(regk, sn)
            if accepted is None or accepted.qb64 != said:
                raise MissingAnchorError(f"Recovered registry {regk} awaits verified replay")
        if self.pending.cnt(keys=regk):
            raise MissingAnchorError(f"Registry {regk} awaits issuer anchors")
        if self.store.head(regk) is None:
            return
        chain = parseTelStream(self.store.cloneTel(regk))
        regeventing.vet(rip=chain[0], updates=chain[1:], db=self.hby.db)

    def hasRegistry(self, regk):
        """True when at least one verified event is stored for ``regk``."""
        return self.store.head(regk) is not None
