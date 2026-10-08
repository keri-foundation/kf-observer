# -*- encoding: utf-8 -*-
"""
kfobserver.core.keling module

Witness KEL fallback for pending observer TEL batches.
"""

import time
from urllib.parse import urlsplit, urlencode

from hio.base import doing
from hio.core import http
from keri import help
from keri.app.httping import CESR_CONTENT_TYPE, CESR_DESTINATION_HEADER

from kfobserver.core.observing import ingestKel


logger = help.ogler.getLogger()


def fetchKelOnce(issuer, url, aid=None, timeout=5.0):
    """GET ``/log?pre=`` from a witness and return KEL CESR bytes.

    Parameters:
        issuer (str): AID whose KEL to clone.
        url (str): witness base URL (e.g. ``http://127.0.0.1:5642/``).
        aid (str | None): witness AID for ``CESR-DESTINATION`` (required by
            witness-hk ``KeyLogEnd``).
        timeout (float): seconds to wait for a response.

    Returns:
        bytes: CESR KEL on HTTP 200; empty bytes on failure.
    """
    if not issuer or not url:
        return b""
    purl = urlsplit(url)
    base = purl.path or "/"
    if not base.endswith("/"):
        base = base + "/"
    path = f"{base}log?{urlencode({'pre': issuer})}"
    headers = {"Accept": CESR_CONTENT_TYPE}
    if aid:
        headers[CESR_DESTINATION_HEADER] = aid

    client = http.clienting.Client(
        scheme=purl.scheme or "http",
        hostname=purl.hostname or "127.0.0.1",
        port=purl.port or 80,
        portOptional=True,
        timeout=timeout,
    )
    try:
        client.request(method="GET", path=path, headers=headers)
        deadline = time.monotonic() + float(timeout)
        while not client.responses and time.monotonic() < deadline:
            if client.respondent is not None and client.respondent.errored:
                break
            client.service()
        if not client.responses:
            logger.info("witness KEL fetch failed for %s at %s", issuer, url)
            return b""
        response = client.respond()
    except Exception as ex:
        logger.info("witness KEL fetch error for %s at %s: %s", issuer, url, ex)
        return b""
    if response.status != 200:
        logger.info(
            "witness KEL fetch %s %s returned HTTP %s",
            issuer,
            url,
            response.status,
        )
        return b""
    return bytes(response.body or b"")


class WitnessKelFetcher(doing.DoDoer):
    """Poll witnesses for KELs of issuers with pending observer TEL batches."""

    def __init__(self, observer, kvy, witnesses=None, tock=5.0):
        """
        Parameters:
            observer (Observer): pending-batch source and ingest target.
            kvy (Kevery): Kevery bound to the observer Habery Baser.
            witnesses (list[dict] | None): entries with ``url`` and optional ``aid``.
            tock (float): poll interval in seconds.
        """
        self.observer = observer
        self.kvy = kvy
        self.witnesses = list(witnesses or [])
        self.tock = float(tock)
        super(WitnessKelFetcher, self).__init__(
            doers=[doing.doify(self.fetchDo, tock=self.tock)]
        )

    def fetchDo(self, tymth=None, tock=0.0, **kwa):
        """Periodic KEL fetch for pending issuers."""
        self.wind(tymth)
        self.tock = tock if tock else self.tock
        _ = yield self.tock
        while True:
            for issuer in self.observer.pendingIssuers():
                for wit in self.witnesses:
                    try:
                        raw = fetchKelOnce(
                            issuer,
                            wit.get("url"),
                            aid=wit.get("aid"),
                        )
                        if raw:
                            ingestKel(self.kvy, raw)
                            moved = self.observer.retryPending()
                            logger.info(
                                "witness KEL for %s from %s: %s",
                                issuer,
                                wit.get("url"),
                                moved,
                            )
                            break
                    except Exception as ex:
                        logger.info(
                            "witness KEL error for %s at %s: %s",
                            issuer,
                            wit.get("url"),
                            ex,
                        )
            yield self.tock
