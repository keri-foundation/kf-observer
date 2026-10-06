# -*- encoding: utf-8 -*-
"""
kfobserver.core.pulling module

Periodic bulk TEL pull from one or more kf-registrar external faces.
"""

from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http
from keri import Vrsn_2_0, help
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import query
from keri.help import helping


logger = help.ogler.getLogger()


def bulkQuery(hab, regk=None, sn=0, route="tels/bulk"):
    """Build a signed-ready V2 qry for registrar bulk TEL.

    Parameters:
        hab (Hab): observer habitat that will endorse the query.
        regk (str | list | None): registry SAID(s); omit for all registries.
        sn (int): first sequence number to include.
        route (str): registrar bulk route (``tels/bulk`` or ``regs``).

    Returns:
        SerderKERI: unsigned query serder (caller endorses).
    """
    q = {}
    if regk is not None:
        q["i"] = regk
    if sn:
        q["sn"] = sn
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def pullOnce(hab, url, regk=None, sn=0, timeout=5.0):
    """Synchronously POST one bulk query and return response body bytes.

    Uses a short-lived hio HTTP client. Suitable for tests and the poll doer.

    Parameters:
        hab (Hab): observer habitat (must be allow-listed on the registrar).
        url (str): registrar external base URL (e.g. ``http://127.0.0.1:6632/``).
        regk (str | list | None): optional registry filter.
        sn (int): optional from-sn clone.
        timeout (float): seconds to wait for a response.

    Returns:
        bytes: CESR body on HTTP 200; empty bytes on failure.
    """
    serder = bulkQuery(hab, regk=regk, sn=sn)
    body = bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))
    purl = urlsplit(url)
    path = purl.path or "/"
    if not path.endswith("/"):
        # registrar BulkQueryEnd is mounted at "/"
        path = path if path else "/"

    client = http.clienting.Client(
        scheme=purl.scheme or "http",
        hostname=purl.hostname or "127.0.0.1",
        port=purl.port or 80,
        portOptional=True,
        timeout=timeout,
    )
    client.request(
        method="POST",
        path=path if path != "" else "/",
        headers={"Content-Type": CESR_CONTENT_TYPE},
        body=body,
    )
    while not client.responses and not client.requester.error:
        client.service()
    if client.requester.error or not client.responses:
        logger.info("registrar pull failed for %s", url)
        return b""
    response = client.respond()
    if response.status != 200:
        logger.info(
            "registrar pull %s returned HTTP %s", url, response.status
        )
        return b""
    return bytes(response.body or b"")


class RegistrarPuller(doing.DoDoer):
    """Poll configured registrar URLs and ingest verified TEL into Observer."""

    def __init__(self, hab, observer, urls=None, tock=5.0, regk=None):
        """
        Parameters:
            hab (Hab): observer habitat used to sign bulk queries.
            observer (Observer): ingest target.
            urls (list[str] | None): registrar external base URLs.
            tock (float): poll interval in seconds.
            regk (str | list | None): optional registry filter for every pull.
        """
        self.hab = hab
        self.observer = observer
        self.urls = list(urls or [])
        self.regk = regk
        self.tock = float(tock)
        super(RegistrarPuller, self).__init__(
            doers=[doing.doify(self.pullDo, tock=self.tock)]
        )

    def pullDo(self, tymth=None, tock=0.0, **kwa):
        """Periodic full-clone pull from each registrar URL."""
        self.wind(tymth)
        self.tock = tock if tock else self.tock
        _ = yield self.tock
        while True:
            for url in self.urls:
                try:
                    raw = pullOnce(self.hab, url, regk=self.regk)
                    if raw:
                        summary = self.observer.ingest(raw)
                        logger.info(
                            "pulled %s bytes from %s: %s",
                            len(raw),
                            url,
                            summary,
                        )
                except Exception as ex:
                    logger.info("registrar pull error for %s: %s", url, ex)
            self.observer.retryPending()
            yield self.tock
