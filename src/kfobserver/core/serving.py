# -*- encoding: utf-8 -*-
"""
kfobserver.core.serving module

HTTP observer node: Habery, verified TEL store, registrar pull, wallet query face.
"""

from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http
from keri import help
from keri.app.indirecting import createHttpServer
from keri.core import Kevery
from keri.core.kraming import Kramer
from keri.db.basing import BaserDoer

from kfobserver.app import httping
from kfobserver.core.observing import Observer
from kfobserver.core.pulling import RegistrarPuller


logger = help.ogler.getLogger()

CORS_EXPOSE = [
    "cesr-attachment",
    "cesr-date",
    "content-type",
    "signature",
    "signature-input",
    "signify-resource",
    "signify-timestamp",
]

DEFAULT_KRAM_CONFIG = {
    "kram": {
        "enabled": True,
        "denials": [],
        "caches": {
            "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
        },
    }
}

DEFAULT_HTTP_PORT = 6633


class StaticConfig:
    """Minimal Configer duck-type for KRAM settings."""

    def __init__(self, data):
        self.data = data

    def get(self):
        return self.data


class Context(doing.DoDoer):
    """Running observer node: Habery, Observer store, KRAM, Falcon app."""

    def __init__(self, hby, hab, observer, kvy, registrars=None, witnesses=None):
        self.hby = hby
        self.hab = hab
        self.observer = observer
        self.kvy = kvy
        self.registrars = list(registrars or [])
        self.witnesses = list(witnesses or [])
        self.app = None
        super(Context, self).__init__(doers=[doing.doify(self.escrowDo)])

    def pullRegistry(self, regk):
        """On-demand bulk pull for one registry SAID from configured registrars.

        Returns:
            dict | None: last non-empty ingest summary, or None if nothing pulled.
        """
        from kfobserver.core.pulling import pullOnce

        summary = None
        for url in self.registrars:
            raw = pullOnce(self.hab, url, regk=regk)
            if raw:
                summary = self.observer.ingest(raw, kvy=self.kvy)
        return summary

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Retry pending TEL batches when issuer KEL anchors arrive."""
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock
        while True:
            self.observer.retryPending()
            yield self.tock


def _configWithKram(cf):
    """Ensure a KRAM block exists so Kramer.intake actually authenticates."""
    data = {}
    if cf is not None:
        loaded = cf.get()
        if loaded:
            data = dict(loaded)
    if "kram" not in data:
        data = {**DEFAULT_KRAM_CONFIG, **data}
        data["kram"] = dict(DEFAULT_KRAM_CONFIG["kram"])
    return StaticConfig(data)


def _blockFromConfig(cf):
    """Return the kf-observer config block or empty dict."""
    if cf is None:
        return {}
    data = cf.get() or {}
    return data.get("kf-observer") or data.get("kfobserver") or {}


def _registrarsFromConfig(cf):
    """Read registrar URLs from the kf-observer config block."""
    block = _blockFromConfig(cf)
    if not block:
        if cf is None:
            return []
        data = cf.get() or {}
        return list(data.get("registrars") or [])
    return list(block.get("registrars") or [])


def _normalizeWitness(entry):
    """Normalize a witness config entry to ``dict(url=..., aid=...).``"""
    if isinstance(entry, str):
        if "#" in entry:
            url, aid = entry.split("#", 1)
            return dict(url=url, aid=aid or None)
        return dict(url=entry, aid=None)
    if isinstance(entry, dict):
        url = entry.get("url") or entry.get("curl")
        aid = entry.get("aid") or entry.get("pre")
        if url:
            return dict(url=url, aid=aid)
    return None


def _witnessesFromConfig(cf):
    """Read witness URL(+AID) entries from the kf-observer config block."""
    block = _blockFromConfig(cf)
    raw = []
    if block:
        raw = list(block.get("witnesses") or [])
    elif cf is not None:
        data = cf.get() or {}
        raw = list(data.get("witnesses") or [])
    out = []
    for entry in raw:
        norm = _normalizeWitness(entry)
        if norm:
            out.append(norm)
    return out


def _dedupeUrls(urls):
    """De-dupe URL strings preserving order."""
    seen = set()
    out = []
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _dedupeWitnesses(entries):
    """De-dupe witness entries by url#aid preserving order."""
    seen = set()
    out = []
    for entry in entries:
        key = f"{entry.get('url')}#{entry.get('aid')}"
        if key not in seen:
            seen.add(key)
            out.append(entry)
    return out


def _applyCurls(cf, host, port):
    """Override advertised host/port from kf-observer.curls when present."""
    block = _blockFromConfig(cf)
    curls = block.get("curls") or []
    if not curls:
        return host, port
    splits = urlsplit(curls[0])
    if splits.hostname:
        host = splits.hostname
    if splits.port:
        port = splits.port
    return host, port


def _corsApp():
    return falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins="*",
            allow_credentials="*",
            expose_headers=CORS_EXPOSE,
        )
    )


def loadEnds(app, ctx):
    """Register wallet/verifier routes on the Falcon app."""
    app.add_route("/health", httping.HealthEnd())
    app.add_route("/", httping.TelQueryEnd(ctx))


def makeContext(hby, alias="observer", registrars=None, witnesses=None, **kwa):
    """Build the observer Context and Falcon app without binding sockets.

    Parameters:
        hby (Habery): habitat environment that owns the observer identifier.
        alias (str): habitat name for the observer controller.
        registrars (list[str] | None): registrar external base URLs.
            Combined with any ``registrars`` list in Habery config.
        witnesses (list | None): witness URL(+AID) entries for KEL fallback.
            Combined with any ``witnesses`` list in Habery config.

    Returns:
        Context: observer node with ``app`` attached.
    """
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True, **kwa)

    cf = _configWithKram(hby.cf)
    kvy = Kevery(
        db=hby.db,
        cf=cf,
        enableKram=True,
        lax=True,
        local=False,
    )
    if kvy.kramer is None:
        kvy.kramer = Kramer(db=hby.db, cf=cf, cues=kvy.cues)

    observer = Observer(hby=hby, kvy=kvy)

    registrars = _dedupeUrls(
        list(registrars or []) + _registrarsFromConfig(hby.cf)
    )
    witEntries = []
    for entry in list(witnesses or []):
        norm = _normalizeWitness(entry)
        if norm:
            witEntries.append(norm)
    witnesses = _dedupeWitnesses(witEntries + _witnessesFromConfig(hby.cf))

    ctx = Context(
        hby=hby,
        hab=hab,
        observer=observer,
        kvy=kvy,
        registrars=registrars,
        witnesses=witnesses,
    )

    app = _corsApp()
    loadEnds(app, ctx)
    ctx.app = app
    return ctx


def setup(
    hby,
    alias="observer",
    host="127.0.0.1",
    port=DEFAULT_HTTP_PORT,
    registrars=None,
    witnesses=None,
    pollTock=5.0,
    keypath=None,
    certpath=None,
    cafilepath=None,
    **kwa,
):
    """Initialize HTTP server and registrar puller for one observer node.

    Parameters:
        hby (Habery): habitat environment that owns the observer identifier.
        alias (str): habitat name for the observer controller.
        host (str): bind address for the wallet-facing API.
        port (int): port for the wallet-facing API.
        registrars (list[str] | None): registrar external base URLs.
        witnesses (list | None): witness URL(+AID) entries for KEL fallback.
        pollTock (float): seconds between full-clone registrar polls.
        keypath, certpath, cafilepath: optional TLS material.

    Returns:
        list: HIO doers including the observer Context, puller, and HTTP server.
    """
    from kfobserver.core.keling import WitnessKelFetcher

    ctx = makeContext(
        hby=hby,
        alias=alias,
        registrars=registrars,
        witnesses=witnesses,
        **kwa,
    )

    advertisedHost, advertisedPort = _applyCurls(hby.cf, host, port)
    ctx.host = advertisedHost
    ctx.port = advertisedPort

    server = createHttpServer(
        host=host,
        port=port,
        app=ctx.app,
        keypath=keypath,
        certpath=certpath,
        cafilepath=cafilepath,
    )
    if not server.reopen():
        raise RuntimeError(f"cannot create observer HTTP server on port {port}")
    srvrDoer = http.ServerDoer(server=server)

    regDoer = BaserDoer(baser=ctx.observer.rgy.baser)

    doers = [ctx, regDoer, srvrDoer]
    if ctx.registrars:
        puller = RegistrarPuller(
            hab=ctx.hab,
            observer=ctx.observer,
            urls=ctx.registrars,
            tock=pollTock,
            kvy=ctx.kvy,
        )
        doers.append(puller)
    if ctx.witnesses:
        doers.append(
            WitnessKelFetcher(
                observer=ctx.observer,
                kvy=ctx.kvy,
                witnesses=ctx.witnesses,
                tock=pollTock,
            )
        )

    logger.info(
        "Observer %s : %s http/%s:%s registrars=%s witnesses=%s",
        ctx.hab.name,
        ctx.hab.pre,
        host,
        port,
        ctx.registrars,
        ctx.witnesses,
    )
    return doers
