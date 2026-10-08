# kf-observer

`kf-observer` is the KERI Foundation observer service: a long-running node that
consumes **bulk TEL** from a registrar, **verifies every event** against the
issuer KEL, stores a verified copy, and answers **wallet/verifier** queries for
one registry’s TEL (last event, all events, or events since `sn`).

It is the ACDC counterpart of a watcher. Watchers serve KELs; this process
serves TELs. Wallets and verifiers must not talk to the registrar — they talk
to an observer (anti-correlation). For SEDI, observers are not optional.

## Trust boundary

```
wallet / verifier  -->  kf-observer  -->  kf-registrar (bulk only)
                         |                 (KEL fallback via witness GET /log)
```

- **Ingest:** signed V2 `qry` POST to the registrar (`r: "tels/bulk"` / `"regs"`),
  KRAM + allow-listed observer AID. Response is concatenated CESR: issuer **KEL**
  clones (when known on the registrar) followed by accepted `rip`/`bup` events.
  This node loads KEL into its Baser, runs `regeventing.vet`, and stores only what
  verifies. Missing anchors escrow until a later poll or witness KEL fetch.
- **Serve** (default `127.0.0.1:6633`): signed V2 `qry` POST for one registry
  SAID — last / all / since `sn`. No blinded-attribute disclosure. No
  “is this ACDC issued?” business logic (that is `vet` on the verifier).
  Unknown registries trigger an on-demand registrar pull (IPEX timing).

## Query contract (wallet / verifier / IPEX)

| Field | Rule |
|-------|------|
| Message | Signed V2 `qry` CESR POST to `/` |
| `r` | `tels` (clone from `sn`) or `tels/head` (head event only) |
| `q.i` | **Single registry SAID** (`rip.d`, including presentation `a.rd`) |
| `q.sn` | Optional; inclusive start sequence for `tels` |
| Forbidden | `tels/bulk`, `regs`, `vcid`, wallet phone-home to the registrar |

Response body is verified TEL CESR only (no KEL). At point of validation the
verifier queries **this observer**, never the registrar.

## Requirements

- Python >= 3.14
- `libsodium` (required by the `keri` package)

### Installing libsodium

**macOS:**

```bash
brew install libsodium
```

**Ubuntu/Debian:**

```bash
sudo apt-get install libsodium-dev
```

## Installation

Published dependency is `keri` from WebOfTrust/keripy. In this umbrella
checkout, `tool.uv.sources` points at the sibling `../keripy` (editable):

```bash
cd kf-observer
uv sync --all-extras
```

Or with pip:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e '.[dev]'
```

Standalone clones without the sibling tree will pull `keri` from git.

## Running

```bash
kf-observer start \
  --alias observer \
  --config-dir /path/to/scripts \
  --config-file kf-observer \
  --host 127.0.0.1 \
  --http 6633 \
  --registrar http://127.0.0.1:6632/ \
  --witness http://127.0.0.1:5642/#<witness-AID>
```

`--config-dir` must point at the directory *above* `keri/cf/` (KERI appends
`keri/cf/` when locating the file). For this repo that is `scripts/`.

Repeat `--registrar` / `--witness` for each peer, or list them in
`scripts/keri/cf/kf-observer.json` under `kf-observer.registrars` and
`kf-observer.witnesses` (witness entries may be `"url#aid"` or
`{"url": "...", "aid": "..."}`).

This node’s AID must be allow-listed on each registrar (`--observer` /
`kf-registrar.observers`).

Witness `GET /log` is a **fallback** when bulk TEL arrives without a usable
issuer KEL. Prefer registrar bulk that already includes the KEL (minted TELs
and admin `POST /ingest`).

## Tests

```bash
export DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib:/usr/local/lib:/usr/lib"
export DYLD_LIBRARY_PATH="$(brew --prefix)/lib"
pytest tests/
```

On Linux, libsodium install is enough; the `DYLD_*` exports are macOS-only.
