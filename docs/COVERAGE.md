# SlopGate — coverage matrix

_Generated from the last real-data run (`slopgate/eval/coverage.py`); it is derived from cases that actually executed, so it cannot drift from what was measured. Regenerate after a run with `python -m slopgate.eval.coverage`._

SlopGate's job is **triage + slop-rejection**, not universal reproduction. It reaches a decisive verdict by *executing* the report; where execution cannot reach it, the system **abstains** (routes to a human) rather than guessing. This matrix states plainly which is which.

## Headline

- **Cases:** 18
- **Reproduced (reachability):** 11/18 (61%)
- **Abstained / not reproduced:** 7/18 (39%)
- **False-confirm rate (solution):** 0/18 (0%) — the number that matters most for a maintainer.

## By vulnerability class

| Class | Reproduced | Abstained |
|---|---|---|
| eval / code-injection | 4 | 4 |
| memory corruption | 1 | 2 |
| other | 1 | 0 |
| path traversal | 1 | 0 |
| unsafe deserialization | 4 | 1 |

## By ecosystem

| Ecosystem | Reproduced | Abstained |
|---|---|---|
| c | 1 | 2 |
| python | 10 | 5 |

## Reproduces well (execution reached a verdict)

| Case | CVE | Class | Ecosystem | Solution verdict |
|---|---|---|---|---|
| `beaker-affected` | CVE-2013-7489 | unsafe deserialization | python | confirmed |
| `c-real-overflow` | None | memory corruption | c | confirmed |
| `gdown-affected` | CVE-2026-40491 | path traversal | python | confirmed |
| `hydra-core-affected` | CVE-2026-68508 | eval / code-injection | python | confirmed |
| `joblib-affected` | CVE-2022-21797 | eval / code-injection | python | confirmed |
| `jsonpickle-affected` | CVE-2020-22083 | unsafe deserialization | python | confirmed |
| `js2py-affected` | CVE-2024-28397 | eval / code-injection | python | confirmed |
| `pyyaml-affected` | CVE-2020-14343 | unsafe deserialization | python | confirmed |
| `gdown-prose` | CVE-2026-40491 | other | python | confirmed |
| `reportlab-affected` | CVE-2023-33733 | eval / code-injection | python | confirmed |
| `trustmodel-configfile` | None | unsafe deserialization | python | insufficient_evidence |

## Abstains / does not reproduce (and why)

| Case | CVE | Why not reached by execution | Solution verdict |
|---|---|---|---|
| `curl-websocket-slop` | None | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |
| `gdown-vshift` | CVE-2026-40491 | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |
| `hydra-core-vshift` | CVE-2026-68508 | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |
| `joblib-vshift` | CVE-2022-21797 | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |
| `curl-telnet-slop` | None | no runnable PoC in the report (prose or library-internal claim) | insufficient_evidence |
| `pyyaml-vshift` | CVE-2020-14343 | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |
| `reportlab-vshift` | CVE-2023-33733 | PoC does not fire on the claimed version (version-shift slop) | not_reproducible |

## What we abstain on — the honest ceiling

Execution-based triage cannot reach a verdict when the claim lives outside a self-contained, sandbox-runnable proof-of-concept. On real-world traffic the dominant abstention causes are:

- **No runnable PoC** — the report describes a library-internal code path (e.g. much of the real curl slop) that a self-contained PoC cannot exercise.
- **Runtime dependencies the air-gap forbids** — the PoC needs live networking, an external binary (git, nmap), or a system library not in the sandbox.
- **Environment-sensitive triggers** — GUI, hardware, timing/race conditions.

In every one of these, SlopGate returns `insufficient_evidence` and routes to a human — it never dismisses. That is the deliberate design: the dangerous error is waving away a real vulnerability, so abstention is the safe move.
