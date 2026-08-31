# R1 — the fail-closed reachability slicer

## The problem it fixes

An enterprise design proposed suppressing a vulnerability advisory as
`not_affected` when a static slicer proved the vulnerable `module.symbol`
`UNREACHABLE_STRICT`. The stated invariant was "default to `DYNAMIC_AMBIGUOUS`"
(fail toward *reachable*). But the **implementation** defined escalation as a
*denylist match* against an enumerated registry of dynamic constructs:

> classify `UNREACHABLE_STRICT` unless the module contains a construct **matching
> the escalation registry**.

That is a contradiction. A denylist match fails **open** on the unknown: a dynamic
construct the registry never listed — `pluggy` hooks, `functools.singledispatch`,
gRPC stubs, a future language feature — is *not matched*, does *not* escalate, and
falls straight through to a signed `not_affected`. The soundness of the whole
signed-attestation liability then rests on the registry being complete, forever.

## The fix: put the soundness bias in the scanner

`slopgate/reach/slicer.py` recognises a **whitelist** of statically-modelable AST
node types (`MODELED_NODES`). The decisive rule is:

```
any node whose type is not in MODELED_NODES  ->  DYNAMIC_AMBIGUOUS
a source that does not parse                 ->  DYNAMIC_AMBIGUOUS
```

The denylist of known-dynamic constructs (`getattr`, `importlib`, `entry_points`,
star-imports, metaclasses, …) still exists — but only as an **optimization** that
produces a precise, human-readable reason. A gap in *that* list is harmless: an
unrecognised dynamic call still lands the symbol as unreferenced-but-escalated (via
a module escape or an unmodeled node). The guarantee comes from the whitelist, not
from the denylist being complete.

Restated as the invariant the enterprise doc wanted but didn't encode:

> A gap in the analyzer's knowledge must cost **noise** (a spurious `AMBIGUOUS`),
> never a **false attestation** (a wrong `UNREACHABLE_STRICT`).

## The three states

| State | Meaning | Effect |
|---|---|---|
| `REACHABLE_CONFIRMED` | the symbol (or an import alias of it) is referenced | not suppressible |
| `DYNAMIC_AMBIGUOUS` | cannot prove non-reachability — dynamic dispatch, a module value that escapes the file, an unmodeled construct, or an unparseable source | not suppressible; escalate to a human |
| `UNREACHABLE_STRICT` | the symbol is provably never referenced **and** nothing dynamic or unmodeled could reach it | suppressible (advisory only here) |

`UNREACHABLE_STRICT` is deliberately narrower — and more useful — than the
enterprise "parent namespace absent" condition: importing a package for *other*
functions does not, by itself, block suppression of a symbol you never call. What
blocks suppression is any path the analyzer cannot see through.

## Scope (honest limits)

- **Single-module, intra-procedural.** A module value passed out of the file
  (as an argument, returned, stored) is treated as `AMBIGUOUS`, not followed. This
  proves the *mechanism* (fail-closed-on-unknown), not whole-program call-graph
  reachability.
- **Advisory-only.** A SlopGate report carries no consuming repository to slice, so
  R1 is a standalone, verified module — not wired into the reproduce pipeline and
  never auto-suppressing. That matches the enterprise resolution that the customer
  signs and suppression is deterministic, not model-driven.

## Verify

```
python -m slopgate.reach.eval        # 12/12 classified, soundness violations: 0
python -m slopgate.sandbox.selftest  # includes the unmodeled-construct invariant
```

The load-bearing case is `unmodeled_match`: a `match` statement is a real,
post-3.10 construct that an earlier slicer or registry would not model. A denylist
that never listed it suppresses to `STRICT`; the fail-closed scanner escalates it to
`AMBIGUOUS`. On Python < 3.10 the same source fails to parse and takes the
parse-fail path to `AMBIGUOUS` — either way, never `STRICT`. On 3.10+ the evidence
shows `unmodeled_nodes: ["Match", "match_case", ...]`.

**Headline metric: soundness violations = 0** — zero cases where the truth was not
strictly-unreachable but the slicer signed `UNREACHABLE_STRICT`.

## At scale

```
python -m slopgate.reach.eval_scale [--limit N]   # default 3000; no network
```

Runs the slicer over thousands of real Python files (stdlib + site-packages + this
repo). Two properties are checked across the whole corpus:

- **Robustness** — the slicer must never raise; a file it cannot handle degrades to
  AMBIGUOUS.
- **Soundness (self-labeled)** — for every file, an `alias.symbol` on a module the
  file imports is, by construction, a real reference; the slicer must classify it
  `REACHABLE_CONFIRMED`, never `UNREACHABLE_STRICT`.

Measured run — **4,000 files**:

| Metric | Result |
|---|---|
| files parsed | 3,992 (8 unparseable → degraded to AMBIGUOUS, no crash) |
| crashes | **0** |
| referenced symbols tested | 2,932 → **100% REACHABLE**, **0 soundness violations** |
| absent-symbol split | 60.3% STRICT / 39.7% AMBIGUOUS / **0% falsely REACHABLE** |

The absent-symbol split is the discrimination evidence: on ~40% of real files a
dynamic or unmodeled construct correctly blocks a strict proof, while ~60% are clean
enough to prove `UNREACHABLE_STRICT` — the slicer is neither trivially always-STRICT
nor always-AMBIGUOUS, and it never invents reachability.
