# SlopGate — Product Roadmap (maintainer-first)

**Owner:** Product (this document)
**Last updated:** 2026-08-31

## Goal & success measure

For **open-source security maintainers** drowning in AI-slop vulnerability reports —
the audience whose pain is already documented (Daniel Stenberg ended curl's $100k+
bug-bounty program on 2026-01-31 over "an explosion in AI slop reports"; every report
engages 3–4 people for 30 min–3 h).

The product's job is **triage + slop-rejection**, *not* universal reproduction. Success is
measured by:

- **Maintainer hours saved per 100 reports** (the business metric).
- **False-confirm rate ≈ 0** — never sign "confirmed" on a report that isn't real.
- **Zero real vulnerabilities wrongly dismissed** — abstain, never guess-dismiss.
- A high **auto-reject rate** on fabricated / version-shift slop, and a
  **reproduce-or-honestly-abstain** outcome on everything else.

The strategic call this roadmap is built on: **maintainer-first is the sharper wedge** —
the pain is louder, the story is concrete (curl), and slop-rejection is demonstrable
today. The enterprise supply-chain direction (R1/R2) is real but is a different product
for a different buyer, and is deliberately parked on the Later track.

## Inputs consulted

- **Architecture:** existing pipeline — triage → fidelity gate → abstain → verify →
  challenge → threat-model gate — over a network-isolated dynamic sandbox that installs
  the exact affected package and runs the PoC by execution.
- **Risk (pre-mortem):** the **coverage ceiling** is the load-bearing risk. Most real
  reports will not reproduce cleanly — observed directly while building the corpus, where
  **6 of 8 researched real CVEs failed sandbox verification** for mundane environmental
  reasons (loopback networking blocked by the air-gap, modern lxml disabling external
  entities, escape payloads not firing, a "fixed" version whose behavior was unchanged).
  In production these are not bugs — they are the *real report population*, and they land
  in `insufficient_evidence → human`.
- **Design / trust POV:** the abstain lane must feel like a **feature**, not a shrug;
  the never-auto-sign guarantee is what makes verdicts safe to act on.

---

## Phase: NOW — win the lane you already win

**Goal:** ship the slop-rejection wedge and make the honesty legible.

| Item | What ships | Why (value / risk retired) | Dependencies | Success metric | Driven by |
|---|---|---|---|---|---|
| Slop-rejection as the headline | Lead every surface with false-confirm ≈ 0% + auto-reject of version-shift / fabricated slop — not reproduction coverage | This is the actual bottleneck (volume of plausible fakes) and it is demonstrable today | Existing pipeline | Auto-reject rate on a slop corpus; 0 false-confirms | Goal + Risk |
| Abstain as a first-class verdict | "Flagged for you — here is the exact command we ran, what we could not reproduce, and why (network / external binary / library internals)" | The ceiling is real; honesty about it *is* the trust | Trajectory + memo surface | Maintainer reports the abstain memo saved triage time even when unconfirmed | Design + Risk |
| Public coverage matrix | "We reproduce X well (deserialization / eval-injection / path-traversal, self-contained Python & C); we abstain on Y (network, GUI, hardware, timing, lib internals)" | Sets the pitch to the lane it wins; pre-empts "why didn't it reproduce mine" | — | Zero "false advertising" complaints; adoption despite stated limits | Risk |
| `verify_cases` as a public trust artifact | The ground-truth gate (reproduces-on-affected, quiet-on-fixed) becomes the credibility proof — every "confirmed" is executable, not asserted | Turns integrity into a visible feature | `slopgate/eval/verify_cases.py` (built) | Judges / maintainers cite it as why they trust the verdicts | Architecture + Goal |

## Phase: NEXT — widen the lane, honestly

**Goal:** raise coverage where it is cheap, without ever faking a confirm.

| Item | What ships | Why (value / risk retired) | Dependencies | Success metric | Driven by |
|---|---|---|---|---|---|
| More ecosystems / better synthesis | Extend beyond Python + generic-C where PoCs are self-contained; improve the prose-to-PoC hit rate | Directly lifts the confirm lane | NOW's coverage matrix (measure gains vs. a stated baseline) | Reproduction rate on a held-out real-CVE set, tracked over time | Architecture |
| Maintainer-in-the-loop workflow | Tracker integration (paste memo into the issue), one-click "re-test on version N", triage-queue ranking | The product is an assistant; value is realized inside the maintainer's existing flow | Memo format | Time-to-first-triage-decision per report | Design + Goal |
| Sandbox environment breadth | Optional egress-controlled reproduction for the network-dependent class (the aiohttp failure class) | Converts a chunk of today's abstains into decisive confirms/rejects | Sandbox hardening | % of prior-abstain cases now decisively classified | Risk |

## Phase: LATER — named, not dropped

**Goal:** adjacent value, deliberately deferred to protect the wedge.

| Item | What ships | Why (value / risk retired) | Dependencies | Success metric | Driven by |
|---|---|---|---|---|---|
| R1 fail-closed reachability slicer | Enterprise supply-chain / CI product; suppress advisories only on a sound `UNREACHABLE_STRICT` proof | Validated at scale (0 soundness violations across 4,000 files) but a different buyer (AppSec) and GTM | Enterprise track | Signed-attestation soundness in a real repo | Goal (focus) |
| R2 warn-only AI-slop name classifier | Same enterprise track; compound-name hallucination detection | Validated (0% FP / 100% recall at scale); it is a supply-chain gate, not a report-triage feature | Enterprise track | Measured FP on *young* legit packages before any block | Goal (focus) |

---

## Open tradeoffs & disagreements

- **Coverage vs. focus (the real one).** Architecture *can* keep widening reproduction;
  Risk says the ceiling is structural and chasing universal repro is a treadmill that
  dilutes the wedge. **Call: Risk wins in NOW** — ship slop-rejection + honest abstain
  first; widen coverage as *measured* increments in NEXT. Reproduction breadth is a
  gradient to climb, not a gate to clear before launch.
- **Assistant vs. autopilot.** Design/trust demands never-auto-sign (which caps time
  savings); Goal wants maximum hours saved. **Call: trust wins** — an autopilot that
  could dismiss a real vuln is un-adoptable; the human sign-off stays.
- **One product or two.** R1/R2 are genuinely good and tempt a broader "supply-chain
  security" pitch now. **Call: maintainer-first wins** — louder pain, concrete story,
  demonstrable today. R1/R2 are parked on Later, not deleted.

## Explicitly out of scope (now)

- **Full libcurl-internal / whole-program reproduction** (heavy per-version source
  builds) — abstain is the correct output there, not a confident verdict.
- **Enterprise CI gate / OpenVEX signing / Firecracker isolation** — the R1/R2 world,
  correctly on the Later track.
- **Auto-actioning verdicts** (CVE assignment, disclosure, reward) without a human —
  permanently out; it is the one unforgivable-error guard the whole product is built on.

---

*Traceability check against the pivotal question ("who is v1's user?"): every NOW and
NEXT item serves the maintainer; R1/R2 are explicitly parked on a separate Later track
rather than silently deferred — the split-focus one-way door is resolved, not dodged.*
