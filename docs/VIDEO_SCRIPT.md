# Solution video script (≤ 5 minutes)

Target: one problem → one baseline → one full realistic execution → the
comparison → the changelog → the single change that helped most + one thing
dropped. Numbers in `<>` are filled from the final evaluation run.

---

## 0:00–0:35 — The problem (with a real face)

> On January 31st 2026, Daniel Stenberg shut down curl's six-year, hundred-
> thousand-dollar bug bounty. Not because they ran out of money — because of, in
> his words, "an explosion in AI slop reports." The rate of *real* vulnerabilities
> fell from over 15% to under 5%. Every report still costs three to four people up
> to a few hours each. The reports look real. That's the whole problem.

On screen: the two curl blog headlines; the 30-min-to-3-hours quote.

## 0:35–1:10 — The baseline

> The obvious thing a swamped maintainer does: paste the report into an LLM and
> ask "is this real?" Here's that baseline on a fabricated report — confident
> prose, a proof-of-concept that never actually does anything.

Show: `runs/<fabricated-case>/` baseline verdict = **confirmed**. It believed it.

> It signed off on slop. It never ran a thing.

## 1:10–3:00 — One full execution of the real system

Pick one case, walk the trajectory live (`runs/<case>/trajectory.md`):

1. **Triage** extracts the claims, resolves the claimed version to a sandbox env,
   writes a PoC.
2. **Tool call** — the PoC runs in the Docker sandbox, `--network none`. Show the
   real captured output and the `REPRODUCED` / `NOT_REPRODUCED` line.
3. **Fidelity gate** — deterministic. Show it downgrading a `confirmed` that had
   no reproduction behind it.
4. **Abstain / verify / challenge** — show the challenger arguing against a
   confirmation and the memo being revised.
5. The **signed memo** renders: verdict, reproduction, claim-by-claim, sign-off.

> Nothing is "confirmed" unless the sandbox actually reproduced it. That rule is
> not a prompt — it's a deterministic gate that reads the execution log.

## 3:00–4:00 — Baseline vs. solution

Show the harness table.

> Same fifteen cases, same evaluation. The baseline — one prompt, no tools —
> confirms slop it never ran: false-confirm rate **20%**, accuracy **53%**. The
> full system: false-confirm **0%**, accuracy **93%**, and execution-fidelity from
> **0% to 100%** — the baseline backs none of its confirmations with a run; the
> solution backs all of them. It never dismissed a genuine vulnerability. Cost:
> about **two-tenths of a cent and under a minute** per report, against 30 minutes
> to 3 hours of human time.

## 4:00–4:40 — Changelog: which change actually mattered

> Here's the honest part. I built five agentic layers. **Exactly one moved the
> numbers — giving the agent the tool to run the code.** That's the whole 53-to-93
> jump. The gate, the abstention, the verifier, the challenger: zero additional
> accuracy on this benchmark. More agentic wasn't better. Contact with reality was.

## 4:40–5:00 — What I dropped, and the hot take

> One experiment I dropped: my first adversarial challenger could *overturn* a
> verdict — and it did, downgrading a genuine vulnerability on a rhetorical
> objection. So I stopped letting rhetoric overturn executable proof. And I keep
> the fidelity gate even though it scored nothing, because its job isn't the
> average case — it's the day the model lies about what it ran. A verifier you
> can't audit is just another generator. Make the check produce an artifact, and
> gate on the artifact — not on the model's say-so.

On screen: the hot-take line. End.
