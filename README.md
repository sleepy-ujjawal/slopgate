# SlopGate — a triage agent for AI-slop vulnerability reports

> An agent that adjudicates an incoming vulnerability report and produces a
> **signed triage memo** — and refuses to write "confirmed" on anything it did
> not actually reproduce.

## Who has this problem

Open-source security maintainers. The people who receive vulnerability reports
and have to decide, one at a time, whether each is real.

The bottleneck is documented first-hand and it is recent. On **2026-01-31**,
Daniel Stenberg **ended curl's six-year, $100k+ bug-bounty program**. His reason,
in his own words:

> "We saw an explosion in AI slop reports."
> — *[The end of the curl bug bounty](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)*

The numbers behind it ([*Death by a thousand slops*](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/), 2025-07-14):

- valid-submission rate fell from **>15% to under 5%** once AI slop arrived;
- roughly **20% of all submissions** were AI-generated slop;
- **"Every report engages 3–4 persons. Perhaps for 30 minutes, sometimes up to
  an hour or three. Each."**

A well-written but false report costs a maintainer real hours, because it *looks*
exactly like a real one. That is the bottleneck: the expensive part isn't fixing
vulnerabilities, it's telling the real reports from the confident fakes.

## Why solving it is valuable

The report reads like a genuine finding. The maintainer cannot dismiss it on
sight — dismissing a real vulnerability is the one unforgivable error — so they
spend the hours. An assistant that does the *reproduction* work, and is
structurally incapable of rubber-stamping a report it never ran, gives that time
back without adding the risk of waving away something real.

## What it produces

For each report, a **triage memo** a maintainer could sign and paste into their
tracker:

- a **verdict**: `confirmed` / `not_reproducible` / `insufficient_evidence`;
- the **reproduction attempt** — the exact command, the environment, and the real
  captured output;
- a **claim-by-claim** assessment of what the report asserted vs. what the
  evidence shows;
- an **abstention list** of anything deferred to a human;
- a **sign-off block** that is never auto-filled — no consequential action
  (CVE assignment, disclosure, reward) happens without a human.

See a real example in [`runs/`](runs/) after a run, or the format in
[`slopgate/agent/memo.py`](slopgate/agent/memo.py).

## How the agent works

```
report ─▶ triage ─▶ [fidelity gate] ─▶ abstain ─▶ verify ─▶ challenge ─▶ memo
             │            (deterministic)                        (adversarial)
             └─ tool: run a proof-of-concept in a network-isolated sandbox
```

Each stage is one row of the changelog:

| Capability | What it adds | Why it is purposeful, not decorative |
|---|---|---|
| **Tool use** | The agent authors a PoC and **runs it** in a Docker sandbox (`--network none`, non-root) against the exact claimed version. | The claim is *checkable by execution*. Nothing else separates a real report from a fluent fake. |
| **Fidelity gate** | Deterministic: any `confirmed` not backed by a real `REPRODUCED` artifact is downgraded. | Instructions alone don't stop an LLM agreeing with a confident report; a non-LLM gate does. |
| **Abstention** | When no decisive test could run, the verdict becomes `insufficient_evidence`, routed to a human. | Avoids the dangerous error — dismissing a real vuln — by deferring instead of guessing. |
| **Verifier** | An independent pass rules on each claim against the evidence. | Catches unsupported assertions a fluent summary would smuggle through. |
| **Challenger** | Argues against every surviving `confirmed` using the same evidence. | Guards the subtle case: a real reproduction that proves a *different* thing than was claimed. |

The design mirrors the human safeguard it automates: a systematic-review-style
**independent second pass**, and a security team's habit of never confirming
without a repro.

## The single biggest design choice

**The execution-fidelity gate.** It is deterministic on purpose. Every LLM stage
can be talked into agreeing with a confident report; the gate reads the
trajectory for an actual `REPRODUCED` tool result and, finding none, refuses the
confirmation. It is also the deterministic secondary metric: after the gate,
100% of `confirmed` verdicts are backed by a real run, by construction.

## Ground truth without a benchmark

No public dataset labels vulnerability reports as real or slop, so we build ground
truth by **adversarial injection**: start from real, historically-accurate
advisories with working PoC gadgets (PyYAML CVE-2020-14343, Jinja2 CVE-2024-22195,
a PyJWT algorithms boundary), then apply named perturbations that each turn a
truthful report into a specific kind of slop —

- **version-shift** — real PoC, but the report claims an already-patched version;
- **fabricated-trigger** — confident prose, a PoC that never actually triggers;
- **wrong-function** — the narrative names an API that isn't where the bug is;
- **misversioned real gadget** *(the challenging case)* — a genuine exploit with
  the wrong version cited, which must be **abstained on, not dismissed**.

Because we author the perturbation, the label is exactly what we planted. The
agent never sees the label ([`slopgate/corpus/build.py`](slopgate/corpus/build.py)
asserts no leakage).

## Improvement Changelog

Measured on **15 cases**, the same cases at every stage. `gemini-3.5-flash`,
temperature 0. Regenerate with `python -m slopgate.eval.harness` then
`python -m slopgate.eval.report_md`.

| Stage | What it added | Accuracy | False-confirm | Exec-fidelity | Decision / learning |
|---|---|---|---|---|---|
| **Baseline** | Single prompt, no tools — what a swamped maintainer does. | 53% | **20%** (3/15) | 0% | Starting point. It confidently confirms slop it never ran — and *nothing* it confirms is execution-backed. |
| **+ Reproduction tool** | Agent authors and **runs** a PoC in the sandbox. | **93%** | **0%** | **100%** | **Kept — the change that mattered.** Execution, not eloquence, is what separates real from fake. |
| **+ Fidelity gate** | Deterministic downgrade of any confirmation with no real run. | 93% | 0% | 100% | Kept as **insurance**, not lift. No numeric change here because the model was already honest post-tool — but the gate makes 100% fidelity a *guarantee* instead of luck (see hot take). |
| **+ Abstention** | Undecidable reproductions → human-review deferrals. | 93% | 0% | 100% | Kept. No change on this corpus (no indecisive outcomes occurred); it exists for env-missing / timeout / ambiguous runs. |
| **+ Verifier** | Independent per-claim check against the evidence. | 93% | 0% | 100% | Kept for **memo quality**, not accuracy: it adds per-claim `supported/unsupported` evidence to the artifact (the 20-pt line), and would catch a confirmation whose claims aren't backed. |
| **+ Challenger** | Adversarial review of every surviving confirmation. | 93% | 0% | 100% | See dropped experiment below. |
| **+ Version sweep** | When a PoC fails on the claimed version, retry on siblings. | 93% | 0% | 100% | Kept as **memo enrichment**, not a verdict change — see the challenging case below. |

**Headline:** false-confirm **20% → 0%**, accuracy **53% → 93%**,
execution-fidelity **0% → 100%**, at **~$0.002 and ~50 s per report** against a
documented **30 min–3 h of human time** ([Stenberg, 2025-07-14](https://daniel.haxx.se/blog/2025/07/14/death-by-a-thousand-slops/)).

> **On reproducibility of these numbers.** Even at temperature 0, `gemini-3.5-flash`
> is not fully deterministic — the agent writes a fresh PoC each run, so an
> individual case can flip. Across runs the solution held at **87–93%** accuracy and
> **0–7%** false-confirm; the direction of every stage delta (and the 0%→100%
> execution-fidelity jump, which is guaranteed by construction) is stable. The table
> above is one representative run; regenerate your own with the two commands above.

### The experiment I dropped

The **first challenger** could *overturn* a confirmation. On a genuine Jinja2
vulnerability it manufactured a plausible-sounding objection and downgraded a
**correct** `confirmed` to `insufficient` — an accuracy loss on a real bug. The
lesson: an adversarial LLM will always find *something* to say, so letting it
overturn **executable proof** trades a real true-positive for rhetoric. The
revised challenger records its dissent and flags the case for a human **but never
overturns a verdict backed by a real reproduction**. Same accuracy, adversarial
review retained where it's safe.

### The one miss, and what it revealed (the challenging case)

`pyyaml-challenge-0` is a **real** exploit gadget reported against an
**already-patched** version (5.4). The agent ran it, got a clean
`NOT_REPRODUCED`, and returned `not_reproducible` — but the ideal answer was
`insufficient_evidence`: *this is a known-good gadget that simply doesn't fire on
the cited version; a human should check the version range.*

**The version sweep (built to address this).** When a PoC fails on the claimed
version, the agent now re-runs it against sibling versions. For this case it finds
the gadget reproduces on `pyyaml-5.3`, and the memo now carries the diagnostic:
*"does NOT reproduce on the claimed 5.4, but DOES on pyyaml-5.3 — confirm the
intended version range before closing."*

**Why the sweep enriches the memo but does not flip the verdict — the real
finding.** The sweep exposes that a genuine version typo (`pyyaml-challenge-0`)
and a careless/exaggerated slop report (`pyyaml-vshift-0`) are **mechanically
identical**: both are real gadgets cited against a patched version. Evidence alone
cannot separate honest mistake from careless claim — only the reporter's intent
differs, which the sandbox cannot measure. So the safe engineering choice is to
surface the fact to the human rather than have the agent guess intent. Auto-
flipping every misversioned gadget to `insufficient` would "fix" the challenge
case but would also stop auto-closing genuine slop — a maintainer's risk-tolerance
call, deliberately left to them.

## Real-world validation (beyond the synthetic corpus)

The synthetic corpus proves the mechanism; this proves it on **real, independent
CVEs**. A dynamic provisioner (`slopgate/sandbox/dynamic.py`) installs the exact
affected package from PyPI on demand into the isolated sandbox, so the agent runs
the reporter's proof-of-concept against the genuine code. Nine cases, five real
CVEs across five vulnerability classes, each as a truthful report (affected
version) and a version-shift slop report (same PoC, patched version):

| CVE | Package | Class | affected → patched |
|---|---|---|---|
| CVE-2026-68508 | hydra-core | code injection | 1.3.3 ✓ / 1.3.4 ✗ |
| CVE-2022-21797 | joblib | eval injection | 1.1.0 ✓ / 1.2.0 ✗ |
| CVE-2023-33733 | reportlab | eval sandbox escape | 3.6.12 ✓ / 3.6.13 ✗ |
| CVE-2026-40491 | gdown | tar-slip path traversal | 5.2.1 ✓ / 5.2.2 ✗ |
| CVE-2020-22083 | jsonpickle | insecure deserialization | 1.4.1 ✓ |

| | Baseline | Full solution |
|---|---|---|
| Correct-verdict rate | 67% (6/9) | **100% (9/9)** |
| False-confirm rate | 33% (3/9) | **0%** |

Two cases carry the whole story:

- **hydra-core (a 2026 CVE):** the baseline answered `not_reproducible` — wrong,
  because the model never memorized a CVE this new. The solution *ran the PoC*,
  reproduced it, and confirmed. **Execution beat memorization on a vuln too recent
  to know.**
- **reportlab / joblib / gdown version-shift:** the baseline **confirmed real
  exploits against already-patched versions** (it didn't know they were fixed).
  The solution ran each, got `NOT_REPRODUCED`, and rejected all three.

Reproduce with `python -m slopgate.eval.realdata_harness` (needs network to
provision packages; cases in `realdata/cases/`).

**Scaled to 8 verified CVEs + the symmetric gate.** The corpus was later expanded to
8 real CVEs (adding pyyaml CVE-2020-14343, js2py CVE-2024-28397, beaker CVE-2013-7489),
each **executably verified** by a ground-truth gate — `slopgate/eval/verify_cases.py`
requires the PoC to reproduce on the affected version and go quiet on the fixed one.
Only 3 of 8 researched candidates survived that gate; the rest did not reproduce as
their advisories claimed and were kept out (a corpus is only as honest as its labels
are executable). On the 18-case run, **false-confirm held at 0%** (baseline 35%),
accuracy 53% → 82%, reachability 59%.

That run also exposed a false-*dismiss*: `joblib-affected` produced a REPRODUCED
artifact on the claimed version, yet the verdict flipped to `not_reproducible` under
model nondeterminism. The fidelity gate only guarded one direction. So the gate is now
**symmetric** (`slopgate/agent/gate.py::apply_reproduction_floor`): if the claimed
version reproduced, the verdict can never be `not_reproducible`. It is deterministic
and self-tested, and keys on the claimed-version signal (not the sweep-inclusive
artifact check), so version-shift slop is never wrongly rescued — never confirm
without a run, and never dismiss despite one.

**Honest limits this surfaced.** (1) *Reachability* — the system only reproduces
when the report carries a runnable PoC; with prose only it abstains. (2) *Language*
— the sandbox is Python; C projects like curl (the motivating case) need a
separate runtime, so curl slop is handled only as a text-level baseline-fooling
test (`realdata/curl_slop_cases.json`).

## The threat-model gate (closing the trust-model-confusion gap)

The scouts' single most important finding: the most common real false-positive is
not fabrication, it is **trust-model confusion**. dnsmasq, Kamailio, Hibernate, and
the `future` CVE-2025-50817 all describe behaviour that genuinely *reproduces* —
but only after the attacker replaces a config file or writes to a trusted path.
Reproduction proves the code runs; it does not prove a trust boundary was crossed.
Pure execution confirms these — wrongly.

So after a confirmation survives the execution and adversarial gates, a
**threat-model gate** (`slopgate/agent/threat_model.py`) asks one question: *what
must the attacker control to trigger this?* If the answer is attacker-reachable
**untrusted input** (a document, token, archive, request, or a config *value*
passed to a call), the confirmation stands. If it is a **trusted resource** the
attacker could only control by already owning the host (overwriting a config file,
placing a file on the import path), the verdict is downgraded to
`insufficient_evidence` and routed to a human. It emits the identified precondition
as its evidence, and is deliberately conservative — on any doubt it keeps the
confirmation, so it never quietly discards a real vulnerability.

Added a trust-model-confusion case (`trustmodel-configfile`: a report whose PoC
reproduces via a config file the attacker must first replace) to the real corpus:

| | Baseline | Solution (with threat-model gate) |
|---|---|---|
| Correct-verdict rate | 50% (5/10) | **100% (10/10)** |
| False-confirm rate | 30% | **0%** |

The gate downgrades `trustmodel-configfile` (precondition: *"attacker must have
write access to replace the application's config file"*) **while keeping all five
genuine CVEs confirmed** — their preconditions are real untrusted input. An earlier,
more aggressive version over-rejected hydra-core and joblib by latching onto
"intended for trusted configuration" phrasing; the fix was to default to
`untrusted_input` and reserve `trusted_resource` for the unambiguous "attacker must
already own the filesystem" case. That tuning is the difference between a gate that
closes the gap and one that discards real bugs.

## v2 — closing the last two gaps

### Prose-to-PoC (reachability)

Real reports do not always ship a runnable PoC, and the agent used to abstain on
prose alone. It now runs a **bounded synthesis loop**
(`slopgate/agent/synthesize.py`): write a PoC → run it → read the error → fix →
retry (≤3). A synthesized reproduction is not trusted on its own — a separate
`demonstrates_claim` pass must confirm the PoC exercises the **claimed** impact
(not just prints the marker) before the confirmation stands, and the threat-model
gate still applies. Validated: on a real advisory with its PoC block removed
(`prose-gdown`), the agent synthesized a working tar-slip PoC on the first attempt
and reached `confirmed` — where the pre-v2 system abstained.

### Language-pluggable runtime + C/ASAN (curl)

The sandbox is no longer Python-only. `slopgate/sandbox/base.py` defines a
`Runtime` seam with `get_runtime(ecosystem)`; the Python path keeps its dynamic
provisioner, and a new **C runtime** (`slopgate/sandbox/c_runtime.py`) compiles a
PoC with `-fsanitize=address` in a gcc image — a real memory bug aborts with an
ASAN signature (→ REPRODUCED), a fabricated one runs clean (→ NOT_REPRODUCED).
This finally lets curl (C) be handled by execution, not just text.

Validated on real cases:
- **`c-real-overflow`** (a genuine stack-buffer-overflow) → ASAN fires → `confirmed`.
- **`curl-websocket-slop` / `curl-telnet-slop`** (real HackerOne AI-slop from
  Stenberg's list) → **neither confirmed** (0 false-confirms): one ran a
  synthesized C PoC that stayed clean under ASAN → `not_reproducible`; the other
  honestly **abstained** (`insufficient`) because a libcurl-*internal* claim
  cannot be proven with a self-contained PoC.

**Honest limit that remains:** the generic C runner proves memory corruption on
**self-contained** PoCs; claims about a library's internal code path (much of the
real curl slop) are not fully reachable this way, so abstention — not a confident
verdict — is the correct outcome there. Per-version libcurl builds would close
that, at the cost of a much heavier harness.

## v3 — turning two enterprise-review blockers into running code

A product team proposed taking SlopGate to an enterprise gate (static reachability
suppression + a slopsquat blocker). A day-100 pre-mortem left **two Sprint-1
blockers**; both are now demonstrated as honest, prototype-scale mechanisms — real
static analysis and real live-PyPI calls, not the aspirational Firecracker/OpenVEX
stack.

### R1 — a reachability slicer whose soundness bias lives in the *scanner*

The enterprise design suppressed an advisory as `not_affected` when a static slicer
marked the vulnerable symbol `UNREACHABLE_STRICT`. Its stated rule was "default to
ambiguous," but its *escalation* was a **denylist match** against an enumerated
registry — so any dynamic construct the registry forgot fell straight through to a
signed `not_affected`. That is failing *open* on the unknown.

`slopgate/reach/slicer.py` inverts it. It recognises a **whitelist of statically-
modelable AST node types**; ANY node outside it — a construct the analyzer doesn't
model, a future language feature, an unparseable file — forces `DYNAMIC_AMBIGUOUS`.
The denylist of known-dynamic constructs still exists, but only as an *optimization*
that yields a precise reason; a gap in it costs **noise** (a spurious AMBIGUOUS),
never a false STRICT. The headline metric is therefore **soundness violations = 0**:

```
python -m slopgate.reach.eval     # 12/12 classified, 0 soundness violations
```

The load-bearing case is `unmodeled_match`: a `match` statement is a real, post-3.10
construct a slicer (or registry) written earlier would not model. A denylist that
never listed it suppresses to STRICT; the fail-closed scanner escalates to AMBIGUOUS
instead (on Python < 3.10 the same source fails to parse and takes the parse-fail
path to AMBIGUOUS — either way, never STRICT). It is standalone and advisory-only: a
report carries no consuming repo to slice, so this proves the *mechanism*, and never
auto-suppresses — consistent with "the customer signs, suppression is deterministic."

**At scale** (`python -m slopgate.reach.eval_scale`, 4,000 real stdlib + site-packages
files, no network): **0 crashes, 0 soundness violations**. All **2,932** genuinely-
referenced symbols classified `REACHABLE_CONFIRMED`; on an absent symbol the split was
60% `STRICT` / 40% `AMBIGUOUS` / **0% falsely reachable** — it escalates exactly when a
file's dynamic/unmodeled constructs block a strict proof, and never signs a false
STRICT on a symbol that is actually used.

### R2 — a name-slop classifier that is warn-only until its FP rate is measured

The enterprise slopsquat gate keyed on Levenshtein distance — i.e. **typosquatting**,
not the AI-hallucination threat the product is named for: an LLM inventing a plausible
*compound* name (`langchain-chroma-retriever`) that isn't a typo of anything. And it
proposed to **synchronously block** on an unmeasured threshold, over vectors that
also fingerprint legitimate young packages.

`slopgate/slop/` scores the real threat — compound-name mimicry + temporal asymmetry
(live PyPI age / absence) + provenance deficit — and is wired into the pipeline as a
**warn-only advisory** (`TriageMemo.slop_advisory`) that records a note and **never
changes the verdict**. The weights are set so the offline name-shape signal alone
cannot cross the flag threshold; a name only flags when a live registry signal
corroborates it. The deliverable is the measurement the review demanded before any
block:

```
python -m slopgate.slop.eval      # live PyPI (cached): FP rate + recall
```

On the labeled corpus (`slopgate/slop/cases/`): **false-positive rate 0/12 (0%)**,
**recall 10/10** on invented names. The honest detail that makes the point: real
compound packages like `django-redis` and `langchain-chroma` score identically to
slop on *name shape alone* (0.45) — only the live age/provenance signal pulls them
below the threshold. And building the corpus surfaced that two names I'd assumed were
invented (`flask-jwt-router`, `fastapi-auth-middleware`) are **real, ~4–7-year-old
packages**; the classifier correctly refused to flag them, and they were relabeled as
legitimate. A brand-new legit compound with missing provenance *would* score higher —
which is exactly why it ships warn-only, not as a synchronous block.

**At scale** (`python -m slopgate.slop.eval_scale`, live PyPI): **300 real
compound-shaped packages → 0 false positives (0.00%)**; **300 genuinely-absent
hallucination-shaped names → 100% recall** (of 900 generated names, 2 turned out to
be already registered on PyPI — real or squatted). The honest caveat: the 300 real
packages come from the top-PyPI list, so they are *established* (old + provenance) and
score ≤0.45 by construction — this proves it never flags established real compounds,
but does not stress *young* legit packages, which stay the real FP risk. That gap is
the reason the classifier stays warn-only rather than blocking.

Both mechanisms are guarded by the sandbox self-test
(`python -m slopgate.sandbox.selftest`): a reachability check (including the
unmodeled-construct-must-not-suppress invariant) and a network-free slop-classifier
check.

## Hot take

I built five agentic safeguards on top of the base model — a reproduction tool, a
deterministic fidelity gate, an abstention branch, an independent verifier, and an
adversarial challenger. **Exactly one moved the numbers: letting the agent run the
code.** Tool use took accuracy from 53% to 93% and false-confirms from 20% to
zero. The other four added *no* accuracy on this benchmark.

That is the lesson, and it's the opposite of "more agentic is better." For a
verification task, the highest-leverage move isn't another reasoning layer — it's
giving the agent a way to **check reality** and the discipline to not answer until
it has. The baseline's failure was never a lack of reasoning; it reasoned
beautifully about slop and confirmed it. It lacked *contact with the world.*

So why keep the gate if it scored nothing? Because its metric isn't accuracy, it's
**execution-fidelity: 0% → 100%.** The baseline backs *none* of its confirmations
with execution — it runs nothing. Once the agent has the tool it happened to be
honest, so the gate had nothing to downgrade in this run. The gate makes that a
*guarantee* rather than luck: the day the model starts hallucinating "yes I
reproduced it" (and they do), the gate is the only thing standing between you and a
93% that has quietly rotted back to baseline. **A verifier you cannot audit is just
another generator.** Make the check emit an artifact, and gate on the artifact —
not on the model's say-so. The gate earns its keep not in the average case, but in
the adversarial one — which, for a tool built to catch AI slop, is the only case
that ultimately matters.

## What existed before vs. built during

- **Before:** the CVE gadgets are public knowledge; Docker; Python stdlib; the
  Gemini API.
- **Built during:** the sandbox harness, the injection corpus, all agent stages,
  the fidelity gate, the trajectory logger, the evaluation harness, and this
  writeup.

## Run it

See [`docs/REPRODUCTION.md`](docs/REPRODUCTION.md). Short version:

```bash
cp .env.example .env            # add your GEMINI_API_KEY
docker build -t slopgate-sandbox:v1 .
python -m slopgate.sandbox.selftest      # sandbox discriminates versions
python -m slopgate.corpus.build          # 15 injected cases
python -m slopgate.eval.harness          # baseline vs solution, all stages
python -m slopgate.reach.eval            # v3 R1: reachability, 0 soundness violations
python -m slopgate.reach.eval_scale      # v3 R1 at scale: 4000 real files, no network
python -m slopgate.slop.eval             # v3 R2: name-slop FP rate (needs network)
python -m slopgate.slop.eval_scale       # v3 R2 at scale: live PyPI FP/recall
```

Host code is Python **stdlib-only** (no `pip install`); the sandbox needs Docker.
The model is `gemini-3.5-flash` (the newer `gemini-3.7-flash` was returning
sustained 503s during the build — see `docs/REPRODUCTION.md`; override with
`SLOPGATE_MODEL`). Cost of a full run is well under $0.05.
