# Improvement Changelog

Problem: an AI-slop triage agent for the open-source security maintainer. The
agent adjudicates an incoming vulnerability report and produces a signed triage
memo — verdict, the reproduction attempt and its actual output, per-claim
evidence, an explicit abstention branch, and a human sign-off. No "confirmed"
verdict is issued without a backing execution artifact and human sign-off.

Measured on **15 cases**, the same cases at every stage. Model `gemini-3.5-flash`,
temperature 0. Reproduce: `python -m slopgate.eval.harness`.

| Stage | What was tried and why | Evidence / result | Decision / learning |
|---|---|---|---|
| Gate 0 — sandbox | Before any agent code, validate the riskiest step: a network-isolated container that runs untrusted PoC code and discriminates a real vulnerability from a patched version. | CVE-2020-14343 / CVE-2024-22195 / PyJWT boundary: REPRODUCED on affected, NOT_REPRODUCED on patched. ~1s/run. | Kept. Executable ground truth confirmed; the confirmation gate cannot be fooled by wording. |
| Baseline | Single prompt, verdict from report text alone — what a swamped maintainer does. | accuracy **53%**, false-confirm **20%** (3/15), exec-fidelity 0%. | Starting point. It reasons fluently about slop and confirms it. |
| + Reproduction tool | Let the agent author and **run** a PoC in the sandbox against the claimed version. | accuracy **93%**, false-confirm **0%**, exec-fidelity **100%**. | **Kept — the single change that mattered.** Execution, not eloquence, separates real from fake. |
| + Fidelity gate | Deterministically downgrade any "confirmed" not backed by a real REPRODUCED artifact. | No accuracy change (model already honest post-tool); exec-fidelity guaranteed 100% by construction. | Kept as **insurance**, not lift — the guarantee that holds when a model starts hallucinating reproductions. |
| + Abstention | When no decisive test could run, defer to a human instead of guessing. | No change on this corpus (no indecisive outcomes occurred). | Kept for robustness on env-missing / timeout / ambiguous runs. |
| + Verifier | Independent per-claim check against the evidence. | No verdict change; adds per-claim supported/unsupported evidence to the memo. | Kept for artifact quality (the 20-pt line), not accuracy. |
| + Challenger v1 | Adversarial reviewer that could **overturn** a confirmation. | **Regression:** overturned a genuine Jinja2 vulnerability on a manufactured objection. | **Removed.** An adversarial LLM always finds something to say; it must not overturn executable proof. |
| + Challenger v2 (final) | Challenger records dissent and flags for a human, but never overturns a verdict backed by a real reproduction. | accuracy **93%**, false-confirm **0%**, exec-fidelity **100%**. | Kept. Adversarial review retained where it is safe. |
| + Version sweep | When a PoC fails on the claimed version, retry it on sibling versions and record where it reproduces. | Verdicts unchanged; the memo now tells a maintainer a real-but-misversioned gadget for what it is. | Kept as memo enrichment. It does NOT flip the verdict: evidence cannot separate an honest version typo from careless slop — that call is surfaced to the human. |

**Headline:** false-confirm 20% → 0%; accuracy 53% → 93%; execution-fidelity
0% → 100%; ~$0.002 and ~50 s per report vs a documented 30 min–3 h of human
time (Stenberg, 2025-07-14). Note: `gemini-3.5-flash` is not fully deterministic
even at temperature 0; across runs the solution held at 87–93% accuracy / 0–7%
false-confirm, with every stage delta stable in direction.

**Main failure mode:** a clean non-reproduction is indistinguishable from a
misversioned real bug (case `pyyaml-challenge-0`): a genuine gadget cited against
a patched version is reported `not_reproducible` when the ideal is
`insufficient_evidence`. The version sweep now surfaces this to the human in the
memo ("reproduces on 5.3, not the claimed 5.4"), but deliberately does not flip
the verdict, because the same evidence also describes careless slop — telling the
two apart needs intent the sandbox cannot measure.

**Hot take:** I built five agentic layers; exactly one moved the numbers — running
the code. For a verification task the highest-leverage move isn't another reasoning
layer, it's contact with reality plus the discipline not to answer without it. The
gate keeps its place not for average-case lift but for the adversarial case: a
verifier you cannot audit is just another generator.

---

## v3 — two enterprise-review blockers, turned into code

After a day-100 pre-mortem of a proposed enterprise gate, two Sprint-1 blockers were
built as honest, prototype-scale mechanisms (real static analysis; real live-PyPI).

| Change | What was tried and why | Evidence / result | Decision / learning |
|---|---|---|---|
| R1 — fail-closed reachability slicer | The enterprise design's reachability suppression escalated via a **denylist** of dynamic constructs, so an unlisted construct fell through to a signed `not_affected`. Move the soundness bias into the scanner: a **whitelist** of modelable AST nodes; anything else ⇒ `DYNAMIC_AMBIGUOUS`. | Labeled: 12/12, **0 soundness violations** (`unmodeled_match` → AMBIGUOUS, never STRICT). **At scale** (`eval_scale`, 4,000 real files): 0 crashes, **0 soundness violations**, 2,932 referenced symbols all REACHABLE; absent-symbol split 60% STRICT / 40% AMBIGUOUS / 0% falsely reachable. | Kept, standalone + advisory-only. Registry gaps now cost noise, never a false attestation. |
| R2 — warn-only name-slop classifier | The enterprise slopsquat gate used Levenshtein (typosquatting), not the compound-name AI-hallucination threat, and proposed a synchronous block on an unmeasured threshold. Score the real threat (mimicry + live temporal + provenance); wire it in **warn-only**; measure the FP rate first. | Labeled (live PyPI): **FP 0/12**, recall 10/10. **At scale** (`eval_scale`): **300 real compound packages → 0 FP (0.00%)**, 300 absent hallucination-shaped names → **100% recall**. Caveat: real set is top-PyPI (established), so young legit packages are not stressed — hence warn-only. | Kept as `TriageMemo.slop_advisory`; **never changes the verdict**. Ships warn-only until the FP rate justifies blocking. |

**Learning:** both fixes are the same shape — the enterprise design let a *denylist*
own a safety decision, so a gap became a silent false negative. The correction in
each case is to make the *unknown* degrade to the conservative outcome (AMBIGUOUS /
warn), and to **measure** before acting automatically. Building R2's corpus also
caught two names I'd assumed were slop but which are real, years-old packages — the
classifier correctly declined to flag them, and they were relabeled (integrity note
in `slopgate/slop/cases/`).
