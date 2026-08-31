# Reproduction guide

Written for someone starting from a clean environment. Every command is exact.

## 0. Prerequisites

| Requirement | Version used | Notes |
|---|---|---|
| Python | 3.9+ | host code is stdlib-only, no `pip install` needed |
| Docker | 29.x | runs the reproduction sandbox |
| Google AI Studio API key | — | free tier works; set as `GEMINI_API_KEY` |

No Python packages are installed on the host. The only heavy dependency is
Docker, which the sandbox genuinely needs to execute proof-of-concept code in
isolation.

## 1. Set the API key

```bash
cp .env.example .env
# edit .env and set GEMINI_API_KEY=<your Google AI Studio key>
```

The `.env` file is git-ignored and must never be committed (hackathon ground
rule 08).

**Model note (honest):** the newest flash model, `gemini-3.7-flash`, was
returning sustained HTTP 503 (capacity) during the build window, at ~60s per
failed attempt — unusable for a multi-call evaluation. The workhorse is therefore
`gemini-3.5-flash` (thinking-capable, ~10s/call, reliably available); the
fallback on overload is `gemini-2.5-flash`. Any fallback is recorded in the
trajectory so results stay auditable. To pin a different model:

```bash
SLOPGATE_MODEL=gemini-3.7-flash python -m slopgate.eval.harness   # if 3.7 frees up
```

## 2. Build the reproduction sandbox (one time, ~1 min)

```bash
docker build -t slopgate-sandbox:v1 .
```

This installs the pinned vulnerable/patched package versions listed in
`corpus/environments.tsv`, each into its own isolated directory. Verify it:

```bash
# should print REPRODUCED on the vulnerable version, NOT_REPRODUCED on the patched
python -m slopgate.sandbox.selftest      # (see §5)
```

## 3. Build the evaluation corpus

```bash
python -m slopgate.corpus.build
# Wrote 15 cases to corpus/cases   verdict distribution: {confirmed:5, not_reproducible:9, insufficient_evidence:1}
```

Cases are generated deterministically by adversarial injection over real
advisories. Each case file has a `report` (all the agent sees) and a
`ground_truth` (read only by the evaluator).

## 4. Run the baseline-vs-solution evaluation

```bash
python -m slopgate.eval.harness            # all 15 cases, all 6 stages
python -m slopgate.eval.harness --limit 3  # quick smoke run
```

Expected runtime: the model carries ~40s of thinking latency per call; the full
run makes roughly 90 calls across 15 cases and, with the default 5 workers,
completes in about **10–15 minutes** for well under **$0.05** total. It prints:

- the **stage comparison table** (accuracy, false-confirm, false-dismiss,
  execution-fidelity, abstention per changelog stage), and
- the **human-time / cost table** (baseline vs full solution).

Per-case results land in `runs/_eval/results.json`; a readable agent trajectory
for every case is written to `runs/<report_id>/trajectory.md`.

## 5. What to expect

- **Baseline** (single prompt, no tools) confirms confidently-worded slop → high
  false-confirm.
- The **fidelity gate** drives false-confirm toward zero and forces
  execution-fidelity to 100%.
- **Abstention** converts undecidable cases into human-review deferrals rather
  than wrong dismissals.

Exact figures are in the README's Improvement Changelog. Because the model is
not fully deterministic even at temperature 0, expect small run-to-run variation;
the direction of every stage delta is stable.
