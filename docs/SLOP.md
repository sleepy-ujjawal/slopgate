# R2 — the warn-only AI-slop name classifier

## The problem it fixes

An enterprise "slopsquat" gate proposed blocking dependencies whose names were
within Levenshtein edit-distance 2 of a top-10k package. That defends against
**typosquatting** — near-miss typos of popular names. But it is blind to the threat
the product is named for: an LLM hallucinating a **plausible compound name**
(`langchain-chroma-retriever`, `flask-jwt-router`) that an attacker then registers.
Those are not typos of anything; they are novel, well-formed tokens. Worse, the gate
proposed to **synchronously block** on an unmeasured threshold, over signals that
also describe many legitimate young packages.

## The fix: score the real threat, warn-only, and measure first

`slopgate/slop/` scores a name on four explicit, tunable vectors:

| Vector | Weight | Signal |
|---|---|---|
| `mimicry` | 0.45 | compound `[framework root] + [domain/utility]` name shape |
| `temporal` | 0.30 | very young, or **absent from PyPI entirely** (a 404 is the purest hallucination signal) |
| `provenance` | 0.20 | no project URLs / homepage (an owned package usually has one) |
| `context` | 0.05 | introduced by an AI-assisted change |

`score = Σ wᵢ·vᵢ`; a name flags at `score ≥ 0.75`. Two deliberate choices, both from
the review:

- **The weights are set so `mimicry` alone (max 0.45) cannot cross the threshold.**
  A name only flags when its shape is corroborated by a *live registry* signal
  (youth / absence / missing provenance). Offline, with no metadata, the classifier
  therefore never flags — the safe direction for a warn-only feature.
- **`context` has near-zero weight on purpose.** By 2026 most legitimate PRs are
  AI-assisted, so "touched by an agent" is a tie-breaker, never a driver.

Levenshtein is demoted to (at most) a secondary typosquat signal; it is not the
primary hallucination signal here.

## Warn-only wiring

`apply_slop_advisory` (`slopgate/slop/advisory.py`) mirrors the *non-downgrading*
path of the threat-model gate: it records a trajectory note and, if the name flags,
sets `TriageMemo.slop_advisory`. **It never touches the verdict** — supply-chain
naming is orthogonal to whether a report reproduces, and the whole point of the
resolution is that this ships warn-only until its false-positive rate is known. The
realdata pipeline runs it against live PyPI; the synthetic multi-stage path runs it
offline (mimicry-only), so the synthetic corpus incurs no network and, by
construction, never flags.

## The measurement (the deliverable the review demanded)

```
python -m slopgate.slop.eval            # live PyPI (cached)
python -m slopgate.slop.eval --offline  # mimicry-only, no network
```

On the labeled corpus (`slopgate/slop/cases/legit.json`, `slop.json`):

- **false-positive rate: 0/12 (0%)** — no real package flagged;
- **recall: 10/10** — every invented compound name flagged.

The honest detail that makes the point: real compound packages like `django-redis`
and `langchain-chroma` score **identically to slop on name shape alone** (0.45).
Only the live age/provenance signal pulls them under the threshold. A brand-new
*legitimate* compound with missing provenance would score higher — which is exactly
why this is warn-only and not a synchronous block.

### At scale

```
python -m slopgate.slop.eval_scale [--limit N]   # live PyPI, cached
```

Pulls hundreds of real compound-shaped packages from the top-PyPI dataset (the FP-risk
set) and generates hundreds of `[framework]+[domain]+[utility]` names, keeping the ones
PyPI 404s (the absent, hallucination-shaped set). Measured run (`--limit 300`):

| Corpus | n | Result |
|---|---|---|
| real compound packages | 300 | **0 false positives (0.00% FP rate)** |
| generated candidates | 900 | 2 already registered on PyPI (real or squatted) |
| confirmed-absent names | 300 | **100% flagged (recall)** |

**The honest caveat.** The 300 real packages come from the top-PyPI list, so they are
all *established* — old, with provenance — and therefore score ≤0.45 by construction.
This proves the classifier never flags an *established* real compound; it does **not**
stress a *young* legitimate package with missing provenance, which remains the real
FP risk. Quantifying that would need a labeled set of recently-published legitimate
packages. Until it exists, warn-only is the only defensible mode — which is exactly
how the classifier is wired.

### An integrity note from building the corpus

Two names I first labeled "slop" — `flask-jwt-router` and `fastapi-auth-middleware`
— turned out to be **real packages, ~4–7 years old, with provenance**. The
classifier correctly refused to flag them (they predate the LLM era and carry
registry provenance), and they were **relabeled as legitimate**. That is the FP test
working: the ground truth was wrong, not the classifier.

## Limits

- **No download counts.** The PyPI JSON API does not expose them; the temporal
  vector uses release age + release count only. pypistats.org is a possible future
  second source.
- **Small corpus.** 22 names. The FP rate is an existence-proof of the measurement
  discipline, not a production-calibrated number — which is the whole reason the
  gate stays warn-only.
- **Provenance is checked, not verified.** We read `project_urls`/`home_page`
  presence; we do not (by default) ping the repo URL to confirm it resolves.
