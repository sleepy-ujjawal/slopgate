# micro1 Frontier Engineering Challenge 2026 — Context

## What this hackathon actually is

- Hosted by micro1, run on HackerEarth: `hackerearth.com/community/challenges/hackathon/micro1-frontier-engineering-challenge-2026/`
- Official brief PDF (confirmed as the real challenge document, hosted on HackerEarth's own asset domain):
  `https://uc.hackerearth.com/he-public-ap-south-1/micro1%20-%20First%20Hackathon97ce7c5.pdf`
- Titled internally "Agentic Workflows Hackathon" — this is the **same** event as the Frontier Engineering Challenge 2026, not a separate one. (Earlier in this research process there was confusion because secondary press coverage described a different, fixed-problem, secret-until-kickoff format — that description does not match the actual PDF and should be disregarded.)
- Format: **you pick your own problem**, use agents to solve it, and prove improvement over a fair baseline. Not a fixed bug/spec handed to you at kickoff.

## The challenge, in the organizers' words

Pick a **specific and meaningful problem you understand**. Use agents to solve it and show through clear evidence that your solution improves how the task is handled today. Start by explaining who has the problem, the bottleneck they face, and why solving it matters. The goal is something a real person would want to use.

**Four questions to keep in mind for the problem statement:**
1. Who has this problem?
2. What bottleneck makes it worth solving?
3. Does the agent solve it well?
4. Can another person reproduce the result?

**Agentic capabilities to draw on (use what fits, not all of them):** better context, better tools, memory across steps, verification/self-correction, specialized skills, multi-agent orchestration. Judges care about whether each design choice was purposeful, not how many components you used.

## Ground rules (mandatory)

1. You may build with tools/components you already know.
2. Be explicit about what existed before the competition vs. what you built during it.
3. Respect every tool/component's license and service terms.
4. Keep consequential actions inside a sandbox or simulation; require human approval before the action happens.
5. A qualified human reviewer must be part of any solution that could significantly affect someone.
6. Use only data you're allowed to share — public, synthetic, or approved anonymous data. No credentials or private info in the submission.
7. Connect every claim about results to the evidence you submit.
8. Give judges enough access to run the project and reproduce the main result.

## Required deliverables

1. **Solution code + Improvement Changelog**
   - README: who the intended user is, their current bottleneck, why solving it is valuable.
   - A changelog table: `Stage | What you tried and why | Evidence/result | Decision or learning`. One row per meaningful iteration, starting from the baseline. Include experiments you tried and removed, and what they taught you.
   - Close with your main failure mode and a "hot take" — a lesson that would change how you build agents next time.

2. **Reproduction guide** — written for someone starting from a clean environment. Setup steps, exact commands for baseline, solution, and evaluation. What data is required, what output to expect, versions used, approximate runtime and cost.

3. **Solution video (≤5 minutes)** — problem + simple baseline → one full realistic execution start to finish → final baseline-vs-solution comparison → brief changelog walkthrough → the single change that helped most + one experiment you dropped.

4. **Agent trajectories** — for every agent used, a readable trace: instructions given → tool calls and their responses → the feedback that shaped the next step → any retries or human checkpoints.

## Scoring (100 points)

| Criterion | Points | What strong work looks like |
|---|---|---|
| Problem & User Value | 15 | Clearly defined user; obvious why the bottleneck matters |
| **Agent Solution & Engineering** | **30** | Purposeful use of context/tools/memory/verification/skills/orchestration — the single biggest line, bigger than Problem + Measured Improvement combined |
| End-to-End Quality | 20 | Output looks like something a person would sign their name to, not an obvious AI draft |
| Measured Improvement | 15 | Fair baseline; changelog ties each iteration to evidence |
| Reproducibility | 15 | Another person can run it from a clean environment and reach the main result |
| Hot Take / Insights | 5 | A real lesson from an observed failure mode, not a platitude |

Key takeaway: **Agent Solution & Engineering (30 pts) should drive where build time goes.** A "call an API, rank results" wrapper will score weakly here even if the idea is good.

## Problem statement brainstorming — how we got to the final pick

Initial memory-grounded brainstorm (rejected by request — user wanted general, not personal/work-specific ideas):
- EDD breach root-cause agent, Core Web Vitals regression triage, dark-pattern checkout compliance auditor, experiment/metrics synthesis agent — all tied to Ujjawal's SleepyCat work. User explicitly asked to move away from these toward generalizable problems.

Deep research pass (`launch_extended_search_task`) produced a ranked shortlist of 8 generalizable, evidence-backed problem spaces, scored against: named persona + documented bottleneck, fair measurable baseline, genuine multi-step agentic depth, and reproducibility from public/synthetic data. Full ranked list:

1. **Evidence-screening agent for systematic literature reviews** — screener for research teams; bottleneck: reviews average 67.3 weeks (Borah et al., BMJ Open 2017), manual screening error rate 6–21%; public datasets: SYNERGY, CLEF TAR; metric: WSS@95.
2. **CVE triage & remediation-planning agent** — SOC analyst prioritizing vulnerabilities; bottleneck: CVSS doesn't prescribe action, NVD 2026 enrichment gaps; public data: NVD API, CISA KEV catalog (free JSON, no key), FIRST EPSS; ground truth: KEV = confirmed exploited in the wild.
3. **Security-questionnaire / RFP response agent** — GRC/security engineer answering vendor questionnaires; bottleneck: 88% of orgs take 2+ weeks per assessment (Iris AI 2026), 54% lose deals over late responses; no ready public dataset, needs a synthetic policy corpus.
4. Contract risk-review agent (CUAD dataset) — solid rubric fit but a crowded commercial space.
5. DevOps incident triage / root-cause-hypothesis agent (Loghub, public postmortems).
6. Customer-support ticket triage + resolution-draft agent (Bitext synthetic dataset, Ubuntu Dialogue Corpus).
7. Financial month-end reconciliation agent — weak spot: no standard public transaction-level reconciliation dataset.
8. Flaky-test triage agent.

Honorable mentions: nonprofit grant-application agent, prior-authorization appeal-letter agent (both weaker on objective ground truth or data sensitivity).

## Feasibility check for a solo 3-day build with Claude Code (Aug 28–31)

| Idea | Data access | Build complexity | Risk |
|---|---|---|---|
| Literature-review screening | SYNERGY/CLEF TAR need downloading/formatting; active-learning loop is nontrivial ML | Medium-high | Unfamiliar metric (WSS@95), easy to implement wrong |
| **CVE triage & remediation** | CISA KEV catalog is a single free JSON file, no key needed (`cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`); NVD and EPSS also free/keyless for light use | Medium | Well-scoped; time goes into agent engineering, not data wrangling |
| Security-questionnaire agent | No ready public dataset — must hand-build a synthetic policy corpus and gold answer set | High | Most of the 3 days would burn on data creation instead of the agent itself |

## Chosen problem statement: CVE Triage & Remediation-Planning Agent

**Who has this problem?** A security engineer / SOC analyst who has to decide, out of a daily flood of CVEs, what to patch first.

**What's the bottleneck?** CVSS severity alone doesn't tell you what's actually being exploited — more than half of published CVEs score high/critical, so a CVSS-only cutoff is close to noise. NIST's 2026 NVD enrichment overhaul is also leaving more CVEs unscored, pushing the triage burden further onto teams. Analysts fall back on arbitrary CVSS thresholds and manual cross-referencing.

**Does the agent solve it well?** Multi-tool orchestration: an enrichment agent pulls NVD + CISA KEV + EPSS data and cross-references a synthetic asset inventory for blast-radius; a ranking agent applies a decision framework (SSVC-style); a verification agent must justify each ranking by citing the retrieved evidence and can flag low-confidence/conflicting cases; nothing becomes "priority-one" without human confirmation (sandbox + human-in-loop, satisfying the ground rules).

**Can it be reproduced?** Yes — NVD, CISA KEV, and EPSS are all free, public, machine-readable data sources; no scraping or private data needed.

**Baseline for comparison:** sort-by-CVSS (what most teams actually do today).

**Measured improvement:** rank quality (e.g., precision@k / nDCG) against CISA KEV as objective, time-separated ground truth — CVEs later confirmed exploited in the wild.

**Hot take candidate:** agents that anchor on CVSS severity systematically underrank low-CVSS-but-actively-exploited CVEs — exactly the ones KEV catches. This is demonstrable and makes a strong changelog + hot-take story.

## What "enough depth to win" requires

A bare "call 3 APIs, rank by score" version is a thin wrapper and would score weakly on the 30-point Agent Solution & Engineering line. To be competitive, the build needs layered agentic design:

1. **Multi-step orchestration, not one call** — separate enrichment / ranking / verification agents (distinct roles), not a single prompt.
2. **A genuine verification/self-correction loop** — the agent justifies each ranking by citing the evidence that drove it, and abstains or flags low confidence on conflicting signals (e.g., high EPSS but no matching asset).
3. **An adversarial "challenger" check** — a second agent argues against the top-ranked CVE using the same evidence, forcing the system to defend or revise its ranking. Strong source material for the Hot Take.
4. **Memory** — the agent retains simulated analyst feedback on past rankings and adjusts future weighting, satisfying the "memory" capability the judges call out explicitly.
5. **A real changelog with 4–5 iterations**, each with its own measured delta against KEV ground truth: baseline (CVSS sort) → + KEV → + EPSS → + verification loop → + adversarial check → final.

If time is tight, prioritize the **verification loop** and the **changelog with real measured deltas** first — together they hit the two heaviest-weighted rubric lines (Agent Solution & Engineering: 30, Measured Improvement: 15).

## Open / not yet done

- Full day-by-day (Day 1 / Day 2 / Day 3) build schedule for Claude Code has been offered but not yet written up in detail.
- Exact synthetic asset-inventory design not yet specified.
- Exact SSVC-style decision framework parameters not yet chosen.
