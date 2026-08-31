"""Generate the coverage matrix — what SlopGate reproduces vs. abstains on — from
the last real-data run. Data-driven honesty: the matrix is derived from results
that actually ran, so the public claim can never drift from the measured reality.

    python -m slopgate.eval.realdata_harness      # produce runs/_realdata/results.json
    python -m slopgate.eval.coverage              # -> docs/COVERAGE.md

The point of the roadmap's NOW lane is to pitch SlopGate to the lane it wins
(slop-rejection + triage), so the coverage matrix must state plainly where execution
reaches a verdict and where it honestly abstains.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "runs" / "_realdata" / "results.json"
CASES = ROOT / "realdata" / "cases"
OUT = ROOT / "docs" / "COVERAGE.md"

# vuln class inferred from the report text — ordered, first match wins.
_CLASS_RULES = [
    ("memory corruption", ("overflow", "buffer", "use-after-free", "asan", "memory")),
    ("unsafe deserialization", ("pickle", "yaml", "deserial", "unpickle", "marshal")),
    ("eval / code-injection", ("eval", "code injection", "exec(", "code exec", "rce")),
    ("path traversal", ("traversal", "tar-slip", "zip-slip", "extractall", "../", "arbitrary file")),
    ("sandbox escape", ("sandbox", "escape", "restrictedpython")),
    ("XXE", ("xxe", "external entity", "xml entity")),
    ("trust-model", ("config file", "trusted", "trust boundary", "import path")),
]


def _infer_class(text: str) -> str:
    t = text.lower()
    for name, kws in _CLASS_RULES:
        if any(k in t for k in kws):
            return name
    return "other"


def _reason(r: dict) -> str:
    outcome = r.get("repro_outcome", "")
    exp = r.get("expected", "")
    if r.get("reproduced"):
        return "reproduced"
    if outcome == "NO_POC":
        return "no runnable PoC in the report (prose or library-internal claim)"
    if outcome == "TIMEOUT":
        return "reproduction timed out"
    if outcome in ("ERRORED", "PROVISION_FAILED", "HARNESS_ERROR", "INCONCLUSIVE"):
        return f"could not run a decisive test ({outcome})"
    if outcome == "NOT_REPRODUCED":
        return ("PoC does not fire on the claimed version (version-shift slop)"
                if exp != "confirmed" else "did not reproduce on the claimed version")
    return outcome or "unknown"


def _load():
    if not RESULTS.exists():
        print(f"no results at {RESULTS}. Run: python -m slopgate.eval.realdata_harness",
              file=sys.stderr)
        return None
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    for r in results:
        case_path = CASES / f"{r['report_id']}.json"
        eco, text = "python", ""
        if case_path.exists():
            c = json.loads(case_path.read_text(encoding="utf-8"))
            eco = c["report"].get("ecosystem", "python")
            text = f"{c['report'].get('title','')} {c['report'].get('body','')}"
        r["_ecosystem"] = eco
        r["_class"] = _infer_class(text or r.get("cve", ""))
        r["_reason"] = _reason(r)
    return results


def _render(results: list) -> str:
    n = len(results)
    reproduced = [r for r in results if r.get("reproduced")]
    abstained = [r for r in results if not r.get("reproduced")]
    fc = sum(r["solution"] == "confirmed" and r["expected"] != "confirmed" for r in results)

    # class x outcome grid
    grid = defaultdict(lambda: {"reproduced": 0, "abstained": 0})
    ecosystems = defaultdict(lambda: {"reproduced": 0, "abstained": 0})
    for r in results:
        k = "reproduced" if r.get("reproduced") else "abstained"
        grid[r["_class"]][k] += 1
        ecosystems[r["_ecosystem"]][k] += 1

    L = [
        "# SlopGate — coverage matrix",
        "",
        "_Generated from the last real-data run (`slopgate/eval/coverage.py`); it is "
        "derived from cases that actually executed, so it cannot drift from what was "
        "measured. Regenerate after a run with `python -m slopgate.eval.coverage`._",
        "",
        "SlopGate's job is **triage + slop-rejection**, not universal reproduction. "
        "It reaches a decisive verdict by *executing* the report; where execution "
        "cannot reach it, the system **abstains** (routes to a human) rather than "
        "guessing. This matrix states plainly which is which.",
        "",
        "## Headline",
        "",
        f"- **Cases:** {n}",
        f"- **Reproduced (reachability):** {len(reproduced)}/{n} "
        f"({len(reproduced)/n:.0%})" if n else "- no cases",
        f"- **Abstained / not reproduced:** {len(abstained)}/{n} "
        f"({len(abstained)/n:.0%})" if n else "",
        f"- **False-confirm rate (solution):** {fc}/{n} ({fc/n:.0%}) — the number "
        "that matters most for a maintainer." if n else "",
        "",
        "## By vulnerability class",
        "",
        "| Class | Reproduced | Abstained |",
        "|---|---|---|",
    ]
    for cls in sorted(grid):
        g = grid[cls]
        L.append(f"| {cls} | {g['reproduced']} | {g['abstained']} |")

    L += ["", "## By ecosystem", "", "| Ecosystem | Reproduced | Abstained |",
          "|---|---|---|"]
    for eco in sorted(ecosystems):
        g = ecosystems[eco]
        L.append(f"| {eco} | {g['reproduced']} | {g['abstained']} |")

    L += ["", "## Reproduces well (execution reached a verdict)", "",
          "| Case | CVE | Class | Ecosystem | Solution verdict |",
          "|---|---|---|---|---|"]
    for r in reproduced:
        L.append(f"| `{r['report_id']}` | {r.get('cve','—')} | {r['_class']} | "
                 f"{r['_ecosystem']} | {r['solution']} |")

    L += ["", "## Abstains / does not reproduce (and why)", "",
          "| Case | CVE | Why not reached by execution | Solution verdict |",
          "|---|---|---|---|"]
    for r in abstained:
        L.append(f"| `{r['report_id']}` | {r.get('cve','—')} | {r['_reason']} | "
                 f"{r['solution']} |")

    L += [
        "",
        "## What we abstain on — the honest ceiling",
        "",
        "Execution-based triage cannot reach a verdict when the claim lives outside a "
        "self-contained, sandbox-runnable proof-of-concept. On real-world traffic the "
        "dominant abstention causes are:",
        "",
        "- **No runnable PoC** — the report describes a library-internal code path "
        "(e.g. much of the real curl slop) that a self-contained PoC cannot exercise.",
        "- **Runtime dependencies the air-gap forbids** — the PoC needs live "
        "networking, an external binary (git, nmap), or a system library not in the "
        "sandbox.",
        "- **Environment-sensitive triggers** — GUI, hardware, timing/race conditions.",
        "",
        "In every one of these, SlopGate returns `insufficient_evidence` and routes to "
        "a human — it never dismisses. That is the deliberate design: the dangerous "
        "error is waving away a real vulnerability, so abstention is the safe move.",
    ]
    return "\n".join(x for x in L if x is not None) + "\n"


def main() -> int:
    results = _load()
    if results is None:
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(_render(results), encoding="utf-8")
    n = len(results)
    reached = sum(r.get("reproduced") for r in results)
    print(f"wrote {OUT}  ({n} cases, {reached}/{n} reproduced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
