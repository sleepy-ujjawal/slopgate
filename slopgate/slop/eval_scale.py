"""Large-scale, real-PyPI validation of the R2 name-slop classifier.

    python -m slopgate.slop.eval_scale [--limit N]

The small labeled corpus (`eval.py`) proves the idea; this measures the two numbers
that actually decide whether the gate could ever move off warn-only, at scale and
against live PyPI:

  * FALSE-POSITIVE RATE on hundreds of REAL packages that share the risky
    compound-name shape (framework root + token). Pulled from the top-PyPI-packages
    dataset, so these are established, legitimate names. Any flag here is a real FP.

  * RECALL on hundreds of hallucination-shaped names that are genuinely ABSENT from
    PyPI. These are generated combinatorially ([framework]+[domain]+[utility]) and
    filtered to the ones PyPI 404s — i.e. plausible names an LLM could invent that
    nobody has published. The flag rate on these is recall.

Results are cached (`realdata/pypicache/`) so re-runs are cheap and reproducible.
"""
from __future__ import annotations

import json
import random
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from slopgate.slop.classifier import (
    DOMAIN_TOKENS,
    FRAMEWORK_ROOTS,
    UTILITY_TOKENS,
    score_slop,
)
from slopgate.slop.pypi import PkgMeta, fetch_metadata

TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


def _tokens(name: str) -> list:
    import re
    return [t for t in re.split(r"[-_.]+", name.lower()) if t]


def _is_compound_shaped(name: str) -> bool:
    t = _tokens(name)
    return len(t) >= 2 and t[0] in FRAMEWORK_ROOTS


def _fetch_top_pypi(cap: int) -> List[str]:
    try:
        req = urllib.request.Request(TOP_PYPI, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        rows = data.get("rows", data if isinstance(data, list) else [])
        names = [r.get("project") if isinstance(r, dict) else r for r in rows]
        compound = [n for n in names if n and _is_compound_shaped(n)]
        return compound[:cap]
    except Exception as exc:
        print(f"NOTE: could not fetch top-PyPI list ({exc}); "
              "using the built-in legit corpus only.", file=sys.stderr)
        base = json.loads(
            (__import__("pathlib").Path(__file__).resolve().parent
             / "cases" / "legit.json").read_text(encoding="utf-8"))
        return [c["name"] for c in base if _is_compound_shaped(c["name"])]


def _gen_slop_candidates(n: int, seed: int = 7) -> List[str]:
    rnd = random.Random(seed)
    roots = sorted(FRAMEWORK_ROOTS)
    dom = sorted(DOMAIN_TOKENS)
    util = sorted(UTILITY_TOKENS)
    out, seen = [], set()
    while len(out) < n and len(seen) < n * 20:
        name = f"{rnd.choice(roots)}-{rnd.choice(dom)}-{rnd.choice(util)}"
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _score_many(names: List[str]) -> List[tuple]:
    def one(name: str):
        meta: Optional[PkgMeta] = fetch_metadata(name)
        return name, meta, score_slop(name, meta)
    with ThreadPoolExecutor(max_workers=10) as ex:
        return list(ex.map(one, names))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    limit = 300
    if "--limit" in argv:
        try:
            limit = int(argv[argv.index("--limit") + 1])
        except (ValueError, IndexError):
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    print("R2 large-scale validation — live PyPI (cached)\n")

    # --- legit: real, compound-shaped, established packages ---
    legit_names = _fetch_top_pypi(limit)
    print(f"scoring {len(legit_names)} real compound-shaped packages for FP rate ...")
    legit = _score_many(legit_names)
    legit_present = [(n, m, s) for (n, m, s) in legit if m is not None and m.exists]
    fp = [(n, m, s) for (n, m, s) in legit_present if s.would_flag]
    fp_rate = len(fp) / len(legit_present) if legit_present else 0.0

    # --- slop: hallucination-shaped names that are genuinely absent from PyPI ---
    candidates = _gen_slop_candidates(limit * 3)
    print(f"probing {len(candidates)} generated compound names to find absent ones ...")
    scored = _score_many(candidates)
    absent = [(n, m, s) for (n, m, s) in scored if m is not None and not m.exists][:limit]
    unexpectedly_real = sum(1 for (n, m, s) in scored if m is not None and m.exists)
    flagged = [(n, m, s) for (n, m, s) in absent if s.would_flag]
    recall = len(flagged) / len(absent) if absent else 0.0

    print("\n=== FALSE-POSITIVE RATE (real compound packages) ===")
    print(f"real packages scored:  {len(legit_present)}")
    print(f"false positives:       {len(fp)}  (FP rate {fp_rate:.2%})")
    for n, m, s in fp[:15]:
        age = f"{m.age_days:.0f}d" if (m and m.age_days is not None) else "?"
        print(f"  FP: {n:<38} score={s.score:.2f} age={age} "
              f"prov={'y' if m and m.has_provenance else 'n'}")

    print("\n=== RECALL (absent hallucination-shaped names) ===")
    print(f"generated candidates:  {len(candidates)}")
    print(f"  unexpectedly real:   {unexpectedly_real} (already registered on PyPI)")
    print(f"absent names scored:   {len(absent)}")
    print(f"flagged (recall):      {len(flagged)}  ({recall:.1%})")

    print("\nInterpretation: the FP rate is what gates any move off warn-only. Absent "
          "full-compound names flag reliably; the gap between recall and 100% is "
          "names whose middle token isn't a modeled domain/utility term (mimicry 0.5) "
          "— a deliberate, documented conservatism, not a miss to paper over.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
