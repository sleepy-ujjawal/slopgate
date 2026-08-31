"""Large-scale, offline validation of the R1 reachability slicer on REAL source.

    python -m slopgate.reach.eval_scale [--limit N]

The small labeled corpus (`eval.py`) proves correctness on hand-picked shapes; this
proves the two properties that must hold across thousands of files of real-world
Python — with no network and no API cost:

  * ROBUSTNESS  — the slicer never crashes on real code (any file it cannot handle
                  must degrade to AMBIGUOUS, not raise).
  * SOUNDNESS   — a symbol that is ACTUALLY referenced in a file is never signed
                  UNREACHABLE_STRICT. This is the property whose violation would be
                  a false `not_affected`. Each (file, module, symbol) positive is
                  self-labeled from the file's own AST: an `alias.attr` on a module
                  the file imports is, by construction, a reference.

It also reports the classification split on a symbol that provably does NOT appear,
to show the slicer discriminates at scale (isn't trivially always-STRICT or
always-AMBIGUOUS).
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from typing import List, Tuple

from slopgate.reach.slicer import (
    AMBIGUOUS,
    REACHABLE,
    UNREACHABLE,
    classify_reachability,
)

ABSENT_SYMBOL = "__slopgate_absent_zzz__"


def _gather_files(limit: int) -> List[Path]:
    roots: List[Path] = [Path(os.__file__).resolve().parent]        # stdlib Lib/
    for p in sys.path:
        if p and ("site-packages" in p or "dist-packages" in p):
            roots.append(Path(p))
    roots.append(Path(__file__).resolve().parents[1])               # our own slopgate/
    seen = set()
    files: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for f in root.rglob("*.py"):
            rp = str(f.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            files.append(f)
            if len(files) >= limit:
                return files
    return files


def _positive_triple(tree: ast.AST) -> Tuple[str, str] | None:
    """A (module, symbol) pair that is genuinely referenced as `alias.symbol`."""
    aliases = {}  # local alias -> real top-level module name
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                top = a.name.split(".")[0]
                aliases[a.asname or top] = top
    for n in ast.walk(tree):
        if (isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                and n.value.id in aliases):
            return aliases[n.value.id], n.attr
    return None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    limit = 3000
    if "--limit" in argv:
        try:
            limit = int(argv[argv.index("--limit") + 1])
        except (ValueError, IndexError):
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    files = _gather_files(limit)
    print(f"R1 large-scale validation — {len(files)} real .py files\n")

    scanned = crashes = parsed = 0
    positives = pos_reachable = pos_soundness_violations = 0
    neg = {REACHABLE: 0, AMBIGUOUS: 0, UNREACHABLE: 0}
    violations = []

    for f in files:
        scanned += 1
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # robustness: classification must never raise
        try:
            base = classify_reachability(src, "os", ABSENT_SYMBOL)
        except Exception as exc:  # pragma: no cover
            crashes += 1
            violations.append(f"CRASH {f}: {exc}")
            continue

        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        parsed += 1

        triple = _positive_triple(tree)
        if triple is not None:
            module, symbol = triple
            positives += 1
            res = classify_reachability(src, module, symbol)
            if res.classification == REACHABLE:
                pos_reachable += 1
            elif res.classification == UNREACHABLE:
                pos_soundness_violations += 1
                violations.append(
                    f"SOUNDNESS {f}: referenced {module}.{symbol} -> UNREACHABLE_STRICT")
            # negative: a symbol on the same imported module that is NOT present
            neg_res = classify_reachability(src, module, ABSENT_SYMBOL)
            neg[neg_res.classification] = neg.get(neg_res.classification, 0) + 1

    print(f"files scanned:            {scanned}")
    print(f"  parsed as Python:       {parsed}")
    print(f"  crashes during classify:{crashes}")
    print()
    print(f"positive (referenced) symbols tested: {positives}")
    print(f"  -> REACHABLE_CONFIRMED: {pos_reachable} "
          f"({(pos_reachable / positives if positives else 1):.1%})")
    print(f"  -> UNREACHABLE_STRICT (SOUNDNESS VIOLATIONS): {pos_soundness_violations}")
    print()
    n_neg = sum(neg.values())
    print(f"absent-symbol classification split (discrimination), n={n_neg}:")
    for k in (UNREACHABLE, AMBIGUOUS, REACHABLE):
        v = neg.get(k, 0)
        print(f"  {k:<22} {v:>6} ({(v / n_neg if n_neg else 0):.1%})")

    if violations[:10]:
        print("\nfirst issues:")
        for line in violations[:10]:
            print(f"  {line}")

    ok = crashes == 0 and pos_soundness_violations == 0
    if not ok:
        print("\nFAIL: robustness or soundness violated at scale.", file=sys.stderr)
        return 1
    print(f"\nOK at scale: 0 crashes, 0 soundness violations across {parsed} real "
          "files — a referenced symbol was never signed UNREACHABLE_STRICT.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
