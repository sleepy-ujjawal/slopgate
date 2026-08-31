"""Evaluate the R1 fail-closed reachability slicer against a labeled corpus.

    python -m slopgate.reach.eval

The headline metric is **soundness violations = 0**: the number of cases whose
ground truth is *not* strictly-unreachable but which the slicer nonetheless marked
UNREACHABLE_STRICT. Any such case is a would-be false `not_affected` attestation —
exactly the R1 blocker. Plain accuracy is reported too, but a wrong AMBIGUOUS (noise)
is a lesser sin than a wrong STRICT (a signed false negative), and the two are scored
separately on purpose.

The load-bearing case is ``unmodeled_match``: a ``match`` statement is a real,
post-3.10 construct that a slicer (or an enumerated escalation registry) written
earlier would not model. A denylist that never listed it would fall through to
UNREACHABLE_STRICT; the fail-closed scanner escalates it to AMBIGUOUS instead. On
interpreters older than 3.10 the same source fails to parse and takes the parse-fail
path to AMBIGUOUS — either way, never STRICT.
"""
from __future__ import annotations

import sys

from slopgate.reach.slicer import (
    AMBIGUOUS,
    REACHABLE,
    UNREACHABLE,
    classify_reachability,
)

# Each case: (name, source, target_module, target_symbol, expected, note)
CASES = [
    (
        "direct_call",
        "import gdown\ngdown.download(url)\n",
        "gdown", "download", REACHABLE,
        "qualified call on an imported module",
    ),
    (
        "aliased_call",
        "from gdown import download as dl\ndl(url)\n",
        "gdown", "download", REACHABLE,
        "from-import with an alias (alias tracking)",
    ),
    (
        "from_import_plain",
        "from gdown import download\ndownload(url)\n",
        "gdown", "download", REACHABLE,
        "from-import bound under its own name",
    ),
    (
        "conditional_reachable",
        "import gdown\nif user.premium:\n    gdown.download(url)\n",
        "gdown", "download", REACHABLE,
        "reachable inside a branch — a reference is a reference",
    ),
    (
        "not_imported",
        "import os\nos.getcwd()\n",
        "gdown", "download", UNREACHABLE,
        "target package never imported",
    ),
    (
        "imported_unused",
        "import gdown\ngdown.extract_id(url)\n",
        "gdown", "download", UNREACHABLE,
        "package imported for a DIFFERENT function; vuln symbol never referenced",
    ),
    (
        "getattr_dispatch",
        "import gdown\nfn = getattr(gdown, name)\nfn(url)\n",
        "gdown", "download", AMBIGUOUS,
        "getattr — the symbol could be reached, opaquely",
    ),
    (
        "entrypoint_plugin",
        ("import gdown\nfrom importlib.metadata import entry_points\n"
         "for ep in entry_points(group='cmd'):\n    ep.load()(url)\n"),
        "gdown", "download", AMBIGUOUS,
        "plugin dispatch via entry points",
    ),
    (
        "star_import",
        "from gdown import *\ndownload(url)\n",
        "gdown", "download", AMBIGUOUS,
        "star-import binds unknown names",
    ),
    (
        "module_escape",
        "import gdown\nregister_backend(gdown)\n",
        "gdown", "download", AMBIGUOUS,
        "module object passed out of the file — cannot follow it",
    ),
    (
        "unmodeled_match",
        ("import gdown\n"
         "def summarize(kind, values):\n"
         "    match kind:\n"
         "        case 'mean':\n"
         "            return sum(values) / len(values)\n"
         "        case 'max':\n"
         "            return max(values)\n"
         "    return None\n"),
        "gdown", "download", AMBIGUOUS,
        "HEADLINE: an unmodeled construct must escalate, never suppress",
    ),
    (
        "syntax_error",
        "def broken(:\n    pass\n",
        "gdown", "download", AMBIGUOUS,
        "unparseable source — fail closed",
    ),
]


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    print("R1 reachability slicer — labeled corpus\n")
    header = f"{'case':<22} {'expected':<20} {'predicted':<20} result"
    print(header)
    print("-" * len(header))

    correct = 0
    soundness_violations = 0
    noise = 0                 # wrong AMBIGUOUS where truth was STRICT (acceptable)
    rows = []
    for name, source, module, symbol, expected, note in CASES:
        res = classify_reachability(source, module, symbol)
        pred = res.classification
        ok = pred == expected
        correct += ok
        if pred == UNREACHABLE and expected != UNREACHABLE:
            soundness_violations += 1
        if pred == AMBIGUOUS and expected == UNREACHABLE:
            noise += 1
        flag = "PASS" if ok else "FAIL"
        print(f"{name:<22} {expected:<20} {pred:<20} {flag}")
        rows.append((name, note, res))

    n = len(CASES)
    print("\nDetail:")
    for name, note, res in rows:
        print(f"  {name}: {note}")
        print(f"      -> {res.reason}")

    print(f"\naccuracy:              {correct}/{n} ({correct / n:.0%})")
    print(f"soundness violations:  {soundness_violations}   "
          "(STRICT asserted when truth was not strictly-unreachable)")
    print(f"conservative noise:    {noise}   "
          "(escalated to AMBIGUOUS where STRICT was provable — safe, just noisier)")

    if soundness_violations:
        print("\nFAIL: the slicer signed a false UNREACHABLE_STRICT — R1 not satisfied.",
              file=sys.stderr)
        return 1
    print("\nOK: zero soundness violations — every unprovable case escalated, none "
          "were suppressed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
