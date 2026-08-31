"""R1: a fail-closed static reachability slicer.

Given a consumer's source and a vulnerable ``module.symbol``, decide whether the
symbol is reachable from that source. This module exists to demonstrate ONE
invariant — the one the enterprise spec stated but whose *implementation* inverted:

    When the slicer cannot PROVE unreachability, it must fail toward
    DYNAMIC_AMBIGUOUS — never UNREACHABLE_STRICT.

The soundness bias therefore lives in the **scanner**, not in a registry of
dangerous constructs. We recognise a whitelist of statically-modelable AST node
types (``MODELED_NODES``); ANY node outside it — a syntax the analyzer does not
model, a future language feature, an unparseable file — forces DYNAMIC_AMBIGUOUS.
A denylist of known-dynamic constructs (``DYNAMIC_CONSTRUCTS`` below) still exists,
but only as an *optimization* that yields a precise reason; a gap in it costs noise
(a spurious AMBIGUOUS), never a false UNREACHABLE_STRICT that would be signed as
``not_affected``. That is the whole point: in the enterprise design a construct the
registry forgot fell through to STRICT; here it falls through to AMBIGUOUS.

Scope (honest limitation): single-module, intra-procedural. It proves the
*mechanism* (fail-closed-on-unknown), not whole-program call-graph reachability. A
module value that escapes the file (passed as an argument, returned, stored) is
treated as AMBIGUOUS rather than followed — the conservative direction.

UNREACHABLE_STRICT here means the specific vulnerable *symbol* is provably never
referenced (directly or via an import alias) and nothing dynamic or unmodeled could
reach it. This is deliberately narrower — and more useful — than the enterprise
"parent namespace absent" condition: importing a package for *other* functions must
not, by itself, block suppression of a symbol you never call.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict

# The three §1.1 states, by their spec names.
REACHABLE = "REACHABLE_CONFIRMED"
AMBIGUOUS = "DYNAMIC_AMBIGUOUS"
UNREACHABLE = "UNREACHABLE_STRICT"


def _cls(*names: str) -> set:
    """Resolve ast class names that exist on this interpreter (version-robust)."""
    out = set()
    for n in names:
        c = getattr(ast, n, None)
        if c is not None:
            out.add(c)
    return out


# Leaf grammar nodes (operators, contexts) are always safe to model. Pulling them
# from their base classes auto-covers every Python version without hand-listing.
_LEAF: set = set()
for _base in (ast.expr_context, ast.boolop, ast.operator, ast.unaryop, ast.cmpop):
    _LEAF |= set(_base.__subclasses__())

# The whitelist of node types we can reason about soundly. Structural nodes are
# listed EXPLICITLY (never harvested from ast.stmt/ast.expr subclasses) so that a
# newer language construct — e.g. the 3.10 ``match`` family, deliberately omitted —
# is NOT silently admitted. Growing the analyzer means adding to this set; until
# then, an unlisted construct escalates to AMBIGUOUS on its own.
MODELED_NODES: set = _LEAF | _cls(
    "Module", "Interactive", "Expression",
    # statements  (Match / match_case / Match* intentionally absent)
    "FunctionDef", "AsyncFunctionDef", "ClassDef", "Return", "Delete", "Assign",
    "AugAssign", "AnnAssign", "For", "AsyncFor", "While", "If", "With", "AsyncWith",
    "Raise", "Try", "TryStar", "Assert", "Import", "ImportFrom", "Global",
    "Nonlocal", "Expr", "Pass", "Break", "Continue",
    # expressions
    "BoolOp", "NamedExpr", "BinOp", "UnaryOp", "Lambda", "IfExp", "Dict", "Set",
    "ListComp", "SetComp", "DictComp", "GeneratorExp", "Await", "Yield",
    "YieldFrom", "Compare", "Call", "FormattedValue", "JoinedStr", "Constant",
    "Attribute", "Subscript", "Starred", "Name", "List", "Tuple", "Slice",
    "Index", "ExtSlice",
    # legacy literal nodes (pre-3.8 parsers) — harmless if present
    "Str", "Num", "Bytes", "NameConstant", "Ellipsis",
    # structural helpers
    "comprehension", "ExceptHandler", "arguments", "arg", "keyword", "alias",
    "withitem",
)

# The optimization registry: known-dynamic constructs that are built from *modeled*
# node types but whose runtime semantics defeat static reachability. Presence of any
# one forces AMBIGUOUS with a precise reason. A GAP here is not a soundness hole —
# an unrecognised dynamic call still gets caught as a module escape or lands the
# symbol as unreferenced; the fail-closed guarantee comes from MODELED_NODES, not
# from this list being complete.
_DYNAMIC_BUILTINS = {"getattr", "setattr", "eval", "exec", "__import__",
                     "globals", "locals", "vars", "compile"}
_DYNAMIC_ATTR_CALLS = {"import_module", "entry_points", "load_entry_point",
                       "get_model", "autodiscover_tasks", "create_model"}
_DYNAMIC_DUNDERS = {"__getattr__", "__getattribute__", "__init_subclass__"}
# A dynamic callable is dynamic whether reached as a bare name (`entry_points(...)`,
# from a `from x import entry_points`) or as an attribute (`importlib.import_module`).
_DYNAMIC_CALL_NAMES = _DYNAMIC_BUILTINS | _DYNAMIC_ATTR_CALLS


@dataclass
class ReachResult:
    classification: str          # REACHABLE_CONFIRMED | DYNAMIC_AMBIGUOUS | UNREACHABLE_STRICT
    reason: str
    evidence: Dict[str, Any]

    @property
    def suppressible(self) -> bool:
        """Only a strict proof of non-reachability may back a `not_affected`."""
        return self.classification == UNREACHABLE


class _RefVisitor(ast.NodeVisitor):
    """Resolve import aliases, then detect references to the vulnerable symbol."""

    def __init__(self, target_module: str, target_symbol: str) -> None:
        self.tm = target_module
        self.top = target_module.split(".")[0]
        self.sym = target_symbol
        self.module_aliases: set = set()   # local names bound to the target module
        self.symbol_locals: set = set()    # local names bound directly to the symbol
        self.imported = False
        self.direct_hit = False
        self.escape = False                # module object used as a bare value
        self.dynamic: set = set()
        self._qualified_ids: set = set()   # id() of Name nodes that are `alias.attr`

    def _matches_module(self, dotted: str) -> bool:
        return bool(dotted) and (dotted == self.tm or dotted.split(".")[0] == self.top)

    def collect_imports(self, tree: ast.AST) -> None:
        # A separate pass so references resolve regardless of source order.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if self._matches_module(a.name):
                        self.imported = True
                        self.module_aliases.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if self._matches_module(node.module or ""):
                    self.imported = True
                    for a in node.names:
                        if a.name == "*":
                            # cannot know what a star-import binds
                            self.dynamic.add("from-import-star")
                        elif a.name == self.sym:
                            self.symbol_locals.add(a.asname or a.name)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in self.module_aliases:
            self._qualified_ids.add(id(node.value))   # this Name is `alias.<attr>`
            if node.attr == self.sym:
                self.direct_hit = True
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in self.symbol_locals:
            self.direct_hit = True
        elif node.id in self.module_aliases and id(node) not in self._qualified_ids:
            # module object referenced as a bare value -> escapes single-file analysis
            self.escape = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fn = node.func
        called = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None)
        if called in _DYNAMIC_CALL_NAMES:
            self.dynamic.add(called)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if any(k.arg == "metaclass" for k in node.keywords):
            self.dynamic.add("metaclass")
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                    stmt.name in _DYNAMIC_DUNDERS:
                self.dynamic.add(stmt.name)
        self.generic_visit(node)


def classify_reachability(source: str, target_module: str,
                          target_symbol: str) -> ReachResult:
    """Classify whether `target_module.target_symbol` is reachable from `source`.

    Fail-closed: anything that blocks a proof of non-reachability yields AMBIGUOUS.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return ReachResult(
            AMBIGUOUS,
            "source did not parse; cannot prove unreachability, escalating",
            {"parse_error": f"{exc.__class__.__name__}: {exc}"},
        )

    # The load-bearing catch-all: any node type we do not model -> AMBIGUOUS.
    unmodeled = sorted({type(n).__name__ for n in ast.walk(tree)
                        if type(n) not in MODELED_NODES})

    visitor = _RefVisitor(target_module, target_symbol)
    visitor.collect_imports(tree)
    visitor.visit(tree)

    evidence: Dict[str, Any] = {
        "imported": visitor.imported,
        "direct_hit": visitor.direct_hit,
        "module_escape": visitor.escape,
        "dynamic_constructs": sorted(visitor.dynamic),
        "unmodeled_nodes": unmodeled,
    }

    if visitor.direct_hit:
        return ReachResult(
            REACHABLE, f"'{target_symbol}' is referenced directly", evidence)

    if visitor.dynamic or visitor.escape or unmodeled:
        bits = []
        if visitor.dynamic:
            bits.append("dynamic dispatch (" + ", ".join(sorted(visitor.dynamic)) + ")")
        if visitor.escape:
            bits.append(f"module '{target_module}' escapes the file as a bare value")
        if unmodeled:
            bits.append("unmodeled construct(s): " + ", ".join(unmodeled))
        return ReachResult(
            AMBIGUOUS,
            "cannot prove unreachability — " + "; ".join(bits) + "; escalating",
            evidence,
        )

    return ReachResult(
        UNREACHABLE,
        f"'{target_symbol}' is provably never referenced and no dynamic or "
        "unmodeled construct could reach it",
        evidence,
    )
