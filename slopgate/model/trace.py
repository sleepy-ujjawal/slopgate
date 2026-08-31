"""Trajectory logging: a readable trace of everything an agent did.

Deliverable 4 of the hackathon requires, for every agent used, a trace that goes
from the instructions it was given, through its tool calls and their responses,
to the feedback that shaped the next step. This module is the single choke point
every LLM call and tool call passes through, so those traces are a byproduct of
running the system rather than something reconstructed afterward.

One Trajectory maps to one case. Each recorded step is one JSON line in
runs/<case_id>/trajectory.jsonl, plus a human-readable runs/<case_id>/trajectory.md.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

RUNS_ROOT = Path(__file__).resolve().parents[2] / "runs"


@dataclass
class Trajectory:
    case_id: str
    root: Path = field(default=None)  # type: ignore[assignment]
    _steps: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.root = RUNS_ROOT / self.case_id
        self.root.mkdir(parents=True, exist_ok=True)
        self._jsonl = self.root / "trajectory.jsonl"
        # Truncate any prior run for this case so a re-run is clean.
        self._jsonl.write_text("", encoding="utf-8")

    def _append(self, record: dict) -> None:
        record["ts"] = round(time.time(), 3)
        self._steps.append(record)
        with self._jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def llm_call(
        self,
        *,
        agent: str,
        system: Optional[str],
        prompt: str,
        response: str,
        prompt_tokens: int,
        output_tokens: int,
        latency_s: float,
        model: str,
    ) -> None:
        self._append({
            "type": "llm_call",
            "agent": agent,
            "model": model,
            "system": system,
            "prompt": prompt,
            "response": response,
            "prompt_tokens": prompt_tokens,
            "output_tokens": output_tokens,
            "latency_s": round(latency_s, 2),
        })

    def tool_call(self, *, agent: str, tool: str, args: dict, result: Any) -> None:
        self._append({
            "type": "tool_call",
            "agent": agent,
            "tool": tool,
            "args": args,
            "result": result,
        })

    def note(self, *, agent: str, message: str, data: Optional[dict] = None) -> None:
        """A decision point: the feedback or gate outcome that shaped the next step."""
        self._append({"type": "note", "agent": agent, "message": message, "data": data or {}})

    # ---- aggregate accounting, surfaced in the metrics table ----
    @property
    def total_prompt_tokens(self) -> int:
        return sum(s.get("prompt_tokens", 0) for s in self._steps)

    @property
    def total_output_tokens(self) -> int:
        return sum(s.get("output_tokens", 0) for s in self._steps)

    @property
    def llm_calls(self) -> int:
        return sum(1 for s in self._steps if s["type"] == "llm_call")

    @property
    def wall_latency_s(self) -> float:
        return round(sum(s.get("latency_s", 0.0) for s in self._steps), 2)

    def has_reproduced_artifact(self) -> bool:
        """True iff some reproduction tool call actually returned REPRODUCED.

        This is the evidence the deterministic fidelity gate consults: a
        'confirmed' verdict is only honest if this is True.
        """
        for s in self._steps:
            if s["type"] == "tool_call" and s.get("tool") == "attempt_reproduction":
                result = s.get("result") or {}
                if isinstance(result, dict) and result.get("outcome") == "REPRODUCED":
                    return True
        return False

    def render_markdown(self) -> Path:
        """Write a human-readable companion to the JSONL, for judges to skim."""
        lines = [f"# Trajectory — case `{self.case_id}`", ""]
        for i, s in enumerate(self._steps, 1):
            if s["type"] == "llm_call":
                lines += [
                    f"## {i}. LLM call — {s['agent']} ({s['model']}, {s['latency_s']}s)",
                    f"*tokens: {s['prompt_tokens']} in / {s['output_tokens']} out*",
                    "", "**System:**", "```", (s.get("system") or "(none)"), "```",
                    "**Prompt:**", "```", _clip(s["prompt"]), "```",
                    "**Response:**", "```", _clip(s["response"]), "```", "",
                ]
            elif s["type"] == "tool_call":
                lines += [
                    f"## {i}. Tool call — {s['agent']} → `{s['tool']}`",
                    "**Args:**", "```json", _clip(json.dumps(s["args"], indent=2)), "```",
                    "**Result:**", "```json", _clip(json.dumps(s["result"], indent=2)), "```", "",
                ]
            else:
                lines += [f"## {i}. Note — {s['agent']}", f"> {s['message']}", ""]
        path = self.root / "trajectory.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path


def _clip(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n… [clipped {len(text) - limit} chars]"
