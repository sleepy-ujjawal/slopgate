"""One place every agent stage calls the model, so every call is traced.

Keeping this thin wrapper separate from the Gemini client means the client stays
a pure transport concern, while this layer owns the concern the hackathon cares
about: that each call appears in the trajectory with its instructions, prompt,
and response, exactly as deliverable 4 requires.
"""
from __future__ import annotations

from typing import Any, Optional

from slopgate.model.gemini import generate, GenResult
from slopgate.model.trace import Trajectory


def ask(
    trajectory: Trajectory,
    *,
    agent: str,
    prompt: str,
    system: Optional[str] = None,
    json_mode: bool = False,
) -> GenResult:
    result = generate(prompt, system=system, json_mode=json_mode)
    trajectory.llm_call(
        agent=agent,
        system=system,
        prompt=prompt,
        response=result.text,
        prompt_tokens=result.prompt_tokens,
        output_tokens=result.output_tokens,
        latency_s=result.latency_s,
        model=result.model,
    )
    return result


def ask_json(
    trajectory: Trajectory,
    *,
    agent: str,
    prompt: str,
    system: Optional[str] = None,
) -> tuple[Any, GenResult]:
    """Ask for JSON and return (parsed, raw_result). Abstains-safe parsing.

    If the model returns unparseable output, we surface it as None rather than
    crashing the pipeline; callers treat None as "no structured answer", which
    downstream becomes abstention, never a confirmation.
    """
    result = ask(trajectory, agent=agent, prompt=prompt, system=system, json_mode=True)
    try:
        return result.json(), result
    except Exception:
        trajectory.note(agent=agent, message="model returned unparseable JSON; treating as no-answer",
                        data={"raw": result.text[:500]})
        return None, result
