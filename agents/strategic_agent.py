"""Maintain command steps and pruned session history."""

from __future__ import annotations

import json

from typing import Any, Dict, List

try:
    from agents.history_pruning import OnlinePruner
except Exception:
    OnlinePruner = None


def _json_compact(obj: Any, limit: int = 20000) -> str:
    """Serialize context compactly and cap its size before model input."""
    try:
        serialized = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        serialized = str(obj)
    if len(serialized) > limit:
        return serialized[:limit] + "...<truncated>"
    return serialized


def build_response_messages(
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
    *,
    system_instruction: str,
) -> List[Dict[str, str]]:
    """Build response-model messages from command history and state transition."""
    if isinstance(system_log, dict) and "pre_snapshot" in system_log:
        pre_snapshot = system_log.get("pre_snapshot") or {}
        post_snapshot = {key: value for key, value in system_log.items() if key != "pre_snapshot"}
    else:
        pre_snapshot = system_log
        post_snapshot = system_log

    snapshot_transition = {
        "pre_snapshot": pre_snapshot,
        "post_snapshot": post_snapshot,
    }
    user_prompt = (
        f"{command}\n\n"
        f"(Planning advice / constraints): {planning_advice}\n"
        f"(Recent command history): {_json_compact(session_log)}\n"
        f"(System snapshot transition): {_json_compact(snapshot_transition)}\n"
    )
    return [
        {"role": "system", "content": system_instruction},
        {"role": "user", "content": user_prompt},
    ]


class PlanningRuntime:
    def __init__(self, K: int = 30):
        self.K = K
        self.t = 0
        self.pruner = OnlinePruner(K=K) if OnlinePruner is not None else None

    def get_pruned_history(self) -> List[Dict[str, Any]]:
        if self.pruner is None:
            return []
        kept = sorted(self.pruner.W, key=lambda e: e.t)
        return [{"t": e.t, "command": e.command, "response": e.response} for e in kept]

    def step(
        self,
        command: str,
        response: str,
        pre_snapshot: Dict[str, Any],
        post_snapshot: Dict[str, Any],
    ) -> None:
        self.t += 1
        if self.pruner is None:
            return
        self.pruner.step(
            t=self.t,
            command=command,
            response=response,
            s_prev=pre_snapshot,
            s_cur=post_snapshot,
        )
