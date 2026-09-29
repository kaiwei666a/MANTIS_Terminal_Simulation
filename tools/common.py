from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

EASTERN_TZ_NAME = "America/New_York"


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def now_eastern() -> datetime:
    if ZoneInfo is not None:
        return datetime.now(tz=ZoneInfo(EASTERN_TZ_NAME))
    return datetime.now().astimezone()


def fmt_eastern(fmt: str) -> str:
    return now_eastern().strftime(fmt)


def ts_utc_isoz() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_exact_command_arguments(
    arguments: str,
    original_command: str,
    expected_fields: Iterable[str] = ("command",),
) -> Dict[str, Any]:
    try:
        parsed = json.loads(arguments or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("tool arguments are not valid JSON") from exc
    expected = set(expected_fields)
    if not isinstance(parsed, dict) or set(parsed) != expected:
        raise ValueError(f"tool arguments must contain exactly: {', '.join(sorted(expected))}")
    if parsed.get("command") != original_command:
        raise ValueError("tool command does not match the original command")
    return parsed


def tool_call_arguments(message: Any, tool_name: str) -> Optional[str]:
    for tool_call in getattr(message, "tool_calls", None) or []:
        function = getattr(tool_call, "function", None)
        if tool_call.type == "function" and function is not None and function.name == tool_name:
            return function.arguments
    return None
