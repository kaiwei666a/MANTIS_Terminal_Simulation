from __future__ import annotations

import os
from typing import Optional

from openai import OpenAI
from tools.interactive_tools import (
    INTERACTIVE_TOOL_DEFINITIONS,
    NO_INTERACTIVE_TOOL,
    fallback_interactive_tool,
)

DEFAULT_ROUTER_MODEL = os.getenv(
    "INTERACTIVE_ROUTER_MODEL", os.getenv("RESPONSE_AGENT_MODEL", "gpt-5.4-mini")
)

def select_interactive_tool(cmd: str, client: Optional[OpenAI], model: Optional[str] = None) -> str:
    if client is None:
        return fallback_interactive_tool(cmd)
    try:
        messages = [
            {
                "role": "developer",
                "content": (
                    "Classify one shell command line purely by its surface syntax -- do not run it or "
                    "reason about semantics. Call exactly one tool: the interactive tool whose "
                    "description matches this command's syntax, or no_interactive_tool if none do."
                ),
            },
            {"role": "user", "content": cmd},
        ]
        resp = client.chat.completions.create(
            model=model or DEFAULT_ROUTER_MODEL,
            messages=messages,
            store=False,
            reasoning_effort="none",
            temperature=0.0,
            max_completion_tokens=32,
            tools=INTERACTIVE_TOOL_DEFINITIONS,
            tool_choice="required",
            parallel_tool_calls=False,
        )
        message = resp.choices[0].message
        for tool_call in getattr(message, "tool_calls", None) or []:
            function = getattr(tool_call, "function", None)
            if function is not None and function.name:
                return function.name
        return NO_INTERACTIVE_TOOL
    except Exception:
        return fallback_interactive_tool(cmd)
