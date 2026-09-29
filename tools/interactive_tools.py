from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


NO_INTERACTIVE_TOOL = "no_interactive_tool"

INTERACTIVE_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "interactive_ping",
            "description": "The command is a 'ping' invocation that streams live ICMP replies.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "interactive_top",
            "description": (
                "The command is 'top' (optionally with flags), a full-screen or --batch process monitor."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "interactive_nano",
            "description": "The command opens the 'nano' full-screen text editor on a file.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cat_stdin_redirect",
            "description": (
                "The command is exactly 'cat > file' or 'cat >> file' with no source file operand, "
                "reading interactive stdin until Ctrl-D/EOF."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": NO_INTERACTIVE_TOOL,
            "description": (
                "None of the other tools match this command's syntax; it should go through the "
                "normal read/write command pipeline instead."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
]


def _parse_cat_redirect(command: str) -> Optional[Tuple[str, str]]:
    match = re.fullmatch(
        r"\s*cat\s*(>>?)\s*(?:'([^']+)'|\"([^\"]+)\"|(\S+))\s*",
        command,
    )
    if not match:
        return None
    operator, single_name, double_name, plain_name = match.groups()
    return operator, single_name or double_name or plain_name or ""


def _is_ping(command: str) -> bool:
    return re.match(r"^\s*ping(?:\s|$)", command) is not None


def _is_top(command: str) -> bool:
    return command == "top" or command.startswith("top ")


def _is_nano(command: str) -> bool:
    return command == "nano" or command.startswith("nano ")


def fallback_interactive_tool(command: str) -> str:
    if _parse_cat_redirect(command) is not None:
        return "cat_stdin_redirect"
    if _is_ping(command):
        return "interactive_ping"
    if _is_top(command):
        return "interactive_top"
    if _is_nano(command):
        return "interactive_nano"
    return NO_INTERACTIVE_TOOL


@dataclass(frozen=True)
class InteractiveToolContext:
    command: str
    prompt: Callable[[], str]
    send_response: Callable[[str, str], None]
    send_text: Callable[[str], None]
    record_session: Callable[[str, str, str], None]
    resolve_path: Callable[[str], str]
    run_cat_stdin_redirect: Callable[[str, bool], bool]
    run_ping_interactive: Callable[[str], Tuple[str, int]]
    render_top_frame: Callable[[], str]
    run_top_interactive: Callable[[float], None]
    run_nano_interactive: Callable[[str], None]
    top_refresh_seconds: float


def _handle_cat_stdin_redirect(context: InteractiveToolContext) -> Optional[int]:
    parsed = _parse_cat_redirect(context.command)
    if parsed is None:
        return None
    operator, target = parsed
    absolute_path = context.resolve_path(target)
    try:
        completed = context.run_cat_stdin_redirect(absolute_path, operator == ">>")
        rendered = "" if completed else "^C"
        status = 0 if completed else 130
    except PermissionError:
        rendered = f"bash: {target}: Permission denied"
        context.send_response(rendered, "")
        status = 1
    context.record_session(context.command, rendered, "write")
    context.send_text(context.prompt())
    return status


def _handle_ping(context: InteractiveToolContext) -> Optional[int]:
    if not _is_ping(context.command):
        return None
    rendered, status = context.run_ping_interactive(context.command)
    context.record_session(context.command, rendered, "read")
    context.send_text(context.prompt())
    return status


def _parse_top_arguments(command: str, default_interval: float) -> Tuple[bool, int, float]:
    args = command.split()[1:]
    batch = False
    iterations = 1
    refresh_interval = default_interval
    index = 0
    while index < len(args):
        argument = args[index]
        if argument == "--batch":
            batch = True
        elif argument == "--iterations" and index + 1 < len(args) and args[index + 1].isdigit():
            iterations = max(1, int(args[index + 1]))
            index += 1
        elif argument == "--delay" and index + 1 < len(args):
            try:
                refresh_interval = max(0.5, float(args[index + 1]))
                index += 1
            except ValueError:
                pass
        elif argument.startswith("-") and not argument.startswith("--") and len(argument) > 1:
            flag_index = 1
            while flag_index < len(argument):
                flag = argument[flag_index]
                if flag == "b":
                    batch = True
                    flag_index += 1
                    continue
                if flag not in {"n", "d"}:
                    flag_index += 1
                    continue
                rest = argument[flag_index + 1:]
                value: Optional[str] = None
                if rest:
                    value = rest
                    flag_index = len(argument)
                elif index + 1 < len(args):
                    value = args[index + 1]
                    index += 1
                    flag_index = len(argument)
                else:
                    flag_index = len(argument)
                if flag == "n" and value is not None and value.isdigit():
                    iterations = max(1, int(value))
                elif flag == "d" and value is not None:
                    try:
                        refresh_interval = max(0.5, float(value))
                    except ValueError:
                        pass
        index += 1
    return batch, iterations, refresh_interval


def _handle_top(context: InteractiveToolContext) -> Optional[int]:
    if not _is_top(context.command):
        return None
    try:
        batch, iterations, refresh_interval = _parse_top_arguments(
            context.command,
            context.top_refresh_seconds,
        )
        if batch:
            frames = []
            for frame_index in range(iterations):
                frames.append(context.render_top_frame())
                if frame_index + 1 < iterations:
                    time.sleep(refresh_interval)
            output = "\n\n".join(frames)
            context.send_response(output, context.prompt())
            context.record_session(context.command, output, "read")
        else:
            context.record_session(context.command, "<interactive top>", "read")
            context.run_top_interactive(refresh_interval)
            context.send_text(context.prompt())
        return 0
    except Exception as exc:
        output = f"top: {exc}"
        context.send_response(output, context.prompt())
        context.record_session(context.command, output, "read")
        return 1


def _handle_nano(context: InteractiveToolContext) -> Optional[int]:
    if not _is_nano(context.command):
        return None
    try:
        parts = context.command.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            output = "nano: missing file operand"
            context.send_response(output, context.prompt())
            context.record_session(context.command, output, "read")
            return 1
        absolute_path = context.resolve_path(parts[1].strip())
        context.record_session(context.command, "<interactive nano>", "read")
        context.run_nano_interactive(absolute_path)
        context.send_text(context.prompt())
        return 0
    except Exception as exc:
        output = f"nano: {exc}"
        context.send_response(output, context.prompt())
        context.record_session(context.command, output, "read")
        return 1


_INTERACTIVE_HANDLERS: Dict[str, Callable[[InteractiveToolContext], Optional[int]]] = {
    "cat_stdin_redirect": _handle_cat_stdin_redirect,
    "interactive_ping": _handle_ping,
    "interactive_top": _handle_top,
    "interactive_nano": _handle_nano,
}


def dispatch_interactive_tool(
    tool_name: str,
    context: InteractiveToolContext,
) -> Optional[int]:
    """Return an exit status when handled, or None when the tool did not apply."""

    handler = _INTERACTIVE_HANDLERS.get(tool_name)
    return handler(context) if handler is not None else None
