from __future__ import annotations

import re
import shlex
import subprocess
from typing import Optional

from terminal_config import DOCKER_MAN_CONTAINER, DOCKER_MAN_TIMEOUT_SEC
from tools.ubuntu_commands import parse_man_request


def _strip_terminal_formatting(text: str) -> str:
    text = re.sub(r".\x08", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return text.replace("\r\n", "\n").replace("\r", "\n").strip("\n")


def _run_in_man_container(command: list[str], unavailable_message: str) -> str:
    if not DOCKER_MAN_CONTAINER:
        return unavailable_message
    try:
        completed = subprocess.run(
            ["docker", "exec", DOCKER_MAN_CONTAINER, *command],
            capture_output=True,
            timeout=DOCKER_MAN_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return unavailable_message
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    output = _strip_terminal_formatting(stdout or stderr)
    return output or unavailable_message


def _render_man(tokens: list[str]) -> str:
    args = tokens[1:]
    if args and args[0] not in {"--help", "-h", "--version", "-V"}:
        request = parse_man_request(args)
        if request is None:
            return "man: invalid manual page request"
        section, topic = request
        args = ([section] if section is not None else []) + [topic]
    return _run_in_man_container(
        [
            "env", "MANWIDTH=80", "MANPAGER=cat", "PAGER=cat", "TERM=dumb",
            "man", "--pager=cat", *args,
        ],
        "man: manual database is unavailable",
    )


def _render_whatis(tokens: list[str]) -> str:
    return _run_in_man_container(
        ["whatis", *tokens[1:]],
        "whatis: manual database is unavailable",
    )


def _render_help(tokens: list[str]) -> str:
    return _run_in_man_container(
        ["bash", "--noprofile", "--norc", "-c", 'help "$@"', "bash", *tokens[1:]],
        "bash: help is unavailable",
    )


def render_manual_or_help(command: str) -> Optional[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return f"bash: syntax error: {exc}"
    if not tokens:
        return None
    if tokens[0] == "man":
        return _render_man(tokens)
    if tokens[0] == "help":
        return _render_help(tokens)
    if tokens[0] == "whatis":
        return _render_whatis(tokens)
    return None
