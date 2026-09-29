from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from tools.ubuntu_commands import render_direct_exec
from tools.ubuntu_ip import render_ip
from tools.ubuntu_ls import render_ls
from tools.ubuntu_read_tools import render_stateful_read
from tools.ubuntu_session_tools import render_user_session_command


RESPONSE_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": (
                "Authoritatively render 'ls'/'ll' family directory-listing commands from the "
                "simulated filesystem state."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show_network_config",
            "description": (
                "Authoritatively render 'ip'/network-inspection commands from the simulated "
                "network state."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_or_stream_file",
            "description": (
                "Authoritatively render 'cat'/'head'/'tail'/'less'/'more'/'wc' and similar "
                "file-reading commands from the simulated filesystem state."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "user_session_command",
            "description": (
                "Authoritatively render 'who'/'users'/'w'/'last'/'lastlog' from the simulated "
                "login-session state."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "direct_exec",
            "description": (
                "Authoritatively validate commands that execute an explicit file path such as "
                "'./script' or '/tmp/program', including missing paths, directories, and execute "
                "permission errors from simulated filesystem state."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
]


def dispatch_response_tool(
    tool_name: str,
    command: str,
    system_log: Dict[str, Any],
    *,
    width: int = 80,
    is_tty: bool = True,
    login_username: str = "",
    remote_addr: str = "",
    login_time: Optional[datetime] = None,
) -> Optional[str]:
    """Run the deterministic renderer selected by the response agent."""

    renderers: Dict[str, Callable[[], Optional[str]]] = {
        "list_directory": lambda: render_ls(command, system_log, width=width, is_tty=is_tty),
        "show_network_config": lambda: render_ip(command, system_log),
        "read_or_stream_file": lambda: render_stateful_read(command, system_log),
        "user_session_command": (
            lambda: render_user_session_command(
                command,
                system_log,
                login_username,
                remote_addr,
                login_time,
            )
            if login_time is not None
            else None
        ),
        "direct_exec": lambda: render_direct_exec(command, system_log),
    }
    renderer = renderers.get(tool_name)
    return renderer() if renderer is not None else None
