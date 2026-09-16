from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from agents.arbiter_agent import VulnerabilityAgentLLM
from system_state import save_system_log
from terminal_config import PERSIST_SYSTEM_TO_FILE
from tools.common import ts_utc_isoz
from tools.ubuntu_commands import (
    command_is_available,
    primary_command_name,
    render_direct_exec,
)
from tools.ubuntu_ip import render_ip
from tools.ubuntu_ls import render_ls
from tools.ubuntu_read_tools import render_stateful_read
from tools.ubuntu_session_tools import render_user_session_command


try:
    from agents.strategic_agent import PlanningRuntime, init_client, validate_command
    client = init_client()
except Exception as e:
    print(f"[strategic_agent import failed] {type(e).__name__}: {e}")
    client = None

    def validate_command(_client, command: str) -> str:
        cmd = command.strip()
        if re.search(r"\b(rm\s+-rf\s+/|mkfs|iptables|dd\s+if=|mount|umount)\b", cmd):
            return "rejection"
        if re.search(r"\b(mkdir|touch|rm|mv|cp|cd|chmod|chown)\b", cmd) or re.search(r"^\s*echo\s+.+\s*(>>|>)\s*.+$", cmd):
            return "write"
        return "read"

    class PlanningRuntime:
        def __init__(self, K: int = 30):
            self.K = K
        def get_pruned_history(self):
            return []
        def step(self, command: str, response: str, pre_snapshot: Dict[str, Any], post_snapshot: Dict[str, Any]) -> None:
            return

def refresh_system_log_for_planning(system_log: Dict[str, Any], vuln_agent: VulnerabilityAgentLLM) -> Dict[str, Any]:
    system_log["timestamp"] = ts_utc_isoz()
    vuln_agent.system_log = system_log
    if PERSIST_SYSTEM_TO_FILE:
        try:
            save_system_log(vuln_agent.system_log_path, system_log)
        except Exception:
            pass
    return system_log

def render_response_once(
    cmd: str,
    classification: str,
    session_log: List[Dict[str, Any]],
    system_log: Dict[str, Any],
    command_available: Optional[bool] = None,
) -> str:
    from agents.response_agent import render_response as _render

    response_advice = (
        "Generate the final terminal output directly in this single call. "
        f"The local command classifier labeled this command as {classification!r}. "
        "Use the pre_snapshot and post_snapshot as the source of truth, do not describe your reasoning."
    )
    if classification != "rejection":
        response_advice += (
            "\nThis command was not explicitly rejected. Do not answer with 'command not found' merely "
            "because its behavior is unfamiliar, infer the normal Ubuntu 22.04 behavior from the command, "
            "options, operands, and supplied snapshot. Only an explicit rejection may be rendered as a "
            "missing executable."
        )
    if command_available is True:
        tool = primary_command_name(cmd)
        response_advice += (
            f"\nThe executable {tool!r} is installed in this simulated Ubuntu system. "
            "That installed-command inventory is authoritative: never report that this executable "
            "is missing, not found, or unavailable. Generate its normal Ubuntu terminal behavior."
        )
    rendered = _render(
        cmd,
        response_advice,
        session_log,
        system_log,
    )
    if command_available is True:
        tool = primary_command_name(cmd)
        if tool and re.search(
            rf"(?im)(?:^|:\s){re.escape(tool)}:\s*(?:command\s+)?not found\b",
            rendered,
        ):
            return f"{tool}: Resource temporarily unavailable"
    return rendered


def render_command_response(
    cmd: str,
    classification: str,
    session_log: List[Dict[str, Any]],
    system_log: Dict[str, Any],
    authoritative_reference: Optional[str] = None,
    width: int = 80,
    is_tty: bool = True,
    login_username: str = "",
    remote_addr: str = "",
    login_time: Optional[datetime] = None,
) -> str:
    command_available = command_is_available(cmd, system_log)
    if authoritative_reference is None and login_time is not None:
        authoritative_reference = render_user_session_command(
            cmd,
            system_log,
            login_username,
            remote_addr,
            login_time,
        )
    if authoritative_reference is None:
        authoritative_reference = render_ls(cmd, system_log, width=width, is_tty=is_tty)
    if authoritative_reference is None:
        authoritative_reference = render_ip(cmd, system_log)
    if authoritative_reference is None:
        authoritative_reference = render_stateful_read(cmd, system_log)
    if authoritative_reference is None:
        authoritative_reference = render_direct_exec(cmd, system_log)
    if authoritative_reference is None and re.match(r"^\s*(?:cd|rmdir)(?:\s|$)", cmd):
        authoritative_reference = str(system_log.get("last_output", ""))
    if authoritative_reference is None and re.match(r"^\s*git\s+clone\b", cmd):
        authoritative_reference = str(system_log.get("last_output", ""))
    if authoritative_reference is not None:
        return authoritative_reference.rstrip("\r\n")
    return render_response_once(
        cmd,
        classification,
        session_log,
        system_log,
        command_available=command_available,
    )
