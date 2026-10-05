from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from agents.arbiter_agent import ArbiterAgent, validate_command
from system_state import save_system_log
from terminal_config import PERSIST_SYSTEM_TO_FILE
from tools.common import ts_utc_isoz
from tools.ubuntu_commands import (
    command_is_available,
    primary_command_name,
)
from tools.ubuntu_read_tools import command_exit_status


try:
    from agents.strategic_agent import PlanningRuntime
except Exception as e:
    print(f"[history runtime import failed] {type(e).__name__}: {e}")
    class PlanningRuntime:
        def __init__(self, K: int = 30):
            self.K = K
        def get_pruned_history(self):
            return []
        def step(self, command: str, response: str, pre_snapshot: Dict[str, Any], post_snapshot: Dict[str, Any]) -> None:
            return

try:
    from agents.response_agent import init_client
    client = init_client()
except Exception as e:
    print(f"[response client initialization failed] {type(e).__name__}: {e}")
    client = None


def refresh_system_log_for_planning(system_log: Dict[str, Any], vuln_agent: ArbiterAgent) -> Dict[str, Any]:
    system_log["timestamp"] = ts_utc_isoz()
    vuln_agent.system_log = system_log
    if PERSIST_SYSTEM_TO_FILE:
        try:
            save_system_log(vuln_agent.system_log_path, system_log)
        except Exception:
            pass
    return system_log


@dataclass(frozen=True)
class CommandExecutionResult:
    system_log: Dict[str, Any]
    classification: str
    rendered: str
    exit_status: int
    pre_snapshot: Dict[str, Any]
    post_snapshot: Dict[str, Any]


AuthoritativeResolver = Callable[[str, int, Dict[str, Any]], Optional[str]]
ErrorLogger = Callable[[str, Exception], None]


def execute_command(
    cmd: str,
    vuln_agent: ArbiterAgent,
    system_log: Dict[str, Any],
    session_history: List[Dict[str, Any]],
    *,
    prior_exit_status: int = 0,
    authoritative_resolver: Optional[AuthoritativeResolver] = None,
    error_logger: Optional[ErrorLogger] = None,
    width: int = 80,
    is_tty: bool = True,
    login_username: str = "",
    remote_addr: str = "",
    login_time: Optional[datetime] = None,
) -> CommandExecutionResult:
    """Run the shared classification, state update, rendering, and status pipeline."""

    def report_error(phase: str, error: Exception) -> None:
        if error_logger is not None:
            error_logger(phase, error)

    try:
        if hasattr(vuln_agent, "route_label"):
            classification = vuln_agent.route_label(cmd, client=client)
        else:
            classification = validate_command(client, cmd)
    except Exception as error:
        report_error("classify", error)
        classification = "read"

    pre_snapshot = copy.deepcopy(system_log)
    post_snapshot = copy.deepcopy(system_log)

    if classification == "rejection":
        tool = (cmd.split() or ["cmd"])[0]
        return CommandExecutionResult(
            system_log=system_log,
            classification=classification,
            rendered=f"bash: {tool}: command not found",
            exit_status=127,
            pre_snapshot=pre_snapshot,
            post_snapshot=post_snapshot,
        )

    try:
        if classification == "write":
            system_log = vuln_agent.process_write_command(cmd, client=client)
            post_snapshot = copy.deepcopy(system_log)
            if not bool(getattr(vuln_agent, "last_handled_local", False)):
                rendered = str(system_log.get("last_output") or "")
                exit_status = int(system_log.get("last_exit_status", 0) or 0)
            else:
                system_context = copy.deepcopy(post_snapshot)
                system_context["pre_snapshot"] = pre_snapshot
                authoritative = None
                if authoritative_resolver is not None:
                    authoritative = authoritative_resolver(cmd, prior_exit_status, system_log)
                if authoritative is None:
                    authoritative = str(system_log.get("last_output") or "")
                rendered = render_command_response(
                    cmd,
                    classification,
                    session_history,
                    system_context,
                    authoritative_reference=authoritative,
                    width=width,
                    is_tty=is_tty,
                    login_username=login_username,
                    remote_addr=remote_addr,
                    login_time=login_time,
                )
                exit_status = command_exit_status(cmd, rendered, classification, system_log)
        else:
            system_log = refresh_system_log_for_planning(system_log, vuln_agent)
            pre_snapshot = copy.deepcopy(system_log)
            post_snapshot = copy.deepcopy(system_log)
            system_context = copy.deepcopy(post_snapshot)
            system_context["pre_snapshot"] = pre_snapshot
            authoritative = None
            if authoritative_resolver is not None:
                authoritative = authoritative_resolver(cmd, prior_exit_status, system_log)
            rendered = render_command_response(
                cmd,
                classification,
                session_history,
                system_context,
                authoritative_reference=authoritative,
                width=width,
                is_tty=is_tty,
                login_username=login_username,
                remote_addr=remote_addr,
                login_time=login_time,
            )
            exit_status = command_exit_status(cmd, rendered, classification, system_log)
    except Exception as error:
        report_error("write render" if classification == "write" else "render", error)
        tool = primary_command_name(cmd) or "cmd"
        if classification == "write" or command_is_available(cmd, system_log) is True:
            rendered = f"{tool}: Resource temporarily unavailable"
            exit_status = 1
        else:
            rendered = f"bash: {tool}: command not found"
            exit_status = 127
        post_snapshot = copy.deepcopy(system_log)

    return CommandExecutionResult(
        system_log=system_log,
        classification=classification,
        rendered=rendered,
        exit_status=exit_status,
        pre_snapshot=pre_snapshot,
        post_snapshot=post_snapshot,
    )

def _generate_command_response(
    cmd: str,
    classification: str,
    session_log: List[Dict[str, Any]],
    system_log: Dict[str, Any],
    command_available: Optional[bool] = None,
    width: int = 80,
    is_tty: bool = True,
    login_username: str = "",
    remote_addr: str = "",
    login_time: Optional[datetime] = None,
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
        width=width,
        is_tty=is_tty,
        login_username=login_username,
        remote_addr=remote_addr,
        login_time=login_time,
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
    if authoritative_reference is not None:
        return authoritative_reference.rstrip("\r\n")
    return _generate_command_response(
        cmd,
        classification,
        session_log,
        system_log,
        command_available=command_available,
        width=width,
        is_tty=is_tty,
        login_username=login_username,
        remote_addr=remote_addr,
        login_time=login_time,
    )
