from __future__ import annotations

import copy
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from agents.arbiter_agent import ArbiterAgent, select_interactive_tool
from system_state import load_system_log, save_system_log
from runtime.command_runtime import (
    PlanningRuntime,
    client,
    execute_command,
    refresh_system_log_for_planning,
)
from storage.session_store import (
    append_auth_log,
    load_session_log,
    log_attack,
    record_session,
    save_session_log,
)
from server.ssh_io import _safe_send
from terminal_config import (
    HOSTNAME,
    LOAD_SESSION_FROM_FILE,
    LOAD_SYSTEM_FROM_FILE,
    PERSIST_SYSTEM_TO_FILE,
    PORT,
    SUDO_PASSWORD,
    SYSTEM_JSON,
    TOP_REFRESH_SEC,
)
from transfer.transfer_backend import docker_fetch_file, docker_fetch_git_clone
from tools.common import fmt_eastern, now_eastern, ts_utc_isoz
from tools.interactive_tools import (
    InteractiveToolContext,
    dispatch_interactive_tool,
)
from tools.ubuntu_commands import (
    ensure_default_packages,
    known_command_names,
)
from tools.ubuntu_fs_session import (
    apply_login_identity,
    read_session_file,
    resolve_session_path,
    write_session_file,
)
from tools.ubuntu_ls import format_name_columns, list_directory_entries
from tools.ubuntu_read_tools import (
    render_authoritative_shell_output,
)
from tools.ubuntu_session_tools import (
    record_login_session,
    record_logout_session,
)
from tools.ubuntu_sysinfo_tools import format_shell_prompt
from tools.ubuntu_top_tool import (
    build_top_state,
    update_time_plus,
)


def send_response_lines_shell(chan, text: str, prompt: str, chunk_size: int = 1024):
    if text is None:
        text = ""
    normalized = text.replace("\r\n", "\n").rstrip("\n")
    lines = normalized.split("\n") if normalized else []
    for line in lines:
        if line == "":
            _safe_send(chan, "\r\n")
            continue
        b = line.encode("utf-8", errors="ignore")
        for i in range(0, len(b), chunk_size):
            chunk = b[i:i+chunk_size].decode("utf-8", errors="ignore")
            _safe_send(chan, chunk)
        _safe_send(chan, "\r\n")
    _safe_send(chan, prompt)


def run_agent_shell(
    chan,
    session_id: str,
    remote_addr: str,
    login_username: str,
    terminal_state: Optional[Any] = None,
):
    login_time = now_eastern()
    vuln_agent = ArbiterAgent(
        session_id=session_id,
        download_file_fetcher=docker_fetch_file,
        download_git_fetcher=docker_fetch_git_clone,
    )

    session_log: List[Dict[str, Any]] = load_session_log() if LOAD_SESSION_FROM_FILE else []
    save_session_log(session_log)

    file_syslog = load_system_log(SYSTEM_JSON) if LOAD_SYSTEM_FROM_FILE else None
    if isinstance(file_syslog, dict):
        system_log: Dict[str, Any] = file_syslog
    else:
        system_log = copy.deepcopy(vuln_agent.system_log)

    system_log["timestamp"] = ts_utc_isoz()
    apply_login_identity(system_log, login_username, HOSTNAME)
    ensure_default_packages(system_log)
    record_login_session(system_log, login_username, remote_addr, login_time, session_id)
    system_log["cwd"] = str(system_log["identity"]["home"])
    vuln_agent.system_log = system_log
    save_system_log(vuln_agent.system_log_path, system_log)

    current_path = system_log.get("cwd", str(system_log["identity"]["home"]))
    file_tree = system_log.get("filesystem", {})

    CSI = "\x1b["

    planner = PlanningRuntime(K=30)

    def _prompt() -> str:
        return format_shell_prompt(
            login_username,
            HOSTNAME,
            current_path,
            system_log.get("identity", {}) or {},
        )

    def _redraw_line(buffer: List[str], cursor: int):
        _safe_send(chan, "\r")
        line = _prompt() + "".join(buffer)
        _safe_send(chan, line)
        _safe_send(chan, "\x1b[K")
        back = len(buffer) - cursor
        if back > 0:
            _safe_send(chan, f"{CSI}{back}D")

    def _tab_complete():
        nonlocal buffer, cursor, last_tab_state
        start = cursor
        while start > 0 and buffer[start - 1] != " ":
            start -= 1
        word = "".join(buffer[start:cursor])
        is_first_word = "".join(buffer[:start]).strip() == ""

        if is_first_word:
            prefix = word
            entries = [(name, False) for name in known_command_names(system_log) if name.startswith(prefix)]
        else:
            if "/" in word:
                dir_part, _, prefix = word.rpartition("/")
                dir_part = dir_part or "/"
            else:
                dir_part, prefix = ".", word
            listing = list_directory_entries(system_log, dir_part)
            entries = [(name, is_dir) for name, is_dir in (listing or []) if name.startswith(prefix)]

        if not entries:
            last_tab_state = None
            return

        names = sorted(name for name, _ in entries)
        if len(entries) == 1:
            name, is_dir = entries[0]
            remainder = name[len(prefix):]
            insertion = list(remainder) + (["/"] if is_dir else [" "])
            buffer[cursor:cursor] = insertion
            cursor += len(insertion)
            _redraw_line(buffer, cursor)
            last_tab_state = None
            return

        common = os.path.commonprefix(names)
        if len(common) > len(prefix):
            remainder = common[len(prefix):]
            buffer[cursor:cursor] = list(remainder)
            cursor += len(remainder)
            _redraw_line(buffer, cursor)
            last_tab_state = None
            return

        state_key = ("".join(buffer), cursor)
        if last_tab_state == state_key:
            _safe_send(chan, "\r\n")
            _safe_send(chan, format_name_columns(names).replace("\n", "\r\n"))
            _safe_send(chan, "\r\n")
            _redraw_line(buffer, cursor)
            last_tab_state = None
        else:
            _safe_send(chan, "\x07")
            last_tab_state = state_key

    def _resolve_path(p: str) -> str:
        home_path = str((system_log.get("identity") or {}).get("home") or "/home/user")
        return resolve_session_path(p, current_path, home_path)

    def _read_file(abs_path: str) -> str:
        return read_session_file(abs_path, system_log)

    def _write_file(abs_path: str, content: str):
        write_session_file(abs_path, content, system_log)
        vuln_agent.system_log = system_log
        if PERSIST_SYSTEM_TO_FILE:
            try:
                save_system_log(vuln_agent.system_log_path, system_log)
            except Exception:
                pass

    _top_session_start = time.time()
    _top_cpu_time_by_pid: Dict[int, float] = {}
    _top_last_frame_time = 0.0
    _top_own_pid: Optional[int] = None

    def _build_top_state(syslog: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal _top_own_pid
        state, _top_own_pid = build_top_state(syslog, _top_session_start, _top_cpu_time_by_pid, _top_own_pid)
        return state

    def _top_frame(terminal_width: int, terminal_height: int) -> str:
        nonlocal _top_last_frame_time

        refresh_system_log_for_planning(system_log, vuln_agent)

        now = time.time()
        delta = now - _top_last_frame_time if _top_last_frame_time > 0 else TOP_REFRESH_SEC
        _top_last_frame_time = now

        state = _build_top_state(system_log)
        update_time_plus(state["processes"], delta, _top_cpu_time_by_pid)
        try:
            from agents.response_agent import render_top_response

            rendered = render_top_response(
                state,
                terminal_width=terminal_width,
                terminal_height=terminal_height,
                client=client,
            )
            from tools.ubuntu_top_tool import validate_top_frame
            return validate_top_frame(rendered, terminal_height)
        except Exception as exc:
            log_attack(f"[{session_id}] top LLM refresh failed: {exc}", "warn")
            raise

    def _run_top_interactive(interval: float = TOP_REFRESH_SEC):
        from tools.ubuntu_top_tool import run_top_interactive
        return run_top_interactive(
            chan=chan, terminal_state=terminal_state, render_frame=_top_frame,
            send=_safe_send, interval=interval,
        )

    def _run_cat_stdin_redirect(abs_path: str, append: bool) -> bool:
        from tools.ubuntu_cat_tool import run_cat_stdin_redirect
        return run_cat_stdin_redirect(
            abs_path, append, chan=chan, read_file=_read_file,
            write_file=_write_file, send=_safe_send,
        )

    def _run_ping_interactive(command: str) -> Tuple[str, int]:
        from agents.response_agent import generate_ping_profile
        from tools.ubuntu_ping_tool import run_ping_interactive
        return run_ping_interactive(
            command, chan=chan, send=_safe_send,
            generate_profile=lambda host: generate_ping_profile(host, client=client),
            report_error=lambda exc: log_attack(f"[{session_id}] ping profile generation failed: {exc}", "warn"),
        )


    def _recv_key_blocking() -> str:
        b = chan.recv(1)
        if not b:
            return ""
        ch = b.decode("utf-8", errors="ignore")
        if ch != "\x1b":
            return ch

        b2 = chan.recv(1)
        if not b2:
            return "\x1b"
        ch2 = b2.decode("utf-8", errors="ignore")
        if ch2 != "[":
            return "\x1b" + ch2

        b3 = chan.recv(1)
        if not b3:
            return "\x1b["
        ch3 = b3.decode("utf-8", errors="ignore")
        return "\x1b[" + ch3

    def _prompt_sudo_password(cmd: str) -> bool:
        from tools.ubuntu_auth_tool import prompt_sudo_password
        return prompt_sudo_password(
            cmd, chan=chan, system_log=system_log, login_username=login_username,
            password=SUDO_PASSWORD, recv_key=_recv_key_blocking, send=_safe_send,
        )


    def _run_nano_interactive(abs_path: str):
        from tools.ubuntu_nano_tool import run_nano_interactive
        return run_nano_interactive(
            abs_path, chan=chan, terminal_state=terminal_state,
            read_file=_read_file, write_file=_write_file,
            recv_key=_recv_key_blocking, send=_safe_send,
        )

    buffer: List[str] = []
    cursor: int = 0
    history: List[str] = []
    hist_idx: int = 0
    last_exit_status: int = 0
    last_tab_state: Optional[Tuple[str, int]] = None
    sudo_authenticated: bool = False

    _safe_send(chan, "\r\n")
    _safe_send(chan, "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-84-generic x86_64)\r\n")
    _safe_send(chan, f"Last login: {fmt_eastern('%a %b %d %H:%M:%S %Y')} from {remote_addr.split(':')[0]}\r\n")
    _safe_send(chan, _prompt())

    esc_mode = False
    esc_buf = ""

    def _authoritative_shell_output(
        command: str,
        prior_status: int,
        active_system_log: Dict[str, Any],
    ) -> Optional[str]:
        return render_authoritative_shell_output(
            command,
            prior_status,
            active_system_log,
            str(active_system_log.get("cwd") or current_path),
            login_username,
            HOSTNAME,
            history,
            lambda: _build_top_state(active_system_log)["processes"],
        )

    def _accept_line():
        nonlocal buffer, cursor, history, hist_idx, system_log, current_path, file_tree, last_exit_status, sudo_authenticated
        cmd = "".join(buffer).strip()
        log_attack(f"[{session_id}] Command received: {cmd}")
        _safe_send(chan, "\r\n")

        if cmd == "":
            _safe_send(chan, _prompt())
            buffer.clear()
            cursor = 0
            hist_idx = len(history)
            return None

        if cmd.lower() == "exit":
            _safe_send(chan, "logout\r\n")
            record_logout_session(system_log, session_id, now_eastern())
            save_system_log(vuln_agent.system_log_path, system_log)
            append_auth_log(event="disconnect", session_id=session_id, username=login_username,
                            hostname=HOSTNAME, remote_addr=remote_addr, success=True, note="session closed", proto="ssh", local_port=PORT)
            try:
                chan.send_exit_status(last_exit_status)
            except Exception:
                pass
            return "EXIT"

        history.append(cmd)
        hist_idx = len(history)
        shell_width = int(getattr(terminal_state, "pty_width", 80) or 80)
        prior_exit_status = last_exit_status

        if not sudo_authenticated and re.match(r"^\s*(?:sudo\b|su\b)", cmd):
            if _prompt_sudo_password(cmd):
                sudo_authenticated = True
            else:
                last_exit_status = 1
                buffer.clear()
                cursor = 0
                _safe_send(chan, _prompt())
                return None

        selected_tool = select_interactive_tool(cmd, client)
        terminal_width = max(20, int(getattr(terminal_state, "pty_width", 80) or 80))
        terminal_height = max(8, int(getattr(terminal_state, "pty_height", 24) or 24))
        interactive_status = dispatch_interactive_tool(
            selected_tool,
            InteractiveToolContext(
                command=cmd,
                prompt=_prompt,
                send_response=lambda text, prompt: send_response_lines_shell(chan, text, prompt),
                send_text=lambda text: _safe_send(chan, text),
                record_session=lambda command, output, classification: record_session(
                    session_log,
                    command,
                    output,
                    classification,
                ),
                resolve_path=_resolve_path,
                run_cat_stdin_redirect=lambda path, append: _run_cat_stdin_redirect(path, append),
                run_ping_interactive=_run_ping_interactive,
                render_top_frame=lambda: _top_frame(terminal_width, terminal_height),
                run_top_interactive=lambda interval: _run_top_interactive(interval=interval),
                run_nano_interactive=_run_nano_interactive,
                top_refresh_seconds=TOP_REFRESH_SEC,
            ),
        )
        if interactive_status is not None:
            last_exit_status = interactive_status
            buffer.clear()
            cursor = 0
            hist_idx = len(history)
            return None

        pruned_history = planner.get_pruned_history() if planner is not None else []
        result = execute_command(
            cmd,
            vuln_agent,
            system_log,
            pruned_history,
            prior_exit_status=prior_exit_status,
            authoritative_resolver=_authoritative_shell_output,
            error_logger=lambda phase, error: log_attack(
                f"[{session_id}] {phase} error: {error}",
                "warn",
            ),
            width=shell_width,
            login_username=login_username,
            remote_addr=remote_addr,
            login_time=login_time,
        )
        system_log = result.system_log
        current_path = system_log.get("cwd", current_path)
        file_tree = system_log.get("filesystem", file_tree)
        last_exit_status = result.exit_status

        if cmd == "clear":
            _safe_send(chan, "\x1b[H\x1b[2J")
            _safe_send(chan, _prompt())
        else:
            send_response_lines_shell(chan, result.rendered, _prompt())
        record_session(session_log, cmd, result.rendered, result.classification)
        try:
            planner.step(
                cmd,
                result.rendered,
                result.pre_snapshot,
                result.post_snapshot,
            )
        except Exception:
            pass
        buffer.clear()
        cursor = 0
        return None

    while True:
        data = chan.recv(1024)
        if not data:
            break
        chunk = data.decode("utf-8", errors="ignore")

        i = 0
        while i < len(chunk):
            ch = chunk[i]
            i += 1

            if esc_mode:
                esc_buf += ch
                if ch.isalpha() or ch == "~":
                    seq = esc_buf
                    esc_mode = False
                    esc_buf = ""
                    last_tab_state = None

                    if seq in ("[C", "OC"):
                        if cursor < len(buffer):
                            cursor += 1
                            _safe_send(chan, CSI + "1C")
                    elif seq in ("[D", "OD"):
                        if cursor > 0:
                            cursor -= 1
                            _safe_send(chan, CSI + "1D")
                    elif seq in ("[A",):
                        if history:
                            if hist_idx > 0:
                                hist_idx -= 1
                            buffer = list(history[hist_idx])
                            cursor = len(buffer)
                            _redraw_line(buffer, cursor)
                    elif seq in ("[B",):
                        if history:
                            if hist_idx < len(history) - 1:
                                hist_idx += 1
                                buffer = list(history[hist_idx])
                            else:
                                hist_idx = len(history)
                                buffer = []
                            cursor = len(buffer)
                            _redraw_line(buffer, cursor)
                    elif seq in ("[3~",):
                        if cursor < len(buffer):
                            del buffer[cursor]
                            _redraw_line(buffer, cursor)
                    elif seq in ("[H", "[1~", "OH"):
                        cursor = 0
                        _redraw_line(buffer, cursor)
                    elif seq in ("[F", "[4~", "OF"):
                        cursor = len(buffer)
                        _redraw_line(buffer, cursor)
                continue

            if ch == "\x1b":
                esc_mode = True
                esc_buf = ""
                continue

            if ch == "\t":
                _tab_complete()
                continue

            last_tab_state = None

            if ch in ("\r", "\n"):
                r = _accept_line()
                if r == "EXIT":
                    return
                continue

            if ch == "\x7f":
                if cursor > 0:
                    cursor -= 1
                    del buffer[cursor]
                    _redraw_line(buffer, cursor)
                continue

            buffer.insert(cursor, ch)
            cursor += 1
            _redraw_line(buffer, cursor)

    record_logout_session(system_log, session_id, now_eastern())
    save_system_log(vuln_agent.system_log_path, system_log)

def handle_exec_command_once(
    chan,
    session_id: str,
    remote_addr: str,
    exec_cmd: str,
    login_username: str,
):
    login_time = now_eastern()

    vuln_agent = ArbiterAgent(
        session_id=session_id,
        download_file_fetcher=docker_fetch_file,
        download_git_fetcher=docker_fetch_git_clone,
    )

    session_log: List[Dict[str, Any]] = load_session_log() if LOAD_SESSION_FROM_FILE else []
    save_session_log(session_log)

    file_syslog = load_system_log(SYSTEM_JSON) if LOAD_SYSTEM_FROM_FILE else None
    if isinstance(file_syslog, dict):
        system_log: Dict[str, Any] = file_syslog
    else:
        system_log = copy.deepcopy(vuln_agent.system_log)

    system_log["timestamp"] = ts_utc_isoz()
    apply_login_identity(system_log, login_username, HOSTNAME)
    ensure_default_packages(system_log)
    system_log["cwd"] = str(system_log["identity"]["home"])
    vuln_agent.system_log = system_log

    cmd = (exec_cmd or "").strip()
    log_attack(f"[{session_id}] EXEC received (no-pty): {cmd}")

    if not cmd:
        try:
            chan.send_exit_status(0)
        except Exception:
            pass
        return

    if re.match(r"^\s*(?:sudo\b(?!.*\s-S(?:\s|$))|su\b)", cmd):
        rendered = "sudo: a terminal is required to read the password\n"
        _safe_send(chan, rendered.replace("\n", "\r\n"))
        record_session(session_log, cmd, rendered, "rejection")
        try:
            chan.send_exit_status(1)
        except Exception:
            pass
        return

    def authoritative_exec_output(
        command: str,
        prior_status: int,
        active_system_log: Dict[str, Any],
    ) -> Optional[str]:
        return render_authoritative_shell_output(
            command,
            prior_status,
            active_system_log,
            str(active_system_log.get("cwd") or active_system_log["identity"]["home"]),
            login_username,
            HOSTNAME,
            [],
            lambda: build_top_state(active_system_log, time.time(), {}, None)[0]["processes"],
        )

    result = execute_command(
        cmd,
        vuln_agent,
        system_log,
        [],
        authoritative_resolver=authoritative_exec_output,
        error_logger=lambda phase, error: log_attack(
            f"[{session_id}] exec {phase} error: {error}",
            "warn",
        ),
        is_tty=False,
        login_username=login_username,
        remote_addr=remote_addr,
        login_time=login_time,
    )
    rendered = result.rendered
    if not rendered.endswith("\n"):
        rendered += "\n"
    _safe_send(chan, rendered.replace("\n", "\r\n"))
    record_session(session_log, cmd, rendered, result.classification)
    try:
        chan.send_exit_status(result.exit_status)
    except Exception:
        pass
