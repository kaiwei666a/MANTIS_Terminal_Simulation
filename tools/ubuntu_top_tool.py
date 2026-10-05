
from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except Exception:
    psutil = None

from tools.common import fmt_eastern

_TOP_METRICS_LOCK = threading.Lock()


def top_size_mib(value: Any) -> float:
    text_value = str(value or "0").strip().lower()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgt]?)", text_value)
    if not match:
        return 0.0
    amount = float(match.group(1))
    unit = match.group(2)
    factors = {"": 1.0 / 1024.0, "k": 1.0 / 1024.0, "m": 1.0, "g": 1024.0, "t": 1024.0 * 1024.0}
    return amount * factors[unit]


def render_ps_aux(processes: List[Dict[str, Any]]) -> str:
    lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
    for proc in processes:
        user = str(proc.get("user") or "root")
        pid = int(proc.get("pid", 0) or 0)
        cpu = float(proc.get("%cpu", 0.0) or 0.0)
        mem = float(proc.get("%mem", 0.0) or 0.0)
        vsz = int(round(top_size_mib(proc.get("virt")) * 1024.0))
        rss = int(round(top_size_mib(proc.get("res")) * 1024.0))
        state = str(proc.get("state") or "S")
        command = str(proc.get("cmd") or "-")
        time_text = str(proc.get("time_plus") or "0:00.00").split(".", 1)[0]
        lines.append(
            f"{user:<8} {pid:7d} {cpu:4.1f} {mem:4.1f} {vsz:6d} {rss:5d} ?        {state:<4} 20:00   {time_text:>4} {command}"
        )
    return "\n".join(lines)


def format_top_uptime(seconds: float) -> str:
    s = int(max(0, seconds))
    days = s // 86400
    s %= 86400
    hours = s // 3600
    s %= 3600
    mins = s // 60
    if days > 0:
        return f"up {days} day{'s' if days != 1 else ''},  {hours:2d}:{mins:02d}"
    return f"up  {hours:2d}:{mins:02d}"


def format_top_memory_size(byte_count: int) -> str:
    mib = max(0.0, float(byte_count) / (1024.0 * 1024.0))
    if mib >= 1024.0:
        return f"{mib / 1024.0:.1f}g"
    return f"{mib:.0f}m"


def collect_live_top_metrics() -> Optional[Dict[str, Any]]:
    if psutil is None:
        return None

    try:
        with _TOP_METRICS_LOCK:
            current_process = psutil.Process(os.getpid())
            process_cpu = float(current_process.cpu_percent(interval=0.05))
            cpu_times = psutil.cpu_times_percent(interval=0.05)
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            proc_mem = current_process.memory_info()
            proc_times = current_process.cpu_times()

        cpu_user = float(getattr(cpu_times, "user", 0.0))
        cpu_nice = float(getattr(cpu_times, "nice", 0.0))
        cpu_system = float(getattr(cpu_times, "system", 0.0))
        cpu_idle = float(getattr(cpu_times, "idle", 0.0))
        cpu_iowait = float(getattr(cpu_times, "iowait", 0.0))
        cpu_irq = float(getattr(cpu_times, "irq", getattr(cpu_times, "interrupt", 0.0)))
        cpu_softirq = float(getattr(cpu_times, "softirq", getattr(cpu_times, "dpc", 0.0)))
        cpu_steal = float(getattr(cpu_times, "steal", 0.0))

        cpu_values = [
            max(0.0, cpu_user), max(0.0, cpu_system), max(0.0, cpu_nice),
            max(0.0, cpu_idle), max(0.0, cpu_iowait), max(0.0, cpu_irq),
            max(0.0, cpu_softirq), max(0.0, cpu_steal),
        ]
        cpu_total = sum(cpu_values)
        if cpu_total > 0.0:
            cpu_values = [value * 100.0 / cpu_total for value in cpu_values]
        (
            cpu_user, cpu_system, cpu_nice, cpu_idle, cpu_iowait,
            cpu_irq, cpu_softirq, cpu_steal,
        ) = cpu_values

        total_bytes = int(vm.total)
        available_bytes = int(vm.available)
        free_bytes = int(vm.free)
        cache_bytes = int(getattr(vm, "cached", 0) or 0) + int(getattr(vm, "buffers", 0) or 0)
        if cache_bytes <= 0:
            cache_bytes = max(0, available_bytes - free_bytes)
        if cache_bytes <= 0 and available_bytes > 0:
            cache_bytes = min(int(total_bytes * 0.15), int(available_bytes * 0.40))
            free_bytes = max(0, available_bytes - cache_bytes)
        used_bytes = max(0, total_bytes - free_bytes - cache_bytes)

        try:
            loadavg = [float(x) for x in psutil.getloadavg()]
        except Exception:
            busy = max(0.0, 100.0 - cpu_idle) / 100.0
            loadavg = [busy, busy, busy]

        proc_state = "R" if current_process.status() == psutil.STATUS_RUNNING else "S"
        proc_cpu_seconds = float(proc_times.user) + float(proc_times.system)
        proc_minutes = int(proc_cpu_seconds // 60)
        proc_seconds = proc_cpu_seconds % 60.0

        return {
            "observed_at": fmt_eastern("%H:%M:%S"),
            "uptime_sec": max(0.0, time.time() - float(psutil.boot_time())),
            "loadavg": loadavg,
            "cpu": {
                "us": cpu_user,
                "sy": cpu_system,
                "ni": cpu_nice,
                "id": cpu_idle,
                "wa": cpu_iowait,
                "hi": cpu_irq,
                "si": cpu_softirq,
                "st": cpu_steal,
            },
            "memory": {
                "total_mib": float(total_bytes) / (1024.0 * 1024.0),
                "free_mib": float(free_bytes) / (1024.0 * 1024.0),
                "used_mib": float(used_bytes) / (1024.0 * 1024.0),
                "buff_cache_mib": float(cache_bytes) / (1024.0 * 1024.0),
            },
            "swap": {
                "total_mib": float(swap.total) / (1024.0 * 1024.0),
                "free_mib": float(swap.free) / (1024.0 * 1024.0),
                "used_mib": float(swap.used) / (1024.0 * 1024.0),
            },
            "simulator_process": {
                "pid": os.getpid(),
                "pr": 20,
                "ni": 0,
                "virt": format_top_memory_size(int(getattr(proc_mem, "vms", 0) or 0)),
                "res": format_top_memory_size(int(getattr(proc_mem, "rss", 0) or 0)),
                "shr": format_top_memory_size(int(getattr(proc_mem, "shared", 0) or 0)),
                "state": proc_state,
                "%cpu": process_cpu,
                "%mem": float(current_process.memory_percent()),
                "time_plus": f"{proc_minutes}:{proc_seconds:05.2f}",
                "cmd": "python3",
                "_preserve_time_plus": True,
            },
        }
    except Exception:
        return None


def style_top_interactive_frame(
    frame: str,
    terminal_width: int = 80,
    terminal_height: int = 24,
) -> str:
    width = max(20, int(terminal_width or 80))
    height = max(8, int(terminal_height or 24))
    content_width = max(1, width - 1)
    lines = frame.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = lines[:height]
    lines.extend([""] * (height - len(lines)))

    styled_lines: List[str] = []
    for line in lines:
        line = line[:content_width]
        if re.match(r"^\s*PID\s+USER\b", line):
            line = f"\x1b[7m{line.ljust(content_width)}\x1b[0m"
        styled_lines.append(line)
    return "\n".join(styled_lines)


def derive_processes_from_system_log(syslog: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(syslog.get("processes"), list):
        out = []
        for p in syslog["processes"]:
            if isinstance(p, dict) and "pid" in p:
                out.append(p)
        if out:
            return out

    procs: List[Dict[str, Any]] = []

    procs.append({
        "pid": 1, "user": "root", "pr": 20, "ni": 0,
        "virt": "168m", "res": "  7m", "shr": "  5m", "state": "S",
        "%cpu": 0.0, "%mem": 0.3, "time_plus": "0:00.16", "cmd": "/sbin/init"
    })

    ports = (((syslog.get("network") or {}).get("listening_ports")) or [])
    seen: set = set()
    for ent in ports:
        if not isinstance(ent, dict):
            continue
        pid = int(ent.get("pid", 0) or 0)
        name = str(ent.get("process") or "unknown")
        if pid <= 0 or pid in seen:
            continue
        seen.add(pid)

        proc_user = "root" if name in ("sshd", "java", "nginx", "apache2") else str((syslog.get("identity", {}) or {}).get("user", "user"))

        if name == "java":
            virt, res, shr, cpu, mem = " 512m", " 96m", " 12m", 0.3, 4.5
        elif name == "sshd":
            virt, res, shr, cpu, mem = "  85m", " 14m", "  8m", 0.0, 0.7
        else:
            virt, res, shr, cpu, mem = " 128m", " 18m", "  6m", 0.0, 0.6

        procs.append({
            "pid": pid, "user": proc_user, "pr": 20, "ni": 0,
            "virt": virt, "res": res, "shr": shr, "state": "S",
            "%cpu": cpu, "%mem": mem, "time_plus": "0:00.00", "cmd": name
        })

    user_name = str((syslog.get("identity", {}) or {}).get("user", "user"))
    procs.append({
        "pid": 613, "user": user_name, "pr": 20, "ni": 0,
        "virt": "  12m", "res": "  5m", "shr": "  4m", "state": "R",
        "%cpu": 0.1, "%mem": 0.2, "time_plus": "0:00.01", "cmd": "bash"
    })

    procs.sort(key=lambda x: (-float(x.get("%cpu", 0.0)), int(x.get("pid", 0))))
    return procs


def update_time_plus(procs: List[Dict[str, Any]], delta: float, cpu_time_by_pid: Dict[int, float]) -> None:
    for p in procs:
        if p.pop("_preserve_time_plus", False):
            continue
        pid = int(p.get("pid", 0) or 0)
        cpu = float(p.get("%cpu", 0.0) or 0.0)
        prev = float(cpu_time_by_pid.get(pid, 0.0))
        inc = max(0.0, min(1.0, cpu / 100.0)) * max(0.0, delta) * 4.0
        cur = prev + inc
        cpu_time_by_pid[pid] = cur

        mm = int(cur // 60)
        ss = cur % 60
        p["time_plus"] = f"{mm}:{ss:05.2f}"


def build_top_state(
    syslog: Dict[str, Any],
    top_session_start: float,
    cpu_time_by_pid: Dict[int, float],
    top_own_pid: Optional[int],
) -> Tuple[Dict[str, Any], Optional[int]]:
    live = collect_live_top_metrics()

    uptime_sec = float((live or {}).get("uptime_sec") or 0.0)
    if uptime_sec <= 0:
        uptime_sec = time.time() - top_session_start

    la = (live or {}).get("loadavg") or syslog.get("loadavg")
    if not (isinstance(la, (list, tuple)) and len(la) >= 3):
        t = int(time.time())
        base = 0.05 + ((t // 2) % 40) / 1000.0
        la = [base, base + 0.01, base + 0.02]

    users = int(syslog.get("users") or 1)

    cpu = (live or {}).get("cpu") or syslog.get("cpu")
    if not isinstance(cpu, dict):
        cpu = {"us": 0.7, "sy": 0.3, "ni": 0.0, "id": 98.7, "wa": 0.2, "hi": 0.0, "si": 0.1, "st": 0.0}

    mem = (live or {}).get("memory") or syslog.get("memory")
    if not isinstance(mem, dict):
        mem = {"total_mib": 2048.0, "free_mib": 812.4, "used_mib": 531.8, "buff_cache_mib": 703.8}

    sw = (live or {}).get("swap") or syslog.get("swap")
    if not isinstance(sw, dict):
        sw = {"total_mib": 1024.0, "free_mib": 1024.0, "used_mib": 0.0}

    procs = derive_processes_from_system_log(syslog)

    if top_own_pid is None:
        existing_pids = [int(p.get("pid", 0) or 0) for p in procs]
        top_own_pid = (max(existing_pids) + 1) if existing_pids else 614
    top_user = str((syslog.get("identity", {}) or {}).get("user", "user"))
    procs.append({
        "pid": top_own_pid, "user": top_user, "pr": 20, "ni": 0,
        "virt": "14m", "res": "6m", "shr": "3m", "state": "R",
        "%cpu": 10.0, "%mem": 0.0,
        "time_plus": "0:00.01",
        "cmd": "top",
    })

    live_process = (live or {}).get("simulator_process")
    if isinstance(live_process, dict):
        live_process = dict(live_process)
        live_process["user"] = "root"
        live_pid = int(live_process.get("pid", 0) or 0)
        procs = [p for p in procs if int(p.get("pid", 0) or 0) != live_pid]
        procs.append(live_process)
        procs.sort(key=lambda x: (-float(x.get("%cpu", 0.0)), int(x.get("pid", 0))))

    total_mib = max(1.0, float(mem.get("total_mib", 0.0) or 0.0))
    for proc in procs:
        proc["%mem"] = 100.0 * top_size_mib(proc.get("res")) / total_mib

    tasks_total = len(procs)
    tasks_running = sum(1 for p in procs if str(p.get("state", "S")) == "R")
    tasks_stopped = sum(1 for p in procs if str(p.get("state", "S")) == "T")
    tasks_zombie = sum(1 for p in procs if str(p.get("state", "S")) == "Z")
    tasks_sleeping = max(0, tasks_total - tasks_running - tasks_stopped - tasks_zombie)

    state = {
        "observed_at": str((live or {}).get("observed_at") or fmt_eastern("%H:%M:%S")),
        "uptime_sec": uptime_sec,
        "uptime_str": format_top_uptime(uptime_sec),
        "users": users,
        "loadavg": [float(la[0]), float(la[1]), float(la[2])],
        "tasks_total": tasks_total,
        "tasks_running": tasks_running if tasks_running > 0 else 1,
        "tasks_sleeping": tasks_sleeping,
        "tasks_stopped": tasks_stopped,
        "tasks_zombie": tasks_zombie,
        "cpu": cpu,
        "memory": mem,
        "swap": sw,
        "processes": procs,
    }
    return state, top_own_pid


def validate_top_frame(rendered: str, terminal_height: int) -> str:
    required_markers = ("top -", "Tasks:", "%Cpu(s):", "MiB Mem", "PID")
    if not rendered or not all(marker in rendered for marker in required_markers):
        raise ValueError("LLM returned an incomplete top frame")
    height = max(8, int(terminal_height or 24))
    normalized = rendered.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    rendered_lines = normalized.split("\n")
    rendered_lines = rendered_lines[:height]

    used_pids = {
        int(match.group(1))
        for line in rendered_lines[7:]
        if (match := re.match(r"^\s*(\d+)\s", line)) is not None
    }
    filler_pid = max(used_pids, default=9000) + 1
    for index in range(7, height):
        if index < len(rendered_lines) and rendered_lines[index].strip():
            continue
        filler = (
            f"{filler_pid:7d} root      20   0       0      0      0 S   "
            "0.0   0.0   0:00.00 kworker/0:0"
        )
        if index < len(rendered_lines):
            rendered_lines[index] = filler
        else:
            rendered_lines.append(filler)
        filler_pid += 1

    process_states = []
    for line in rendered_lines[7:]:
        fields = line.split()
        if len(fields) >= 8 and fields[0].isdigit():
            process_states.append(fields[7][:1])
    if process_states:
        running = process_states.count("R")
        stopped = process_states.count("T")
        zombie = process_states.count("Z")
        sleeping = len(process_states) - running - stopped - zombie
        tasks_index = next(
            (index for index, line in enumerate(rendered_lines) if line.startswith("Tasks:")),
            None,
        )
        if tasks_index is not None:
            rendered_lines[tasks_index] = (
                f"Tasks: {len(process_states):3d} total, {running:3d} running, "
                f"{sleeping:3d} sleeping, {stopped:3d} stopped, {zombie:3d} zombie"
            )
    return "\n".join(rendered_lines)


def run_top_interactive(*, chan, terminal_state, render_frame, send, interval: float):
    old_timeout = None
    last_frame = ""
    try:
        try:
            old_timeout = chan.gettimeout()
        except Exception:
            old_timeout = None

        try:
            chan.settimeout(0.0)
        except Exception:
            pass

        terminal_width = max(20, int(getattr(terminal_state, "pty_width", 80) or 80))
        terminal_height = max(8, int(getattr(terminal_state, "pty_height", 24) or 24))
        last_frame = style_top_interactive_frame(
            render_frame(terminal_width, terminal_height),
            terminal_width=terminal_width,
            terminal_height=terminal_height,
        ).replace("\n", "\r\n")
        send(chan, "\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
        send(chan, last_frame)
        last_render = time.time()

        while True:
            if chan.recv_ready():
                data = chan.recv(1024)
                if not data:
                    return
                if b"q" in data or b"Q" in data or b"\x03" in data:
                    return

            now = time.time()
            if now - last_render >= interval:
                terminal_width = max(20, int(getattr(terminal_state, "pty_width", 80) or 80))
                terminal_height = max(8, int(getattr(terminal_state, "pty_height", 24) or 24))
                last_render = now
                last_frame = style_top_interactive_frame(
                    render_frame(terminal_width, terminal_height),
                    terminal_width=terminal_width,
                    terminal_height=terminal_height,
                ).replace("\n", "\r\n")

                send(chan, "\x1b[H\x1b[2J")
                send(chan, last_frame)

            time.sleep(0.05)
    finally:
        send(chan, "\x1b[0m\x1b[?25h\x1b[?1049l\r\x1b[K")
        if last_frame:
            send(chan, last_frame)
            send(chan, "\x1b[0m\r\n")
        try:
            chan.settimeout(old_timeout)
        except Exception:
            pass
