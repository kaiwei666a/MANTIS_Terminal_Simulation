from __future__ import annotations

import os
import re
import shlex
from typing import Any, Dict, Optional

from tools.ubuntu_ls import resolve_path_kind


UBUNTU_BASE_COMMANDS = {
    "[", "alias", "apt", "apt-cache", "apt-get", "awk", "basename", "bash",
    "bg", "bunzip2", "bzcat", "bzip2", "cat", "cd", "chgrp", "chmod", "chown",
    "chroot", "cksum", "clear", "cmp", "comm", "command", "cp", "crontab", "curl",
    "cut", "date", "dd", "df", "diff", "diff3", "dirname", "dmesg", "dpkg",
    "dpkg-query", "du", "echo", "egrep", "env", "expand", "export", "expr",
    "false", "fg", "fgrep", "file", "find", "free", "getent", "getopts", "grep",
    "groups", "gunzip", "gzip", "head", "help", "history", "hostname", "hostnamectl",
    "git", "id", "install", "ip", "journalctl", "jobs", "join", "kill",
    "killall", "last", "lastlog", "less", "link", "ll", "ln", "locale", "logger", "loginctl",
    "logname", "ls", "lsblk", "lscpu", "lsof", "man", "md5sum", "mkdir", "mkfifo",
    "mknod", "mktemp", "more", "mount", "mv", "nano", "nice", "nl",
    "nohup", "nproc", "od", "passwd", "paste", "pgrep", "pidof", "ping", "pkill",
    "printenv", "printf", "ps", "pwd", "read", "readlink", "realpath", "renice",
    "reset", "rm", "rmdir", "run-parts", "scp", "sed", "seq", "service",
    "sha1sum", "sha256sum", "shred", "sleep", "sort", "split", "ss", "ssh",
    "stat", "strings", "su", "sudo", "sync", "systemctl", "tail", "tar", "tee",
    "test", "time", "timeout", "top", "touch", "tr", "true", "truncate", "tty",
    "type", "ulimit", "umask", "umount", "unalias", "uname", "unexpand", "uniq",
    "unlink", "unzip", "unset", "uptime", "users", "vmstat", "w", "wait", "watch",
    "wc", "wget", "whatis", "whereis", "which", "who", "whoami", "xargs", "xxd", "yes",
    "zip", "zcat",
}


PACKAGE_COMMANDS = {
    "iproute2": {"ip", "ss"},
    "net-tools": {"ifconfig", "netstat", "route"},
    "procps": {"free", "pgrep", "pkill", "ps", "sysctl", "top", "uptime", "vmstat", "w", "watch"},
    "coreutils": {"cat", "chmod", "chown", "cp", "date", "df", "du", "echo", "id", "ls", "mkdir", "mv", "pwd", "rm", "rmdir", "sort", "tail", "touch", "uname", "wc", "whoami"},
    "curl": {"curl"},
    "wget": {"wget"},
    "git": {"git"},
    "openssh-client": {"scp", "sftp", "ssh"},
    "vim-tiny": {"vi", "vim.tiny"},
}


def parse_man_request(args: list[str]) -> Optional[tuple[Optional[str], str]]:
    if not args:
        return None
    section: Optional[str] = None
    topic_index = 0
    if len(args) >= 2 and re.fullmatch(r"[0-9][A-Za-z]*", args[0]):
        section = args[0]
        topic_index = 1
    if topic_index + 1 != len(args):
        return None
    topic = args[topic_index]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]*", topic):
        return None
    return section, topic


def is_manual_or_help_command(command: str) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not tokens or tokens[0] not in {"man", "help", "whatis"}:
        return False

    args = tokens[1:]
    if not args or args[0] in {"--help", "-h", "--version", "-V"}:
        return True
    if tokens[0] == "man":
        return parse_man_request(args) is not None
    if tokens[0] == "whatis":
        return all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]*", topic) for topic in args)

    remaining = list(args)
    while remaining and remaining[0] in {"-d", "-m", "-s"}:
        remaining.pop(0)
    return len(remaining) <= 1 and (
        not remaining or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+-]*", remaining[0]) is not None
    )



DEFAULT_PACKAGE_STATE: Dict[str, bool] = {
    "iproute2": True,
    "net-tools": False,
    "vim-tiny": False,
}


def ensure_default_packages(system_log: Dict[str, Any]) -> Dict[str, Any]:
    packages = system_log.setdefault("packages", {})
    if not isinstance(packages, dict):
        return {}
    for name, installed in DEFAULT_PACKAGE_STATE.items():
        if name not in packages:
            packages[name] = {"installed": installed}
    return packages


WRITE_PATTERNS = (
    r"^\s*(?:cd|mkdir|touch|rm|rmdir|mv|cp|chmod|chown|chgrp|ln|install|truncate|unlink)\b",
    r"^\s*(?:apt|apt-get)\s+(?:update|install|remove|purge|upgrade|full-upgrade|autoremove)\b",
    r"^\s*dpkg\s+(?:-i|--install|-r|--remove|-P|--purge)\b",
    r"^\s*sed\b[^\n]*(?:\s-i[^\s]*(?:\s|$)|\s--in-place(?:=[^\s]*)?(?:\s|$))",
    r"^\s*(?:tee|crontab|passwd|useradd|userdel|usermod|groupadd|groupdel|groupmod)\b",
    r"^\s*(?:kill|killall|pkill|renice)\b",
    r"^\s*(?:mount|umount)\b",
    r"^\s*(?:export|unset)\b",
    r"^\s*(?:systemctl|service)\s+(?:start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload|set-default|isolate)\b",
    r"^\s*hostnamectl\s+set-hostname\b",
    r"^\s*ip\s+(?:address|addr|a|link|route|r|neighbor|neigh|n)\s+(?:add|append|change|delete|del|flush|replace|set)\b",
    r"^\s*wget\b",
    r"^\s*curl\b[^\n]*(?:(?:^|\s)-[A-Za-z]*O(?:[A-Za-z]|\s|$)|\s-o(?:\s|=)|--output(?:=|\s)|--remote-name\b)",
    r"^\s*git\s+clone\b",
    r"(?:^|\s)(?:>|>>|2>|2>>|&>)\s*\S+",
)


OPTION_DEPENDENT_WRITE_COMMANDS = {
    "bash",
    "bunzip2",
    "bzip2",
    "dd",
    "gunzip",
    "gzip",
    "mkfifo",
    "mknod",
    "mktemp",
    "nohup",
    "shred",
    "sort",
    "split",
    "tar",
    "unzip",
    "xargs",
    "zip",
}


def primary_command_name(command: str) -> str:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.strip().split()
    if not tokens:
        return ""
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    while index < len(tokens) and tokens[index] in {"command", "builtin", "nohup", "time"}:
        index += 1
    if index < len(tokens) and tokens[index] == "sudo":
        index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
        if index >= len(tokens):
            return "sudo"
    if index >= len(tokens):
        return ""
    return os.path.basename(tokens[index])


def _dynamic_commands(system_log: Dict[str, Any]) -> set[str]:
    commands: set[str] = set()
    configured = system_log.get("installed_commands") or system_log.get("commands") or []
    if isinstance(configured, dict):
        commands.update(str(name) for name, present in configured.items() if bool(present))
    elif isinstance(configured, list):
        commands.update(str(name) for name in configured)

    packages = system_log.get("packages") or {}
    if isinstance(packages, dict):
        for package, metadata in packages.items():
            installed = bool(metadata.get("installed", True)) if isinstance(metadata, dict) else bool(metadata)
            if not installed:
                continue
            package_name = str(package)
            commands.update(PACKAGE_COMMANDS.get(package_name, set()))
            commands.add(package_name)
            if isinstance(metadata, dict) and isinstance(metadata.get("commands"), list):
                commands.update(str(name) for name in metadata["commands"])
    return commands


def _explicit_command_state(name: str, system_log: Dict[str, Any]) -> Optional[bool]:
    configured = system_log.get("installed_commands") or system_log.get("commands") or {}
    if isinstance(configured, dict) and name in configured:
        return bool(configured[name])

    packages = system_log.get("packages") or {}
    if not isinstance(packages, dict):
        return None
    for package, metadata in packages.items():
        supplied = set(PACKAGE_COMMANDS.get(str(package), set()))
        if isinstance(metadata, dict) and isinstance(metadata.get("commands"), list):
            supplied.update(str(item) for item in metadata["commands"])
        supplied.add(str(package))
        if name not in supplied:
            continue
        installed = bool(metadata.get("installed", True)) if isinstance(metadata, dict) else bool(metadata)
        return installed
    return None


def command_is_available(command: str, system_log: Dict[str, Any]) -> Optional[bool]:
    ensure_default_packages(system_log)
    name = primary_command_name(command)
    if not name:
        return None
    explicit = _explicit_command_state(name, system_log)
    if explicit is not None:
        return explicit
    if name in UBUNTU_BASE_COMMANDS or name in _dynamic_commands(system_log):
        return True
    return None


def known_command_names(system_log: Dict[str, Any]) -> list[str]:
    ensure_default_packages(system_log)
    names = set(UBUNTU_BASE_COMMANDS) | _dynamic_commands(system_log)
    configured = system_log.get("installed_commands") or system_log.get("commands") or {}
    if isinstance(configured, dict):
        names -= {name for name, present in configured.items() if not present}
    packages = system_log.get("packages") or {}
    if isinstance(packages, dict):
        for package, metadata in packages.items():
            if isinstance(metadata, dict) and not bool(metadata.get("installed", True)):
                names -= set(PACKAGE_COMMANDS.get(str(package), set()))
    return sorted(names)


def is_direct_exec_target(command: str) -> bool:
    tokens = command.strip().split(None, 1)
    return bool(tokens) and "/" in tokens[0]


def render_direct_exec(command: str, system_log: Dict[str, Any]) -> Optional[str]:
    tokens = command.strip().split(None, 1)
    if not tokens or "/" not in tokens[0]:
        return None
    target = tokens[0]

    kind, entry = resolve_path_kind(system_log, target)
    if kind == "missing":
        return f"bash: {target}: No such file or directory"
    if kind == "dir":
        return f"bash: {target}: Is a directory"

    mode = str((entry or {}).get("mode") or "-rw-r--r--")
    owner_x = len(mode) > 3 and mode[3] == "x"
    group_x = len(mode) > 6 and mode[6] == "x"
    other_x = len(mode) > 9 and mode[9] == "x"

    identity = system_log.get("identity") or {}
    current_uid = int(identity.get("euid", identity.get("uid", 1000)) or 1000)
    file_uid = int((entry or {}).get("uid", 1000) or 1000)

    if current_uid == 0:
        executable = owner_x or group_x or other_x
    elif current_uid == file_uid:
        executable = owner_x
    else:
        executable = other_x

    if not executable:
        return f"bash: {target}: Permission denied"
    return None


def classify_known_ubuntu_command(command: str, system_log: Dict[str, Any]) -> Optional[str]:
    if is_direct_exec_target(command):
        return "read"
    available = command_is_available(command, system_log)
    if available is False:
        return "rejection"
    if available is not True:
        return None
    if re.match(r"^\s*su\b", command) or re.match(
        r"^\s*sudo\s+(?:-\S+\s+)*(?:-i|-s|--login|--shell|su)\b", command
    ):
        return "write"
    normalized = re.sub(r"^\s*sudo(?:\s+-\S+)*\s+", "", command, count=1)
    if primary_command_name(normalized) == "find":
        return "write" if re.search(r"(?:^|\s)-(?:delete|exec|execdir|ok|okdir)(?:\s|$)", normalized) else "read"
    if any(re.search(pattern, normalized) for pattern in WRITE_PATTERNS):
        return "write"
    if primary_command_name(normalized) in OPTION_DEPENDENT_WRITE_COMMANDS:
        return "write"
    return "read"
