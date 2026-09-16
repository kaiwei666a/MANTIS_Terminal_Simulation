
from __future__ import annotations

import re
import shlex
from typing import Dict, Optional

_MANUALS: Dict[str, Dict[str, str]] = {
    "ls": {
        "section": "1",
        "category": "User Commands",
        "name": "ls - list directory contents",
        "synopsis": "ls [OPTION]... [FILE]...",
        "description": (
            "List information about the FILEs (the current directory by default).\n"
            "Sort entries alphabetically if none of -cftuvSUX nor --sort is specified."
        ),
        "options": (
            "  -a, --all                  do not ignore entries starting with .\n"
            "  -l                         use a long listing format\n"
            "  -h, --human-readable       print sizes in human readable format\n"
            "  -r, --reverse              reverse order while sorting\n"
            "  -R, --recursive            list subdirectories recursively\n"
            "  -S                         sort by file size, largest first\n"
            "  -t                         sort by time, newest first"
        ),
    },
    "man": {
        "section": "1",
        "category": "Manual pager utils",
        "name": "man - an interface to the system reference manuals",
        "synopsis": "man [man options] [[section] page ...] ...",
        "description": "man is the system's manual pager. Each page argument is normally the name of a program, utility or function.",
        "options": "  -k, --apropos            search the short manual page descriptions\n  -f, --whatis             display short manual page descriptions",
    },
    "who": {
        "section": "1",
        "category": "User Commands",
        "name": "who - show who is logged on",
        "synopsis": "who [OPTION]... [ FILE | ARG1 ARG2 ]",
        "description": "Print information about users who are currently logged in.",
        "options": "  -a, --all                same as -b -d --login -p -r -t -T -u\n  -q, --count              all login names and number of users logged on",
    },
    "users": {
        "section": "1",
        "category": "User Commands",
        "name": "users - print the user names of users currently logged in",
        "synopsis": "users [OPTION]... [FILE]",
        "description": "Output who is currently logged in according to FILE. If FILE is not specified, use /var/run/utmp.",
        "options": "  --help                   display this help and exit\n  --version                output version information and exit",
    },
    "w": {
        "section": "1",
        "category": "User Commands",
        "name": "w - Show who is logged on and what they are doing.",
        "synopsis": "w [options] [user]",
        "description": "w displays information about the users currently on the machine and their processes.",
        "options": "  -h, --no-header          do not print the header\n  -s, --short              use the short format\n  -f, --from               toggle printing the remote hostname",
    },
    "touch": {
        "section": "1",
        "category": "User Commands",
        "name": "touch - change file timestamps",
        "synopsis": "touch [OPTION]... FILE...",
        "description": "Update the access and modification times of each FILE to the current time. A FILE argument that does not exist is created empty unless -c is supplied.",
        "options": (
            "  -a                         change only the access time\n"
            "  -c, --no-create           do not create any files\n"
            "  -d, --date=STRING         parse STRING and use it instead of current time\n"
            "  -m                         change only the modification time\n"
            "  -r, --reference=FILE      use this file's times instead of current time\n"
            "  -t STAMP                   use [[CC]YY]MMDDhhmm[.ss] instead of current time"
        ),
    },
}


_BUILTIN_SUMMARIES: Dict[str, str] = {
    "alias": "Define or display aliases.",
    "bg": "Move jobs to the background.",
    "cd": "Change the shell working directory.",
    "command": "Execute a simple command or display information about commands.",
    "echo": "Write arguments to the standard output.",
    "exit": "Exit the shell.",
    "export": "Set export attribute for shell variables.",
    "fg": "Move job to the foreground.",
    "help": "Display information about builtin commands.",
    "history": "Display or manipulate the history list.",
    "jobs": "Display status of jobs.",
    "printf": "Formats and prints ARGUMENTS under control of the FORMAT.",
    "pwd": "Print the name of the current working directory.",
    "read": "Read a line from the standard input and split it into fields.",
    "set": "Set or unset values of shell options and positional parameters.",
    "source": "Execute commands from a file in the current shell.",
    "test": "Evaluate conditional expression.",
    "type": "Display information about command type.",
    "ulimit": "Modify shell resource limits.",
    "umask": "Display or set file mode mask.",
    "unalias": "Remove each NAME from the list of defined aliases.",
    "unset": "Unset values and attributes of shell variables and functions.",
    "wait": "Wait for job completion and return exit status.",
}


def is_manual_or_help_command(command: str) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not tokens or tokens[0] not in {"man", "help", "whatis"}:
        return False

    args = tokens[1:]
    if not args:
        return True
    if args[0] in {"--help", "-h", "--version", "-V"}:
        return True

    if tokens[0] == "man":
        topic = args[1] if len(args) >= 2 and re.fullmatch(r"[0-9][A-Za-z]*", args[0]) else args[0]
        return topic in _MANUALS
    if tokens[0] == "whatis":
        return all(topic in _MANUALS for topic in args)
    if tokens[0] == "help":
        remaining = list(args)
        while remaining and remaining[0] in {"-d", "-m", "-s"}:
            remaining.pop(0)
        if not remaining:
            return True
        return remaining[0] in _BUILTIN_SUMMARIES
    return False


def _render_man_page(topic: str) -> str:
    page = _MANUALS.get(topic)
    if page is None:
        return f"No manual entry for {topic}"
    section = page["section"]
    title = f"{topic.upper()}({section})"
    lines = [
        f"{title:<28}{page['category']:^24}{title:>28}",
        "",
        "NAME",
        f"       {page['name']}",
        "",
        "SYNOPSIS",
        f"       {page['synopsis']}",
        "",
        "DESCRIPTION",
    ]
    lines.extend(f"       {line}" if line else "" for line in page["description"].splitlines())
    if page.get("options"):
        lines.extend(["", "OPTIONS"])
        lines.extend(f"       {line}" for line in page["options"].splitlines())
    lines.extend(["", f"Ubuntu 22.04                    {title}"])
    return "\n".join(lines)


def _render_man(tokens: list[str]) -> str:
    args = tokens[1:]
    if not args:
        return "What manual page do you want?"
    if args[0] in {"--help", "-h"}:
        return "Usage: man [OPTION...] [SECTION] PAGE..."
    if args[0] in {"--version", "-V"}:
        return "man 2.10.2"
    topic = args[1] if len(args) >= 2 and re.fullmatch(r"[0-9][A-Za-z]*", args[0]) else args[0]
    return _render_man_page(topic)


def _render_help(tokens: list[str]) -> str:
    args = tokens[1:]
    mode = "normal"
    while args and args[0] in {"-d", "-m", "-s"}:
        mode = {"-d": "description", "-m": "man", "-s": "synopsis"}[args.pop(0)]

    if not args:
        names = sorted(_BUILTIN_SUMMARIES)
        rows = [
            "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)",
            "These shell commands are defined internally.  Type `help' to see this list.",
        ]
        for index in range(0, len(names), 2):
            left = names[index]
            right = names[index + 1] if index + 1 < len(names) else ""
            left_text = f"{left} - {_BUILTIN_SUMMARIES[left]}"
            right_text = f"{right} - {_BUILTIN_SUMMARIES[right]}" if right else ""
            rows.append(f"{left_text:<40}{right_text}".rstrip())
        return "\n".join(rows)

    topic = args[0]
    summary = _BUILTIN_SUMMARIES.get(topic)
    if summary is None:
        return f"bash: help: no help topics match `{topic}'.  Try `help help' or `man -k {topic}' or `info {topic}'."
    if mode == "description":
        return summary
    synopsis = {
        "cd": "cd [-L|[-P [-e]] [-@]] [dir]",
        "help": "help [-dms] [pattern ...]",
        "echo": "echo [-neE] [arg ...]",
        "pwd": "pwd [-LP]",
        "export": "export [-fn] [name[=value] ...] or export -p",
        "unset": "unset [-f] [-v] [-n] [name ...]",
    }.get(topic, f"{topic} [arguments]")
    if mode == "synopsis":
        return synopsis
    if mode == "man":
        return "\n".join([topic.upper() + "(1)", "", "NAME", f"    {topic} - {summary}", "", "SYNOPSIS", f"    {synopsis}"])
    return "\n".join([f"{topic}: {synopsis}", f"    {summary}"])


def _render_whatis(tokens: list[str]) -> str:
    args = tokens[1:]
    if not args:
        return "whatis what?"
    if args[0] in {"--help", "-h"}:
        return "Usage: whatis [OPTION...] KEYWORD..."
    if args[0] in {"--version", "-V"}:
        return "whatis 2.10.2"

    lines = []
    for topic in args:
        page = _MANUALS.get(topic)
        if page is None:
            lines.append(f"{topic}: nothing appropriate.")
        else:
            lines.append(f"{topic} ({page['section']}) - {page['name'].split(' - ', 1)[-1]}")
    return "\n".join(lines)


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
