
from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from tools.ubuntu_ls import resolve_path_kind


def is_touch_command(command: str) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    return bool(tokens) and tokens[0] == "touch"


def _normalize_path(cwd: str, target: str, home: str) -> str:
    if target == "~":
        target = home
    elif target.startswith("~/"):
        target = home.rstrip("/") + target[1:]
    raw = target if target.startswith("/") else f"{cwd.rstrip('/')}/{target}"
    parts: List[str] = []
    for part in PurePosixPath(raw).parts:
        if part in {"", "/", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _parse_date(value: str) -> Optional[str]:
    text = value.strip()
    now = datetime.now(timezone.utc)
    if text.lower() == "now":
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if text.startswith("@"):
        try:
            return datetime.fromtimestamp(float(text[1:]), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError, OSError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _parse_stamp(value: str) -> Optional[str]:
    match = re.fullmatch(r"(?:(\d{2})?(\d{2}))?(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{2}))?", value)
    if not match:
        return None
    century, year, month, day, hour, minute, second = match.groups()
    current_year = datetime.now(timezone.utc).year
    if century is not None and year is not None:
        full_year = int(century) * 100 + int(year)
    elif year is not None:
        yy = int(year)
        full_year = 1900 + yy if yy >= 69 else 2000 + yy
    else:
        full_year = current_year
    try:
        parsed = datetime(
            full_year,
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second or 0),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _option_error(option: str, *, long: bool = False) -> Dict[str, Any]:
    if long:
        text = f"touch: unrecognized option '{option}'\nTry 'touch --help' for more information."
    else:
        text = f"touch: invalid option -- '{option}'\nTry 'touch --help' for more information."
    return {"terminal_output": text, "exit_status": 1, "mutations": []}


def _take_option_value(tokens: List[str], index: int, option: str) -> Tuple[Optional[str], int, Optional[Dict[str, Any]]]:
    if index + 1 >= len(tokens):
        return None, index, {
            "terminal_output": f"touch: option requires an argument -- '{option}'\nTry 'touch --help' for more information.",
            "exit_status": 1,
            "mutations": [],
        }
    return tokens[index + 1], index + 1, None


def plan_touch_command(command: str, system_log: Dict[str, Any]) -> Dict[str, Any]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return {"terminal_output": f"bash: syntax error: {exc}", "exit_status": 2, "mutations": []}
    if not tokens or tokens[0] != "touch":
        raise ValueError("touch tool received a different command")

    operands: List[str] = []
    no_create = False
    explicit_a = False
    explicit_m = False
    timestamp: Optional[str] = None
    reference: Optional[str] = None
    parsing_options = True
    index = 1

    while index < len(tokens):
        token = tokens[index]
        if parsing_options and token == "--":
            parsing_options = False
            index += 1
            continue
        if parsing_options and token.startswith("--"):
            if token == "--help":
                return {
                    "terminal_output": "Usage: touch [OPTION]... FILE...\nUpdate the access and modification times of each FILE to the current time.",
                    "exit_status": 0,
                    "mutations": [],
                }
            if token == "--version":
                return {"terminal_output": "touch (GNU coreutils) 8.32", "exit_status": 0, "mutations": []}
            if token in {"--no-create", "--no-dereference"}:
                no_create = no_create or token == "--no-create"
                index += 1
                continue
            if token.startswith("--date="):
                raw_date = token.split("=", 1)[1]
                timestamp = _parse_date(raw_date)
                if timestamp is None:
                    return {"terminal_output": f"touch: invalid date format '{raw_date}'", "exit_status": 1, "mutations": []}
                index += 1
                continue
            if token.startswith("--reference="):
                reference = token.split("=", 1)[1]
                index += 1
                continue
            if token.startswith("--time="):
                word = token.split("=", 1)[1]
                if word in {"atime", "access", "use"}:
                    explicit_a, explicit_m = True, False
                elif word in {"mtime", "modify"}:
                    explicit_a, explicit_m = False, True
                else:
                    return {"terminal_output": f"touch: invalid argument '{word}' for '--time'", "exit_status": 1, "mutations": []}
                index += 1
                continue
            return _option_error(token, long=True)

        if parsing_options and token.startswith("-") and token != "-":
            flags = token[1:]
            flag_index = 0
            while flag_index < len(flags):
                flag = flags[flag_index]
                if flag == "a":
                    explicit_a = True
                elif flag == "m":
                    explicit_m = True
                elif flag == "c":
                    no_create = True
                elif flag in {"f", "h"}:
                    pass
                elif flag in {"d", "r", "t"}:
                    attached = flags[flag_index + 1:]
                    if attached:
                        value = attached
                    else:
                        value, index, error = _take_option_value(tokens, index, flag)
                        if error is not None:
                            return error
                    if flag == "d":
                        timestamp = _parse_date(str(value))
                        if timestamp is None:
                            return {"terminal_output": f"touch: invalid date format '{value}'", "exit_status": 1, "mutations": []}
                    elif flag == "r":
                        reference = str(value)
                    else:
                        timestamp = _parse_stamp(str(value))
                        if timestamp is None:
                            return {"terminal_output": f"touch: invalid date format '{value}'", "exit_status": 1, "mutations": []}
                    flag_index = len(flags)
                    continue
                else:
                    return _option_error(flag)
                flag_index += 1
            index += 1
            continue

        operands.append(token)
        index += 1

    if not operands:
        return {
            "terminal_output": "touch: missing file operand\nTry 'touch --help' for more information.",
            "exit_status": 1,
            "mutations": [],
        }

    identity = system_log.get("identity") or {}
    home = str(identity.get("home") or "/home/user")
    cwd = str(system_log.get("cwd") or home)
    change_atime = explicit_a or not (explicit_a or explicit_m)
    change_mtime = explicit_m or not (explicit_a or explicit_m)

    reference_atime: Optional[str] = None
    reference_mtime: Optional[str] = None
    if reference is not None:
        kind, metadata = resolve_path_kind(system_log, reference)
        if kind == "missing" or metadata is None:
            return {
                "terminal_output": f"touch: failed to get attributes of '{reference}': No such file or directory",
                "exit_status": 1,
                "mutations": [],
            }
        reference_mtime = str(metadata.get("mtime") or metadata.get("dir_mtime") or "")
        reference_atime = str(metadata.get("atime") or metadata.get("dir_atime") or reference_mtime)

    mutations: List[Dict[str, Any]] = []
    errors: List[str] = []
    for operand in operands:
        absolute = _normalize_path(cwd, operand, home)
        kind, _ = resolve_path_kind(system_log, absolute)
        if kind == "missing":
            if no_create:
                continue
            parent = str(PurePosixPath(absolute).parent)
            parent_kind, _ = resolve_path_kind(system_log, parent)
            if parent_kind != "dir":
                errors.append(f"touch: cannot touch '{operand}': No such file or directory")
                continue
        mutation: Dict[str, Any] = {
            "op": "touch_path",
            "path": absolute,
            "create": not no_create,
            "access_time": change_atime,
            "modification_time": change_mtime,
        }
        if timestamp is not None:
            mutation["timestamp"] = timestamp
        if reference is not None:
            mutation["atime"] = reference_atime
            mutation["mtime"] = reference_mtime
        mutations.append(mutation)

    return {
        "terminal_output": "\n".join(errors),
        "exit_status": 1 if errors else 0,
        "mutations": mutations,
    }
