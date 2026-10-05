
from __future__ import annotations

import math
import re
import shlex
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

try:
    from zoneinfo import ZoneInfo
    _DISPLAY_TZ = ZoneInfo("America/New_York")
except Exception:
    _DISPLAY_TZ = timezone.utc


EXT4_BLOCK_BYTES = 4096
STAT_BLOCK_BYTES = 512
LS_BLOCK_BYTES = 1024
LEGACY_BASELINE_MTIME = datetime(2025, 12, 3, tzinfo=timezone.utc)

_SHELL_OPERATOR_TOKENS = {"|", "||", "&&", ";", "&", ">", ">>", "<", "<<"}

LS_HELP = """Usage: ls [OPTION]... [FILE]...
List information about the FILEs (the current directory by default).
Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

  -a, --all                  do not ignore entries starting with .
  -A, --almost-all           do not list implied . and ..
  -h, --human-readable       with -l, print sizes in human readable format
  -l                         use a long listing format
  -m                         fill width with a comma separated list of entries
  -Q, --quote-name           enclose entry names in double quotes
  -r, --reverse              reverse order while sorting
  -R, --recursive            list subdirectories recursively
  -S                         sort by file size, largest first
  -t                         sort by time, newest first
  -1                         list one file per line
      --help                 display this help and exit
      --version              output version information and exit"""


def allocated_blocks_512(size: int) -> int:
    size = max(0, int(size))
    if size == 0:
        return 0
    return math.ceil(size / EXT4_BLOCK_BYTES) * (EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES)


def _normalize_path(cwd: str, target: str, home: Optional[str] = None) -> str:
    if not target:
        target = "."
    if home and target == "~":
        target = home
    elif home and target.startswith("~/"):
        target = home.rstrip("/") + target[1:]
    raw = target if target.startswith("/") else f"{cwd.rstrip('/')}/{target}"
    parts: List[str] = []
    for part in PurePosixPath(raw).parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def _synthetic_home_root(filesystem: Dict[str, Any]) -> Dict[str, Any]:
    folders = {
        name: node
        for name, node in (
            (str(PurePosixPath(key).name), value)
            for key, value in filesystem.items()
            if isinstance(key, str) and isinstance(value, dict)
            and re.match(r"^/home/[^/]+$", key)
        )
    }
    return {
        "files": [],
        "folders": folders,
        "file_contents": {},
        "file_meta": {},
        "dir_mode": "drwxr-xr-x",
        "dir_mtime": LEGACY_BASELINE_MTIME.isoformat().replace("+00:00", "Z"),
        "dir_uid": 0,
        "dir_gid": 0,
        "dir_size": EXT4_BLOCK_BYTES,
        "dir_blocks": EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES,
    }


def _synthetic_filesystem_root(filesystem: Dict[str, Any]) -> Dict[str, Any]:
    folders: Dict[str, Any] = {}
    if any(isinstance(k, str) and re.match(r"^/home/[^/]+$", k) for k in filesystem):
        folders["home"] = _synthetic_home_root(filesystem)
    for name, path in (("root", "/root"), ("tmp", "/tmp")):
        node = filesystem.get(path)
        if isinstance(node, dict):
            folders[name] = node
    return {
        "files": [],
        "folders": folders,
        "file_contents": {},
        "file_meta": {},
        "dir_mode": "drwxr-xr-x",
        "dir_mtime": LEGACY_BASELINE_MTIME.isoformat().replace("+00:00", "Z"),
        "dir_uid": 0,
        "dir_gid": 0,
        "dir_size": EXT4_BLOCK_BYTES,
        "dir_blocks": EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES,
    }


def _find_dir(filesystem: Dict[str, Any], abs_path: str) -> Optional[Dict[str, Any]]:
    if abs_path == "/home":
        return _synthetic_home_root(filesystem)
    if abs_path == "/":
        return _synthetic_filesystem_root(filesystem)

    direct = filesystem.get(abs_path)
    if isinstance(direct, dict):
        return direct

    roots = sorted(
        (root for root, node in filesystem.items() if isinstance(root, str) and isinstance(node, dict)),
        key=len,
        reverse=True,
    )
    for root in roots:
        if not (abs_path == root or abs_path.startswith(root.rstrip("/") + "/")):
            continue
        node = filesystem[root]
        suffix = abs_path[len(root):].strip("/")
        if not suffix:
            return node
        for part in PurePosixPath(suffix).parts:
            folders = node.get("folders") or {}
            child = folders.get(part)
            if not isinstance(child, dict):
                return None
            node = child
        return node
    return None


def _find_entry(
    filesystem: Dict[str, Any], abs_path: str
) -> Optional[Tuple[str, Dict[str, Any], Optional[Dict[str, Any]]]]:
    directory = _find_dir(filesystem, abs_path)
    if directory is not None:
        return "dir", directory, None

    parent_path = str(PurePosixPath(abs_path).parent)
    parent = _find_dir(filesystem, parent_path)
    name = PurePosixPath(abs_path).name
    if parent is not None and name in (parent.get("files") or []):
        meta = (parent.get("file_meta") or {}).get(name) or {}
        return "file", meta, parent
    return None


def resolve_path_kind(system_log: Dict[str, Any], target: str) -> Tuple[str, Optional[Dict[str, Any]]]:
    filesystem = system_log.get("filesystem") or {}
    identity = system_log.get("identity") or {}
    cwd = str(system_log.get("cwd") or identity.get("home") or "/home/user")
    abs_path = _normalize_path(cwd, target, str(identity.get("home") or "/home/user"))
    found = _find_entry(filesystem, abs_path)
    if found is None:
        return "missing", None
    kind, payload, _ = found
    return kind, payload


def resolve_path_entry(
    system_log: Dict[str, Any], target: str
) -> Tuple[str, str, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    filesystem = system_log.get("filesystem") or {}
    identity = system_log.get("identity") or {}
    cwd = str(system_log.get("cwd") or identity.get("home") or "/home/user")
    absolute = _normalize_path(cwd, target, str(identity.get("home") or "/home/user"))
    found = _find_entry(filesystem, absolute)
    if found is None:
        return absolute, "missing", None, None
    kind, payload, parent = found
    return absolute, kind, payload, parent


def list_directory_entries(system_log: Dict[str, Any], target: str) -> Optional[List[Tuple[str, bool]]]:
    filesystem = system_log.get("filesystem") or {}
    identity = system_log.get("identity") or {}
    cwd = str(system_log.get("cwd") or identity.get("home") or "/home/user")
    abs_path = _normalize_path(cwd, target, str(identity.get("home") or "/home/user"))
    node = _find_dir(filesystem, abs_path)
    if node is None:
        return None
    folders = node.get("folders") or {}
    files = node.get("files") or []
    names = sorted(set(folders.keys()) | set(files))
    return [(name, name in folders) for name in names]


def format_name_columns(names: List[str], width: int = 80) -> str:
    return _format_columns(names, width=width)


def _uid_name(uid: int, identity: Dict[str, Any]) -> str:
    if uid == 0:
        return "root"
    if uid == int(identity.get("uid", 1000) or 1000):
        return str(identity.get("user") or uid)
    return str(uid)


def _gid_name(gid: int, identity: Dict[str, Any]) -> str:
    if gid == 0:
        return "root"
    if gid == int(identity.get("gid", 1000) or 1000):
        return str(identity.get("group") or identity.get("user") or gid)
    return str(gid)


def _parse_mtime(value: Any) -> datetime:
    text = str(value or "1970-01-01T00:00:00Z")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _effective_dir_mtime(node: Dict[str, Any]) -> datetime:
    own_mtime = _parse_mtime(node.get("dir_mtime"))
    candidates = [LEGACY_BASELINE_MTIME if own_mtime.year <= 1970 else own_mtime]
    for child in (node.get("folders") or {}).values():
        if isinstance(child, dict):
            candidates.append(_parse_mtime(child.get("dir_mtime")))
    for meta in (node.get("file_meta") or {}).values():
        if isinstance(meta, dict):
            candidates.append(_parse_mtime(meta.get("mtime")))
    return max(candidates)


def _format_mtime(value: datetime, now: datetime) -> str:
    value = value.astimezone(_DISPLAY_TZ)
    now = now.astimezone(_DISPLAY_TZ)
    age_seconds = (now - value).total_seconds()
    if age_seconds > 180 * 24 * 60 * 60 or age_seconds < -60 * 60:
        return value.strftime("%b %e  %Y")
    return value.strftime("%b %e %H:%M")


def _human_size(size: int) -> str:
    if size < 1024:
        return str(size)
    units = ["K", "M", "G", "T", "P"]
    value = float(size)
    for unit in units:
        value /= 1024.0
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f}{unit}" if value < 10 and not value.is_integer() else f"{value:.0f}{unit}"
    return str(size)


def _entry_from_dir(name: str, node: Dict[str, Any], identity: Dict[str, Any]) -> Dict[str, Any]:
    uid = int(node.get("dir_uid", 1000))
    gid = int(node.get("dir_gid", 1000))
    return {
        "name": name,
        "mode": str(node.get("dir_mode") or "drwxr-xr-x"),
        "nlink": 2 + len(node.get("folders") or {}),
        "owner": _uid_name(uid, identity),
        "group": _gid_name(gid, identity),
        "size": int(node.get("dir_size", EXT4_BLOCK_BYTES)),
        "blocks": int(node.get("dir_blocks", EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES)),
        "mtime": _effective_dir_mtime(node),
    }


def _entry_from_file(
    name: str, meta: Dict[str, Any], identity: Dict[str, Any]
) -> Dict[str, Any]:
    size = int(meta.get("size", 0))
    uid = int(meta.get("uid", 1000))
    gid = int(meta.get("gid", 1000))
    return {
        "name": name,
        "mode": str(meta.get("mode") or "-rw-r--r--"),
        "nlink": int(meta.get("nlink", 1)),
        "owner": _uid_name(uid, identity),
        "group": _gid_name(gid, identity),
        "size": size,
        "blocks": int(meta.get("blocks", allocated_blocks_512(size))),
        "mtime": _parse_mtime(meta.get("mtime")),
    }


def _synthetic_parent(abs_dir: str, identity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": "..",
        "mode": "drwxr-xr-x",
        "nlink": 3 if re.match(r"^/home/[^/]+$", abs_dir) else 2,
        "owner": "root",
        "group": "root",
        "size": EXT4_BLOCK_BYTES,
        "blocks": EXT4_BLOCK_BYTES // STAT_BLOCK_BYTES,
        "mtime": LEGACY_BASELINE_MTIME,
    }


def _directory_entries(
    filesystem: Dict[str, Any],
    abs_dir: str,
    node: Dict[str, Any],
    identity: Dict[str, Any],
    show_all: bool,
    almost_all: bool,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if show_all:
        entries.append(_entry_from_dir(".", node, identity))
        parent_path = str(PurePosixPath(abs_dir).parent)
        parent = _find_dir(filesystem, parent_path)
        entries.append(
            _entry_from_dir("..", parent, identity)
            if parent is not None
            else _synthetic_parent(abs_dir, identity)
        )

    folders = node.get("folders") or {}
    files = node.get("files") or []
    file_meta = node.get("file_meta") or {}
    names = sorted(set(folders.keys()) | set(files))
    for name in names:
        if name.startswith(".") and not (show_all or almost_all):
            continue
        if name in folders and isinstance(folders[name], dict):
            entries.append(_entry_from_dir(name, folders[name], identity))
        else:
            entries.append(_entry_from_file(name, file_meta.get(name) or {}, identity))
    return entries


def _format_columns(names: List[str], width: int = 80) -> str:
    if not names:
        return ""
    max_columns = max(1, width // max(1, max(len(name) for name in names) + 2))
    for columns in range(min(max_columns, len(names)), 0, -1):
        rows = math.ceil(len(names) / columns)
        widths: List[int] = []
        for column in range(columns):
            column_names = names[column * rows : min((column + 1) * rows, len(names))]
            widths.append(max((len(name) for name in column_names), default=0) + 2)
        if sum(widths) > width + 2:
            continue
        rendered: List[str] = []
        for row in range(rows):
            cells: List[str] = []
            for column in range(columns):
                index = column * rows + row
                if index >= len(names):
                    continue
                value = names[index]
                cells.append(value if column == columns - 1 else value.ljust(widths[column]))
            rendered.append("".join(cells).rstrip())
        return "\n".join(rendered)
    return "\n".join(names)


def _format_commas(names: List[str], width: int = 80) -> str:
    lines: List[str] = []
    current = ""
    for index, name in enumerate(names):
        piece = name + (", " if index + 1 < len(names) else "")
        if current and len(current) + len(piece) > max(1, width):
            lines.append(current.rstrip())
            current = piece
        else:
            current += piece
    if current or not lines:
        lines.append(current.rstrip())
    return "\n".join(lines)


def _quoted_name(name: str) -> str:
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _sort_entries(entries: List[Dict[str, Any]], options: Dict[str, Any]) -> List[Dict[str, Any]]:
    if options["sort_time"]:
        ordered = sorted(entries, key=lambda entry: (-entry["mtime"].timestamp(), entry["name"]))
    elif options["sort_size"]:
        ordered = sorted(entries, key=lambda entry: (-int(entry["size"]), entry["name"]))
    else:
        ordered = sorted(entries, key=lambda entry: entry["name"])
    if options["reverse"]:
        ordered.reverse()
    return ordered


def _format_long(entries: List[Dict[str, Any]], human: bool, include_total: bool) -> str:
    now = datetime.now(timezone.utc)
    sizes = [_human_size(e["size"]) if human else str(e["size"]) for e in entries]
    nlink_width = max([1, *(len(str(e["nlink"])) for e in entries)])
    owner_width = max([1, *(len(e["owner"]) for e in entries)])
    group_width = max([1, *(len(e["group"]) for e in entries)])
    size_width = max([1, *(len(size) for size in sizes)])
    lines: List[str] = []
    if include_total:
        blocks_512 = sum(int(e["blocks"]) for e in entries)
        total_kib = math.ceil((blocks_512 * STAT_BLOCK_BYTES) / LS_BLOCK_BYTES)
        lines.append(f"total {_human_size(total_kib * LS_BLOCK_BYTES) if human else total_kib}")
    for entry, size in zip(entries, sizes):
        lines.append(
            f"{entry['mode']} {entry['nlink']:>{nlink_width}} "
            f"{entry['owner']:<{owner_width}} {entry['group']:<{group_width}} {size:>{size_width}} "
            f"{_format_mtime(entry['mtime'], now)} {entry['name']}"
        )
    return "\n".join(lines)


def _parse_options(tokens: List[str]) -> Tuple[Optional[Dict[str, Any]], List[str], Optional[str]]:
    options: Dict[str, Any] = {
        "all": False,
        "almost_all": False,
        "long": False,
        "human": False,
        "one": False,
        "directory": False,
        "comma": False,
        "quote": False,
        "reverse": False,
        "recursive": False,
        "sort_size": False,
        "sort_time": False,
        "help": False,
        "version": False,
    }
    targets: List[str] = []
    parsing_options = True
    short_map = {
        "a": "all", "A": "almost_all", "l": "long", "h": "human",
        "1": "one", "d": "directory", "m": "comma", "Q": "quote",
        "r": "reverse", "R": "recursive", "S": "sort_size", "t": "sort_time",
    }
    deferred_short = set("BbCcDfgGHiIkLnopqsuTUvwXxZ")
    long_map = {
        "--all": "all",
        "--almost-all": "almost_all",
        "--human-readable": "human",
        "--directory": "directory",
        "--quote-name": "quote",
        "--recursive": "recursive",
        "--reverse": "reverse",
        "--help": "help",
        "--version": "version",
    }
    deferred_long_exact = {
        "--author", "--escape", "--ignore-backups", "--inode", "--kibibytes",
        "--literal", "--numeric-uid-gid", "--size", "--zero", "--classify", "--file-type",
        "--group-directories-first", "--hide-control-chars", "--show-control-chars",
        "--full-time", "--si",
    }
    deferred_long_prefixes = (
        "--block-size=", "--format=", "--hide=", "--hyperlink=", "--ignore=",
        "--indicator-style=", "--quoting-style=", "--sort=", "--time=",
        "--time-style=", "--tabsize=", "--width=",
    )
    for token in tokens:
        if parsing_options and token == "--":
            parsing_options = False
            continue
        if parsing_options and token.startswith("--"):
            if token.startswith("--color"):
                continue
            key = long_map.get(token)
            if key is None:
                if token in deferred_long_exact or token.startswith(deferred_long_prefixes):
                    return None, [], None
                return None, [], f"ls: unrecognized option '{token}'\nTry 'ls --help' for more information."
            options[key] = True
            continue
        if parsing_options and token.startswith("-") and token != "-":
            for flag in token[1:]:
                key = short_map.get(flag)
                if key is None:
                    if flag in deferred_short:
                        return None, [], None
                    return None, [], f"ls: invalid option -- '{flag}'\nTry 'ls --help' for more information."
                options[key] = True
            continue
        targets.append(token)
    return options, targets or ["."], None


def _format_directory_body(
    filesystem: Dict[str, Any],
    abs_path: str,
    node: Dict[str, Any],
    identity: Dict[str, Any],
    options: Dict[str, Any],
    width: int,
    is_tty: bool,
) -> Tuple[str, List[Dict[str, Any]]]:
    entries = _directory_entries(
        filesystem,
        abs_path,
        node,
        identity,
        options["all"],
        options["almost_all"],
    )
    entries = _sort_entries(entries, options)
    rendered_entries = entries
    if options["quote"]:
        rendered_entries = [dict(entry, name=_quoted_name(entry["name"])) for entry in entries]

    if options["long"]:
        body = _format_long(rendered_entries, options["human"], include_total=True)
    else:
        names = [entry["name"] for entry in rendered_entries]
        if options["comma"]:
            body = _format_commas(names, width=width)
        elif options["one"] or not is_tty:
            body = "\n".join(names)
        else:
            body = _format_columns(names, width=width)
    return body, entries


def _render_recursive_directory(
    filesystem: Dict[str, Any],
    abs_path: str,
    display_path: str,
    node: Dict[str, Any],
    identity: Dict[str, Any],
    options: Dict[str, Any],
    width: int,
    is_tty: bool,
) -> List[str]:
    body, entries = _format_directory_body(
        filesystem, abs_path, node, identity, options, width, is_tty
    )
    sections = [f"{display_path}:\n{body}"]
    folders = node.get("folders") or {}
    for entry in entries:
        name = entry["name"]
        if name in {".", ".."} or name not in folders or name.startswith(".") and not (options["all"] or options["almost_all"]):
            continue
        child = folders.get(name)
        if not isinstance(child, dict):
            continue
        child_abs = _normalize_path(abs_path, name)
        child_display = f"{display_path.rstrip('/')}/{name}" if display_path != "/" else f"/{name}"
        sections.extend(
            _render_recursive_directory(
                filesystem, child_abs, child_display, child, identity, options, width, is_tty
            )
        )
    return sections


def render_ls(
    command: str,
    system_log: Dict[str, Any],
    width: int = 80,
    is_tty: bool = True,
) -> Optional[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return f"bash: syntax error: {exc}"
    if not tokens or tokens[0] not in {"ls", "ll"}:
        return None
    if any(token in _SHELL_OPERATOR_TOKENS for token in tokens[1:]):
        return None
    if tokens[0] == "ll":
        tokens = ["ls", "-al", *tokens[1:]]

    options, targets, error = _parse_options(tokens[1:])
    if options is None:
        return error
    if options["help"]:
        return LS_HELP
    if options["version"]:
        return "ls (GNU coreutils) 8.32\nCopyright (C) 2020 Free Software Foundation, Inc."

    filesystem = system_log.get("filesystem") or {}
    identity = system_log.get("identity") or {}
    cwd = str(system_log.get("cwd") or identity.get("home") or "/home/user")
    chunks: List[str] = []
    errors: List[str] = []
    multiple = len(targets) > 1

    for target in targets:
        abs_path = _normalize_path(cwd, target, str(identity.get("home") or "/home/user"))
        found = _find_entry(filesystem, abs_path)
        if found is None:
            errors.append(f"ls: cannot access '{target}': No such file or directory")
            continue
        kind, payload, _ = found

        if kind == "file" or options["directory"]:
            name = target
            entry = (
                _entry_from_file(name, payload, identity)
                if kind == "file"
                else _entry_from_dir(name, payload, identity)
            )
            if options["quote"]:
                entry = dict(entry, name=_quoted_name(entry["name"]))
            body = _format_long([entry], options["human"], include_total=False) if options["long"] else entry["name"]
        elif options["recursive"]:
            display_path = target if target != "." else "."
            chunks.extend(
                _render_recursive_directory(
                    filesystem,
                    abs_path,
                    display_path,
                    payload,
                    identity,
                    options,
                    width,
                    is_tty,
                )
            )
            continue
        else:
            body, _ = _format_directory_body(
                filesystem, abs_path, payload, identity, options, width, is_tty
            )
        if multiple:
            body = f"{target}:\n{body}"
        chunks.append(body)

    output_parts = [*errors, *chunks]
    return "\n\n".join(part for part in output_parts if part != "")
