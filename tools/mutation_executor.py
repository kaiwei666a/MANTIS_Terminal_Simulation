from __future__ import annotations

import copy
import hashlib
import re
import shlex
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Protocol

from system_state import (
    ALLOWED_FS_ROOTS as _ALLOWED_FS_ROOTS,
    CRITICAL_CONFIG_PATHS as _CRITICAL_CFG_WHITELIST,
    DEFAULT_HOME as _DEFAULT_HOME,
    EXT4_BLOCK_BYTES as _EXT4_BLOCK_BYTES,
    STAT_BLOCK_BYTES as _STAT_BLOCK_BYTES,
    allocated_blocks_512,
    apply_symbolic_chmod as _apply_symbolic_chmod,
    ensure_dir_node,
    ensure_file_meta,
    hydrate_snapshot,
    is_under_allowed_fs_roots,
    normalize_path,
    now_file_mtime,
    octal_from_mode_string as _octal_from_mode_string,
    resolve_dir,
    save_system_log,
    split_parent_child,
    utc_now_iso,
    mode_string_from_octal as _mode_string_from_octal,
)
from tools.common import sha1_text


class MutationHost(Protocol):
    system_log: Dict[str, Any]
    system_log_path: str
    last_handled_llm: bool
    session_id: str
    download_file_fetcher: Any
    download_git_fetcher: Any


class MutationExecutor:
    """Validate and apply mutation tool calls against a simulator host."""

    def __init__(self, host: MutationHost):
        self.host = host

    @property
    def system_log(self) -> Dict[str, Any]:
        return self.host.system_log

    @system_log.setter
    def system_log(self, value: Dict[str, Any]) -> None:
        self.host.system_log = value

    @property
    def session_id(self) -> str:
        return self.host.session_id

    @property
    def download_file_fetcher(self) -> Any:
        return self.host.download_file_fetcher

    @property
    def download_git_fetcher(self) -> Any:
        return self.host.download_git_fetcher

    def _emit(self, message: str) -> None:
        self.system_log["last_output"] = message

    def apply_plan(self, plan: Dict[str, Any]) -> int:
        if not isinstance(plan, dict):
            raise ValueError("write plan must be an object")
        output = plan.get("terminal_output", "")
        mutations = plan.get("mutations", [])
        exit_status = plan.get("exit_status", 1)
        if not isinstance(output, str) or len(output) > 65536:
            raise ValueError("invalid terminal_output")
        if not isinstance(exit_status, int) or not 0 <= exit_status <= 255:
            raise ValueError("invalid exit_status")
        if not isinstance(mutations, list) or len(mutations) > 32:
            raise ValueError("invalid mutations")

        before = copy.deepcopy(self.host.system_log)
        applied = 0
        identity = self.host.system_log.get("identity", {}) or {}
        home = str(identity.get("home") or _DEFAULT_HOME)
        cwd = str(self.host.system_log.get("cwd") or home)

        def absolute_path(value: Any, *, allow_critical: bool = False) -> str:
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError("invalid mutation path")
            path = normalize_path(cwd, value, home=home)
            if is_under_allowed_fs_roots(path):
                return path
            if allow_critical and path in _CRITICAL_CFG_WHITELIST:
                return path
            raise ValueError(f"mutation path outside simulated roots: {path}")

        def write_file(path: str, content: str, append: bool, mode: Optional[str]) -> None:
            if len(content.encode("utf-8", errors="ignore")) > 1024 * 1024:
                raise ValueError("simulated file content exceeds 1 MiB")
            if path in _CRITICAL_CFG_WHITELIST:
                previous = self.host.system_log["critical_configs"]["files"].get(path, {})
                previous_hash = str(previous.get("hash") or "")
                material = previous_hash + content if append else content
                self.host.system_log["critical_configs"]["files"][path] = {
                    "hash": sha1_text(material),
                    "mode_octal": str(mode or previous.get("mode_octal") or "0644"),
                    "uid": int(previous.get("uid", 0) or 0),
                    "gid": int(previous.get("gid", 0) or 0),
                }
                return
            parent, name = split_parent_child(path)
            node = resolve_dir(self.host.system_log["filesystem"], parent, create=True)
            if node is None or not name:
                raise ValueError(f"cannot create simulated file: {path}")
            ensure_dir_node(node)
            created = name not in node["files"]
            if created:
                node["files"].append(name)
            previous_content = str(node["file_contents"].get(name, ""))
            new_content = previous_content + content if append else content
            node["file_contents"][name] = new_content
            meta = node["file_meta"].setdefault(name, {})
            ensure_file_meta(meta)
            meta.update({
                "uid": int(identity.get("euid", identity.get("uid", 1000)) or 0),
                "gid": int(identity.get("egid", identity.get("gid", 1000)) or 0),
                "mtime": now_file_mtime(),
                "size": len(new_content.encode("utf-8", errors="ignore")),
                "hash": sha1_text(new_content),
            })
            meta["blocks"] = allocated_blocks_512(int(meta["size"]))
            if mode is not None and re.fullmatch(r"0?[0-7]{3}", str(mode)):
                meta["mode_octal"] = str(mode).zfill(4)
            if created:
                node["dir_mtime"] = meta["mtime"]

        def _mut_write_file(mutation: Dict[str, Any]) -> None:
            path = absolute_path(mutation.get("path"), allow_critical=True)
            content = mutation.get("content", "")
            if not isinstance(content, str):
                raise ValueError("write_file content must be a string")
            write_file(path, content, bool(mutation.get("append", False)), mutation.get("mode"))

        def _mut_touch_path(mutation: Dict[str, Any]) -> Optional[bool]:
            path = absolute_path(mutation.get("path"))
            create = bool(mutation.get("create", True))
            change_atime = bool(mutation.get("access_time", True))
            change_mtime = bool(mutation.get("modification_time", True))
            supplied_timestamp = mutation.get("timestamp")
            if supplied_timestamp is not None and not isinstance(supplied_timestamp, str):
                raise ValueError("invalid touch timestamp")
            for time_key in ("timestamp", "atime", "mtime"):
                time_value = mutation.get(time_key)
                if time_value is None:
                    continue
                if not isinstance(time_value, str):
                    raise ValueError(f"invalid touch {time_key}")
                try:
                    parsed_time = datetime.fromisoformat(time_value.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError(f"invalid touch {time_key}") from exc
                if parsed_time.tzinfo is None:
                    raise ValueError(f"touch {time_key} must include a timezone")
            timestamp = str(supplied_timestamp or now_file_mtime())

            directory = resolve_dir(self.host.system_log["filesystem"], path, create=False)
            if directory is not None:
                ensure_dir_node(directory)
                if change_atime:
                    directory["dir_atime"] = str(mutation.get("atime") or timestamp)
                if change_mtime:
                    directory["dir_mtime"] = str(mutation.get("mtime") or timestamp)
                return None
            parent, name = split_parent_child(path)
            node = resolve_dir(self.host.system_log["filesystem"], parent, create=False)
            if node is None or not name:
                raise ValueError(f"cannot touch simulated file: {path}")
            ensure_dir_node(node)
            exists = name in node["files"]
            if not exists and not create:
                return False
            if not exists:
                node["files"].append(name)
                node["file_contents"][name] = ""
            meta = node["file_meta"].setdefault(name, {})
            ensure_file_meta(meta)
            created_at = now_file_mtime()
            if not exists:
                meta["atime"] = str(mutation.get("atime") or supplied_timestamp or created_at)
                meta["mtime"] = str(mutation.get("mtime") or supplied_timestamp or created_at)
                node["dir_mtime"] = created_at
            else:
                if change_atime:
                    meta["atime"] = str(mutation.get("atime") or timestamp)
                if change_mtime:
                    meta["mtime"] = str(mutation.get("mtime") or timestamp)
            return None

        def _mut_remove_path(mutation: Dict[str, Any]) -> None:
            path = absolute_path(mutation.get("path"), allow_critical=True)
            if path in _CRITICAL_CFG_WHITELIST:
                self.update_critical_cfg(path, "")
            elif bool(mutation.get("recursive", False)):
                self.apply_rm_recursive(path, force=True)
            elif resolve_dir(self.host.system_log["filesystem"], path, create=False) is not None:
                error = self.apply_rmdir(path)
                if error:
                    raise ValueError(error.strip())
            else:
                self.apply_rm(path)

        def _mut_make_directory(mutation: Dict[str, Any]) -> None:
            self.apply_mkdir(absolute_path(mutation.get("path")))

        def _mut_move_path(mutation: Dict[str, Any]) -> None:
            self.apply_mv(
                absolute_path(mutation.get("source")),
                absolute_path(mutation.get("destination")),
            )

        def _mut_copy_path(mutation: Dict[str, Any]) -> None:
            source = absolute_path(mutation.get("source"))
            destination = absolute_path(mutation.get("destination"))
            if bool(mutation.get("recursive", False)):
                self.apply_cp_r(source, destination)
            else:
                self.apply_cp(source, destination)

        def _mut_change_mode(mutation: Dict[str, Any]) -> None:
            mode = str(mutation.get("mode") or "")
            if not re.fullmatch(
                r"(?:0?[0-7]{3}|[ugoa]*[+\-=][rwxXst]+(?:,[ugoa]*[+\-=][rwxXst]+)*)",
                mode,
            ):
                raise ValueError("invalid chmod mode")
            normalized_mode = mode[-3:] if re.fullmatch(r"0?[0-7]{3}", mode) else mode
            self.apply_chmod(normalized_mode, absolute_path(mutation.get("path"), allow_critical=True))

        def _mut_change_owner(mutation: Dict[str, Any]) -> None:
            user = str(mutation.get("user") or "")
            group = mutation.get("group")
            if not user or (group is not None and not isinstance(group, str)):
                raise ValueError("invalid owner")
            self.apply_chown(user, group, absolute_path(mutation.get("path"), allow_critical=True))

        def _mut_set_cwd(mutation: Dict[str, Any]) -> None:
            path = absolute_path(mutation.get("path"))
            error = self.apply_cd(path)
            if error:
                raise ValueError(error.strip())

        def _mut_set_service(mutation: Dict[str, Any]) -> None:
            name = str(mutation.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", name):
                raise ValueError("invalid service name")
            self.apply_systemctl("enable" if bool(mutation.get("enabled")) else "disable", name)

        def _mut_set_listener(mutation: Dict[str, Any]) -> None:
            port = int(mutation.get("port", 0) or 0)
            protocol = str(mutation.get("protocol") or "tcp").lower()
            if not 1 <= port <= 65535 or protocol not in {"tcp", "udp"}:
                raise ValueError("invalid listener")
            listeners = self.host.system_log.setdefault("network", {}).setdefault("listening_ports", [])
            listeners[:] = [
                item for item in listeners
                if not (int(item.get("port", -1)) == port and str(item.get("proto")) == protocol)
            ]
            if bool(mutation.get("present", True)):
                listeners.append({
                    "proto": protocol,
                    "ip": "0.0.0.0",
                    "port": port,
                    "pid": 9999,
                    "process": str(mutation.get("process") or "unknown")[:128],
                })

        def _mut_set_package(mutation: Dict[str, Any]) -> None:
            name = str(mutation.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9.+-]{1,128}", name):
                raise ValueError("invalid package name")
            packages = self.host.system_log.setdefault("packages", {})
            commands = mutation.get("commands", [])
            if not isinstance(commands, list) or len(commands) > 128:
                raise ValueError("invalid package commands")
            safe_commands = []
            for command_name in commands:
                command_name = str(command_name)
                if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", command_name):
                    raise ValueError("invalid package command")
                safe_commands.append(command_name)
            if bool(mutation.get("installed", True)):
                packages[name] = {
                    "version": str(mutation.get("version") or "latest"),
                    "installed": True,
                    "commands": safe_commands,
                }
            else:
                packages[name] = {
                    "version": str(mutation.get("version") or ""),
                    "installed": False,
                    "commands": safe_commands,
                }

        def _mut_set_environment(mutation: Dict[str, Any]) -> None:
            name = str(mutation.get("name") or "")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                raise ValueError("invalid environment variable")
            environment = self.host.system_log.setdefault("environment", {})
            if bool(mutation.get("present", True)):
                environment[name] = str(mutation.get("value") or "")[:65536]
            else:
                environment.pop(name, None)

        def _mut_set_process(mutation: Dict[str, Any]) -> None:
            pid = int(mutation.get("pid", 0) or 0)
            if not 1 <= pid <= 4194304:
                raise ValueError("invalid process pid")
            processes = self.host.system_log.setdefault("processes", [])
            processes[:] = [item for item in processes if int(item.get("pid", -1)) != pid]
            if bool(mutation.get("present", True)):
                processes.append({
                    "pid": pid,
                    "user": str(mutation.get("user") or identity.get("user") or "user")[:32],
                    "pr": 20,
                    "ni": 0,
                    "virt": "32m",
                    "res": "8m",
                    "shr": "4m",
                    "state": str(mutation.get("state") or "S")[:1],
                    "%cpu": 0.0,
                    "%mem": 0.0,
                    "time_plus": "0:00.00",
                    "cmd": str(mutation.get("command") or "unknown")[:256],
                })

        mutation_handlers: Dict[str, Callable[[Dict[str, Any]], Optional[bool]]] = {
            "write_file": _mut_write_file,
            "touch_path": _mut_touch_path,
            "remove_path": _mut_remove_path,
            "make_directory": _mut_make_directory,
            "move_path": _mut_move_path,
            "copy_path": _mut_copy_path,
            "change_mode": _mut_change_mode,
            "change_owner": _mut_change_owner,
            "set_cwd": _mut_set_cwd,
            "set_service": _mut_set_service,
            "set_listener": _mut_set_listener,
            "set_package": _mut_set_package,
            "set_environment": _mut_set_environment,
            "set_process": _mut_set_process,
        }

        try:
            for mutation in mutations:
                if not isinstance(mutation, dict):
                    raise ValueError("mutation must be an object")
                op = str(mutation.get("op") or "")
                handler = mutation_handlers.get(op)
                if handler is None:
                    raise ValueError(f"unsupported mutation operation: {op}")
                if handler(mutation) is not False:
                    applied += 1

            self.host.system_log["last_output"] = output
            self.host.system_log["last_exit_status"] = exit_status
            self.host.system_log["timestamp"] = utc_now_iso()
            hydrate_snapshot(self.host.system_log)
            save_system_log(self.host.system_log_path, self.host.system_log)
            self.host.last_handled_llm = True
            return applied
        except Exception:
            self.host.system_log = before
            self.host.last_handled_llm = False
            raise

    def apply_command_local(self, cmd: str) -> bool:
        try:
            tokens = shlex.split(cmd)
        except Exception:
            tokens = cmd.split()
        if not tokens:
            return True

        if tokens[0] == "sudo" and len(tokens) == 2 and tokens[1] in ("-i", "-s", "--login", "--shell", "su"):
            identity = self.system_log["identity"]
            identity["user"] = "root"
            identity["uid"] = identity["euid"] = 0
            identity["gid"] = identity["egid"] = 0
            self._emit("root shell started\n")
            return True

        if tokens[0] == "su" and len(tokens) <= 2 and (len(tokens) == 1 or not tokens[1].startswith("-")):
            user = tokens[1] if len(tokens) >= 2 and not tokens[1].startswith("-") else "root"
            identity = self.system_log["identity"]
            identity["user"] = user
            new_id = 0 if user == "root" else 1000
            identity["uid"] = identity["euid"] = new_id
            identity["gid"] = identity["egid"] = new_id
            self._emit(f"switched user to {user}\n")
            return True

        if tokens[0] == "cd" and len(tokens) <= 2 and (
            len(tokens) == 1 or tokens[1] == "-" or not tokens[1].startswith("-")
        ):
            target = tokens[1] if len(tokens) == 2 else "~"
            self._emit(self.apply_cd(target))
            return True

        if tokens[0] == "mv" and len(tokens) == 3 and not any(token.startswith("-") for token in tokens[1:]):
            self.apply_mv(tokens[1], tokens[2])
            return True

        if tokens[0] == "cp" and len(tokens) == 4 and tokens[1] == "-r" and not any(
            token.startswith("-") for token in tokens[2:]
        ):
            self.apply_cp_r(tokens[2], tokens[3])
            return True
        if tokens[0] == "cp" and len(tokens) == 3 and not any(token.startswith("-") for token in tokens[1:]):
            self.apply_cp(tokens[1], tokens[2])
            return True

        if tokens[0] == "wget" and len(tokens) == 2 and not tokens[1].startswith("-"):
            self.apply_download("wget", cmd[len("wget"):])
            return True

        if tokens[0] == "systemctl" and len(tokens) == 3 and tokens[1] in {"enable", "disable"} and not tokens[2].startswith("-"):
            self.apply_systemctl(tokens[1], tokens[2])
            return True

        if tokens[0] in {"python", "python3"} and len(tokens) in {3, 4} and tokens[1:3] == ["-m", "http.server"] and (
            len(tokens) == 3 or tokens[3].isdigit()
        ):
            port = int(tokens[3]) if len(tokens) == 4 else 8000
            self.apply_open_port(port, process="python-http.server")
            self._emit(f"Serving HTTP on 0.0.0.0 port {port} ...\n")
            return True


        if len(tokens) in {3, 4} and tokens[0] == "git" and tokens[1] == "clone" and not tokens[2].startswith("-"):
            self.apply_git_clone(tokens)
            return True

        return False 



    def apply_cd(self, target: str) -> str:
        identity = self.system_log.get("identity", {}) or {}
        home = str(identity.get("home") or _DEFAULT_HOME)
        current = str(self.system_log.get("cwd", home) or home)
        display_target = target
        if target == "-":
            target = str(self.system_log.get("oldpwd") or "")
            if not target:
                return "bash: cd: OLDPWD not set\n"
        new_path = normalize_path(current, target, home=home)
        if new_path in ("/", "/home"):
            self.system_log["oldpwd"] = current
            self.system_log["cwd"] = new_path
            return f"{new_path}\n" if display_target == "-" else ""
        if not is_under_allowed_fs_roots(new_path):
            return f"bash: cd: {display_target}: No such file or directory\n"
        fs = self.system_log["filesystem"]
        node = resolve_dir(fs, new_path, create=False)
        if node is not None:
            self.system_log["oldpwd"] = current
            self.system_log["cwd"] = new_path
            return f"{new_path}\n" if display_target == "-" else ""

        parent, name = split_parent_child(new_path)
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is not None:
            ensure_dir_node(parent_node)
            if name in parent_node["files"]:
                return f"bash: cd: {display_target}: Not a directory\n"
        return f"bash: cd: {display_target}: No such file or directory\n"

    def _mark_dir_changed(self, abs_dir: str, timestamp: Optional[str] = None) -> None:
        node = resolve_dir(self.system_log["filesystem"], abs_dir, create=False)
        if node is not None:
            ensure_dir_node(node)
            node["dir_mtime"] = timestamp or now_file_mtime()

    def apply_mkdir(self, path: str) -> None:
        abs_dir = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_dir):
            return
        fs = self.system_log["filesystem"]
        existed = resolve_dir(fs, abs_dir, create=False) is not None
        node = resolve_dir(fs, abs_dir, create=True)
        if node is not None and not existed:
            timestamp = now_file_mtime()
            identity = self.system_log.get("identity", {}) or {}
            node["dir_mtime"] = timestamp
            node["dir_uid"] = int(identity.get("euid", identity.get("uid", 1000)) or 1000)
            node["dir_gid"] = int(identity.get("egid", identity.get("gid", 1000)) or 1000)
            node["dir_size"] = _EXT4_BLOCK_BYTES
            node["dir_blocks"] = _EXT4_BLOCK_BYTES // _STAT_BLOCK_BYTES
            parent, _ = split_parent_child(abs_dir)
            self._mark_dir_changed(parent, timestamp)

    def apply_rm(self, path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)

        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            self.update_critical_cfg(abs_path, "")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        node = resolve_dir(fs, parent, create=False)
        if node is None:
            return
        ensure_dir_node(node)
        removed = name in node["files"]
        if removed:
            node["files"].remove(name)
        node.get("file_contents", {}).pop(name, None)
        node.get("file_meta", {}).pop(name, None)
        if removed:
            node["dir_mtime"] = now_file_mtime()

    def apply_rm_recursive(self, path: str, force: bool = False) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_path):
            return
        if abs_path in _ALLOWED_FS_ROOTS:
            return
        fs = self.system_log["filesystem"]
        parent, name = split_parent_child(abs_path)
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None or not name:
            return
        ensure_dir_node(parent_node)
        if name in parent_node["folders"]:
            del parent_node["folders"][name]
            parent_node["dir_mtime"] = now_file_mtime()
            return
        if name in parent_node.get("files", []):
            parent_node["files"].remove(name)
            parent_node.get("file_contents", {}).pop(name, None)
            parent_node.get("file_meta", {}).pop(name, None)
            parent_node["dir_mtime"] = now_file_mtime()

    def apply_rmdir(self, path: str) -> str:
        abs_dir = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        if not is_under_allowed_fs_roots(abs_dir):
            return f"rmdir: failed to remove '{path}': Permission denied\n"
        if abs_dir in _ALLOWED_FS_ROOTS:
            return f"rmdir: failed to remove '{path}': Permission denied\n"
        fs = self.system_log["filesystem"]
        parent, name = split_parent_child(abs_dir)
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None or not name:
            return f"rmdir: failed to remove '{path}': No such file or directory\n"
        ensure_dir_node(parent_node)
        if name in parent_node["files"]:
            return f"rmdir: failed to remove '{path}': Not a directory\n"
        sub = parent_node["folders"].get(name)
        if sub is None:
            return f"rmdir: failed to remove '{path}': No such file or directory\n"
        ensure_dir_node(sub)
        if sub["folders"] or sub["files"]:
            return f"rmdir: failed to remove '{path}': Directory not empty\n"

        del parent_node["folders"][name]
        parent_node["dir_mtime"] = now_file_mtime()
        return ""

    def apply_mv(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        fs = self.system_log["filesystem"]
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)


        if src_name in src_parent_node["files"]:
            content = src_parent_node["file_contents"].pop(src_name, "")
            meta = src_parent_node["file_meta"].pop(src_name, None)

            src_parent_node["files"].remove(src_name)


            if dst_name in dst_parent_node["files"]:
                dst_parent_node["files"].remove(dst_name)
                dst_parent_node["file_contents"].pop(dst_name, None)
                dst_parent_node["file_meta"].pop(dst_name, None)

            dst_parent_node["files"].append(dst_name)
            dst_parent_node["file_contents"][dst_name] = content
            if meta is None:
                meta = {}
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["blocks"] = allocated_blocks_512(meta["size"])
            meta["hash"] = sha1_text(content)
            dst_parent_node["file_meta"][dst_name] = meta
            return


        if src_name in src_parent_node["folders"]:
            if dst_name in dst_parent_node["folders"]:
                del dst_parent_node["folders"][dst_name]
            dst_parent_node["folders"][dst_name] = src_parent_node["folders"].pop(src_name)

    def apply_cp(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        fs = self.system_log["filesystem"]
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)
        if src_name in src_parent_node["files"]:
            content = src_parent_node["file_contents"].get(src_name, "")
            if dst_name not in dst_parent_node["files"]:
                dst_parent_node["files"].append(dst_name)
            dst_parent_node["file_contents"][dst_name] = content
            meta = dst_parent_node["file_meta"].setdefault(dst_name, {})
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["blocks"] = allocated_blocks_512(meta["size"])
            meta["hash"] = sha1_text(content)

    def apply_cp_r(self, src: str, dst: str) -> None:
        src_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), src)
        dst_abs = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), dst)
        if not (is_under_allowed_fs_roots(src_abs) and is_under_allowed_fs_roots(dst_abs)):
            return
        fs = self.system_log["filesystem"]
        src_parent, src_name = split_parent_child(src_abs)
        dst_parent, dst_name = split_parent_child(dst_abs)
        src_parent_node = resolve_dir(fs, src_parent, create=False)
        dst_parent_node = resolve_dir(fs, dst_parent, create=True)
        if src_parent_node is None or dst_parent_node is None:
            return
        ensure_dir_node(src_parent_node)
        ensure_dir_node(dst_parent_node)
        if src_name in src_parent_node["folders"]:
            if dst_name not in dst_parent_node["folders"]:
                dst_parent_node["folders"][dst_name] = {}
            dst_dir = dst_parent_node["folders"][dst_name]
            ensure_dir_node(dst_dir)
            self.copy_dir_recursive(src_parent_node["folders"][src_name], dst_dir)
            return
        self.apply_cp(src, dst)

    def copy_dir_recursive(self, src_dir: Dict[str, Any], dst_dir: Dict[str, Any]) -> None:
        ensure_dir_node(src_dir)
        ensure_dir_node(dst_dir)
        for fname in src_dir.get("files", []):
            if fname not in dst_dir["files"]:
                dst_dir["files"].append(fname)
            content = src_dir.get("file_contents", {}).get(fname, "")
            dst_dir["file_contents"][fname] = content
            meta = dst_dir["file_meta"].setdefault(fname, {})
            ensure_file_meta(meta)
            meta["mtime"] = now_file_mtime()
            meta["size"] = len(content)
            meta["blocks"] = allocated_blocks_512(meta["size"])
            meta["hash"] = sha1_text(content)

        for subname, subnode in src_dir.get("folders", {}).items():
            if subname not in dst_dir["folders"]:
                dst_dir["folders"][subname] = {}
            self.copy_dir_recursive(subnode, dst_dir["folders"][subname])

    def apply_chmod(self, mode_expr: str, path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)
        is_numeric = bool(re.fullmatch(r"[0-7]{3,4}", mode_expr))

        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            cfg = self.system_log["critical_configs"]["files"].setdefault(abs_path, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})
            mode_octal = mode_expr if is_numeric else _octal_from_mode_string(
                _apply_symbolic_chmod(_mode_string_from_octal(cfg.get("mode_octal", "0644")), mode_expr)
            )
            cfg["mode_octal"] = mode_octal
            self._emit(f"(simulated) chmod {mode_expr} {abs_path}\n")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        directory = resolve_dir(self.system_log["filesystem"], abs_path, create=False)
        if directory is not None:
            ensure_dir_node(directory)
            if is_numeric:
                directory["dir_mode"] = _mode_string_from_octal(mode_expr, is_dir=True)
                directory["dir_mode_octal"] = mode_expr
            else:
                directory["dir_mode"] = _apply_symbolic_chmod(
                    str(directory.get("dir_mode") or "drwxr-xr-x"),
                    mode_expr,
                    is_dir=True,
                )
                directory["dir_mode_octal"] = _octal_from_mode_string(directory["dir_mode"])
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None:
            return
        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            return
        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        if is_numeric:
            mode_octal = mode_expr
            mode_str = _mode_string_from_octal(mode_octal)
        else:
            mode_str = _apply_symbolic_chmod(str(meta.get("mode") or "-rw-r--r--"), mode_expr)
            mode_octal = _octal_from_mode_string(mode_str)
        meta["mode"] = mode_str
        meta["mode_octal"] = mode_octal
        meta["mtime"] = now_file_mtime()

    def apply_chown(self, user: str, group: Optional[str], path: str) -> None:
        abs_path = normalize_path(self.system_log.get("cwd", _DEFAULT_HOME), path)


        uid = 0 if user == "root" else 1000
        gid = 0 if (group == "root") else 1000


        if abs_path in _CRITICAL_CFG_WHITELIST and not is_under_allowed_fs_roots(abs_path):
            cfg = self.system_log["critical_configs"]["files"].setdefault(abs_path, {"hash": "", "mode_octal": "0644", "uid": 0, "gid": 0})
            cfg["uid"] = uid
            cfg["gid"] = gid
            self._emit(f"(simulated) chown {user}:{group or ''} {abs_path}\n")
            return

        if not is_under_allowed_fs_roots(abs_path):
            return
        directory = resolve_dir(self.system_log["filesystem"], abs_path, create=False)
        if directory is not None:
            ensure_dir_node(directory)
            directory["dir_uid"] = uid
            directory["dir_gid"] = gid
            return
        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=False)
        if parent_node is None:
            return
        ensure_dir_node(parent_node)
        if name not in parent_node["files"]:
            return
        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["uid"] = uid
        meta["gid"] = gid
        meta["mtime"] = now_file_mtime()

    def apply_systemctl(self, action: str, unit: str) -> None:
        enabled = self.system_log["persistence"]["systemd"].setdefault("enabled_units", [])
        if action == "enable":
            if unit not in enabled:
                enabled.append(unit)
            self._emit(f"Created symlink /etc/systemd/system/multi-user.target.wants/{unit}.\n")
        else:
            if unit in enabled:
                enabled.remove(unit)
            self._emit(f"Removed symlink for {unit}.\n")

    def apply_open_port(self, port: int, process: str = "unknown") -> None:
        ports = self.system_log["network"].setdefault("listening_ports", [])

        for p in ports:
            if int(p.get("port", -1)) == port and p.get("proto") == "tcp":
                return
        ports.append({"proto": "tcp", "ip": "0.0.0.0", "port": port, "pid": 9999, "process": process})

    def update_critical_cfg(self, path: str, content: str) -> None:
        files = self.system_log["critical_configs"].setdefault("files", {})
        files[path] = {"hash": sha1_text(content), "mode_octal": "0644", "uid": 0, "gid": 0}

    def apply_download(self, tool: str, args_str: str) -> None:
        try:
            tokens = shlex.split(args_str)
        except ValueError:
            tokens = args_str.split()

        value_flags = {"-O", "--output-document"} if tool == "wget" else {"-o", "--output"}
        toggle_flags = {"-O", "--remote-name"} if tool == "curl" else set()

        url = None
        explicit_name = None
        remote_name_flag = False
        skip_next = False
        for index, token in enumerate(tokens):
            if skip_next:
                skip_next = False
                continue
            if token in value_flags:
                if index + 1 < len(tokens):
                    explicit_name = tokens[index + 1]
                    skip_next = True
                continue
            if token.startswith("--output-document="):
                explicit_name = token.split("=", 1)[1]
                continue
            if token.startswith("--output="):
                explicit_name = token.split("=", 1)[1]
                continue
            if token in toggle_flags or (tool == "curl" and re.fullmatch(r"-[A-Za-z]*O[A-Za-z]*", token)):
                remote_name_flag = True
                continue
            if token.startswith("-"):
                continue
            if url is None or "://" in token:
                url = token

        if not url:
            return

        if explicit_name:
            filename = PurePosixPath(explicit_name).name or "index.html"
        else:
            url_path = re.sub(r"^\w+://[^/]+", "", url)
            filename = PurePosixPath(url_path).name
            if not filename:
                filename = "index.html"
        if not (explicit_name or remote_name_flag or tool == "wget"):
            return

        cwd = self.system_log.get("cwd", _DEFAULT_HOME)
        abs_path = normalize_path(cwd, filename)
        if not is_under_allowed_fs_roots(abs_path):
            return

        parent, name = split_parent_child(abs_path)
        fs = self.system_log["filesystem"]
        parent_node = resolve_dir(fs, parent, create=True)
        if parent_node is None or not name:
            return
        ensure_dir_node(parent_node)

        real_result = None
        if self.download_file_fetcher is not None:
            try:
                real_result = self.download_file_fetcher(tool, url, name, self.session_id or "session")
            except Exception:
                real_result = None

        if real_result:
            name = real_result.get("name") or name
            size = int(real_result.get("size") or 0)
            digest = str(real_result.get("hash") or "")
        else:
            digest = hashlib.sha1(f"{url}:{name}".encode("utf-8", errors="ignore")).hexdigest()
            size = 512 + (int(digest[:8], 16) % 65024)

        if name not in parent_node["files"]:
            parent_node["files"].append(name)
        parent_node["file_contents"].pop(name, None)

        meta = parent_node["file_meta"].setdefault(name, {})
        ensure_file_meta(meta)
        meta["mode"] = "-rw-r--r--"
        meta["mode_octal"] = "0644"
        meta["uid"] = int((self.system_log.get("identity") or {}).get("uid", 1000) or 1000)
        meta["gid"] = int((self.system_log.get("identity") or {}).get("gid", 1000) or 1000)
        meta["mtime"] = now_file_mtime()
        meta["size"] = size
        meta["blocks"] = allocated_blocks_512(size)
        meta["hash"] = digest
        meta["source_url"] = url
        parent_node["dir_mtime"] = meta["mtime"]

    def apply_git_clone(self, tokens: List[str]) -> None:
        cwd = self.system_log.get("cwd", _DEFAULT_HOME)
        url = None
        dst_dir = None

        nonopts: List[str] = []
        for t in tokens[2:]:
            if t.startswith("-"):
                continue
            nonopts.append(t)
        if nonopts:
            url = nonopts[0]
            if len(nonopts) >= 2:
                dst_dir = nonopts[1]
        if not url:
            return

        if not dst_dir:
            base = PurePosixPath(url).name or "repo"
            if base.endswith(".git"):
                base = base[:-4] or "repo"
            dst_dir = base

        repo_abs = normalize_path(cwd, dst_dir)
        if not is_under_allowed_fs_roots(repo_abs):
            return

        repo_node = resolve_dir(self.system_log["filesystem"], repo_abs, create=True)
        if repo_node is None:
            return
        ensure_dir_node(repo_node)

        real_result = None
        if self.download_git_fetcher is not None:
            try:
                real_result = self.download_git_fetcher(url, dst_dir, self.session_id or "session")
            except Exception:
                real_result = None

        if real_result and real_result.get("entries"):
            identity = self.system_log.get("identity") or {}
            uid = int(identity.get("uid", 1000) or 1000)
            gid = int(identity.get("gid", 1000) or 1000)
            timestamp = now_file_mtime()
            for entry in real_result["entries"]:
                entry_name = str(entry.get("name") or "").strip()
                if not entry_name:
                    continue
                size_val = max(0, int(entry.get("size") or 0))
                if entry.get("is_dir"):
                    node = repo_node["folders"].setdefault(entry_name, {})
                    ensure_dir_node(node)
                    node["dir_mtime"] = timestamp
                    node["dir_uid"] = uid
                    node["dir_gid"] = gid
                    node["dir_size"] = size_val or _EXT4_BLOCK_BYTES
                    node["dir_blocks"] = allocated_blocks_512(size_val or _EXT4_BLOCK_BYTES)
                else:
                    if entry_name not in repo_node["files"]:
                        repo_node["files"].append(entry_name)
                    repo_node["file_contents"].pop(entry_name, None)
                    meta = repo_node["file_meta"].setdefault(entry_name, {})
                    ensure_file_meta(meta)
                    meta["mtime"] = timestamp
                    meta["uid"] = uid
                    meta["gid"] = gid
                    meta["size"] = size_val
                    meta["blocks"] = allocated_blocks_512(size_val)
            repo_node["dir_mtime"] = timestamp
            clone_output = str(real_result.get("clone_output") or "").strip("\n")
            if not clone_output:
                repo_name = PurePosixPath(repo_abs).name or "repo"
                clone_output = f"Cloning into '{repo_name}'...\ndone."
            self._emit(clone_output + "\n")
            return

        if "README.md" not in repo_node["files"]:
            repo_node["files"].append("README.md")
        repo_node["file_contents"]["README.md"] = f"# Simulated clone\n\nCloned from: {url}\nTime: {utc_now_iso()}\n"
        repo_node["file_meta"].setdefault("README.md", {})
        ensure_file_meta(repo_node["file_meta"]["README.md"])
        repo_node["file_meta"]["README.md"]["mtime"] = now_file_mtime()
        repo_node["file_meta"]["README.md"]["size"] = len(repo_node["file_contents"]["README.md"])
        repo_node["file_meta"]["README.md"]["hash"] = sha1_text(repo_node["file_contents"]["README.md"])

        if "main.py" not in repo_node["files"]:
            repo_node["files"].append("main.py")
        repo_node["file_contents"]["main.py"] = 'print("hello from cloned repo")\n'
        repo_node["file_meta"].setdefault("main.py", {})
        ensure_file_meta(repo_node["file_meta"]["main.py"])
        repo_node["file_meta"]["main.py"]["mtime"] = now_file_mtime()
        repo_node["file_meta"]["main.py"]["size"] = len(repo_node["file_contents"]["main.py"])
        repo_node["file_meta"]["main.py"]["hash"] = sha1_text(repo_node["file_contents"]["main.py"])

        if ".git" not in repo_node["folders"]:
            repo_node["folders"][".git"] = {"files": [], "folders": {}, "file_contents": {}, "file_meta": {}, "dir_mode": "drwxr-xr-x", "dir_mtime": now_file_mtime()}
        git_dir = repo_node["folders"][".git"]
        ensure_dir_node(git_dir)

        if "HEAD" not in git_dir["files"]:
            git_dir["files"].append("HEAD")
        git_dir["file_contents"]["HEAD"] = "ref: refs/heads/main\n"
        git_dir["file_meta"].setdefault("HEAD", {})
        ensure_file_meta(git_dir["file_meta"]["HEAD"])
        git_dir["file_meta"]["HEAD"]["mtime"] = now_file_mtime()
        git_dir["file_meta"]["HEAD"]["size"] = len(git_dir["file_contents"]["HEAD"])
        git_dir["file_meta"]["HEAD"]["hash"] = sha1_text(git_dir["file_contents"]["HEAD"])

        if "config" not in git_dir["files"]:
            git_dir["files"].append("config")
        git_dir["file_contents"]["config"] = f"[remote \"origin\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        git_dir["file_meta"].setdefault("config", {})
        ensure_file_meta(git_dir["file_meta"]["config"])
        git_dir["file_meta"]["config"]["mtime"] = now_file_mtime()
        git_dir["file_meta"]["config"]["size"] = len(git_dir["file_contents"]["config"])
        git_dir["file_meta"]["config"]["hash"] = sha1_text(git_dir["file_contents"]["config"])

        repo_name = PurePosixPath(repo_abs).name or "repo"
        self._emit(
            f"Cloning into '{repo_name}'...\n"
            "remote: Enumerating objects: 42, done.\n"
            "remote: Counting objects: 100% (42/42), done.\n"
            "remote: Compressing objects: 100% (26/26), done.\n"
            "Receiving objects: 100% (42/42), 8.12 KiB | 1.02 MiB/s, done.\n"
            "Resolving deltas: 100% (12/12), done.\n"
        )
