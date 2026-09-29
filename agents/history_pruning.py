from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from tools.common import sha1_text


SYSTEM_DIR_PREFIXES = (
    "/etc/", "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/var/", "/root/", "/boot/", "/opt/"
)

def is_system_path(path: str) -> bool:
    if not path.startswith("/"):
        return False
    if path in {"/etc", "/bin", "/usr", "/var", "/root"}:
        return True
    return any(path.startswith(p) for p in SYSTEM_DIR_PREFIXES)

def safe_join(parent: str, child: str) -> str:
    if parent.endswith("/"):
        parent = parent[:-1]
    if child.startswith("/"):
        return child
    return f"{parent}/{child}"



def _normalize_identity(identity: Any) -> Any:
    if not isinstance(identity, dict):
        return identity
    out = dict(identity)
    groups = out.get("groups")
    if isinstance(groups, list):
        out["groups"] = sorted(groups)
    return out

def _normalize_privilege(priv: Any) -> Any:
    if not isinstance(priv, dict):
        return priv
    out = dict(priv)
    caps = out.get("capabilities")
    if isinstance(caps, dict):
        caps2 = dict(caps)
        for k in ("effective", "permitted", "bounding"):
            if isinstance(caps2.get(k), list):
                caps2[k] = sorted(caps2[k])
        out["capabilities"] = caps2
    return out

def _normalize_network(net: Any) -> Any:
    if not isinstance(net, dict):
        return net
    out = dict(net)

    ports = out.get("listening_ports")
    if isinstance(ports, list):
        norm_ports = []
        for p in ports:
            if isinstance(p, dict):
                norm_ports.append({
                    "proto": p.get("proto"),
                    "ip": p.get("ip"),
                    "port": p.get("port"),
                    "process": p.get("process"),
                })
            else:
                norm_ports.append(p)
        norm_ports.sort(key=lambda x: (
            (x.get("proto") if isinstance(x, dict) else ""),
            (x.get("ip") if isinstance(x, dict) else ""),
            (x.get("port") if isinstance(x, dict) else -1),
            (x.get("process") if isinstance(x, dict) else ""),
        ))
        out["listening_ports"] = norm_ports

    return out


def flatten_filesystem(snapshot: Dict[str, Any]) -> Dict[str, str]:

    fs = snapshot.get("filesystem") or {}
    flat: Dict[str, str] = {}

    def file_sig(fname: str, file_contents: Dict[str, Any], file_meta: Dict[str, Any]) -> str:
        meta = file_meta.get(fname) if isinstance(file_meta, dict) else None
        if isinstance(meta, dict):
            h = meta.get("hash")
            size = meta.get("size")
            mtime = meta.get("mtime")
            if not h:
                content = (file_contents or {}).get(fname, "")
                h = sha1_text(content if isinstance(content, str) else str(content))
            return f"FILE|h={h}|sz={size}|mt={mtime}"
        content = (file_contents or {}).get(fname, "")
        h = sha1_text(content if isinstance(content, str) else str(content))
        return f"FILE|h={h}"

    def dir_sig(files: List[str], folders: Dict[str, Any]) -> str:
        f = sorted([x for x in files if isinstance(x, str)])
        d = sorted([k for k in folders.keys() if isinstance(k, str)]) if isinstance(folders, dict) else []
        return "DIR|" + "|".join([
            "files=" + ",".join(f),
            "dirs=" + ",".join(d),
        ])

    def walk_dir(abs_dir: str, node: Dict[str, Any]) -> None:
        files = node.get("files") or []
        folders = node.get("folders") or {}
        file_contents = node.get("file_contents") or {}
        file_meta = node.get("file_meta") or {}

        flat[abs_dir] = dir_sig(files, folders)

        for fname in files:
            if not isinstance(fname, str):
                continue
            fpath = safe_join(abs_dir, fname)
            flat[fpath] = file_sig(fname, file_contents, file_meta)

        if isinstance(folders, dict):
            for dname, dnode in folders.items():
                if not isinstance(dname, str):
                    continue
                dpath = safe_join(abs_dir, dname)
                if isinstance(dnode, dict):
                    walk_dir(dpath, dnode)
                else:
                    flat[dpath] = "DIR|files=|dirs="

    for root_dir, root_node in fs.items():
        if isinstance(root_dir, str) and isinstance(root_node, dict):
            walk_dir(root_dir, root_node)

    return flat


def extract_fs_perm_meta(snapshot: Dict[str, Any]) -> Dict[str, Tuple[str, int, int]]:
    fs = snapshot.get("filesystem") or {}
    out: Dict[str, Tuple[str, int, int]] = {}

    def walk_dir(abs_dir: str, node: Dict[str, Any]) -> None:
        dir_mode_octal = node.get("dir_mode_octal") or node.get("dir_mode") 
        dir_uid = node.get("dir_uid")
        dir_gid = node.get("dir_gid")
        if dir_mode_octal is not None and dir_uid is not None and dir_gid is not None:
            try:
                out[abs_dir] = (str(dir_mode_octal), int(dir_uid), int(dir_gid))
            except Exception:
                pass

        files = node.get("files") or []
        file_meta = node.get("file_meta") or {}

        if isinstance(file_meta, dict):
            for fname in files:
                if not isinstance(fname, str):
                    continue
                meta = file_meta.get(fname)
                if not isinstance(meta, dict):
                    continue
                mode_octal = meta.get("mode_octal")
                uid = meta.get("uid")
                gid = meta.get("gid")
                if mode_octal is None or uid is None or gid is None:
                    continue
                try:
                    out[safe_join(abs_dir, fname)] = (str(mode_octal), int(uid), int(gid))
                except Exception:
                    pass

        folders = node.get("folders") or {}
        if isinstance(folders, dict):
            for dname, dnode in folders.items():
                if not isinstance(dname, str):
                    continue
                dpath = safe_join(abs_dir, dname)
                if isinstance(dnode, dict):
                    walk_dir(dpath, dnode)

    for root_dir, root_node in fs.items():
        if isinstance(root_dir, str) and isinstance(root_node, dict):
            walk_dir(root_dir, root_node)

    return out



@dataclass
class StateDiff:
    perm_changed: bool = False
    persist_changed: bool = False
    net_changed: bool = False
    cfg_changed: bool = False


    cwd_changed: bool = False


    fs_created: List[str] = field(default_factory=list)
    fs_deleted: List[str] = field(default_factory=list)
    fs_modified: List[str] = field(default_factory=list)


    read_only: bool = True

    def has_any_persistent_change(self) -> bool:
        return (
            self.perm_changed
            or self.persist_changed
            or self.net_changed
            or self.cfg_changed
            or bool(self.fs_created or self.fs_deleted or self.fs_modified)
        )


def compute_state_diff(prev: Dict[str, Any], cur: Dict[str, Any]) -> StateDiff:
    d = StateDiff()

    prev_cwd = prev.get("cwd")
    cur_cwd = cur.get("cwd")
    if prev_cwd is not None or cur_cwd is not None:
        d.cwd_changed = (prev_cwd != cur_cwd)

    prev_id = _normalize_identity(prev.get("identity"))
    cur_id = _normalize_identity(cur.get("identity"))
    if (prev_id is not None or cur_id is not None) and prev_id != cur_id:
        d.perm_changed = True

    prev_priv = _normalize_privilege(prev.get("privilege"))
    cur_priv = _normalize_privilege(cur.get("privilege"))
    if (prev_priv is not None or cur_priv is not None) and prev_priv != cur_priv:
        d.perm_changed = True

    prev_perm = extract_fs_perm_meta(prev)
    cur_perm = extract_fs_perm_meta(cur)
    if prev_perm or cur_perm:

        if prev_perm != cur_perm:
            d.perm_changed = True

    prev_persist = prev.get("persistence")
    cur_persist = cur.get("persistence")
    if (prev_persist is not None or cur_persist is not None) and prev_persist != cur_persist:
        d.persist_changed = True


    prev_net = _normalize_network(prev.get("network"))
    cur_net = _normalize_network(cur.get("network"))
    if (prev_net is not None or cur_net is not None) and prev_net != cur_net:
        d.net_changed = True


    prev_cfg = prev.get("critical_configs")
    cur_cfg = cur.get("critical_configs")
    if (prev_cfg is not None or cur_cfg is not None) and prev_cfg != cur_cfg:
        d.cfg_changed = True

    prev_flat = flatten_filesystem(prev)
    cur_flat = flatten_filesystem(cur)

    prev_paths = set(prev_flat.keys())
    cur_paths = set(cur_flat.keys())

    d.fs_created = sorted(cur_paths - prev_paths)
    d.fs_deleted = sorted(prev_paths - cur_paths)

    modified: List[str] = []
    for p in sorted(prev_paths & cur_paths):
        if prev_flat[p] != cur_flat[p]:
            modified.append(p)
    d.fs_modified = modified


    d.read_only = not d.has_any_persistent_change()

 
    return d




def grade_from_diff(diff: StateDiff) -> int:

    if diff.read_only:
        return 0

    if diff.perm_changed or diff.persist_changed or diff.net_changed:
        return 3

    if diff.cfg_changed:
        return 2

    touched = diff.fs_created + diff.fs_deleted + diff.fs_modified
    if any(is_system_path(p) for p in touched):
        return 2

    if touched:
        return 1

    return 0



@dataclass
class InteractionEntry:
    t: int
    command: str
    response: str
    prev_snapshot: Dict[str, Any]
    cur_snapshot: Dict[str, Any]

    diff: StateDiff = field(init=False)
    grade: int = field(init=False)

    U_red: int = 0
    U_grade: int = 0
    U_stale: int = 0

    def __post_init__(self) -> None:
        self.diff = compute_state_diff(self.prev_snapshot, self.cur_snapshot)
        self.grade = grade_from_diff(self.diff)


def update_unimportance(context: List[InteractionEntry], current_t: int, G_max: int = 3) -> None:

    cmd_count: Dict[str, int] = {}
    for e in context:
        cmd_count[e.command] = cmd_count.get(e.command, 0) + 1

    for e in context:
        e.U_red = 1 if cmd_count.get(e.command, 0) >= 2 else 0
        e.U_grade = G_max - e.grade
        e.U_stale = current_t - e.t


def U_tuple(e: InteractionEntry) -> Tuple[int, int, int]:
    return (e.U_red, e.U_grade, e.U_stale)



class OnlinePruner:
    def __init__(self, K: int = 30, G_max: int = 3) -> None:
        self.K = K
        self.G_max = G_max
        self.H: List[InteractionEntry] = []
        self.W: List[InteractionEntry] = []

    def step(self, t: int, command: str, response: str, s_prev: Dict[str, Any], s_cur: Dict[str, Any]) -> None:
        e = InteractionEntry(
            t=t,
            command=command,
            response=response,
            prev_snapshot=copy.deepcopy(s_prev),
            cur_snapshot=copy.deepcopy(s_cur),
        )

        self.H.append(e)
        self.W.append(e)

        while len(self.W) > self.K:
            update_unimportance(self.W, current_t=t, G_max=self.G_max)
            worst = max(self.W, key=lambda x: (U_tuple(x), -x.t))
            self.W.remove(worst)
