from __future__ import annotations

import json
from typing import Any, Dict, List

MUTATION_TOOL_NAMES: tuple = (
    "write_file",
    "touch_path",
    "remove_path",
    "make_directory",
    "move_path",
    "copy_path",
    "change_mode",
    "change_owner",
    "set_cwd",
    "set_service",
    "set_listener",
    "set_package",
    "set_environment",
    "set_process",
)

def _mutation_tool(
    name: str,
    description: str,
    properties: Dict[str, Any],
    required: List[str],
) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


def mutation_tool_definitions() -> List[Dict[str, Any]]:
    return [
        _mutation_tool(
            "write_file",
            "Create, overwrite, or append to a simulated file with the given content.",
            {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "append": {"type": "boolean"},
                "mode": {"type": "string", "description": "Octal file mode, e.g. '0644'."},
            },
            ["path", "content"],
        ),
        _mutation_tool(
            "touch_path",
            "Update (or create) a file or directory's access and/or modification time.",
            {
                "path": {"type": "string"},
                "create": {"type": "boolean"},
                "access_time": {"type": "boolean"},
                "modification_time": {"type": "boolean"},
                "timestamp": {"type": "string", "description": "ISO-8601 timestamp with timezone."},
                "atime": {"type": "string", "description": "ISO-8601 timestamp with timezone."},
                "mtime": {"type": "string", "description": "ISO-8601 timestamp with timezone."},
            },
            ["path"],
        ),
        _mutation_tool(
            "remove_path",
            "Delete a file or directory.",
            {
                "path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            ["path"],
        ),
        _mutation_tool(
            "make_directory",
            "Create a directory.",
            {
                "path": {"type": "string"},
                "parents": {"type": "boolean"},
            },
            ["path"],
        ),
        _mutation_tool(
            "move_path",
            "Move or rename a file or directory.",
            {
                "source": {"type": "string"},
                "destination": {"type": "string"},
            },
            ["source", "destination"],
        ),
        _mutation_tool(
            "copy_path",
            "Copy a file or directory.",
            {
                "source": {"type": "string"},
                "destination": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            ["source", "destination"],
        ),
        _mutation_tool(
            "change_mode",
            "Change a path's permission mode (chmod).",
            {
                "path": {"type": "string"},
                "mode": {
                    "type": "string",
                    "description": "Octal mode (e.g. '0755') or a symbolic mode (e.g. 'u+x').",
                },
            },
            ["path", "mode"],
        ),
        _mutation_tool(
            "change_owner",
            "Change a path's owning user and/or group (chown).",
            {
                "path": {"type": "string"},
                "user": {"type": "string"},
                "group": {"type": "string"},
            },
            ["path", "user"],
        ),
        _mutation_tool(
            "set_cwd",
            "Change the shell's current working directory (cd).",
            {"path": {"type": "string"}},
            ["path"],
        ),
        _mutation_tool(
            "set_service",
            "Enable or disable a systemd service.",
            {
                "name": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            ["name", "enabled"],
        ),
        _mutation_tool(
            "set_listener",
            "Add or remove a listening network port.",
            {
                "port": {"type": "integer"},
                "protocol": {"type": "string", "enum": ["tcp", "udp"]},
                "process": {"type": "string"},
                "present": {"type": "boolean"},
            },
            ["port"],
        ),
        _mutation_tool(
            "set_package",
            "Install or remove a package, or change its recorded version.",
            {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "installed": {"type": "boolean"},
                "commands": {"type": "array", "items": {"type": "string"}},
            },
            ["name"],
        ),
        _mutation_tool(
            "set_environment",
            "Set or unset an environment variable.",
            {
                "name": {"type": "string"},
                "value": {"type": "string"},
                "present": {"type": "boolean"},
            },
            ["name"],
        ),
        _mutation_tool(
            "set_process",
            "Add or remove a running process entry.",
            {
                "pid": {"type": "integer"},
                "user": {"type": "string"},
                "command": {"type": "string"},
                "state": {"type": "string"},
                "present": {"type": "boolean"},
            },
            ["pid"],
        ),
    ]

def parse_mutation_tool_call(tool_name: str, arguments: str) -> Dict[str, Any]:
    """Turn one mutation tool call into the {"op": <name>, ...args} shape
    apply_llm_write_plan expects, so its validation/apply code stays unchanged."""
    if tool_name not in MUTATION_TOOL_NAMES:
        raise ValueError(f"unknown mutation tool: {tool_name}")
    try:
        parsed = json.loads(arguments or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("mutation tool arguments are not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("mutation tool arguments must be an object")
    return {"op": tool_name, **parsed}
