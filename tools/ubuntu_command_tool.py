from __future__ import annotations


from typing import Any, Dict

from tools.common import parse_exact_command_arguments


TOOL_NAME = "execute_ubuntu_command"

def tool_definition(command: str) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": (
                "Report the terminal output and exit status produced by executing the exact command "
                "using Ubuntu 22.04/GNU utility semantics. Parse all short, combined-short, long, "
                "attached-value and -- option forms before identifying operands. Call this tool "
                "exactly once. In the same turn, also call one of the mutation tools (write_file, "
                "touch_path, remove_path, make_directory, move_path, copy_path, change_mode, "
                "change_owner, set_cwd, set_service, set_listener, set_package, set_environment, "
                "set_process) once for every persistent effect the command actually produced, in "
                "execution order. Call no mutation tool when the command had no persistent effect."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": [command],
                        "description": "The original terminal command, byte-for-byte unchanged.",
                    },
                    "terminal_output": {
                        "type": "string",
                        "description": "Raw Ubuntu terminal output without a prompt or Markdown.",
                    },
                    "exit_status": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 255,
                    },
                },
                "required": ["command", "terminal_output", "exit_status"],
                "additionalProperties": False,
            },
        },
    }

def execute_tool_call(tool_name: str, arguments: str, original_command: str) -> Dict[str, Any]:
    if tool_name != TOOL_NAME:
        raise ValueError(f"unknown tool: {tool_name}")
    parsed = parse_exact_command_arguments(
        arguments,
        original_command,
        ("command", "terminal_output", "exit_status"),
    )
    return {
        "terminal_output": parsed["terminal_output"],
        "exit_status": parsed["exit_status"],
    }
