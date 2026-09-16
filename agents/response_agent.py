from __future__ import annotations

import os
import re
import json
from typing import Any, Dict, List, Optional

from openai import OpenAI
from tools.ubuntu_help_tools import (
    is_manual_or_help_command,
    render_manual_or_help,
)

DEFAULT_RESPONSE_MODEL = os.getenv("RESPONSE_AGENT_MODEL", "gpt-5.4-mini")

MAX_NEW_TOKENS = int(os.getenv("RESPONSE_AGENT_MAX_NEW_TOKENS", "512"))
TOP_MAX_NEW_TOKENS = int(os.getenv("TOP_MAX_COMPLETION_TOKENS", "1600"))
TEMPERATURE = float(os.getenv("RESPONSE_AGENT_TEMPERATURE", "0.3"))
TOP_P = float(os.getenv("RESPONSE_AGENT_TOP_P", "0.95"))

DUMP_PROMPT = os.getenv("RESPONSE_AGENT_DUMP_PROMPT", "0").strip() == "1"
DUMP_PROMPT_PATH = os.getenv("RESPONSE_AGENT_DUMP_PROMPT_PATH", "response_agent_last_prompt.txt")


TRAIN_INSTRUCTION = (
    "You are a Linux OS terminal. Your task is to simulate exact CLI behavior. "
    "You must only respond with the terminal output enclosed in a single code block (```), "
    "with no explanations or additional text. Do not generate any commands yourself. "
    "For each user input, respond exactly as a real Linux terminal would, including errors "
    "or empty outputs when appropriate. For invalid or non-Linux commands, return the typical shell error. "
    "The system snapshot contains pre_snapshot and post_snapshot. pre_snapshot is the authoritative state "
    "immediately BEFORE command execution, and post_snapshot is the authoritative state immediately AFTER "
    "command execution. You MUST compare them to determine success or failure. A path absent before but "
    "present after was created successfully; a path present before but absent after was deleted successfully; "
    "and changed content or metadata means the modification succeeded. Never report 'File exists' merely "
    "because a newly created path appears in post_snapshot. The system snapshot's identity.hostname field is "
    "the machine's authoritative hostname; the 'hostname' command (no arguments, anywhere it appears, including "
    "inside chained/piped command lines) must print exactly that value on its own line and never an error. "
    "When planning advice states that an executable is installed, that inventory is authoritative and you "
    "must never respond with 'command not found' or an equivalent missing-executable error for it. "
    "The caller directly handles commands explicitly classified as rejection. Therefore, when this response "
    "agent is invoked, do not use 'command not found' simply because a valid Ubuntu command or option is "
    "unfamiliar; produce its normal Ubuntu 22.04 behavior from the supplied state. "
    "A file listed in a directory's 'files' array is real even when it has no matching entry in "
    "'file_contents' (or an empty one) -- this happens for files landed by a real download, upload, or git "
    "clone whose actual bytes were deliberately never captured into this snapshot. Never report such a file "
    "as missing or inaccessible; commands that read it (cat, head, less, ...) must synthesize plausible "
    "content consistent with its name, extension, and recorded size instead. "
    "Successful commands that normally print nothing "
    "must return an empty code block. For plain 'ls' without '-1', '-l', or '--format=single-column', render "
    "entries horizontally in terminal columns separated by at least two spaces, assuming an 80-column terminal. "
    "Do not put every entry on a separate line when the entries fit within 80 columns. Use one entry per line "
    "only for 'ls -1'; use one detailed record per line for 'ls -l' and 'ls -la'."
)


def init_client(api_key: Optional[str] = None) -> OpenAI:
    key = api_key or os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE"
    return OpenAI(api_key=key)


def _json_compact(obj: Any, limit: int = 20000) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        s = str(obj)
    if len(s) > limit:
        return s[:limit] + "...<truncated>"
    return s


def _extract_code_block(text: Optional[str]) -> str:
    if text is None:
        return ""

    s = text.strip()

    m = re.search(r"```[^\n]*\n?(.*?)```", s, flags=re.DOTALL)
    if m:
        inner = m.group(1)
        if inner.startswith("\n"):
            inner = inner[1:]
        return inner

    if s.startswith("```"):
        s2 = re.sub(r"^\s*```[^\n]*\n?", "", s)
        return s2

    return s


def _build_messages(
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
) -> List[Dict[str, str]]:


    if isinstance(system_log, dict) and "pre_snapshot" in system_log:
        pre_snapshot = system_log.get("pre_snapshot") or {}
        post_snapshot = {k: v for k, v in system_log.items() if k != "pre_snapshot"}
        snapshot_transition = {
            "pre_snapshot": pre_snapshot,
            "post_snapshot": post_snapshot,
        }
    else:
        snapshot_transition = {
            "pre_snapshot": system_log,
            "post_snapshot": system_log,
        }

    user_prompt = (
        f"{command}\n\n"
        f"(Planning advice / constraints): {planning_advice}\n"
        f"(Recent command history): {_json_compact(session_log)}\n"
        f"(System snapshot transition): {_json_compact(snapshot_transition)}\n"
    )

    return [
        {"role": "system", "content": TRAIN_INSTRUCTION},
        {"role": "user", "content": user_prompt},
    ]


def _generate_gpt(
    client: OpenAI,
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
    model: Optional[str] = None,
) -> str:
    if is_manual_or_help_command(command):
        rendered = render_manual_or_help(command)
        if rendered is not None:
            return rendered
    messages = _build_messages(command, planning_advice, session_log, system_log)

    if DUMP_PROMPT:
        try:
            with open(DUMP_PROMPT_PATH, "w", encoding="utf-8") as f:
                f.write(json.dumps(messages, ensure_ascii=False, indent=2))
        except Exception:
            pass

    request: Dict[str, Any] = dict(
        model=model or DEFAULT_RESPONSE_MODEL,
        messages=messages,
        store=True,
        reasoning_effort="none",
        temperature=TEMPERATURE,
        top_p=TOP_P,
        max_completion_tokens=MAX_NEW_TOKENS,
    )
    resp = client.chat.completions.create(**request)

    message = resp.choices[0].message
    raw = (message.content or "").strip()
    return _extract_code_block(raw)


def render_response(
    command: str,
    planning_advice: str,
    session_log: Any,
    system_log: Any,
    client: Optional[OpenAI] = None,
    model: Optional[str] = None,
) -> str:
    c = client or init_client()
    return _generate_gpt(
        client=c,
        command=command,
        planning_advice=planning_advice,
        session_log=session_log,
        system_log=system_log,
        model=model,
    )


def render_top_response(
    top_state: Dict[str, Any],
    terminal_width: int = 80,
    terminal_height: int = 24,
    client: Optional[OpenAI] = None,
    model: Optional[str] = None,
) -> str:
    """Ask the model to turn measured state into a full-screen top frame."""
    width = max(20, int(terminal_width or 80))
    height = max(8, int(terminal_height or 24))
    process_rows = max(1, height - 7)
    messages = [
        {
            "role": "developer",
            "content": (
                "Render one realistic Ubuntu 22.04 top screen as raw terminal text. "
                f"The screen is {width} columns by {height} rows. Return exactly {height} lines: "
                "five summary lines, one blank line, one process header, then "
                f"exactly {process_rows} process rows. Never use Markdown or ANSI escape sequences. "
                "Use the supplied clock, uptime, load, CPU and memory values without changing them. "
                "Keep every supplied process and its supplied values. If more rows are needed, fill them "
                "with distinct, realistic low-activity Ubuntu background processes that fit the simulated "
                "host; use unique positive PIDs and make the Tasks counts consistent with the completed "
                "process list. Do not leave blank process rows. Clip each line to the requested width."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "terminal": {"width": width, "height": height},
                    "top_state": top_state,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        },
    ]
    c = client or init_client()
    resp = c.chat.completions.create(
        model=model or DEFAULT_RESPONSE_MODEL,
        messages=messages,
        store=False,
        reasoning_effort="none",
        temperature=0.2,
        top_p=TOP_P,
        max_completion_tokens=min(4000, max(TOP_MAX_NEW_TOKENS, height * 60)),
    )
    raw = resp.choices[0].message.content or ""
    return _extract_code_block(raw).strip("\r\n")
