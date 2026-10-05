from __future__ import annotations

import json
import logging
import os
import copy
import traceback
import re
from typing import Any, Callable, Dict, Optional, List

from openai import OpenAI
from tools.interactive_tools import (
    INTERACTIVE_TOOL_DEFINITIONS,
    NO_INTERACTIVE_TOOL,
    fallback_interactive_tool,
)

from terminal_config import SYSTEM_JSON, CLASSIFIER_MODEL_DIR
from tools.mutation_executor import MutationExecutor
from tools.mutation_tools import (
    MUTATION_TOOL_NAMES,
    mutation_tool_definitions,
    parse_mutation_tool_call,
)
from tools.ubuntu_command_tool import (
    TOOL_NAME as UBUNTU_COMMAND_TOOL_NAME,
    execute_tool_call as execute_ubuntu_command_tool,
    tool_definition as ubuntu_command_tool_definition,
)
from tools.ubuntu_fs_write_tools import (
    is_deterministic_fs_write,
    plan_deterministic_fs_write,
)
from tools.ubuntu_touch_tool import (
    is_touch_command,
    plan_touch_command,
)
from tools.common import tool_call_arguments
from tools.ubuntu_commands import classify_known_ubuntu_command

from system_state import (
    build_default_system_log,
    hydrate_snapshot,
    load_system_log,
    save_system_log,
    utc_now_iso,
)

DEFAULT_PLANNER_MODEL = os.getenv("RESPONSE_AGENT_MODEL", "gpt-5.4-mini")
PLANNER_MAX_NEW_TOKENS = int(os.getenv("RESPONSE_AGENT_MAX_NEW_TOKENS", "512"))


DEFAULT_ROUTER_MODEL = os.getenv(
    "INTERACTIVE_ROUTER_MODEL", os.getenv("RESPONSE_AGENT_MODEL", "gpt-5.4-mini")
)

def select_interactive_tool(cmd: str, client: Optional[OpenAI], model: Optional[str] = None) -> str:
    if client is None:
        return fallback_interactive_tool(cmd)
    try:
        messages = [
            {
                "role": "developer",
                "content": (
                    "Classify one shell command line purely by its surface syntax -- do not run it or "
                    "reason about semantics. Call exactly one tool: the interactive tool whose "
                    "description matches this command's syntax, or no_interactive_tool if none do."
                ),
            },
            {"role": "user", "content": cmd},
        ]
        resp = client.chat.completions.create(
            model=model or DEFAULT_ROUTER_MODEL,
            messages=messages,
            store=False,
            reasoning_effort="none",
            temperature=0.0,
            max_completion_tokens=32,
            tools=INTERACTIVE_TOOL_DEFINITIONS,
            tool_choice="required",
            parallel_tool_calls=False,
        )
        message = resp.choices[0].message
        for tool_call in getattr(message, "tool_calls", None) or []:
            function = getattr(tool_call, "function", None)
            if function is not None and function.name:
                return function.name
        return NO_INTERACTIVE_TOOL
    except Exception:
        return fallback_interactive_tool(cmd)


logger = logging.getLogger(__name__)


ID2LABEL = {0: "read", 1: "write", 2: "rejection"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}


class LocalClassifier:
    def __init__(self, model_dir: str = CLASSIFIER_MODEL_DIR, device: Optional[str] = None):
        if not os.path.isdir(model_dir):
            raise FileNotFoundError(
                f"Classifier model directory does not exist: {model_dir}. "
                "Place the model in model/modernbert_par_2_jaur_1 or set CLASSIFIER_MODEL_DIR."
            )
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()
        logger.info("Local classifier loaded from %s on %s", model_dir, self.device)

    def predict_label(self, text: str) -> str:
        import torch

        inputs = self.tokenizer(
            text,
            truncation=True,
            max_length=256,
            padding="max_length",
            return_tensors="pt",
        ).to(self.device)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        pred_id = int(torch.argmax(logits, dim=-1).item())
        return ID2LABEL.get(pred_id, "rejection")


_classifier: Optional[LocalClassifier] = None


def _get_classifier() -> LocalClassifier:
    global _classifier
    if _classifier is None:
        _classifier = LocalClassifier()
    return _classifier


def validate_command(
    _client: Any,
    command: str,
) -> str:
    try:
        clf = _get_classifier()
        label = clf.predict_label(command)
        if label in {"read", "write", "rejection"}:
            return label
        return "read"
    except Exception:
        logger.exception(
            "Local classifier failed (model directory: %s); falling back to read. "
            "Check CLASSIFIER_MODEL_DIR, model files, and runtime dependencies.",
            CLASSIFIER_MODEL_DIR,
        )
        return "read"


class ArbiterAgent:
    def __init__(
        self,
        cve_list: Optional[List[str]] = None,
        system_log_path: str = SYSTEM_JSON,
        session_id: str = "",
        download_file_fetcher: Optional[Callable[[str, str, str, str], Optional[Dict[str, Any]]]] = None,
        download_git_fetcher: Optional[Callable[[str, str, str], Optional[Dict[str, Any]]]] = None,
    ):
        self.system_log_path = system_log_path
        self.session_id = session_id
        self.download_file_fetcher = download_file_fetcher
        self.download_git_fetcher = download_git_fetcher
        self.last_local_outcome = "unsupported"
        self.last_handled_local = False
        self.last_handled_llm = False
        self.last_unhandled_command = ""

        log = load_system_log(self.system_log_path)
        if not log:
            log = build_default_system_log()
        if cve_list is not None:
            log["vulnerabilities"] = list(cve_list)

        self.system_log: Dict[str, Any] = log
        hydrate_snapshot(self.system_log)
        save_system_log(self.system_log_path, self.system_log)


    def process_safe_fs(self, command: str) -> str:
        cmd = command.strip()
        self.system_log["timestamp"] = utc_now_iso()
        self.system_log["last_output"] = ""

        self.system_log["step"] = int(self.system_log.get("step", 0)) + 1

        handled = False
        self.last_local_outcome = "unsupported"
        try:
            handled = MutationExecutor(self).apply_command_local(cmd)
        except Exception:
            traceback.print_exc()
            handled = False

        self.last_handled_local = bool(handled)
        self.last_unhandled_command = "" if handled else cmd
        if handled:
            self.last_local_outcome = "authoritative"
        elif not handled:
            self.last_local_outcome = "unsupported"

        try:
            self.system_log["timestamp"] = utc_now_iso()
            hydrate_snapshot(self.system_log)
            save_system_log(self.system_log_path, self.system_log)
        except Exception:
            traceback.print_exc()

        return json.dumps(self.system_log, ensure_ascii=False, indent=2)

    def process_write_command(
        self,
        command: str,
        client: Optional[Any] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        self.last_handled_llm = False
        self.process_safe_fs(command)
        if not self.last_handled_local:
            plan = self.plan_state_mutations(command, client=client, model=model)
            self.apply_llm_write_plan(plan)
        return copy.deepcopy(self.system_log)

    def plan_state_mutations(
        self,
        command: str,
        client: Optional[Any] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        system_log = self.system_log
        if is_deterministic_fs_write(command, system_log):
            return plan_deterministic_fs_write(command, system_log)
        if is_touch_command(command):
            return plan_touch_command(command, system_log)
        c = client
        if c is None:
            from openai import OpenAI

            c = OpenAI(api_key=os.getenv("OPENAI_API_KEY") or "YOUR_API_KEY_HERE")
        planner_instruction = (
            "You execute one state-changing command inside an Ubuntu 22.04 terminal simulator. "
            "Call execute_ubuntu_command exactly once with the raw terminal output and 0-255 exit status. "
            "For every successful persistent change, also call the matching mutation tool once, in "
            "execution order. Do not return Markdown or ordinary assistant text. Use the supplied state "
            "as authoritative. Never claim success "
            "when a necessary mutation cannot be represented. Parse the entire command with Ubuntu 22.04 "
            "and GNU utility semantics before deciding its output or mutations. A token beginning with '-' "
            "before a '--' delimiter is an option, not a pathname. Correctly handle combined short options, "
            "long options, attached option values, repeated options, '--', quoted operands, missing operands, "
            "and invalid options. Do not reinterpret an option token as a filename. Partial success must "
            "include only mutations that really succeeded and the diagnostics and exit status Ubuntu would "
            "produce. The available mutation tools define the allowed effects and arguments. "
            "Filesystem paths must be absolute and confined to the authenticated user's home, /root, or "
            "/tmp. Critical configuration writes may target only paths already present in "
            "critical_configs.files. Use normal Ubuntu output and an empty string for silent success."
        )
        messages = [
            {
                "role": "developer",
                "content": planner_instruction,
            },
            {
                "role": "user",
                "content": json.dumps(
                    {"command": command, "current_state": system_log},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
        ]
        request: Dict[str, Any] = dict(
            model=model or DEFAULT_PLANNER_MODEL,
            messages=messages,
            store=False,
            reasoning_effort="none",
            temperature=0.0,
            max_completion_tokens=max(PLANNER_MAX_NEW_TOKENS, 1200),
        )
        request["tools"] = [
            ubuntu_command_tool_definition(command),
            *mutation_tool_definitions(),
        ]
        request["tool_choice"] = "auto"
        request["parallel_tool_calls"] = True
        resp = c.chat.completions.create(**request)
        message = resp.choices[0].message
        arguments = tool_call_arguments(message, UBUNTU_COMMAND_TOOL_NAME)
        if arguments is None:
            raise ValueError("write planner did not call the required Ubuntu command tool")
        result = execute_ubuntu_command_tool(
            UBUNTU_COMMAND_TOOL_NAME,
            arguments,
            command,
        )
        mutations: List[Dict[str, Any]] = []
        for tool_call in getattr(message, "tool_calls", None) or []:
            function = getattr(tool_call, "function", None)
            if function is None or function.name not in MUTATION_TOOL_NAMES:
                continue
            mutations.append(parse_mutation_tool_call(function.name, function.arguments))
        result["mutations"] = mutations
        return result

    def apply_llm_write_plan(self, plan: Dict[str, Any]) -> int:
        return MutationExecutor(self).apply_plan(plan)





    def route_label(self, command: str, client: Any = None) -> str:
        cmd = (command or "").strip()
        if not cmd:
            return "read"
        if re.search(r"(ignore\s+previous|reveal\s+system\s+prompt|system\s+prompt|jailbreak)", cmd, flags=re.I):
            return "rejection"
        known_label = classify_known_ubuntu_command(cmd, self.system_log)
        if known_label is not None:
            return known_label
        if re.search(r"^\s*(cd|mkdir|touch|rm|rmdir|mv|cp|chmod|chown)\b", cmd):
            return "write"
        if re.search(r"^\s*echo\s+.+\s*(>>|>)\s*.+$", cmd):
            return "write"
        if re.search(
            r"^\s*(pwd|whoami|id|ls|cat|head|tail|grep|find|hostname|uname|date|ps|ip|history|clear|true|false|echo)\b",
            cmd,
        ):
            return "read"
        try:
            if client is not None:
                label = validate_command(client, command)
                if label in {"read", "write", "rejection"}:
                    return label
        except Exception:
            pass

        return "read"

