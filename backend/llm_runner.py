from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scan_cancellation import ScanCancelledError


SUPPORTED_LLM_PROVIDERS = {"auto", "codex", "claude"}


@dataclass(slots=True)
class LLMInvocationResult:
    provider: str
    output: str


def available_llm_providers() -> list[str]:
    available: list[str] = []
    for provider in ("codex", "claude"):
        if shutil.which(provider):
            available.append(provider)
    return available


def resolve_llm_provider(provider: str | None = None) -> str:
    requested = (
        provider
        or os.environ.get("CLOUDSENTINEL_LLM_PROVIDER")
        or "auto"
    ).strip().lower()

    if requested not in SUPPORTED_LLM_PROVIDERS:
        raise ValueError(
            f"Unsupported LLM provider: {requested}. "
            f"Choose from: {sorted(SUPPORTED_LLM_PROVIDERS)}"
        )

    available = available_llm_providers()
    if requested == "auto":
        for candidate in ("codex", "claude"):
            if candidate in available:
                return candidate
        raise RuntimeError(
            "No supported AI CLI found. Install the Codex CLI or Claude CLI."
        )

    if requested not in available:
        installed = ", ".join(available) if available else "none"
        raise RuntimeError(
            f"{requested} CLI is not installed. Available providers: {installed}."
        )

    return requested


def extract_json_from_response(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    inner_lines: list[str] = []
    in_block = False
    for line in lines:
        if line.startswith("```") and not in_block:
            in_block = True
            continue
        if line.startswith("```") and in_block:
            break
        if in_block:
            inner_lines.append(line)
    return "\n".join(inner_lines).strip()


def _run_process(
    *,
    cmd: list[str],
    cwd: Path,
    input_text: str,
    cancel_label: str,
    should_cancel: Callable[[], bool] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(cwd),
        )
    except FileNotFoundError:
        raise

    pending_input: str | None = input_text
    try:
        while True:
            try:
                stdout, stderr = process.communicate(input=pending_input, timeout=0.25)
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=process.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            except subprocess.TimeoutExpired:
                pending_input = None
                if should_cancel and should_cancel():
                    process.kill()
                    process.communicate()
                    raise ScanCancelledError(f"Scan cancelled by user during {cancel_label}.")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def run_claude(
    *,
    system_prompt: str | None,
    user_prompt: str,
    cwd: Path,
    model: str | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> str:
    """Run Claude CLI with explicit system prompt via --system-prompt flag.

    Claude auto-loads CLAUDE.md from cwd, but --system-prompt overrides it
    so the pipeline controls exactly which contract the LLM sees.
    """
    cmd = ["claude", "--print", "--output-format", "text", "--tools", ""]
    if system_prompt:
        cmd += ["--system-prompt", system_prompt]
    if model:
        cmd += ["--model", model]

    try:
        result = _run_process(
            cmd=cmd,
            cwd=cwd,
            input_text=user_prompt,
            cancel_label="Claude analysis",
            should_cancel=should_cancel,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "'claude' command not found. "
            "Make sure Claude Code CLI is installed and on your PATH."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"Claude CLI exited with code {result.returncode}.\n"
            + (result.stderr.strip() or "(no stderr)")
        )

    return result.stdout


def run_codex(
    *,
    user_prompt: str,
    cwd: Path,
    model: str | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> str:
    """Run Codex CLI with user_prompt only.

    Codex auto-loads AGENTS.md from cwd as project instructions.
    The contract is NOT embedded in the prompt — that caused duplication
    and bloated the token count.
    """
    with tempfile.NamedTemporaryFile(
        prefix="cloudsentinel-codex-",
        suffix=".txt",
        delete=False,
    ) as output_file:
        output_path = Path(output_file.name)

    cmd = [
        "codex",
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--color",
        "never",
        "--output-last-message",
        str(output_path),
        "-",
    ]
    if model:
        cmd[2:2] = ["--model", model]

    try:
        result = _run_process(
            cmd=cmd,
            cwd=cwd,
            input_text=user_prompt,
            cancel_label="Codex analysis",
            should_cancel=should_cancel,
        )
    except FileNotFoundError as exc:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(
            "'codex' command not found. "
            "Make sure the Codex CLI is installed and on your PATH."
        ) from exc

    try:
        if result.returncode != 0:
            raise RuntimeError(
                f"Codex CLI exited with code {result.returncode}.\n"
                + (result.stderr.strip() or result.stdout.strip() or "(no output)")
            )

        if not output_path.exists():
            raise RuntimeError("Codex CLI did not write a final response file.")

        content = output_path.read_text(encoding="utf-8").strip()
        if not content:
            raise RuntimeError("Codex CLI returned an empty final response.")
        return content
    finally:
        output_path.unlink(missing_ok=True)


def run_llm(
    *,
    system_prompt: str | None = None,
    user_prompt: str,
    provider: str | None = None,
    model: str | None = None,
    cwd: Path,
    should_cancel: Callable[[], bool] | None = None,
) -> LLMInvocationResult:
    """Dispatch to the appropriate LLM CLI.

    - Claude: system_prompt passed via --system-prompt flag.
    - Codex: system_prompt not needed — Codex auto-loads AGENTS.md from cwd.
    """
    resolved_provider = resolve_llm_provider(provider)
    if resolved_provider == "codex":
        output = run_codex(
            user_prompt=user_prompt,
            cwd=cwd,
            model=model,
            should_cancel=should_cancel,
        )
    else:
        output = run_claude(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            cwd=cwd,
            model=model,
            should_cancel=should_cancel,
        )
    return LLMInvocationResult(provider=resolved_provider, output=output)
