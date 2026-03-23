#!/usr/bin/env python3
"""CloudSentinel — end-to-end pipeline.

Runs a scanner, parses the output, builds the analysis prompt,
and pipes it to the configured AI CLI. No API key wiring is needed here
as long as the selected CLI is already authenticated.

Importable by api.py:
    from cloudsentinel import run_pipeline
"""

from __future__ import annotations

import importlib
import json
import os
import threading
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from analysis_bridge import build_analysis_bundle
from credential_utils import sanitize_error
from llm_runner import extract_json_from_response, resolve_llm_provider, run_llm
from scan_parser import parse_scan_text


BASE_DIR = Path(__file__).resolve().parent          # backend/
PROJECT_ROOT = BASE_DIR.parent                       # CloudSentinel/
SCANNERS_DIR = BASE_DIR / "scanners"

SUPPORTED_SERVICES = {"ec2", "s3", "iam", "vpc", "rds", "ebs", "ami", "elb"}

# Ensure scanners/ is importable as top-level modules (e.g. ec2_scanner).
import sys as _sys
_scanners_str = str(SCANNERS_DIR)
if _scanners_str not in _sys.path:
    _sys.path.insert(0, _scanners_str)

# Only one scan runs at a time — prevents concurrent env-var conflicts.
_scan_lock = threading.Lock()


# ── AWS credential context ────────────────────────────────────────────────────

@contextmanager
def _aws_env(*, access_key: str, secret_key: str, region: str, session_token: str | None = None):
    """Temporarily inject AWS credentials into the process environment.

    AWS CLI subprocesses spawned inside this block inherit these variables.
    Original values are restored on exit, even if an exception is raised.
    """
    inject = {
        "AWS_ACCESS_KEY_ID": access_key,
        "AWS_SECRET_ACCESS_KEY": secret_key,
        "AWS_DEFAULT_REGION": region,
    }
    if session_token:
        inject["AWS_SESSION_TOKEN"] = session_token

    previous = {k: os.environ.get(k) for k in inject}
    os.environ.update(inject)
    try:
        yield
    finally:
        for key, old_val in previous.items():
            if old_val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_val


# ── Scanner loader ────────────────────────────────────────────────────────────

def _load_scanner(service: str) -> Callable[[Namespace], str]:
    if service not in SUPPORTED_SERVICES:
        raise ValueError(f"Unsupported service: {service}. Choose from: {sorted(SUPPORTED_SERVICES)}")
    module = importlib.import_module(f"{service}_scanner")
    return module.build_scan_output  # type: ignore[no-any-return]


def _scanner_args(*, region: str, profile: str | None = None) -> Namespace:
    """Build the Namespace that every scanner's build_scan_output() expects."""
    return Namespace(
        region=region,
        profile=profile,
        timeout_seconds=60,
        output_file=None,
    )


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    *,
    service: str,
    region: str,
    access_key: str | None = None,
    secret_key: str | None = None,
    session_token: str | None = None,
    profile: str | None = None,
    llm_provider: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> str:
    """
    Full CloudSentinel pipeline for one service.

    Blocks the calling thread. Designed to be run inside a thread pool
    when called from the async API server.

    Supports two credential modes:
    - **Key mode**: pass ``access_key`` and ``secret_key`` (+ optional ``session_token``).
    - **Profile mode**: pass ``profile`` name — credentials are read from ``~/.aws/credentials``.

    Returns the final analysis as a JSON string.
    Calls on_progress(message) at each major step so callers can stream
    progress events to the frontend.
    """
    use_profile = bool(profile)

    if not use_profile and (not access_key or not secret_key):
        raise ValueError("Either 'profile' or both 'access_key' and 'secret_key' must be provided.")

    # Collect credential strings for sanitization of any errors.
    _redact_keys: list[str] = []
    if access_key:
        _redact_keys.append(access_key)
    if secret_key:
        _redact_keys.append(secret_key)
    if session_token:
        _redact_keys.append(session_token)

    def progress(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    try:
        with _scan_lock:
            if use_profile:
                # Profile mode: set AWS_PROFILE + region only.
                prev_profile = os.environ.get("AWS_PROFILE")
                prev_region = os.environ.get("AWS_DEFAULT_REGION")
                os.environ["AWS_PROFILE"] = profile  # type: ignore[assignment]
                os.environ["AWS_DEFAULT_REGION"] = region
                try:
                    return _run_scan_and_analyze(
                        service=service,
                        region=region,
                        profile=profile,
                        progress=progress,
                        llm_provider=llm_provider,
                    )
                finally:
                    if prev_profile is None:
                        os.environ.pop("AWS_PROFILE", None)
                    else:
                        os.environ["AWS_PROFILE"] = prev_profile
                    if prev_region is None:
                        os.environ.pop("AWS_DEFAULT_REGION", None)
                    else:
                        os.environ["AWS_DEFAULT_REGION"] = prev_region
            else:
                assert access_key is not None and secret_key is not None
                with _aws_env(
                    access_key=access_key,
                    secret_key=secret_key,
                    region=region,
                    session_token=session_token,
                ):
                    return _run_scan_and_analyze(
                        service=service,
                        region=region,
                        profile=None,
                        progress=progress,
                        llm_provider=llm_provider,
                    )
    except Exception as exc:
        # Sanitize credentials from any error that bubbles up.
        safe_msg = sanitize_error(str(exc), _redact_keys)
        if safe_msg != str(exc):
            raise RuntimeError(safe_msg) from None
        raise


def _run_scan_and_analyze(
    *,
    service: str,
    region: str,
    profile: str | None,
    progress: Callable[[str], None],
    llm_provider: str | None,
) -> str:
    """Inner pipeline logic shared by key-mode and profile-mode."""

    # 1. Run scanner
    progress(f"Scanning {service.upper()} resources in {region}...")
    scanner_fn = _load_scanner(service)
    scan_text = scanner_fn(_scanner_args(region=region, profile=profile))

    if not scan_text.strip():
        raise RuntimeError(
            "Scanner returned empty output. "
            "Check that your AWS credentials are valid and have sufficient permissions."
        )

    # 2. Parse
    progress("Parsing scan output...")
    parsed_scan = parse_scan_text(scan_text)

    # 3. Build analysis prompt (service skill is auto-selected from parsed_scan.primary_service)
    progress("Building analysis prompt...")
    bundle = build_analysis_bundle(
        parsed_scan,
        scan_source=f"{service}:{region}",
    )
    resolved_provider = resolve_llm_provider(llm_provider)
    user_prompt = bundle["llm_request"]["user_prompt"]

    # Provider-specific contract selection:
    # - Claude: CLAUDE.md passed explicitly via --system-prompt flag
    # - Codex: AGENTS.md auto-loaded from cwd (no embedding needed)
    system_prompt: str | None = None
    if resolved_provider == "claude":
        claude_md = PROJECT_ROOT / "CLAUDE.md"
        if claude_md.exists():
            system_prompt = claude_md.read_text(encoding="utf-8")

    # 4. Send to the selected provider
    progress(
        f"{resolved_provider.upper()} is analyzing findings — this may take a minute..."
    )
    raw_output = run_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        provider=resolved_provider,
        cwd=PROJECT_ROOT,
    ).output

    # 5. Clean and validate JSON
    clean = extract_json_from_response(raw_output)
    try:
        parsed = json.loads(clean)
        return json.dumps(parsed, indent=2, sort_keys=False)
    except json.JSONDecodeError:
        return clean
