#!/usr/bin/env python3
"""CloudSentinel API server.

Exposes streaming scan endpoints plus scan-history CRUD.
Runs the full scan -> parse -> AI analysis pipeline and streams
progress events back via Server-Sent Events (SSE).

Start with:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /scan           — start a scan (credentials via X-AWS-* headers)
    GET  /scans          — list past scan metadata
    GET  /scans/{id}     — full scan record with analysis JSON
    DELETE /scans/{id}   — delete all scans in a session
    GET  /health         — backend health check

SSE events streamed from /scan:
    { "type": "progress", "service": "ec2", "message": "..." }
    { "type": "result",   "service": "ec2", "analysis": {...}, "scan_id": "...", "session_id": "..." }
    { "type": "error",    "service": "ec2", "message": "...", "category": "auth", "scan_id": "...", "session_id": "..." }
    { "type": "done",     "session_id": "..." }
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from cloudsentinel import SUPPORTED_SERVICES, run_pipeline
from credential_utils import sanitize_error, classify_aws_error
from llm_runner import SUPPORTED_LLM_PROVIDERS, available_llm_providers, resolve_llm_provider
from scan_cancellation import ScanCancellationRegistry, ScanCancelledError
from scan_store import ScanStore


app = FastAPI(title="CloudSentinel API", version="1.1.0")

# Allow all origins so any frontend (Lovable, localhost, etc.) can connect.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ── Scan history store ───────────────────────────────────────────────────────

store = ScanStore(Path(__file__).resolve().parent.parent / "cloudsentinel.db")
scan_cancellations = ScanCancellationRegistry()


# ── Startup warning ──────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup_warning() -> None:
    print(
        "\n  WARNING: This server uses plain HTTP. Do NOT expose it to the "
        "internet without a TLS-terminating reverse proxy.\n",
        file=sys.stderr,
    )


# ── Credential extraction ───────────────────────────────────────────────────

class AWSCredentials:
    """Holds AWS credential values extracted from request headers."""

    __slots__ = ("access_key", "secret_key", "session_token")

    def __init__(self, access_key: str, secret_key: str, session_token: str | None = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token


async def get_aws_credentials(request: Request) -> AWSCredentials | None:
    """FastAPI dependency: extract AWS credentials from X-AWS-* headers.

    Returns ``None`` when no credential headers are present (profile mode).
    """
    access_key = request.headers.get("X-AWS-Access-Key-Id", "").strip()
    secret_key = request.headers.get("X-AWS-Secret-Access-Key", "").strip()
    session_token = request.headers.get("X-AWS-Session-Token", "").strip() or None

    if not access_key and not secret_key:
        return None  # profile mode — no header creds

    if not access_key or not secret_key:
        raise HTTPException(
            status_code=400,
            detail="Both X-AWS-Access-Key-Id and X-AWS-Secret-Access-Key headers are required.",
        )
    return AWSCredentials(access_key, secret_key, session_token)


# ── Request model ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    services: list[str]
    region: str
    profile: str | None = None
    llm_provider: str | None = None
    session_id: str | None = None

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: list[str]) -> list[str]:
        invalid = set(v) - SUPPORTED_SERVICES
        if invalid:
            raise ValueError(
                f"Unsupported services: {sorted(invalid)}. "
                f"Supported: {sorted(SUPPORTED_SERVICES)}"
            )
        if not v:
            raise ValueError("At least one service must be specified.")
        return v

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in SUPPORTED_LLM_PROVIDERS:
            raise ValueError(
                f"Unsupported llm_provider: {normalized}. "
                f"Supported: {sorted(SUPPORTED_LLM_PROVIDERS)}"
            )
        return normalized

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip()
        return normalized or None


# ── SSE helper ───────────────────────────────────────────────────────────────

def _sse(payload: dict) -> str:
    """Format a dict as a single SSE data line."""
    return f"data: {json.dumps(payload)}\n\n"


def _run_scan_job(
    *,
    scan_id: str,
    session_id: str,
    service: str,
    pipeline_kwargs: dict,
    redact_keys: list[str],
) -> dict:
    try:
        result_json_str = run_pipeline(**pipeline_kwargs)
        record = store.get_scan(scan_id)
        if record and record.get("status") == "cancelled":
            return {
                "type": "cancelled",
                "service": service,
                "message": record.get("error_message") or "Scan cancelled by user.",
                "scan_id": scan_id,
                "session_id": session_id,
            }

        try:
            analysis = json.loads(result_json_str)
        except json.JSONDecodeError:
            message = "AI analysis did not return valid JSON."
            store.fail_scan(scan_id, message)
            return {
                "type": "error",
                "service": service,
                "message": message,
                "category": "unknown",
                "scan_id": scan_id,
                "session_id": session_id,
            }

        store.complete_scan(scan_id, result_json_str)
        return {
            "type": "result",
            "service": service,
            "analysis": analysis,
            "scan_id": scan_id,
            "session_id": session_id,
        }
    except ScanCancelledError as exc:
        message = str(exc) or "Scan cancelled by user."
        store.cancel_scan(scan_id, message)
        return {
            "type": "cancelled",
            "service": service,
            "message": message,
            "scan_id": scan_id,
            "session_id": session_id,
        }
    except Exception as exc:
        safe_msg = sanitize_error(str(exc), redact_keys)
        classified = classify_aws_error(safe_msg)
        store.fail_scan(scan_id, classified["message"])
        return {
            "type": "error",
            "service": service,
            "message": classified["message"],
            "category": classified["category"],
            "scan_id": scan_id,
            "session_id": session_id,
        }
    finally:
        scan_cancellations.finish_job(session_id)


# ── Streaming scan endpoint ─────────────────────────────────────────────────

@app.post("/scan")
async def scan(
    request: ScanRequest,
    creds: AWSCredentials | None = Depends(get_aws_credentials),
) -> StreamingResponse:
    """
    Run one or more service scans sequentially and stream SSE events.

    AWS credentials are read from X-AWS-* headers.
    Alternatively, pass ``profile`` in the JSON body for AWS-profile mode.
    """

    # Validate: must have either header creds or a profile name.
    if creds is None and not request.profile:
        raise HTTPException(
            status_code=400,
            detail="Provide AWS credentials via X-AWS-* headers or a 'profile' name in the body.",
        )

    session_id = request.session_id or str(uuid.uuid4())

    async def generate() -> AsyncGenerator[str, None]:
        loop = asyncio.get_event_loop()
        session_cancelled = False

        for service in request.services:
            scan_id = str(uuid.uuid4())
            store.create_scan(
                id=scan_id,
                session_id=session_id,
                service=service,
                region=request.region,
            )

            # ── Progress bridge ───────────────────────────────────────────
            progress_queue: asyncio.Queue[str] = asyncio.Queue()

            def on_progress(message: str) -> None:
                loop.call_soon_threadsafe(progress_queue.put_nowait, message)

            # ── Build pipeline kwargs ─────────────────────────────────────
            pipeline_kwargs: dict = dict(
                service=service,
                region=request.region,
                llm_provider=request.llm_provider,
                on_progress=on_progress,
            )
            if request.profile:
                pipeline_kwargs["profile"] = request.profile
                redact_keys: list[str] = []
            else:
                assert creds is not None
                pipeline_kwargs["access_key"] = creds.access_key
                pipeline_kwargs["secret_key"] = creds.secret_key
                pipeline_kwargs["session_token"] = creds.session_token
                redact_keys = [creds.access_key, creds.secret_key]
                if creds.session_token:
                    redact_keys.append(creds.session_token)

            pipeline_kwargs["should_cancel"] = scan_cancellations.should_cancel(session_id)

            # ── Start pipeline in thread pool ─────────────────────────────
            scan_cancellations.begin_job(session_id)
            future = loop.run_in_executor(
                None,
                lambda kw=pipeline_kwargs, sid=scan_id, sess=session_id, svc=service, rk=redact_keys: _run_scan_job(
                    scan_id=sid,
                    session_id=sess,
                    service=svc,
                    pipeline_kwargs=kw,
                    redact_keys=rk,
                ),
            )

            # ── Drain progress queue until the pipeline finishes ──────────
            while not future.done():
                try:
                    message = await asyncio.wait_for(
                        progress_queue.get(), timeout=0.3
                    )
                    yield _sse({"type": "progress", "service": service, "message": message})
                except asyncio.TimeoutError:
                    pass

            # Flush remaining progress messages
            while not progress_queue.empty():
                message = progress_queue.get_nowait()
                yield _sse({"type": "progress", "service": service, "message": message})

            # ── Emit result or error ──────────────────────────────────────
            try:
                payload = await future
                yield _sse(payload)
                if payload.get("type") == "cancelled":
                    session_cancelled = True
                    break
            except Exception as exc:  # pragma: no cover - defensive
                classified = classify_aws_error(str(exc))
                yield _sse({
                    "type": "error",
                    "service": service,
                    "message": classified["message"],
                    "category": classified["category"],
                    "scan_id": scan_id,
                    "session_id": session_id,
                })

        if not session_cancelled:
            yield _sse({"type": "done", "session_id": session_id})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Scan history endpoints ───────────────────────────────────────────────────

@app.get("/scans")
async def list_scans(limit: int = 50) -> dict:
    """Return recent scan metadata (no analysis_json)."""
    return {"scans": store.list_scans(limit=limit)}


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Return a full scan record including analysis_json."""
    record = store.get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    # Parse the stored JSON string so the response is a proper object.
    if record.get("analysis_json"):
        try:
            record["analysis_json"] = json.loads(record["analysis_json"])
        except (json.JSONDecodeError, TypeError):
            pass
    return record


@app.delete("/scans/{session_id}")
async def delete_session(session_id: str) -> dict:
    """Delete all scans belonging to a session."""
    deleted = store.delete_session(session_id)
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Session not found.")
    return {"deleted": deleted}


@app.post("/scans/{session_id}/cancel")
async def cancel_session(session_id: str) -> dict:
    """Request cancellation for a running scan session."""
    known_session = scan_cancellations.has_session(session_id)
    scan_cancellations.request_cancel(session_id)
    cancelled_rows = store.cancel_session(session_id, "Scan cancelled by user.")
    if not known_session and cancelled_rows == 0:
        scan_cancellations.clear(session_id)
        raise HTTPException(status_code=404, detail="No active scan session found.")
    return {
        "status": "cancel_requested",
        "session_id": session_id,
        "cancelled_rows": cancelled_rows,
    }


# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    default_provider = None
    try:
        default_provider = resolve_llm_provider("auto")
    except RuntimeError:
        default_provider = None

    return {
        "status": "ok",
        "supported_services": sorted(SUPPORTED_SERVICES),
        "available_llm_providers": available_llm_providers(),
        "default_llm_provider": default_provider,
    }
