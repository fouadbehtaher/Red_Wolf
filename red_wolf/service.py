"""Privacy-first HTTP service for authorized Red Wolf scans.

Run with:
    uvicorn red_wolf.service:app --host 127.0.0.1 --port 8000

The service is intentionally conservative: HTTPS targets must be in
RED_WOLF_ALLOWED_HOSTS, only read-only methods are accepted, and persisted
records contain no target URL, response body, headers, credentials, or API key.
"""

import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import socket
import uuid
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, HttpUrl, field_validator

from .learning import LearningStore, normalize_path
from .scanner import ScanConfig, UnauthAccessScanner



@asynccontextmanager
async def _lifespan(_: FastAPI):
    _recover_interrupted_jobs()
    _cleanup_expired_jobs()
    try:
        yield
    finally:
        _executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="Red Wolf",
    version="1.1.0",
    description="Privacy-first authorized reconnaissance service.",
    lifespan=_lifespan,
)
_executor = ThreadPoolExecutor(max_workers=int(os.environ.get("RED_WOLF_WORKERS", "2")))
_MAX_JOBS_PER_WINDOW = int(os.environ.get("RED_WOLF_MAX_JOBS_PER_WINDOW", "5"))
_JOB_WINDOW_SECONDS = int(os.environ.get("RED_WOLF_JOB_WINDOW_SECONDS", "3600"))


def _db_path() -> Path:
    return Path(os.environ.get("RED_WOLF_SERVICE_DB", "red_wolf_service.db")).expanduser()


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target_fingerprint TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            result_json TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS job_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_event(
    job_id: str,
    tenant_id: str,
    event_type: str,
) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (job_id, tenant_id, event_type, _now()),
        )


def _recover_interrupted_jobs() -> None:
    with _connect() as db:
        rows = db.execute(
            "SELECT job_id, tenant_id FROM jobs WHERE state IN ('queued', 'running')"
        ).fetchall()
        now = _now()
        db.execute(
            "UPDATE jobs SET state = 'failed', updated_at = ?, "
            "result_json = ? WHERE state IN ('queued', 'running')",
            (now, json.dumps({"error": "service_restarted"})),
        )
        for row in rows:
            db.execute(
                "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (row["job_id"], row["tenant_id"], "service_restarted", now),
            )


def _retention_days() -> int:
    try:
        return max(1, int(os.environ.get("RED_WOLF_RETENTION_DAYS", "30")))
    except ValueError as exc:
        raise RuntimeError("RED_WOLF_RETENTION_DAYS must be an integer") from exc


def _cleanup_expired_jobs() -> int:
    cutoff = datetime.now(timezone.utc).timestamp() - (_retention_days() * 86400)
    deleted = 0
    with _connect() as db:
        rows = db.execute("SELECT job_id, created_at FROM jobs").fetchall()
        expired = []
        for row in rows:
            try:
                is_expired = datetime.fromisoformat(row["created_at"]).timestamp() < cutoff
            except ValueError:
                is_expired = False
            if is_expired:
                expired.append(row["job_id"])
        for job_id in expired:
            db.execute("DELETE FROM job_events WHERE job_id = ?", (job_id,))
            db.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
        deleted = len(expired)
    return deleted


def _job_counts() -> dict[str, int]:
    with _connect() as db:
        rows = db.execute("SELECT state, COUNT(*) AS count FROM jobs GROUP BY state").fetchall()
    return {row["state"]: row["count"] for row in rows}


def _token_tenant(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def _configured_tokens() -> list[str]:
    values = os.environ.get("RED_WOLF_SERVICE_TOKENS", "")
    if values.strip():
        return [item.strip() for item in values.split(",") if item.strip()]
    legacy = os.environ.get("RED_WOLF_SERVICE_TOKEN", "")
    return [legacy] if legacy else []


def _require_token(x_api_key: str | None = Header(default=None)) -> str:
    configured = _configured_tokens()
    if not configured:
        raise HTTPException(503, "Service authentication is not configured")
    if not x_api_key:
        raise HTTPException(401, "Invalid service token")
    for expected in configured:
        if secrets.compare_digest(x_api_key, expected):
            return _token_tenant(x_api_key)
    raise HTTPException(401, "Invalid service token")


def _allowed_hosts() -> set[str]:
    return {
        item.strip().lower()
        for item in os.environ.get("RED_WOLF_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }


def _blocked_ip(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def _resolved_addresses(hostname: str) -> set[str]:
    try:
        return {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise HTTPException(400, "Target hostname could not be resolved") from exc


def _validate_target(target: str) -> str:
    parsed = urlparse(target)
    allowed = _allowed_hosts()
    if parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(400, "Only HTTPS targets are accepted")
    if parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(400, "Target must not contain credentials or a fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise HTTPException(400, "Target port is invalid") from exc
    if not allowed or parsed.hostname.lower() not in allowed:
        raise HTTPException(403, "Target is not in the server allowlist")
    addresses = _resolved_addresses(parsed.hostname)
    if not addresses or any(_blocked_ip(address) for address in addresses):
        raise HTTPException(403, "Target resolves to a blocked network address")
    return target.rstrip("/")


def _check_job_quota(tenant_id: str) -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - _JOB_WINDOW_SECONDS
    with _connect() as db:
        rows = db.execute(
            "SELECT created_at FROM jobs WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    recent = 0
    for row in rows:
        try:
            created = datetime.fromisoformat(row["created_at"]).timestamp()
        except ValueError:
            continue
        recent += created >= cutoff
    if recent >= _MAX_JOBS_PER_WINDOW:
        raise HTTPException(429, "Job quota exceeded for this tenant")


class ScanRequest(BaseModel):
    target: HttpUrl
    authorized: bool = False
    methods: List[str] = Field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    profile: Literal["focused", "balanced", "full", "comprehensive"] = "comprehensive"
    max_discovered: int = Field(default=100, ge=1, le=500)
    excluded_paths: List[str] = Field(default_factory=list, max_length=100)
    timeout: int = Field(default=10, ge=1, le=60)
    delay: float = Field(default=0.3, ge=0, le=10)
    discovery: bool = True
    smart_order: bool = True
    learning: bool = True
    share_learning: bool = False
    auto_verify: bool = True
    max_response_bytes: int = Field(default=1_000_000, ge=16_384, le=5_000_000)
    max_requests: int = Field(default=2_000, ge=1, le=10_000)

    @field_validator("methods")
    @classmethod
    def read_only_methods(cls, value: List[str]) -> List[str]:
        methods = list(dict.fromkeys(item.upper() for item in value))
        if not methods or any(item not in {"GET", "HEAD", "OPTIONS"} for item in methods):
            raise ValueError("Service scans only GET, HEAD, and OPTIONS")
        return methods

    @field_validator("excluded_paths")
    @classmethod
    def relative_exclusions(cls, value: List[str]) -> List[str]:
        cleaned = []
        for item in value:
            path = item.strip()
            if not path.startswith("/") or "://" in path or any(
                char in path for char in "\r\n"
            ):
                raise ValueError("Excluded paths must be relative URL paths")
            normalized = "/" + path.strip("/")
            if normalized != "/" and normalized not in cleaned:
                cleaned.append(normalized)
        return cleaned


class FeedbackRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    useful: bool


def _save_job(job_id: str, tenant_id: str, target: str, payload: dict) -> None:
    now = _now()
    hostname = urlparse(target).hostname
    if not hostname:
        raise ValueError("Target hostname is required")
    fingerprint = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:24]
    with _connect() as db:
        db.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (job_id, tenant_id, "queued", now, now, fingerprint, json.dumps(payload), None),
        )
        db.execute(
            "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (job_id, tenant_id, "queued", now),
        )


def _reserve_job(job_id: str, tenant_id: str, target: str, payload: dict) -> None:
    """Atomically enforce the tenant quota and insert a queued job."""
    hostname = urlparse(target).hostname
    if not hostname:
        raise ValueError("Target hostname is required")
    cutoff = datetime.now(timezone.utc).timestamp() - _JOB_WINDOW_SECONDS
    now = _now()
    fingerprint = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:24]
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute(
            "SELECT created_at FROM jobs WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        recent = 0
        for row in rows:
            try:
                recent += datetime.fromisoformat(row["created_at"]).timestamp() >= cutoff
            except ValueError:
                continue
        if recent >= _MAX_JOBS_PER_WINDOW:
            raise HTTPException(429, "Job quota exceeded for this tenant")
        db.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (job_id, tenant_id, "queued", now, now, fingerprint, json.dumps(payload), None),
        )
        db.execute(
            "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (job_id, tenant_id, "queued", now),
        )


def _update_job(
    job_id: str,
    state: str,
    result: dict | None = None,
    tenant_id: str | None = None,
) -> None:
    with _connect() as db:
        db.execute(
            "UPDATE jobs SET state = ?, updated_at = ?, result_json = ? WHERE job_id = ?",
            (state, _now(), json.dumps(result) if result is not None else None, job_id),
        )
        if tenant_id is not None:
            db.execute(
                "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (job_id, tenant_id, state, _now()),
            )


def _mark_job_running(job_id: str, tenant_id: str) -> bool:
    now = _now()
    with _connect() as db:
        updated = db.execute(
            "UPDATE jobs SET state = ?, updated_at = ? "
            "WHERE job_id = ? AND tenant_id = ? AND state = 'queued'",
            ("running", now, job_id, tenant_id),
        ).rowcount
        if updated:
            db.execute(
                "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (job_id, tenant_id, "running", now),
            )
    return bool(updated)


def _public_result(scanner: UnauthAccessScanner, results: list) -> dict:
    findings = []
    for result in results:
        if not result.is_finding():
            continue
        findings.append(
            {
                "path": normalize_path(urlparse(result.url).path),
                "method": result.method,
                "status_code": result.status_code,
                "verification_status": result.verification_status,
                "confidence": result.confidence,
                "evidence_score": result.evidence_score,
                "evidence_reasons": result.evidence_reasons,
                "response_size": result.response_size,
            }
        )
    return {
        "total_tested": len(results),
        "accessible": sum(item.accessible for item in results),
        "findings": findings,
        "learning": scanner.learning_summary(),
    }


def _run_job(job_id: str, tenant_id: str, target: str, payload: dict) -> None:
    if not _mark_job_running(job_id, tenant_id):
        return
    try:
        scanner = UnauthAccessScanner(
            ScanConfig(
                base_url=target,
                methods=payload["methods"],
                wordlist_profile=payload["profile"],
                use_wordlist=True,
                max_discovered_paths=payload["max_discovered"],
                excluded_paths=payload.get("excluded_paths", []),
                timeout=payload.get("timeout", 10),
                delay=payload.get("delay", 0.3),
                discovery=payload.get("discovery", True),
                smart_order=payload.get("smart_order", True),
                learning=payload.get("learning", True),
                auto_verify=payload.get("auto_verify", True),
                max_response_bytes=payload.get("max_response_bytes", 1_000_000),
                max_requests=payload.get("max_requests", 2_000),
                learning_namespace=tenant_id,
            )
        )
        results = scanner.run()
        with _connect() as db:
            current = db.execute(
                "SELECT state FROM jobs WHERE job_id = ? AND tenant_id = ?",
                (job_id, tenant_id),
            ).fetchone()
        if current is None or current["state"] == "cancelled":
            return
        if payload.get("share_learning", False):
            LearningStore("https://shared.local", "shared").record_shared(
                (item.url, item.accessible, item.is_finding()) for item in results
            )
        _update_job(
            job_id,
            "completed",
            _public_result(scanner, results),
            tenant_id,
        )
    except Exception as exc:
        with _connect() as db:
            current = db.execute(
                "SELECT state FROM jobs WHERE job_id = ? AND tenant_id = ?",
                (job_id, tenant_id),
            ).fetchone()
        if current is None or current["state"] == "cancelled":
            return
        _update_job(
            job_id,
            "failed",
            {"error": type(exc).__name__},
            tenant_id,
        )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "red-wolf", "version": app.version}


@app.get("/metrics", response_class=Response)
def metrics(_: str = Depends(_require_token)) -> Response:
    counts = _job_counts()
    lines = [
        "# HELP red_wolf_jobs_total Jobs currently retained by state.",
        "# TYPE red_wolf_jobs_total gauge",
    ]
    for state in ("queued", "running", "completed", "failed", "cancelled"):
        lines.append(f'red_wolf_jobs_total{{state="{state}"}} {counts.get(state, 0)}')
    lines.append(
        f"red_wolf_workers_configured {int(os.environ.get('RED_WOLF_WORKERS', '2'))}"
    )
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/readyz")
def readyz() -> dict:
    try:
        with _connect() as db:
            db.execute("SELECT 1").fetchone()
    except sqlite3.Error as exc:
        raise HTTPException(503, "Service database is unavailable") from exc
    if not _configured_tokens():
        raise HTTPException(503, "Service authentication is not configured")
    if not _allowed_hosts():
        raise HTTPException(503, "No target hosts are configured")
    return {"status": "ready", "service": "red-wolf", "version": app.version}


@app.get("/")
def service_info() -> dict:
    return {
        "service": "red-wolf",
        "version": app.version,
        "documentation": "/docs",
        "authorization_required": True,
        "read_only_methods": ["GET", "HEAD", "OPTIONS"],
    }


@app.get("/dashboard", response_class=FileResponse)
def dashboard() -> FileResponse:
    path = Path(__file__).resolve().parent.parent / "assets" / "dashboard.html"
    if not path.is_file():
        raise HTTPException(503, "Dashboard asset is unavailable")
    return FileResponse(path, media_type="text/html")


@app.post("/v1/jobs", status_code=202)
def create_job(request: ScanRequest, tenant_id: str = Depends(_require_token)) -> dict:
    if not request.authorized:
        raise HTTPException(400, "Explicit authorization confirmation is required")
    target = _validate_target(str(request.target))
    job_id = str(uuid.uuid4())
    payload = {
        "methods": request.methods,
        "profile": request.profile,
        "max_discovered": request.max_discovered,
        "excluded_paths": request.excluded_paths,
        "timeout": request.timeout,
        "delay": request.delay,
        "discovery": request.discovery,
        "smart_order": request.smart_order,
        "learning": request.learning,
        "share_learning": request.share_learning,
        "auto_verify": request.auto_verify,
        "max_response_bytes": request.max_response_bytes,
        "max_requests": request.max_requests,
    }
    _reserve_job(job_id, tenant_id, target, payload)
    try:
        _executor.submit(_run_job, job_id, tenant_id, target, payload)
    except RuntimeError as exc:
        _update_job(
            job_id,
            "failed",
            {"error": "worker_unavailable"},
            tenant_id,
        )
        raise HTTPException(503, "Job worker is unavailable") from exc
    return {"job_id": job_id, "state": "queued"}


@app.post("/v1/jobs/{job_id}/cancel")
def cancel_job(job_id: str, tenant_id: str = Depends(_require_token)) -> dict:
    with _connect() as db:
        row = db.execute(
            "SELECT state FROM jobs WHERE job_id = ? AND tenant_id = ?",
            (job_id, tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Job not found")
        if row["state"] in {"completed", "failed", "cancelled"}:
            return {"job_id": job_id, "state": row["state"]}
        db.execute(
            "UPDATE jobs SET state = ?, updated_at = ? WHERE job_id = ? AND tenant_id = ?",
            ("cancelled", _now(), job_id, tenant_id),
        )
        db.execute(
            "INSERT INTO job_events (job_id, tenant_id, event_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (job_id, tenant_id, "cancelled", _now()),
        )
    return {"job_id": job_id, "state": "cancelled"}


@app.get("/v1/jobs/{job_id}")
def get_job(job_id: str, tenant_id: str = Depends(_require_token)) -> dict:
    with _connect() as db:
        row = db.execute(
            "SELECT job_id, state, created_at, updated_at, result_json FROM jobs "
            "WHERE job_id = ? AND tenant_id = ?",
            (job_id, tenant_id),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "Job not found")
    return {
        "job_id": row["job_id"],
        "state": row["state"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "result": json.loads(row["result_json"]) if row["result_json"] else None,
    }


@app.get("/v1/jobs")
def list_jobs(
    tenant_id: str = Depends(_require_token),
    limit: int = Query(default=25, ge=1, le=100),
    state: str | None = Query(default=None),
) -> dict:
    allowed_states = {"queued", "running", "completed", "failed", "cancelled"}
    if state is not None and state not in allowed_states:
        raise HTTPException(400, "Invalid job state")
    query = (
        "SELECT job_id, state, created_at, updated_at FROM jobs "
        "WHERE tenant_id = ?"
    )
    params: list[object] = [tenant_id]
    if state is not None:
        query += " AND state = ?"
        params.append(state)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _connect() as db:
        rows = db.execute(query, params).fetchall()
    return {
        "jobs": [
            {
                "job_id": row["job_id"],
                "state": row["state"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.get("/v1/jobs/{job_id}/events")
def get_job_events(job_id: str, tenant_id: str = Depends(_require_token)) -> dict:
    with _connect() as db:
        job = db.execute(
            "SELECT 1 FROM jobs WHERE job_id = ? AND tenant_id = ?",
            (job_id, tenant_id),
        ).fetchone()
        if job is None:
            raise HTTPException(404, "Job not found")
        rows = db.execute(
            "SELECT event_type, created_at FROM job_events "
            "WHERE job_id = ? AND tenant_id = ? ORDER BY event_id",
            (job_id, tenant_id),
        ).fetchall()
    return {
        "job_id": job_id,
        "events": [
            {"event_type": row["event_type"], "created_at": row["created_at"]}
            for row in rows
        ],
    }


@app.post("/v1/feedback")
def feedback(request: FeedbackRequest, tenant_id: str = Depends(_require_token)) -> dict:
    # tenant_id is intentionally part of the local store namespace.
    if "://" in request.path or any(char in request.path for char in "\r\n"):
        raise HTTPException(400, "Only a relative path is accepted")
    LearningStore("https://tenant.local", tenant_id).add_feedback(request.path, request.useful)
    return {"status": "recorded"}
