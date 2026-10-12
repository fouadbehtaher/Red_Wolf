"""Small local, privacy-conscious learning store for Red Wolf.

Only path patterns and numeric outcome signals are persisted. Response
bodies, headers, credentials, query values, and complete target URLs are
never written to the store.
"""

import hashlib
import os
import re
import sqlite3
from pathlib import Path
from typing import Dict, Iterable
from urllib.parse import urlparse


def _database_path() -> Path:
    configured = os.environ.get("RED_WOLF_LEARNING_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".red_wolf" / "learning.db"


def _target_key(base_url: str, namespace: str = "") -> str:
    parsed = urlparse(base_url)
    host = (parsed.netloc or parsed.path).lower()
    return hashlib.sha256(f"{namespace}|{host}".encode("utf-8")).hexdigest()[:24]


def normalize_path(path: str) -> str:
    """Turn an endpoint into a reusable, non-sensitive path pattern."""
    parsed = urlparse(path)
    value = parsed.path or path
    value = re.sub(r"/\d+(?=/|$)", "/:id", value)
    value = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/:id", value, flags=re.I)
    value = re.sub(r"/[A-Za-z0-9_-]{24,}(?=/|$)", "/:token", value)
    return value.lower().strip("/") or "/"


class LearningStore:
    """SQLite-backed adaptive ordering and explicit user feedback."""

    def __init__(self, base_url: str, namespace: str = ""):
        self._path = _database_path()
        self._target = _target_key(base_url, namespace)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS path_observations (
                    target_key TEXT NOT NULL,
                    path_pattern TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    accessible INTEGER NOT NULL DEFAULT 0,
                    findings INTEGER NOT NULL DEFAULT 0,
                    useful_votes INTEGER NOT NULL DEFAULT 0,
                    not_useful_votes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (target_key, path_pattern)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self._path), timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def ranking(self) -> Dict[str, float]:
        """Return bounded learned bonuses for target and global patterns."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT path_pattern,
                       SUM(attempts), SUM(accessible), SUM(findings),
                       SUM(useful_votes), SUM(not_useful_votes)
                FROM path_observations
                WHERE target_key IN (?, '*')
                GROUP BY path_pattern
                """,
                (self._target,),
            ).fetchall()
        scores: Dict[str, float] = {}
        for pattern, attempts, accessible, findings, useful, not_useful in rows:
            # Laplace smoothing prevents a single old result dominating.
            value = (
                (findings * 8.0)
                + (accessible * 1.5)
                + (useful * 4.0)
                - (not_useful * 2.0)
            ) / max(attempts + 2, 2)
            scores[pattern] = max(-15.0, min(value, 35.0))
        return scores

    def record(self, observations: Iterable[tuple[str, bool, bool]]) -> None:
        with self._connect() as connection:
            for path, accessible, finding in observations:
                pattern = normalize_path(path)
                self._record_row(connection, self._target, pattern, accessible, finding)
            connection.commit()

    @staticmethod
    def _record_row(connection: sqlite3.Connection, target_key: str, pattern: str,
                    accessible: bool, finding: bool) -> None:
        connection.execute(
            """
            INSERT INTO path_observations
                (target_key, path_pattern, attempts, accessible, findings)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(target_key, path_pattern) DO UPDATE SET
                attempts = attempts + 1,
                accessible = accessible + excluded.accessible,
                findings = findings + excluded.findings
            """,
            (target_key, pattern, int(accessible), int(finding)),
        )

    def record_shared(self, observations: Iterable[tuple[str, bool, bool]]) -> None:
        """Store aggregate path signals without a host or tenant identifier."""
        with self._connect() as connection:
            for path, accessible, finding in observations:
                self._record_row(
                    connection, "*", normalize_path(path), accessible, finding
                )
            connection.commit()

    def add_feedback(self, path: str, useful: bool) -> None:
        column = "useful_votes" if useful else "not_useful_votes"
        with self._connect() as connection:
            connection.execute(
                f"""
                INSERT INTO path_observations (target_key, path_pattern, {column})
                VALUES (?, ?, 1)
                ON CONFLICT(target_key, path_pattern) DO UPDATE SET
                    {column} = {column} + 1
                """,
                (self._target, normalize_path(path)),
            )

    def summary(self) -> dict:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(attempts), 0),
                       COALESCE(SUM(findings), 0)
                FROM path_observations
                WHERE target_key = ?
                """,
                (self._target,),
            ).fetchone()
        return {
            "enabled": True,
            "database": str(self._path),
            "target_specific_patterns": row[0],
            "target_specific_observations": row[1],
            "target_specific_findings": row[2],
        }
