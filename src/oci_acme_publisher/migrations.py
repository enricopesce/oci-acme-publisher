"""Versioned SQLite schema migrations."""

from __future__ import annotations

import sqlite3

from .clock import utc_now_rfc3339

_MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        (
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE operations (
                operation_id TEXT PRIMARY KEY,
                certificate_id TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                state TEXT NOT NULL,
                local_fingerprint TEXT,
                oci_certificate_ocid TEXT,
                oci_version_number INTEGER,
                opc_request_id TEXT,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                error_code TEXT,
                error_message_redacted TEXT
            )
            """,
            """
            CREATE TABLE certificate_state (
                certificate_id TEXT PRIMARY KEY,
                last_local_fingerprint TEXT,
                last_oci_current_fingerprint TEXT,
                last_oci_current_version INTEGER,
                last_successful_renewal_at TEXT,
                last_successful_publication_at TEXT,
                last_successful_audit_at TEXT,
                last_error_code TEXT,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE alert_dedup (
                dedup_key TEXT PRIMARY KEY,
                last_sent_at TEXT NOT NULL,
                last_status TEXT NOT NULL
            )
            """,
            "CREATE INDEX operations_certificate_state ON operations(certificate_id, state)",
        ),
    ),
)


def apply_migrations(connection: sqlite3.Connection) -> None:
    """Apply each schema migration exactly once in one transaction."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_meta "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    applied = {row[0] for row in connection.execute("SELECT version FROM schema_meta")}
    for version, statements in _MIGRATIONS:
        if version in applied:
            continue
        with connection:
            for statement in statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_meta(version, applied_at) VALUES (?, ?)",
                (version, utc_now_rfc3339()),
            )
