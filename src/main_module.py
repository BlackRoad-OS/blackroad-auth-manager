#!/usr/bin/env python3
"""
blackroad-auth-manager: Auth token lifecycle management.
SHA-256 token hashing, scopes, TTL, revocation.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

DB_PATH = Path.home() / ".blackroad" / "auth-manager.db"
TOKEN_BYTES = 32
ALGORITHM = "sha256"


@dataclass
class Token:
    token_id: str
    subject: str
    scopes: List[str]
    issued_at: str
    expires_at: str
    token_hash: str
    metadata: dict = field(default_factory=dict)
    revoked: bool = False
    db_id: Optional[int] = None


@dataclass
class TokenValidationResult:
    valid: bool
    token: Optional[Token] = None
    error: Optional[str] = None


def get_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT    NOT NULL UNIQUE,
            subject     TEXT    NOT NULL,
            scopes      TEXT    NOT NULL DEFAULT '[]',
            issued_at   TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            token_hash  TEXT    NOT NULL UNIQUE,
            metadata    TEXT    NOT NULL DEFAULT '{}',
            revoked     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS revocation (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT    NOT NULL UNIQUE,
            revoked_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            reason      TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT,
            action      TEXT    NOT NULL,
            subject     TEXT,
            success     INTEGER NOT NULL DEFAULT 1,
            detail      TEXT,
            ts          TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tokens_subject  ON tokens(subject);
        CREATE INDEX IF NOT EXISTS idx_tokens_hash     ON tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_tokens_expires  ON tokens(expires_at);
        CREATE INDEX IF NOT EXISTS idx_revocation_tid  ON revocation(token_id);
    """)
    conn.commit()


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _audit(conn: sqlite3.Connection, action: str, token_id: Optional[str] = None,
           subject: Optional[str] = None, success: bool = True, detail: Optional[str] = None):
    conn.execute(
        "INSERT INTO audit_log(token_id, action, subject, success, detail) VALUES(?,?,?,?,?)",
        (token_id, action, subject, int(success), detail),
    )


def generate_token(
    subject: str,
    scopes: List[str],
    ttl: int = 3600,
    metadata: Optional[dict] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> tuple:
    """
    Generate a new auth token.
    Returns (raw_token_string, Token dataclass).
    The raw_token is shown once; only its SHA-256 hash is stored.
    """
    if not subject:
        raise ValueError("Subject is required")
    if ttl <= 0:
        raise ValueError(f"TTL must be positive, got {ttl}")

    raw_token = secrets.token_hex(TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    now = _now_utc()
    expires = now + timedelta(seconds=ttl)
    token_id = f"tok_{secrets.token_hex(8)}"

    token = Token(
        token_id=token_id,
        subject=subject,
        scopes=list(scopes),
        issued_at=_iso(now),
        expires_at=_iso(expires),
        token_hash=token_hash,
        metadata=metadata or {},
    )

    if conn:
        cur = conn.execute(
            "INSERT INTO tokens(token_id, subject, scopes, issued_at, expires_at, "
            "token_hash, metadata) VALUES(?,?,?,?,?,?,?)",
            (token.token_id, token.subject, json.dumps(token.scopes),
             token.issued_at, token.expires_at, token.token_hash,
             json.dumps(token.metadata)),
        )
        token.db_id = cur.lastrowid
        _audit(conn, "generate", token.token_id, subject)
        conn.commit()

    return raw_token, token


def validate_token(
    token_str: str,
    required_scopes: Optional[List[str]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> TokenValidationResult:
    """Validate a raw token string. Returns TokenValidationResult."""
    token_hash = _hash_token(token_str)

    if not conn:
        return TokenValidationResult(valid=False, error="No database connection")

    row = conn.execute(
        "SELECT * FROM tokens WHERE token_hash=?", (token_hash,)
    ).fetchone()

    if not row:
        if conn:
            _audit(conn, "validate", success=False, detail="Token not found")
            conn.commit()
        return TokenValidationResult(valid=False, error="Token not found")

    token = Token(
        token_id=row["token_id"],
        subject=row["subject"],
        scopes=json.loads(row["scopes"]),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        token_hash=row["token_hash"],
        metadata=json.loads(row["metadata"]),
        revoked=bool(row["revoked"]),
        db_id=row["id"],
    )

    if token.revoked:
        _audit(conn, "validate", token.token_id, token.subject, success=False, detail="Revoked")
        conn.commit()
        return TokenValidationResult(valid=False, token=token, error="Token has been revoked")

    now = _now_utc()
    expires = _parse_iso(token.expires_at)
    if now > expires:
        _audit(conn, "validate", token.token_id, token.subject, success=False, detail="Expired")
        conn.commit()
        return TokenValidationResult(valid=False, token=token, error="Token has expired")

    if required_scopes:
        missing = [s for s in required_scopes if s not in token.scopes]
        if missing:
            detail = f"Missing scopes: {missing}"
            _audit(conn, "validate", token.token_id, token.subject, success=False, detail=detail)
            conn.commit()
            return TokenValidationResult(valid=False, token=token, error=detail)

    _audit(conn, "validate", token.token_id, token.subject, success=True)
    conn.commit()
    return TokenValidationResult(valid=True, token=token)


def revoke_token(
    token_id: str,
    reason: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """Revoke a token by its token_id. Returns True if revoked."""
    if not conn:
        return False

    row = conn.execute("SELECT id FROM tokens WHERE token_id=?", (token_id,)).fetchone()
    if not row:
        return False

    conn.execute("UPDATE tokens SET revoked=1 WHERE token_id=?", (token_id,))
    conn.execute(
        "INSERT OR REPLACE INTO revocation(token_id, reason) VALUES(?,?)",
        (token_id, reason),
    )
    _audit(conn, "revoke", token_id, detail=reason)
    conn.commit()
    return True


def refresh_token(
    token_str: str,
    ttl: int = 3600,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[tuple]:
    """
    Refresh a token: validate, revoke old, issue new with same subject/scopes.
    Returns (new_raw_token, new_Token) or None if invalid.
    """
    result = validate_token(token_str, conn=conn)
    if not result.valid:
        return None

    old_token = result.token
    revoke_token(old_token.token_id, reason="refreshed", conn=conn)
    new_raw, new_token = generate_token(
        subject=old_token.subject,
        scopes=old_token.scopes,
        ttl=ttl,
        metadata=old_token.metadata,
        conn=conn,
    )
    if conn:
        _audit(conn, "refresh", new_token.token_id, old_token.subject,
               detail=f"replaced {old_token.token_id}")
        conn.commit()
    return new_raw, new_token


def list_active_tokens(
    subject: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> List[Token]:
    """List non-revoked, non-expired tokens, optionally filtered by subject."""
    if not conn:
        return []
    now_str = _iso(_now_utc())
    if subject:
        rows = conn.execute(
            "SELECT * FROM tokens WHERE subject=? AND revoked=0 AND expires_at > ? ORDER BY issued_at DESC",
            (subject, now_str),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM tokens WHERE revoked=0 AND expires_at > ? ORDER BY issued_at DESC",
            (now_str,),
        ).fetchall()
    return [Token(
        token_id=r["token_id"], subject=r["subject"],
        scopes=json.loads(r["scopes"]), issued_at=r["issued_at"],
        expires_at=r["expires_at"], token_hash=r["token_hash"],
        metadata=json.loads(r["metadata"]), revoked=bool(r["revoked"]), db_id=r["id"],
    ) for r in rows]


def get_token_by_id(token_id: str, conn: sqlite3.Connection) -> Optional[Token]:
    row = conn.execute("SELECT * FROM tokens WHERE token_id=?", (token_id,)).fetchone()
    if not row:
        return None
    return Token(
        token_id=row["token_id"], subject=row["subject"],
        scopes=json.loads(row["scopes"]), issued_at=row["issued_at"],
        expires_at=row["expires_at"], token_hash=row["token_hash"],
        metadata=json.loads(row["metadata"]), revoked=bool(row["revoked"]), db_id=row["id"],
    )


def purge_expired(conn: sqlite3.Connection) -> int:
    """Delete expired revoked tokens. Returns count deleted."""
    now_str = _iso(_now_utc())
    cur = conn.execute(
        "DELETE FROM tokens WHERE revoked=1 AND expires_at < ?", (now_str,)
    )
    conn.commit()
    return cur.rowcount


def get_audit_log(conn: sqlite3.Connection, limit: int = 50) -> List[dict]:
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def token_stats(conn: sqlite3.Connection) -> dict:
    now_str = _iso(_now_utc())
    total = conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]
    active = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked=0 AND expires_at > ?", (now_str,)
    ).fetchone()[0]
    revoked = conn.execute("SELECT COUNT(*) FROM revocation").fetchone()[0]
    expired = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE expires_at <= ? AND revoked=0", (now_str,)
    ).fetchone()[0]
    return {"total": total, "active": active, "revoked": revoked, "expired": expired}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auth-manager",
                                description="Auth Token Manager - blackroad-auth-manager")
    p.add_argument("--db", default=str(DB_PATH))
    sub = p.add_subparsers(dest="command", required=True)

    # generate
    g = sub.add_parser("generate", help="Generate a new token")
    g.add_argument("subject")
    g.add_argument("--scopes", default="read", help="Comma-separated scopes")
    g.add_argument("--ttl", type=int, default=3600, help="TTL in seconds")
    g.add_argument("--metadata", default="{}")

    # validate
    v = sub.add_parser("validate", help="Validate a token string")
    v.add_argument("token")
    v.add_argument("--scopes", help="Required scopes (comma-separated)")

    # revoke
    r = sub.add_parser("revoke")
    r.add_argument("token_id")
    r.add_argument("--reason")

    # refresh
    rf = sub.add_parser("refresh")
    rf.add_argument("token")
    rf.add_argument("--ttl", type=int, default=3600)

    # list
    ls = sub.add_parser("list", help="List active tokens")
    ls.add_argument("--subject")

    # info
    info = sub.add_parser("info", help="Get token info by ID")
    info.add_argument("token_id")

    # stats
    sub.add_parser("stats")

    # audit
    audit = sub.add_parser("audit")
    audit.add_argument("--limit", type=int, default=20)

    # purge
    sub.add_parser("purge", help="Delete expired revoked tokens")

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    conn = get_db(Path(args.db))

    if args.command == "generate":
        scopes = [s.strip() for s in args.scopes.split(",")]
        metadata = json.loads(args.metadata)
        raw, token = generate_token(args.subject, scopes, ttl=args.ttl,
                                    metadata=metadata, conn=conn)
        print(f"Token ID:  {token.token_id}")
        print(f"Subject:   {token.subject}")
        print(f"Scopes:    {token.scopes}")
        print(f"Expires:   {token.expires_at}")
        print(f"RAW TOKEN: {raw}")
        print("(Save the raw token — it will not be shown again)")

    elif args.command == "validate":
        required = [s.strip() for s in args.scopes.split(",")] if args.scopes else None
        result = validate_token(args.token, required_scopes=required, conn=conn)
        if result.valid:
            t = result.token
            print(f"Valid  subject={t.subject} scopes={t.scopes} expires={t.expires_at}")
        else:
            print(f"Invalid: {result.error}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "revoke":
        if revoke_token(args.token_id, reason=args.reason, conn=conn):
            print(f"Revoked {args.token_id}")
        else:
            print("Token not found", file=sys.stderr); sys.exit(1)

    elif args.command == "refresh":
        result = refresh_token(args.token, ttl=args.ttl, conn=conn)
        if result:
            raw, token = result
            print(f"New Token ID: {token.token_id}")
            print(f"RAW TOKEN:    {raw}")
        else:
            print("Could not refresh token", file=sys.stderr); sys.exit(1)

    elif args.command == "list":
        tokens = list_active_tokens(subject=args.subject, conn=conn)
        if not tokens:
            print("No active tokens.")
        for t in tokens:
            print(f"  {t.token_id}  sub={t.subject:20s} scopes={t.scopes}  exp={t.expires_at[:19]}")

    elif args.command == "info":
        t = get_token_by_id(args.token_id, conn)
        if not t:
            print("Not found", file=sys.stderr); sys.exit(1)
        print(json.dumps({
            "token_id": t.token_id, "subject": t.subject, "scopes": t.scopes,
            "issued_at": t.issued_at, "expires_at": t.expires_at,
            "revoked": t.revoked, "metadata": t.metadata,
        }, indent=2))

    elif args.command == "stats":
        print(json.dumps(token_stats(conn), indent=2))

    elif args.command == "audit":
        for row in get_audit_log(conn, limit=args.limit):
            ok = "+" if row["success"] else "-"
            print(f"[{row['ts'][:19]}] {ok} {row['action']:12s} {row.get('token_id','')[:20]} {row.get('detail','')}")

    elif args.command == "purge":
        n = purge_expired(conn)
        print(f"Purged {n} expired token(s)")


if __name__ == "__main__":
    main()
