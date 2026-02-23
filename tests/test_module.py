"""Tests for blackroad-auth-manager."""
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from main_module import (
    Token, TokenValidationResult, get_db,
    generate_token, validate_token, revoke_token,
    refresh_token, list_active_tokens, get_token_by_id,
    purge_expired, token_stats, get_audit_log, _hash_token,
)


@pytest.fixture
def tmp_db(tmp_path):
    return get_db(tmp_path / "auth_test.db")


def test_generate_token(tmp_db):
    raw, token = generate_token("user:alice", ["read", "write"], ttl=3600, conn=tmp_db)
    assert len(raw) == 64  # 32 bytes = 64 hex chars
    assert token.token_id.startswith("tok_")
    assert token.subject == "user:alice"
    assert "read" in token.scopes
    assert token.db_id is not None


def test_token_hash_stored_not_raw(tmp_db):
    raw, token = generate_token("user:bob", ["read"], conn=tmp_db)
    expected_hash = _hash_token(raw)
    assert token.token_hash == expected_hash
    # Raw should NOT be stored
    row = tmp_db.execute("SELECT token_hash FROM tokens WHERE token_id=?", (token.token_id,)).fetchone()
    assert row["token_hash"] == expected_hash
    assert row["token_hash"] != raw


def test_validate_valid_token(tmp_db):
    raw, token = generate_token("user:carol", ["read"], conn=tmp_db)
    result = validate_token(raw, conn=tmp_db)
    assert result.valid is True
    assert result.token.subject == "user:carol"
    assert result.error is None


def test_validate_wrong_token(tmp_db):
    result = validate_token("invalid_token_string_12345", conn=tmp_db)
    assert result.valid is False
    assert result.error is not None


def test_validate_required_scopes_pass(tmp_db):
    raw, _ = generate_token("user:dave", ["read", "write", "admin"], conn=tmp_db)
    result = validate_token(raw, required_scopes=["read", "write"], conn=tmp_db)
    assert result.valid is True


def test_validate_required_scopes_fail(tmp_db):
    raw, _ = generate_token("user:eve", ["read"], conn=tmp_db)
    result = validate_token(raw, required_scopes=["admin"], conn=tmp_db)
    assert result.valid is False
    assert "Missing scopes" in result.error


def test_revoke_token(tmp_db):
    raw, token = generate_token("user:frank", ["read"], conn=tmp_db)
    assert revoke_token(token.token_id, reason="test revocation", conn=tmp_db) is True
    result = validate_token(raw, conn=tmp_db)
    assert result.valid is False
    assert "revoked" in result.error.lower()


def test_revoke_nonexistent(tmp_db):
    assert revoke_token("tok_doesnotexist", conn=tmp_db) is False


def test_refresh_token(tmp_db):
    raw, old_token = generate_token("user:grace", ["read", "write"], conn=tmp_db)
    result = refresh_token(raw, ttl=7200, conn=tmp_db)
    assert result is not None
    new_raw, new_token = result
    assert new_token.token_id != old_token.token_id
    assert new_token.subject == "user:grace"
    assert set(new_token.scopes) == {"read", "write"}
    # Old token should be revoked
    old_result = validate_token(raw, conn=tmp_db)
    assert old_result.valid is False


def test_refresh_invalid_token(tmp_db):
    result = refresh_token("notavalidtoken123", conn=tmp_db)
    assert result is None


def test_list_active_tokens(tmp_db):
    generate_token("user:henry", ["read"], conn=tmp_db)
    generate_token("user:henry", ["write"], conn=tmp_db)
    generate_token("user:irene", ["admin"], conn=tmp_db)

    henry_tokens = list_active_tokens(subject="user:henry", conn=tmp_db)
    assert len(henry_tokens) == 2

    all_tokens = list_active_tokens(conn=tmp_db)
    assert len(all_tokens) >= 3


def test_token_stats(tmp_db):
    generate_token("user:stats1", ["read"], conn=tmp_db)
    raw2, tok2 = generate_token("user:stats2", ["write"], conn=tmp_db)
    revoke_token(tok2.token_id, conn=tmp_db)

    stats = token_stats(conn=tmp_db)
    assert stats["total"] >= 2
    assert stats["active"] >= 1
    assert stats["revoked"] >= 1


def test_audit_log_written(tmp_db):
    raw, token = generate_token("user:audit", ["read"], conn=tmp_db)
    validate_token(raw, conn=tmp_db)
    revoke_token(token.token_id, conn=tmp_db)

    log = get_audit_log(tmp_db, limit=50)
    actions = [l["action"] for l in log]
    assert "generate" in actions
    assert "validate" in actions
    assert "revoke" in actions


def test_generate_with_metadata(tmp_db):
    raw, token = generate_token(
        "user:meta", ["read"],
        metadata={"ip": "10.0.0.1", "device": "mobile"},
        conn=tmp_db,
    )
    loaded = get_token_by_id(token.token_id, tmp_db)
    assert loaded.metadata["ip"] == "10.0.0.1"
    assert loaded.metadata["device"] == "mobile"


def test_expired_token_invalid(tmp_db):
    raw, token = generate_token("user:expire", ["read"], ttl=1, conn=tmp_db)
    # Manually expire by updating DB
    tmp_db.execute(
        "UPDATE tokens SET expires_at=? WHERE token_id=?",
        ("2000-01-01T00:00:00+00:00", token.token_id),
    )
    tmp_db.commit()
    result = validate_token(raw, conn=tmp_db)
    assert result.valid is False
    assert "expired" in result.error.lower()
