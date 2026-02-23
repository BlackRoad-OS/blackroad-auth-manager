# blackroad-auth-manager

Auth token lifecycle manager for BlackRoad OS.

## Features
- Generate cryptographically secure tokens (secrets.token_hex, 32 bytes)
- SHA-256 hashing — raw token stored nowhere, only hash
- Token scopes (read, write, admin, custom)
- TTL-based expiration with timezone-aware datetime handling
- Revocation with reason tracking
- Token refresh (revoke + reissue with same subject/scopes)
- List active tokens per subject
- Full audit log (generate, validate, revoke, refresh)
- SQLite: `tokens` + `revocation` + `audit_log` tables

## Usage
```bash
# Generate a token (TTL=1 hour)
python src/main_module.py generate user:alice --scopes read,write --ttl 3600

# Validate
python src/main_module.py validate <raw_token>

# Validate with required scopes
python src/main_module.py validate <raw_token> --scopes admin

# Revoke
python src/main_module.py revoke tok_abc123 --reason "security incident"

# Refresh
python src/main_module.py refresh <raw_token> --ttl 7200

# List active tokens
python src/main_module.py list
python src/main_module.py list --subject user:alice

# Stats
python src/main_module.py stats

# Audit log
python src/main_module.py audit --limit 50

# Purge expired tokens
python src/main_module.py purge
```

## Security Design
- Raw tokens are **never stored** — only SHA-256 hash
- Secrets generated with `secrets.token_hex(32)` (CSPRNG)
- All operations written to audit log
- Revocation table prevents race conditions
- Timezone-aware expiry checking

## API
```python
from src.main_module import generate_token, validate_token, revoke_token, get_db

conn = get_db()
raw, token = generate_token("user:alice", ["read", "write"], ttl=3600, conn=conn)

result = validate_token(raw, required_scopes=["read"], conn=conn)
if result.valid:
    print(f"Authenticated: {result.token.subject}")
```

## Testing
```bash
python -m pytest tests/ -v
```
