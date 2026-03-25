<!-- BlackRoad SEO Enhanced -->

# ulackroad auth manager

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad OS](https://img.shields.io/badge/Org-BlackRoad-OS-2979ff?style=for-the-badge)](https://github.com/BlackRoad-OS)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad auth manager** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


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
