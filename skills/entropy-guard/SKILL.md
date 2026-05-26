---
name: entropy-guard
description: "Security pre-check and audit for all tool calls. Calls EntropyGuard to verify commands before execution."
version: 1.0.0
author: EntropyGuard
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, audit, guard, pre-check, safety, entropy]
    related_skills: [red-teaming]
---

# EntropyGuard Security Skill

## When to Use

Trigger when the user asks about security, wants to verify a command, or needs system security status.

## Pre-Check Workflow

Before executing ANY shell command:

1. Load the guard script:
   exec(open(os.path.expanduser(
       os.path.join(os.environ.get("HERMES_HOME", "~/.hermes"),
       "skills/entropy-guard/scripts/guard_check.py")
   )).read())

2. Call: result = guard_precheck("the command")

3. If result["action"] == "block": STOP and tell user why.
   If result["action"] == "allow": proceed.
   If result["status"] == "error": STOP (Fail-Closed).

## Principles

- **Fail-Closed**: EntropyGuard unreachable = refuse all commands.
- **Audit Everything**: Every call logged with SHA-256 hash chain.
- **No Bypass**: Check applies to ALL commands.
