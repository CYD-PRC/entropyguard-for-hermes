import os, json, re
import urllib.request, urllib.error

ENTROPYGUARD_URL = os.environ.get("ENTROPYGUARD_URL", "http://127.0.0.1:8000")
TIMEOUT = 5

DANGEROUS_PATTERNS = [
    "rm -rf", "rm -fr", "mkfs", "dd if=", "> /dev/sd",
    "chmod 777", "chmod -R 777", "/etc/shadow", "/etc/passwd",
    "curl.*|.*bash", "wget.*|.*sh", "wget.*|.*bash",
    "python -c", "python3 -c", "exec(", "eval(",
    "base64 -d", "nc -e", "ncat", "/dev/tcp/",
    "iptables -F", "systemctl stop", "kill -9 1",
]

def guard_health():
    try:
        req = urllib.request.Request(f"{ENTROPYGUARD_URL}/api/health")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"status": "error", "error": str(e)}

def guard_state():
    try:
        req = urllib.request.Request(f"{ENTROPYGUARD_URL}/api/state")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"status": "error", "error": str(e)}

def guard_precheck(command):
    if not command or not command.strip():
        return {"action": "allow", "reason": "empty command", "score": 100}

    health = guard_health()
    if health.get("status") == "error" or not health.get("checks"):
        return {"action": "block", "reason": "EntropyGuard unavailable (Fail-Closed)", "score": 0}

    if health["checks"].get("entropyguard_process") != "healthy":
        return {"action": "block", "reason": "EntropyGuard process unhealthy", "score": 0}

    score = health.get("score", 0)
    cmd_lower = command.lower().strip()

    for pattern in DANGEROUS_PATTERNS:
        try:
            if re.search(pattern.lower(), cmd_lower):
                return {"action": "block", "reason": f"Blocked: matches pattern '{pattern}'", "score": score}
        except re.error:
            if pattern.lower() in cmd_lower:
                return {"action": "block", "reason": f"Blocked: matches pattern '{pattern}'", "score": score}

    state = guard_state()
    if state.get("status") != "error":
        entropy = state.get("control_entropy", 0)
        if entropy > 0.8:
            return {"action": "block", "reason": f"Entropy too high ({entropy:.2f})", "score": score}

    return {"action": "allow", "reason": "passed all checks", "score": score}
