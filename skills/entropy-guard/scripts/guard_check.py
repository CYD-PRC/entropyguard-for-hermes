import os, json, re
import urllib.request, urllib.error

ENTROPYGUARD_URL = os.environ.get("ENTROPYGUARD_URL", "http://127.0.0.1:8000")
TIMEOUT = 5

# Literal string patterns (checked with `in`, case-insensitive, after whitespace normalization)
DANGEROUS_LITERAL = [
    "rm -rf", "rm -fr", "mkfs", "dd if=", "> /dev/sd",
    "chmod 777", "chmod -r 777", "/etc/shadow", "/etc/passwd",
    "python -c", "python3 -c", "exec(", "eval(",
    "base64 -d", "nc -e", "ncat", "/dev/tcp/",
    "iptables -f", "kill -9 1",
    # FIX A5-01: kernel panic trigger
    "/proc/sysrq-trigger",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
]

# Regex patterns — shell-pipe patterns need proper anchoring
# FIX A1: Use proper pipe-aware regex instead of ambiguous OR
DANGEROUS_REGEX = [
    # curl/wget piped to shell  (shell pipe = literal |, not regex OR)
    r"curl\s+.+\|\s*(bash|sh|python|perl|ruby)",
    r"wget\s+.+\|\s*(bash|sh|python|perl|ruby)",
    r"wget\s+-[^\s]*O\s*-\s+.+\|\s*(bash|sh)",  # wget -O - url | sh
    # Encoded execution bypass
    r"base64\s+-d\s*[|>]",
    r"\$\(.*base64",
    # systemctl stop/disable critical services
    r"systemctl\s+(stop|disable|mask)\s+(sshd|entropyguard|nginx|docker)",
]

# FIX A3: Shell obfuscation normalization
# Strip common shell obfuscation before pattern matching
def normalize_command(cmd):
    """Normalize shell obfuscation techniques."""
    # Remove bash quoting tricks: r''m -> rm, e''cho -> echo
    cmd = re.sub(r"([a-z])''([a-z])", r"\1\2", cmd)
    cmd = re.sub(r"([a-z])\"\"([a-z])", r"\1\2", cmd)
    # Replace $IFS with space (common IFS bypass)
    cmd = re.sub(r"\$\{?IFS\}?", " ", cmd)
    # Remove backslash-newline continuations (multiline obfuscation)
    cmd = cmd.replace("\\\n", " ")
    cmd = cmd.replace("\\\r\n", " ")
    # Collapse multiple spaces
    cmd = re.sub(r"\s+", " ", cmd)
    return cmd.strip()


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

    # FIX A3: Normalize before matching
    cmd_normalized = normalize_command(command)
    cmd_lower = cmd_normalized.lower()

    # Literal pattern checks
    for pattern in DANGEROUS_LITERAL:
        if pattern.lower() in cmd_lower:
            return {"action": "block", "reason": f"Blocked: matches pattern '{pattern}'", "score": score}

    # Regex pattern checks
    for pattern in DANGEROUS_REGEX:
        try:
            if re.search(pattern, cmd_lower):
                return {"action": "block", "reason": f"Blocked: matches regex '{pattern}'", "score": score}
        except re.error:
            pass

    state = guard_state()
    if state.get("status") != "error":
        entropy = state.get("control_entropy", 0)
        if entropy > 0.8:
            return {"action": "block", "reason": f"Entropy too high ({entropy:.2f})", "score": score}

    return {"action": "allow", "reason": "passed all checks", "score": score}
