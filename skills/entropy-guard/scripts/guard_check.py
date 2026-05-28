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
    "/proc/sysrq-trigger",
    ".ssh/authorized_keys",
    ".ssh/known_hosts",
    # HRT-fix: credential exfiltration patterns
    "curl.*metadata", "wget.*metadata",
    "curl.*169.254", "wget.*169.254",
    "curl.*100.100.100", "wget.*100.100.100",
    # HRT-fix: alias bypass indicators
    "alias ", "unalias ",
]

# Regex patterns
DANGEROUS_REGEX = [
    # curl/wget piped to shell
    r"curl\s+.+\|\s*(bash|sh|python|perl|ruby)",
    r"wget\s+.+\|\s*(bash|sh|python|perl|ruby)",
    r"wget\s+-[^\s]*O\s*-\s+.+\|\s*(bash|sh)",
    # Encoded execution bypass
    r"base64\s+-d\s*[|>]",
    r"\$\(.*base64",
    # systemctl stop/disable critical services
    r"systemctl\s+(stop|disable|mask)\s+(sshd|entropyguard|nginx|docker)",
    # HRT-fix: newline injection — detect \n, $'\n', literal newlines in command
    r"[\n\r]",
    r"\\n",
    r"\$\{?['\"]\\n['\"]?\}",
    # HRT-fix: credential pattern in URLs/commands
    r"(ghp_|gho_|github_pat_)[A-Za-z0-9_]{36,}",
    r"(sk|pk|rk)-[A-Za-z0-9]{32,}",
    # HRT-fix: SSRF to cloud metadata
    r"169\.254\.169\.254",
    r"100\.100\.100\.200",
    r"metadata\.google\.internal",
    r"metadata\.goog",
]

# FIX A3: Shell obfuscation normalization
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
    # HRT-fix: strip literal newlines (newline injection)
    cmd = cmd.replace("\n", " ")
    cmd = cmd.replace("\r", " ")
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

    # HRT-fix: immediate block on newline injection (before any processing)
    if "\n" in command or "\r" in command:
        return {"action": "block", "reason": "Blocked: newline injection detected", "score": 0}

    health = guard_health()
    if health.get("status") == "error" or not health.get("checks"):
        return {"action": "block", "reason": "EntropyGuard unavailable (Fail-Closed)", "score": 0}

    if health["checks"].get("entropyguard_process") != "healthy":
        return {"action": "block", "reason": "EntropyGuard process unhealthy", "score": 0}

    score = health.get("score", 0)

    # Normalize before matching
    cmd_normalized = normalize_command(command)
    cmd_lower = cmd_normalized.lower()

    # HRT-fix: check for residual newlines after normalization
    if "\n" in cmd_normalized or "\r" in cmd_normalized:
        return {"action": "block", "reason": "Blocked: newline injection after normalization", "score": 0}

    # Literal pattern checks
    for pattern in DANGEROUS_LITERAL:
        if pattern.lower() in cmd_lower:
            return {"action": "block", "reason": f"Blocked: matches pattern '{pattern}'", "score": score}

    # Regex pattern checks
    for pattern in DANGEROUS_REGEX:
        try:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                return {"action": "block", "reason": f"Blocked: matches regex '{pattern}'", "score": score}
        except re.error:
            pass

    state = guard_state()
    if state.get("status") != "error":
        entropy = state.get("control_entropy", 0)
        if entropy > 0.8:
            return {"action": "block", "reason": f"Entropy too high ({entropy:.2f})", "score": score}

    return {"action": "allow", "reason": "passed all checks", "score": score}
