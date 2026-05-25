# Blocked Command Patterns

| Pattern | Risk | Description |
|---------|------|-------------|
| rm -rf / | Critical | Recursive delete |
| chmod 777 | High | Open permissions |
| curl pipe bash | Critical | Remote code exec |
| base64 -d | Critical | Encoded bypass |
| /etc/shadow | High | Password access |
| iptables -F | Critical | Flush firewall |
| nc -e | Critical | Reverse shell |
| python -c | Medium | Inline code exec |

Fail-Closed: EntropyGuard unreachable = all commands blocked.
