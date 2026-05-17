import re
import socket
import subprocess

def is_valid_ip(value: str, family: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET if family == "v4" else socket.AF_INET6, str(value))
        return True
    except (OSError, ValueError):
        return False

def is_ipv4_literal(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))

def is_ipv6_literal(host: str) -> bool:
    return ":" in host and not is_ipv4_literal(host)

def run(cmd: list[str], timeout: float = 3.0) -> tuple[int, str]:
    try:
        safe_cmd = [str(part) for part in cmd]
        if not safe_cmd:
            raise ValueError("empty command")
        p = subprocess.run(
            safe_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except (OSError, TypeError, ValueError, UnicodeError, IndexError) as e:
        return 1, f"command error: {e}"
