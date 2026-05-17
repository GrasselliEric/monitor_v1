import re

_CREDENTIAL_REDACT_RES = [
    re.compile(r"(key|token|api[_-]?key|password|secret)=([^&\s\"']+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)([A-Za-z0-9._\-]+)", re.IGNORECASE),
    re.compile(r"(\"(?:webhook|token|api[_-]?key|secret|password)\"\s*:\s*\")([^\"]+)(\")", re.IGNORECASE),
    re.compile(r"([\'\"](?:key|token|api[_-]?key|password|secret)[\'\"]\s*:\s*[\'\"])([^\'\"]+)([\'\"])", re.IGNORECASE),
    re.compile(r"([\/?&]access_token=)([^&\s]+)", re.IGNORECASE),
    re.compile(r"([\/?&]refresh_token=)([^&\s]+)", re.IGNORECASE),
]

def redact_credentials(msg: object) -> str:
    """Remove key/token de URLs/headers/JSON em mensagens de log/erro."""
    if msg is None:
        return ""
    out = str(msg)
    if not out:
        return out
    for rx in _CREDENTIAL_REDACT_RES:
        if rx.groups == 3:
            out = rx.sub(r"\1REDACTED\3", out)
        else:
            out = rx.sub(r"\1REDACTED", out)
    return out
