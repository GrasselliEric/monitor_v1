"""Módulos auxiliares do NetWatcher — utilitários de rede, log, alertas e redação."""
__version__ = "1.1.0"

from netwatcher_lib.alert_queue import AlertQueue
from netwatcher_lib.json_utils import DuplicateKeyError, load_json_strict, loads_json_strict
from netwatcher_lib.log_utils import DailyRotatingFileHandler
from netwatcher_lib.network_utils import is_valid_ip, is_ipv4_literal, is_ipv6_literal, run
from netwatcher_lib.redact_utils import redact_credentials

__all__ = [
    "AlertQueue",
    "DuplicateKeyError",
    "DailyRotatingFileHandler",
    "is_valid_ip",
    "is_ipv4_literal",
    "is_ipv6_literal",
    "load_json_strict",
    "loads_json_strict",
    "run",
    "redact_credentials",
]
