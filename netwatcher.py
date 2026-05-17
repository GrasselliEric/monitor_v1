#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import ssl
import time
from collections import deque
from datetime import datetime, timezone
from netwatcher_lib.alert_queue import AlertQueue

from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait, TimeoutError as FuturesTimeoutError, CancelledError
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, TypedDict
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from netwatcher_lib.log_utils import DailyRotatingFileHandler
from netwatcher_lib.network_utils import is_valid_ip, is_ipv4_literal, is_ipv6_literal, run as _run
from netwatcher_lib.json_utils import DuplicateKeyError, load_json_strict, loads_json_strict

# Contexto de log por thread — permite que o formatter estruturado inclua cycle_id
# nos logs emitidos pela thread principal sem poluir os workers do executor.
_log_context: threading.local = threading.local()

# --- Dataclasses de estado e resultado ---
@dataclass
class MonitorState:
    fail_count: int = 0
    alert_active: bool = False
    outage_t0: float | None = None
    incident_thread: str | None = None
    incident_thread_name: str | None = None
    trace_target: 'TraceTarget | None' = None
    incident_future: Future | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

@dataclass
class TestResult:
    ok: bool
    metric: str
    error: str
    target: str
    resolved_ip: str | None = None
    family: str | None = None
    state: str | None = None
    ping_count: int | None = None
    packet_loss_pct: int | None = None

@dataclass
class TraceTarget:
    target: str
    family: str | None = None
    skip_reason: str | None = None


class _ForcedIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection que conecta em IP fixo mantendo SNI no hostname original."""

    def __init__(
        self,
        host: str,
        forced_ip: str,
        port: int | None = None,
        timeout: float = 10.0,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._forced_ip = forced_ip

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self._forced_ip, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host

        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)

# Limites de proteção da fila offline contra crescimento ilimitado em outage prolongado.
MAX_ALERT_QUEUE_SIZE = 5000
ALERT_QUEUE_TTL_SECONDS = 24 * 3600

# Timeout reduzido aplicado a urlopen quando shutdown está em andamento, para
# garantir que o daemon respeite TimeoutStopSec=30 do systemd.
_GCHAT_TIMEOUT_NORMAL = 10.0
_GCHAT_TIMEOUT_SHUTDOWN = 3.0

# Tempo máximo para aguardar conclusão do worker async de incidente antes de
# enviar a mensagem de resolução. Garante que thread_name esteja disponível
# para agrupar no GChat.
_INCIDENT_FUTURE_JOIN_TIMEOUT = 5.0
_TRACE_TIMEOUT_NORMAL = 20.0
_TRACE_TIMEOUT_SHUTDOWN = 4.0
_RETRY_AFTER_MAX_SECONDS = 3600
_MAX_GCHAT_RESPONSE_BYTES = 65_536
_MAX_ALERT_TEXT_CHARS = 3800
_MAX_THREAD_REF_CHARS = 512
_INSECURE_TLS_ENV_FLAG = "NETWATCHER_ENABLE_INSECURE_TLS_FALLBACK"

from netwatcher_lib.redact_utils import redact_credentials as _redact_credentials


class _GChatThread(TypedDict, total=False):
    name: str


class _GChatResponse(TypedDict, total=False):
    thread: _GChatThread


class _RedactingFormatter(logging.Formatter):
    """Formatter que aplica redaction no texto final, incluindo traceback."""

    def format(self, record: logging.LogRecord) -> str:
        return _redact_credentials(super().format(record))


class _PrettyFormatter(logging.Formatter):
    """Formato legível para humanos: dd-mm-yyyy HH:MM:SS:mmm "LEVEL" "message"."""

    def format(self, record: logging.LogRecord) -> str:
        ct = datetime.fromtimestamp(record.created)
        ts = ct.strftime("%d-%m-%Y %H:%M:%S") + f":{int(record.msecs):03d}"
        message = _redact_credentials(record.getMessage())
        line = f'{ts} "{record.levelname}" "{message}"'
        if record.exc_info:
            exc_text = _redact_credentials(self.formatException(record.exc_info))
            line += f'\n  exception: {exc_text}'
        return line


class _JsonRedactingFormatter(logging.Formatter):
    """Formatter estruturado em JSON lines para ingestão por log aggregators (Loki, ELK)."""

    def format(self, record: logging.LogRecord) -> str:
        message = _redact_credentials(record.getMessage())
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "message": message,
            "service_name": "NetWatcher",
            "environment": os.environ.get("NETWATCHER_ENVIRONMENT", "unknown"),
        }
        cycle_id = getattr(_log_context, "cycle_id", None)
        if cycle_id:
            payload["cycle_id"] = cycle_id
            payload["trace_id"] = cycle_id
            payload["correlation_id"] = cycle_id
        if record.exc_info:
            payload["exception"] = _redact_credentials(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class ProbeFutureMeta:
    kind: Literal["domain", "tcp", "infra"]
    label: str
    family: str | None = None
    item: dict[str, Any] | None = None




class NetWatcher:
    def _process_check_result(
        self,
        kind: Literal["domain", "tcp", "infra"],
        label: str,
        err: TestResult | None,
        bundle: dict[str, Any] | None = None,
    ) -> None:
        """
        Processa resultado de checagem para domínios/tcp/infra de forma thread-safe e genérica.
        Atualiza estado, dispara incidentes e resoluções conforme necessário.
        :param kind: Tipo do alvo (domain/tcp/infra)
        :param label: Identificador do alvo
        :param err: Resultado de falha (ou None para sucesso)
        :param bundle: Resultados detalhados (opcional)
        """
        if kind == "domain":
            state = self.dom_states[label]
            max_fails = self._domain_max_fails()
            prefix = "dom"
        elif kind == "tcp":
            state = self.tcp_states[label]
            max_fails = self._tcp_max_fails()
            prefix = "tcp"
        elif kind == "infra":
            state = self.infra_states[label]
            max_fails = self._ping_max_fails()
            prefix = "infra"
        else:
            raise NotImplementedError(f"kind {kind} não implementado ainda")

        tcp_item = self._tcp_item_by_label.get(label) if kind == "tcp" else None

        if err:
            should_open_incident = False
            incident_key = None
            with state.lock:
                state.fail_count += 1
                if state.fail_count == 1:
                    state.outage_t0 = time.time()
                if state.fail_count >= max_fails and not state.alert_active:
                    state.alert_active = True
                    incident_key = self._new_thread_key(prefix, label)
                    state.incident_thread = incident_key
                    should_open_incident = True
            if should_open_incident and incident_key:
                fut = self._handle_incident_async(
                    kind, label, False, bundle, err, item=tcp_item, incident_key=incident_key
                )
                with state.lock:
                    # Em caso de corrida rara (reset entre submit e gravação), só mantém
                    # o future se o incidente ainda estiver ativo para este alvo.
                    if state.alert_active and state.incident_thread == incident_key:
                        state.incident_future = fut
        else:
            with state.lock:
                pending_future = state.incident_future if state.alert_active else None

            self._await_incident_future(pending_future)

            snapshot = None
            with state.lock:
                if state.alert_active:
                    snapshot = {
                        "thread_key": state.incident_thread,
                        "thread_name": state.incident_thread_name,
                        "outage_t0": state.outage_t0,
                        "trace_target": state.trace_target,
                    }
                state.fail_count = 0
                state.alert_active = False
                state.outage_t0 = None
                state.incident_thread = None
                state.trace_target = None
                state.incident_thread_name = None
                state.incident_future = None
            if snapshot is not None:
                self._handle_incident_async(
                    kind, label, True, state_snapshot=snapshot, item=tcp_item
                )
    def __init__(self, config_path: str, dry_run: bool = False):
        """
        Inicializa o NetWatcher carregando configuração, preparando estados e pools de threads.
        :param config_path: Caminho para o arquivo de configuração JSON.
        :param dry_run: Se True, não envia alertas ao GChat.
        """
        self.script_dir = os.path.abspath(os.path.dirname(__file__))
        resolved_config_path = config_path
        if not os.path.isabs(resolved_config_path) and not os.path.exists(resolved_config_path):
            candidate = os.path.join(self.script_dir, resolved_config_path)
            if os.path.exists(candidate):
                resolved_config_path = candidate
        _MAX_CONFIG_BYTES = 1 * 1024 * 1024  # 1 MB
        try:
            config_size = os.path.getsize(resolved_config_path)
        except OSError as exc:
            sys.stderr.write(f"FATAL: Não foi possível ler config ({resolved_config_path}): {exc.strerror}\n")
            sys.exit(2)
        if config_size > _MAX_CONFIG_BYTES:
            sys.stderr.write(
                f"FATAL: Config ({resolved_config_path}) excede limite de 1 MB ({config_size} bytes)\n"
            )
            sys.exit(2)
        try:
            with open(resolved_config_path, "r", encoding="utf-8") as f:
                self.cfg = load_json_strict(f)
        except DuplicateKeyError as exc:
            sys.stderr.write(f"FATAL: Config inválida ({resolved_config_path}): {exc}\n")
            sys.exit(2)
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"FATAL: Config inválida ({resolved_config_path}): JSON malformado em linha {exc.lineno}\n")
            sys.exit(2)
        except UnicodeDecodeError as exc:
            sys.stderr.write(f"FATAL: Config inválida ({resolved_config_path}): encoding inválido ({exc})\n")
            sys.exit(2)
        except RecursionError:
            sys.stderr.write(f"FATAL: Config inválida ({resolved_config_path}): JSON com aninhamento excessivo (provável JSON-bomb)\n")
            sys.exit(2)
        except OSError as exc:
            sys.stderr.write(f"FATAL: Não foi possível ler config ({resolved_config_path}): {exc.strerror}\n")
            sys.exit(2)

        self._validate_config()
        self._resolve_env_placeholders()
        self._validate_webhook_url()
        self._normalize_domains()
        self._verify_system_requirements()

        self.logger = logging.getLogger("NetWatcher")
        self._setup_logging()
        # ... restante da inicialização ...
        self.webhook_url = self._with_gchat_thread_reply_option(self.cfg["webhook_url"])
        self.dry_run = dry_run
        self.alerts_enabled = not dry_run
        self.server_name = platform.node() or "unknown-host"
        self.server_ip = self._get_primary_ip()
        _tz_name = str(self.cfg.get("alert_timezone") or "America/Sao_Paulo")
        try:
            self._alert_tz = ZoneInfo(_tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            self.logger.warning("alert_timezone %r inválido; usando UTC", _tz_name)
            self._alert_tz = ZoneInfo("UTC")

        # Refatoração: encapsula estado de domínio, TCP e infra em dataclasses thread-safe
        self.tcp_checks = self.cfg.get("tcp_checks", [])
        self.dom_states = {d: MonitorState() for d in self._flat_domains}
        self.tcp_states = {}
        self._tcp_item_by_label: dict[str, dict] = {}
        for item in self.tcp_checks:
            label = str(item.get("label") or f"{self._tcp_display_host(item)}:{item['port']}")
            self.tcp_states[label] = MonitorState()
            self._tcp_item_by_label[label] = item
        infra_labels = [i["label"] for i in self.cfg["icmp_targets"]] + ["gateway"]
        self.infra_states = {lbl: MonitorState() for lbl in infra_labels}

        self._alert_executor = ThreadPoolExecutor(max_workers=int(self.cfg.get("alert_workers", 10)), thread_name_prefix="alert")
        # Pool dedicado para traceroutes — limita mtr simultâneos em quedas massivas
        # (cada mtr pode consumir 20s e CPU significativa).
        self._traceroute_executor = ThreadPoolExecutor(max_workers=int(self.cfg.get("traceroute_workers", 3)), thread_name_prefix="trace")
        # Pool reutilizado a cada ciclo para as sondas (evita overhead de spinup/teardown).
        # Dimensionado pelo somatório de tarefas simultâneas no pior caso.
        probe_max = self._estimate_probe_workers()
        self._probe_executor = ThreadPoolExecutor(max_workers=probe_max, thread_name_prefix="probe")
        self._queue_lock = threading.Lock()
        self._queue_cooldown_until = 0.0  # Epoch até quando o envio ao GChat deve aguardar após um 429
        self._alert_dedupe_window_seconds = float(self.cfg.get("alert_dedupe_window_seconds", 60.0))
        self._alert_dedupe_lock = threading.Lock()
        self._recent_alert_fingerprints: dict[str, float] = {}
        self._recent_alert_fingerprint_order: deque[tuple[float, str]] = deque()
        self._active_futures_lock = threading.Lock()
        self._active_alert_futures: set[Future] = set()
        self._active_trace_futures: set[Future] = set()
        self._gchat_ip_cache = {"ip": None, "expiry": 0.0}
        self._gchat_cache_lock = threading.Lock()
        _default_queue_file = os.path.join(self.script_dir, "pending_alerts.json")
        self.queue_file = self.cfg.get("queue_file") or _default_queue_file
        self.alert_queue = AlertQueue(
            self.queue_file,
            ALERT_QUEUE_TTL_SECONDS,
            MAX_ALERT_QUEUE_SIZE,
            save_every_ops=int(self.cfg.get("queue_save_every_ops", 20)),
            save_interval_seconds=float(self.cfg.get("queue_save_interval_seconds", 1.0)),
        )
        self._stop_event = threading.Event()  # Sinalizado por SIGTERM/SIGINT para shutdown gracioso
        self.domain_index = 0

    def _estimate_probe_workers(self) -> int:
        domains_per_cycle = max(1, int(self.cfg.get("domains_per_cycle", 1)))
        icmp_task_count = sum(
            (1 if item.get("ip_v4") else 0) + (1 if item.get("ip_v6") else 0)
            for item in self.cfg.get("icmp_targets", [])
        )
        gw_task_count = 0
        if self.cfg.get("enable_gateway_test", True):
            gw_task_count = 2  # v4 + v6
        tcp_count = len(self.cfg.get("tcp_checks", []))
        return max(2, domains_per_cycle + icmp_task_count + gw_task_count + tcp_count)

    # ------------------------------------------------------------------
    # Validação de configuração e resolução de placeholders de ambiente
    # ------------------------------------------------------------------
    _DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?$")
    _LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

    # Padrões pré-compilados usados nos hot paths de probe (chamados dezenas de vezes por ciclo).
    _RE_IPV4       = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    _RE_TIME_MS    = re.compile(r"time=([0-9.]+) ms")
    _RE_PING_STATS = re.compile(r"(\d+) packets transmitted, (\d+) received,.*?(\d+)% packet loss")
    _RE_LATENCY_STR = re.compile(r"(\d+(?:\.\d+)?ms)")
    _RE_DNS_ANSWER = re.compile(r"ANSWER:\s*(\d+)")
    _RE_DNS_STATUS = re.compile(r"status: ([A-Z]+)")
    _RE_DNS_QTIME  = re.compile(r"Query time: (\d+) msec")
    _RE_SAFE_CHARS = re.compile(r"[^a-z0-9._-]")

    def _validate_config(self) -> None:
        """Valida o schema da config no startup. Sai com código 2 se inválido (impede loop de restart)."""
        cfg = self.cfg
        if not isinstance(cfg, dict):
            sys.stderr.write("FATAL: Config inválida: raiz JSON deve ser objeto (dict).\n")
            sys.exit(2)
        icmp_targets_cfg = cfg.get("icmp_targets")
        icmp_targets: list[Any] = icmp_targets_cfg if isinstance(icmp_targets_cfg, list) else []
        tcp_checks_cfg = cfg.get("tcp_checks")
        tcp_checks: list[Any] = tcp_checks_cfg if isinstance(tcp_checks_cfg, list) else []
        errors: list[str] = []
        _is_int = lambda v: isinstance(v, int) and not isinstance(v, bool)
        _is_number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)

        for key in ("webhook_url", "domains", "icmp_targets", "max_latency_ms"):
            if key not in cfg:
                errors.append(f"Campo obrigatório ausente: '{key}'")

        if "webhook_url" in cfg and not isinstance(cfg["webhook_url"], str):
            errors.append("'webhook_url' deve ser string")
        if "domains" in cfg:
            if not isinstance(cfg["domains"], list) or not cfg["domains"]:
                errors.append("'domains' deve ser lista não-vazia")
            elif len(cfg["domains"]) > 500:
                errors.append("'domains' excede limite seguro de 500 entradas")
            else:
                _valid_domain_ports = {80, 443}
                for i, entry in enumerate(cfg["domains"]):
                    if isinstance(entry, str):
                        d = entry
                    elif isinstance(entry, dict):
                        d = entry.get("domain", "")
                        if not isinstance(d, str) or not d:
                            errors.append(f"domains[{i}]: campo 'domain' ausente ou vazio")
                            continue
                        ports = entry.get("ports")
                        if ports is not None:
                            if not isinstance(ports, list):
                                errors.append(f"domains[{i}] ({d!r}): 'ports' deve ser lista (ex: [80, 443], [443], [])")
                            else:
                                for p in ports:
                                    if not _is_int(p) or p not in _valid_domain_ports:
                                        errors.append(f"domains[{i}] ({d!r}): porta inválida {p!r} — aceita: 80, 443")
                    else:
                        errors.append(f"domains[{i}]: deve ser string ou objeto {{\"domain\": ..., \"ports\": [...]}}, recebido: {type(entry).__name__}")
                        continue
                    if len(d) > 255:
                        errors.append(f"domains[{i}]: domínio excede limite de 255 caracteres")
                        continue
                    if not self._DOMAIN_RE.match(d) or d.startswith("-"):
                        errors.append(f"Domínio inválido: {d!r}")
        if "icmp_targets" in cfg:
            if not isinstance(cfg["icmp_targets"], list):
                errors.append("'icmp_targets' deve ser lista")
            elif len(cfg["icmp_targets"]) > 200:
                errors.append("'icmp_targets' excede limite seguro de 200 entradas")
            else:
                for i, item in enumerate(icmp_targets):
                    if not isinstance(item, dict) or "label" not in item:
                        errors.append(f"icmp_targets[{i}]: precisa de 'label'")
                        continue
                    if not isinstance(item["label"], str) or not self._LABEL_RE.match(item["label"]):
                        errors.append(f"icmp_targets[{i}].label inválido: {item['label']!r}")
                    if "ip_v4" not in item and "ip_v6" not in item:
                        errors.append(f"icmp_targets[{i}]: precisa de ip_v4 e/ou ip_v6")
                    for k in ("ip_v4", "ip_v6"):
                        if k in item:
                            if not isinstance(item[k], str):
                                errors.append(f"icmp_targets[{i}].{k} deve ser string")
                            elif not is_valid_ip(item[k], k[-2:]):
                                errors.append(f"icmp_targets[{i}].{k} inválido: {item[k]!r}")
        if "tcp_checks" in cfg and not isinstance(cfg["tcp_checks"], list):
            errors.append("'tcp_checks' deve ser lista")
        elif "tcp_checks" in cfg and isinstance(cfg["tcp_checks"], list) and len(cfg["tcp_checks"]) > 500:
            errors.append("'tcp_checks' excede limite seguro de 500 entradas")
        elif "tcp_checks" in cfg and isinstance(cfg["tcp_checks"], list):
            for i, item in enumerate(tcp_checks):
                if not isinstance(item, dict):
                    errors.append(f"tcp_checks[{i}]: deve ser objeto")
                    continue
                for k in ("label", "port"):
                    if k not in item:
                        errors.append(f"tcp_checks[{i}]: campo '{k}' ausente")
                if "label" in item and (not isinstance(item["label"], str) or not self._LABEL_RE.match(item["label"])):
                    errors.append(f"tcp_checks[{i}].label inválido: {item['label']!r}")
                _tcp_host_fields = ("host", "hostva", "hostv4", "hostv6")
                _present_host_fields = [k for k in _tcp_host_fields if k in item]
                if not _present_host_fields:
                    errors.append(f"tcp_checks[{i}]: informe ao menos um host ({', '.join(_tcp_host_fields)})")

                valid_hosts: dict[str, str] = {}
                for hk in _present_host_fields:
                    if not isinstance(item[hk], str):
                        errors.append(f"tcp_checks[{i}].{hk} deve ser string")
                        continue
                    h = item[hk]
                    if not h:
                        errors.append(f"tcp_checks[{i}].{hk} não pode ser vazio")
                        continue
                    if len(h) > 255:
                        errors.append(f"tcp_checks[{i}].{hk} excede limite de 255 caracteres")
                        continue
                    if h.startswith("-") or not (self._DOMAIN_RE.match(h) or is_valid_ip(h, "v4") or is_valid_ip(h, "v6")):
                        errors.append(f"tcp_checks[{i}].{hk} inválido: {h!r}")
                        continue
                    valid_hosts[hk] = h

                if "hostv4" in valid_hosts and is_ipv6_literal(valid_hosts["hostv4"]):
                    errors.append(f"tcp_checks[{i}].hostv4 não pode ser literal IPv6")
                if "hostv6" in valid_hosts and is_ipv4_literal(valid_hosts["hostv6"]):
                    errors.append(f"tcp_checks[{i}].hostv6 não pode ser literal IPv4")

                family_mode = self._tcp_family_mode(item)
                if family_mode not in ("v4", "v6", "dualstack"):
                    errors.append(
                        f"tcp_checks[{i}].family deve ser 'v4', 'v6' ou 'dualstack' "
                        f"(aceita também 'ipv4', 'ipv6', 'dual'), recebido: {item.get('family')!r}"
                    )
                base_host = valid_hosts.get("hostva") or valid_hosts.get("host")
                host_v4 = valid_hosts.get("hostv4") or base_host
                host_v6 = valid_hosts.get("hostv6") or base_host
                if family_mode == "v4" and not host_v4:
                    errors.append(f"tcp_checks[{i}]: family=v4 exige hostv4, hostva ou host")
                elif family_mode == "v6" and not host_v6:
                    errors.append(f"tcp_checks[{i}]: family=v6 exige hostv6, hostva ou host")
                elif family_mode == "dualstack" and (not host_v4 or not host_v6):
                    errors.append(
                        f"tcp_checks[{i}]: family=dualstack exige host para v4 e v6 "
                        f"(use hostva/host ou hostv4+hostv6)"
                    )
                if "port" in item:
                    p = item["port"]
                    if not _is_int(p) or not (1 <= p <= 65535):
                        errors.append(f"tcp_checks[{i}].port inválido: {p!r}")

        # Unicidade de labels: colisão corrompe o state-machine de incidentes.
        # "gateway" é label reservado usado internamente pelo runtime.
        _RESERVED_LABELS = {"gateway"}
        icmp_labels = [
            str(item["label"])
            for item in icmp_targets
            if isinstance(item, dict) and "label" in item
        ]
        if len(icmp_labels) != len(set(icmp_labels)):
            errors.append("'icmp_targets': labels duplicados detectados")
        reserved_collision = _RESERVED_LABELS & set(icmp_labels)
        if reserved_collision:
            errors.append(f"'icmp_targets': label(s) reservado(s) em uso: {sorted(reserved_collision)}")
        tcp_labels = [
            str(item["label"])
            for item in tcp_checks
            if isinstance(item, dict) and "label" in item
        ]
        if len(tcp_labels) != len(set(tcp_labels)):
            errors.append("'tcp_checks': labels duplicados detectados")

        _TRACEROUTE_ALLOWLIST = {"mtr", "traceroute", "tracepath"}
        _TRACEROUTE_ARG_RE = re.compile(r"^[-a-zA-Z0-9._]+$")
        tc = cfg.get("traceroute_cmd")
        if tc is not None:
            if not isinstance(tc, list) or not tc:
                errors.append("'traceroute_cmd' deve ser lista não-vazia")
            elif len(tc) > 16:
                errors.append("'traceroute_cmd' excede limite seguro de 16 argumentos")
            else:
                bin_name = os.path.basename(str(tc[0]))
                if bin_name not in _TRACEROUTE_ALLOWLIST:
                    errors.append(
                        f"'traceroute_cmd[0]' binário não permitido: {tc[0]!r} "
                        f"(aceitos: {', '.join(sorted(_TRACEROUTE_ALLOWLIST))})"
                    )
                for i, arg in enumerate(tc[1:], 1):
                    if not isinstance(arg, str) or not _TRACEROUTE_ARG_RE.match(arg):
                        errors.append(f"'traceroute_cmd[{i}]' argumento inválido: {arg!r}")
                    elif len(arg) > 64:
                        errors.append(f"'traceroute_cmd[{i}]' excede tamanho máximo de 64 caracteres")

        for k in (
            "max_fails",
            "domain_max_fails",
            "tcp_max_fails",
            "ping_max_fails",
            "domains_per_cycle",
            "icmp_count",
            "max_queue_drain_per_cycle",
            "queue_save_every_ops",
            "alert_workers",
            "traceroute_workers",
            "probe_timeout_seconds",
        ):
            v = cfg.get(k)
            if v is not None and (not _is_int(v) or v < 1):
                errors.append(f"'{k}' deve ser inteiro >= 1, recebido: {v!r}")
        v = cfg.get("max_latency_ms")
        if v is not None and (not _is_int(v) or v < 50):
            errors.append(f"'max_latency_ms' deve ser inteiro >= 50, recebido: {v!r}")
        _WORKER_LIMITS: dict[str, int] = {"alert_workers": 50, "traceroute_workers": 10, "domains_per_cycle": 30}
        for wk, wmax in _WORKER_LIMITS.items():
            wv = cfg.get(wk)
            if wv is not None and _is_int(wv) and wv > wmax:
                errors.append(f"'{wk}' excede limite seguro de {wmax}, recebido: {wv!r}")
        v = cfg.get("probe_timeout_seconds")
        if v is not None and _is_int(v) and v > 300:
            errors.append(f"'probe_timeout_seconds' excede limite seguro de 300s, recebido: {v!r}")
        v = cfg.get("loop_interval_seconds")
        if v is not None and (not _is_number(v) or v <= 0):
            errors.append(f"'loop_interval_seconds' deve ser número > 0, recebido: {v!r}")
        v = cfg.get("queue_save_interval_seconds")
        if v is not None and (not _is_number(v) or v < 0):
            errors.append(f"'queue_save_interval_seconds' deve ser número >= 0, recebido: {v!r}")
        v = cfg.get("alert_dedupe_window_seconds")
        if v is not None and (not _is_number(v) or v < 0):
            errors.append(f"'alert_dedupe_window_seconds' deve ser número >= 0, recebido: {v!r}")
        v = cfg.get("traceroute_timeout_seconds")
        if v is not None and (not _is_number(v) or v <= 0):
            errors.append(f"'traceroute_timeout_seconds' deve ser número > 0, recebido: {v!r}")
        v = cfg.get("traceroute_timeout_shutdown_seconds")
        if v is not None and (not _is_number(v) or v <= 0):
            errors.append(f"'traceroute_timeout_shutdown_seconds' deve ser número > 0, recebido: {v!r}")
        ll = cfg.get("log_level")
        if ll is not None and (not isinstance(ll, str) or ll.lower() not in ("debug", "info", "warning", "error")):
            errors.append(f"'log_level' deve ser 'debug', 'info', 'warning' ou 'error', recebido: {ll!r}")

        dtm = cfg.get("domain_test_mode")
        if dtm is not None:
            normalized = self._DOMAIN_TEST_MODE_ALIASES.get(str(dtm).lower(), str(dtm).lower())
            if normalized not in ("v4", "v6", "dualstack"):
                errors.append(f"'domain_test_mode' deve ser 'v4', 'v6' ou 'dualstack' (aceita também 'ipv4', 'ipv6', 'dual'), recebido: {dtm!r}")

        for k in (
            "allow_insecure_redundant_tls",
            "alert_on_dns_failure",
            "dns_random_subdomain",
            "enable_gateway_test",
            "enable_traceroute_on_fail",
            "log_infra_each_domain",
            "require_ipv6",
            "structured_logs",
        ):
            v = cfg.get(k)
            if v is not None and not isinstance(v, bool):
                errors.append(f"'{k}' deve ser booleano, recebido: {v!r}")

        for k in ("log_dir", "queue_file"):
            v = cfg.get(k)
            if v is not None and not isinstance(v, str):
                errors.append(f"'{k}' deve ser string, recebido: {type(v).__name__}")
            elif isinstance(v, str):
                if len(v) > 1024:
                    errors.append(f"'{k}' excede limite de 1024 caracteres")
                if any(ord(ch) < 32 for ch in v):
                    errors.append(f"'{k}' contém caracteres de controle inválidos")

        if errors:
            sys.stderr.write("FATAL: Config inválida:\n  - " + "\n  - ".join(errors) + "\n")
            sys.exit(2)


    _ENV_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
    _ENV_RESOLVABLE_KEYS = {"webhook_url"}
    _WEBHOOK_ALLOWED_HOSTS = {"chat.googleapis.com"}

    def _resolve_env_placeholders(self) -> None:
        """Substitui valores no formato ${ENV_VAR} pelo conteúdo da variável de ambiente.
        Permite manter o webhook fora do JSON commitado (segurança).
        Aplica-se apenas a chaves de topo de _ENV_RESOLVABLE_KEYS para evitar substituições
        não-intencionais em nomes de host."""
        for key in self._ENV_RESOLVABLE_KEYS:
            value = self.cfg.get(key)
            if not isinstance(value, str):
                continue
            m = self._ENV_PLACEHOLDER_RE.match(value)
            if not m:
                continue
            var = m.group(1)
            resolved = os.environ.get(var)
            if not resolved:
                sys.stderr.write(f"FATAL: '{key}' referencia ${{{var}}} mas a variável de ambiente não está definida.\n")
                sys.exit(2)
            self.cfg[key] = resolved

    def _validate_webhook_url(self) -> None:
        """Validação fail-fast de URL do webhook após resolução de placeholders."""
        raw = self.cfg.get("webhook_url")
        if not isinstance(raw, str):
            sys.stderr.write("FATAL: 'webhook_url' deve ser string.\n")
            sys.exit(2)
        if len(raw) > 4096:
            sys.stderr.write("FATAL: 'webhook_url' excede limite de 4096 caracteres.\n")
            sys.exit(2)
        if any(ch.isspace() for ch in raw):
            sys.stderr.write("FATAL: 'webhook_url' contém whitespace inválido.\n")
            sys.exit(2)
        if any(ord(ch) < 32 for ch in raw):
            sys.stderr.write("FATAL: 'webhook_url' contém caracteres de controle inválidos.\n")
            sys.exit(2)
        try:
            parts = urlsplit(raw)
            # Força validação de porta (urlsplit pode atrasar o ValueError para accesso .port).
            _ = parts.port
        except ValueError as exc:
            sys.stderr.write(f"FATAL: 'webhook_url' inválida: {exc}\n")
            sys.exit(2)
        if parts.scheme.lower() != "https":
            sys.stderr.write("FATAL: 'webhook_url' deve usar esquema https.\n")
            sys.exit(2)
        if parts.username is not None or parts.password is not None:
            sys.stderr.write("FATAL: 'webhook_url' não deve conter credenciais no netloc.\n")
            sys.exit(2)
        if not parts.hostname:
            sys.stderr.write("FATAL: 'webhook_url' sem hostname.\n")
            sys.exit(2)
        if parts.hostname.lower() not in self._WEBHOOK_ALLOWED_HOSTS:
            sys.stderr.write(
                "FATAL: 'webhook_url' hostname não permitido. Use chat.googleapis.com.\n"
            )
            sys.exit(2)
        if parts.fragment:
            sys.stderr.write("FATAL: 'webhook_url' não deve conter fragment (#...).\n")
            sys.exit(2)
        if not parts.path.startswith("/v1/spaces/") or not parts.path.endswith("/messages"):
            sys.stderr.write(
                "FATAL: 'webhook_url' inválida: path esperado '/v1/spaces/.../messages'.\n"
            )
            sys.exit(2)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        query_counts: dict[str, int] = {}
        query_values: dict[str, str] = {}
        for key, value in query_pairs:
            query_counts[key] = query_counts.get(key, 0) + 1
            if key not in query_values:
                query_values[key] = value
        if query_counts.get("key", 0) != 1 or not query_values.get("key"):
            sys.stderr.write("FATAL: 'webhook_url' inválida: parâmetro 'key' ausente/inválido.\n")
            sys.exit(2)
        if query_counts.get("token", 0) != 1 or not query_values.get("token"):
            sys.stderr.write("FATAL: 'webhook_url' inválida: parâmetro 'token' ausente/inválido.\n")
            sys.exit(2)
        for p in ("key", "token"):
            value = query_values[p]
            if len(value) > 2048:
                sys.stderr.write(f"FATAL: 'webhook_url' inválida: parâmetro '{p}' excede 2048 caracteres.\n")
                sys.exit(2)
            if any(ch.isspace() for ch in value) or any(ord(ch) < 32 for ch in value):
                sys.stderr.write(
                    f"FATAL: 'webhook_url' inválida: parâmetro '{p}' contém whitespace/controle.\n"
                )
                sys.exit(2)

    _DOMAIN_DEFAULT_PORTS = [80, 443]

    def _normalize_domains(self) -> None:
        """Normaliza a lista de domínios em estruturas internas, sem mutar self.cfg.

        - self._domain_ports: mapa domínio -> portas habilitadas.
        - self._flat_domains: lista plana de domínios (str), preservando ordem.
        """
        self._domain_ports = {}
        flat: list[str] = []
        for entry in self.cfg.get("domains", []):
            if isinstance(entry, str):
                flat.append(entry)
                self._domain_ports[entry] = self._DOMAIN_DEFAULT_PORTS
            elif isinstance(entry, dict):
                dom = entry["domain"]
                ports = entry.get("ports", self._DOMAIN_DEFAULT_PORTS)
                flat.append(dom)
                self._domain_ports[dom] = sorted(set(ports))
        self._flat_domains = flat

    def _verify_system_requirements(self) -> None:
        self._ping_bin_v4 = "ping"
        self._ping_bin_v6 = "ping6" if shutil.which("ping6") else "ping"

        required = ["dig", "ping", "ip"]
        if self.cfg.get("enable_traceroute_on_fail", True):
            trace_cmd = self.cfg.get("traceroute_cmd", ["mtr"])
            trace_bin = os.path.basename(str(trace_cmd[0])) if isinstance(trace_cmd, list) and trace_cmd else "mtr"
            required.append(trace_bin)
        missing = [cmd for cmd in required if shutil.which(cmd) is None]
        if missing:
            sys.stderr.write(f"FATAL: Dependências ausentes: {', '.join(missing)}. Instale-as antes de rodar o NetWatcher.\n")
            sys.exit(1)

    def _setup_logging(self) -> None:
        log_dir = self.cfg.get("log_dir", self.script_dir)
        if not os.path.isabs(log_dir):
            log_dir = os.path.join(self.script_dir, log_dir)

        _LEVEL_MAP = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
        level = _LEVEL_MAP.get((self.cfg.get("log_level") or "info").lower(), logging.INFO)
        self.logger.setLevel(level)
        self.logger.propagate = False
        # Evita duplicidade de handlers e fecha fds antigos em reinicializações.
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
            try:
                handler.close()
            except OSError:
                pass

        if self.cfg.get("structured_logs", False):
            file_formatter: logging.Formatter = _JsonRedactingFormatter()
        else:
            file_formatter = _PrettyFormatter()

        try:
            os.makedirs(log_dir, exist_ok=True)
            handler = DailyRotatingFileHandler(log_dir, prefix="monitor", backup_count=7, encoding="utf-8")
            handler.setFormatter(file_formatter)
            self.logger.addHandler(handler)
        except OSError as exc:
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(file_formatter)
            self.logger.addHandler(stream_handler)
            self.logger.warning("Falha ao criar diretório de log %s: %s", log_dir, exc)

    def _log(self, msg: str, *args: Any) -> None:
        self.logger.info(msg, *args)

    def _log_debug(self, msg: str, *args: Any) -> None:
        self.logger.debug(msg, *args)

    def _log_warn(self, msg: str, *args: Any) -> None:
        self.logger.warning(msg, *args)

    def _log_error(self, msg: str, *args: Any) -> None:
        self.logger.error(msg, *args)

    def _get_primary_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except (OSError, socket.error):
            self.logger.debug("Não foi possível detectar o IP primário.")
            return "0.0.0.0"


    def _with_gchat_thread_reply_option(self, url: str) -> str:
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.setdefault("messageReplyOption", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    def _family_name(self, family: str | None) -> str:
        if family == "v6":
            return "IPv6"
        if family == "v4":
            return "IPv4"
        return "IP"

    _TCP_FAMILY_ALIASES = {"ipv4": "v4", "ipv6": "v6", "dual": "dualstack"}

    def _tcp_family_mode(self, item: dict[str, Any]) -> str:
        raw = str(item.get("family", "dualstack")).lower()
        return self._TCP_FAMILY_ALIASES.get(raw, raw)

    def _tcp_base_host(self, item: dict[str, Any]) -> str | None:
        for key in ("hostva", "host"):
            value = item.get(key)
            if value is None:
                continue
            return str(value)
        return None

    def _tcp_host_for_family(self, item: dict[str, Any], family: str) -> str | None:
        if family == "v4":
            v4_host = item.get("hostv4")
            if v4_host is not None:
                return str(v4_host)
        elif family == "v6":
            v6_host = item.get("hostv6")
            if v6_host is not None:
                return str(v6_host)
        return self._tcp_base_host(item)

    def _tcp_display_host(self, item: dict[str, Any], family: str | None = None) -> str:
        if family in ("v4", "v6"):
            family_host = self._tcp_host_for_family(item, family)
            if family_host:
                return family_host
        base_host = self._tcp_base_host(item)
        if base_host:
            return base_host
        for key in ("hostv4", "hostv6"):
            value = item.get(key)
            if value:
                return str(value)
        return "?"

    def _resolve_domain_ips(self, domain: str) -> dict[str, list[str]]:
        resolved = {"v4": [], "v6": []}
        for family in ["v4", "v6"]:
            rr = "A" if family == "v4" else "AAAA"
            code, out = _run(["dig", domain, rr, "+short", "+time=1", "+tries=1"], timeout=1.5)
            if code == 0:
                for line in out.strip().splitlines():
                    candidate = line.strip()
                    if family == "v4" and is_valid_ip(candidate, "v4"):
                        resolved[family].append(candidate)
                    elif family == "v6" and is_valid_ip(candidate, "v6"):
                        resolved[family].append(candidate)
        return resolved

    def _format_ip_list(self, ips: list[str]) -> str:
        if not ips:
            return "nao resolvido"
        shown = ips[:3]
        suffix = f" (+{len(ips) - len(shown)})" if len(ips) > len(shown) else ""
        return ", ".join(shown) + suffix

    def _format_domain_ip_summary(self, resolved_ips: dict[str, list[str]]) -> str:
        return (
            f"IPv4: {self._format_ip_list(resolved_ips['v4'])} | "
            f"IPv6: {self._format_ip_list(resolved_ips['v6'])}"
        )

    def _result_state(self, result: TestResult) -> str:
        return result.state or ("OK" if result.ok else "FAIL")

    def _format_probe(self, name: str, result: TestResult, target: str | None = None) -> str:
        actual_target = target or result.target
        ip_part = f",ip={result.resolved_ip}" if result.resolved_ip else ""
        return f"{name}[target={actual_target}{ip_part},status={self._result_state(result)},metric={result.metric}]"

    def _probe_summary(self, name: str, result: TestResult) -> str:
        return f"{name}={result.metric}"

    def _family_summary(self, family: str, dns: TestResult, tcp80: TestResult, tcp443: TestResult, tested_ip: str) -> str:
        return (
            f"{family}=[{dns.metric} "
            f"{tcp80.metric} "
            f"{tcp443.metric}] "
            f"IP testado={family}:{tested_ip}"
        )

    def _tested_ip(self, tcp80: TestResult, tcp443: TestResult) -> str:
        return tcp80.resolved_ip or tcp443.resolved_ip or "nao resolvido"

    def _latency_text(self, result: TestResult) -> str:
        m = self._RE_LATENCY_STR.search(result.metric)
        return m.group(1) if m else result.metric

    def _parse_ping_stats(self, output: str) -> tuple[int, int, int | None]:
        transmitted = 1
        received = 1
        loss = 0
        m = self._RE_PING_STATS.search(output)
        if m:
            transmitted = int(m.group(1))
            received = int(m.group(2))
            loss = int(m.group(3))
        return transmitted, received, loss

    def _icmp_log_line(self, label: str, result: TestResult, fail_count: int, fail_limit: int) -> str:
        ip = result.resolved_ip or result.target
        if result.state == "SKIP" and ip == result.target:
            ip = "N/A"
        ping_count = result.ping_count if result.ping_count is not None else 1
        loss_pct = result.packet_loss_pct if result.packet_loss_pct is not None else 0
        return (
            f"{label} IP testado ip={ip},status={self._result_state(result)},fails={fail_count}/{fail_limit},"
            f"latencia {self._latency_text(result)}, icmp: {ping_count}, lost: {loss_pct}%"
        )

    def _dns_answer_count(self, output: str) -> int | None:
        m = self._RE_DNS_ANSWER.search(output)
        return int(m.group(1)) if m else None

    def _test_dns(self, domain: str, family: str) -> TestResult:
        random_subdomain = self.cfg.get("dns_random_subdomain", True)
        if random_subdomain:
            prefix = secrets.token_hex(2)
            fqdn = f"{prefix}.{domain}"
        else:
            fqdn = domain
        rr = "A" if family == "v4" else "AAAA"
        # Timeout reduzido para o dig não segurar o pool por muito tempo
        code, out = _run(["dig", "+time=1", "+tries=1", fqdn, rr, "+stats"], timeout=2.0)
        if code != 0:
            return TestResult(False, f"DNS-{family} FAIL", f"DNS {family} command failed", fqdn, family=family)

        # Tenta extrair o IP resolvido para passar para o TCP
        ip_match = re.search(fr"^{re.escape(fqdn)}\.\s+\d+\s+IN\s+{rr}\s+([^\s]+)", out, re.MULTILINE)
        resolved_ip = ip_match.group(1) if ip_match else None

        status = self._RE_DNS_STATUS.search(out)
        if not status:
            return TestResult(False, f"DNS-{family} FAIL", f"DNS {family} status missing", fqdn, family=family, resolved_ip=resolved_ip)

        status_name = status.group(1)
        valid_statuses = {"NOERROR", "NXDOMAIN"} if random_subdomain else {"NOERROR"}
        if status_name not in valid_statuses:
            return TestResult(False, f"DNS-{family} FAIL", f"DNS {family} status {status_name}", fqdn, family=family, resolved_ip=resolved_ip)

        m = self._RE_DNS_QTIME.search(out)
        if not m:
            return TestResult(False, f"DNS-{family} FAIL", f"DNS {family} resolution failed", fqdn, family=family, resolved_ip=resolved_ip)

        latency = int(m.group(1))
        max_ms = self.cfg["max_latency_ms"]
        answer_count = self._dns_answer_count(out)

        status_disp = f"rand-{status_name}" if random_subdomain else status_name
        metric_label = f"DNS-{family} {status_disp} {latency}ms"

        if (
            not random_subdomain
            and status_name == "NOERROR"
            and answer_count == 0
            and family == "v6"
            and not self.cfg.get("require_ipv6", False)
        ):
            return TestResult(True, f"DNS-{family} SKIP sem AAAA {latency}ms", "", fqdn, family=family, state="SKIP", resolved_ip=resolved_ip)
        if not random_subdomain and status_name == "NOERROR" and answer_count == 0:
            return TestResult(False, f"DNS-{family} FAIL", f"DNS {family} sem resposta {rr}", fqdn, family=family, resolved_ip=resolved_ip)
        if latency > max_ms:
            return TestResult(False, metric_label, f"DNS {family} latency {latency}ms > {max_ms}ms", fqdn, family=family, resolved_ip=resolved_ip)
        return TestResult(True, metric_label, "", fqdn, family=family, resolved_ip=resolved_ip)

    def _quick_resolve(self, host: str, family: str) -> str | None:
        """Resolve IP via dig com timeout agressivo para evitar hang do socket.getaddrinfo."""
        rr = "A" if family == "v4" else "AAAA"
        code, out = _run(["dig", host, rr, "+short", "+time=1", "+tries=1"], timeout=1.5)
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                candidate = line.strip()
                if family == "v4" and is_valid_ip(candidate, "v4"):
                    return candidate
                if family == "v6" and is_valid_ip(candidate, "v6"):
                    return candidate
        return None

    def _test_tcp(self, host: str, port: int, family: str, resolved_ip: str | None = None) -> TestResult:
        af = socket.AF_INET if family == "v4" else socket.AF_INET6
        t0 = time.time()

        if not resolved_ip:
            # Evita o hang do getaddrinfo (timeout de OS de 20s+) usando resolução controlada
            resolved_ip = self._quick_resolve(host, family)

        if not resolved_ip:
            return self._tcp_no_address_result(host, port, family)

        sockaddr = (resolved_ip, port)
        fam = af
        socktype = socket.SOCK_STREAM
        proto = 0

        try:
            with socket.socket(fam, socktype, proto) as sock:
                sock.settimeout(2.0) # Timeout da conexão TCP (handshake)
                sock.connect(sockaddr)
        except (OSError, ConnectionRefusedError, TimeoutError):
            return TestResult(False, f"TCP{port}-{family} FAIL", f"TCP {port} {family} closed/unreachable", host, resolved_ip, family)

        latency = int((time.time() - t0) * 1000)
        max_ms = self.cfg["max_latency_ms"]
        if latency > max_ms:
            return TestResult(False, f"TCP{port}-{family} {latency}ms", f"TCP {port} {family} latency {latency}ms > {max_ms}ms", host, resolved_ip, family)
        return TestResult(True, f"TCP{port}-{family} {latency}ms", "", host, resolved_ip, family)

    def _tcp_no_address_result(self, host: str, port: int, family: str) -> TestResult:
        if family == "v6" and not self.cfg.get("require_ipv6", False):
            return TestResult(True, f"TCP{port}-{family} SKIP sem AAAA", "", host, family=family, state="SKIP")
        return TestResult(False, f"TCP{port}-{family} FAIL", f"TCP {port} {family} DNS resolution failed", host, family=family)


    def _tcp_check_label(self, item: dict[str, Any]) -> str:
        return str(item.get("label") or f"{self._tcp_display_host(item)}:{item['port']}")

    def _tcp_trace_target(self, item: dict[str, Any], err: TestResult) -> TraceTarget:
        if err.resolved_ip:
            return TraceTarget(str(err.resolved_ip), err.family)
        family = err.family if err.family in ("v4", "v6") else None
        host = self._tcp_display_host(item, family)
        if is_ipv6_literal(host):
            return TraceTarget(host, "v6")
        if is_ipv4_literal(host):
            return TraceTarget(host, "v4")
        return TraceTarget(host, family)

    def _alert_service_type(self, err: TestResult) -> str:
        """Deriva o tipo de serviço que falhou a partir do erro para uso no título do alerta."""
        metric = (err.metric or "").upper()
        if metric.startswith("DNS"):
            return "DNS"
        if metric.startswith("TCP"):
            return "TCP"
        if metric.startswith("GW"):
            return "Gateway"
        error = (err.error or "").upper()
        if "ICMP" in error or "LATENCY" in error:
            return "ICMP"
        return "Conectividade"

    def _stack_label(self, family: str | None, dualstack: bool = False) -> str:
        """Retorna o label de pilha padronizado para exibição no alerta."""
        if not family:
            return "Dual-Stack" if dualstack else "Desconhecido"
        fname = self._family_name(family)
        if dualstack:
            return f"Dual-Stack (falha em {fname})"
        return fname

    def _dest_label(self, label: str, resolved_ip: str | None) -> str:
        """Formata o destino da falha com IP resolvido."""
        if resolved_ip:
            return f"{label} (IP Resolvido: {resolved_ip})"
        return label

    def _format_error_detail(self, error: str, resolved_ip: str | None = None) -> str:
        clean_error = str(error or "").strip() or "erro não informado"
        if not resolved_ip:
            return clean_error
        # Evita repetir o mesmo IP no detalhe quando ele já está em "Destino da Falha".
        clean_error = clean_error.replace(f"({resolved_ip})", "").replace(f"[{resolved_ip}]", "")
        clean_error = " ".join(clean_error.split())
        return clean_error or "erro não informado"

    def _fmt_alert(self, service: str, stack: str, dest: str, error: str, resolved_ip: str | None = None) -> str:
        """Template unificado de alerta para todos os tipos."""
        error_time_brt = datetime.now(self._alert_tz).strftime("%H:%M:%S")
        clean_error = self._format_error_detail(error, resolved_ip)
        return (
            f"🚨 ALERTA DE FALHA {service}\n\n"
            f"🌐 Pilha: {stack}\n"
            f"🖥️ Origem: {self.server_name} ({self.server_ip})\n"
            f"🎯 Destino da Falha: {dest}\n"
            f"❌ Detalhe do Erro: \"{clean_error}\"\n"
            f"⏱️ Horário do erro: {error_time_brt}"
        )

    def _fmt_resolved(self, _service: str, dest: str, duration: str) -> str:
        """Template unificado de resolução para todos os tipos."""
        resolved_time_brt = datetime.now(self._alert_tz).strftime("%H:%M:%S")
        return (
            f"✅ RESOLVIDO\n\n"
            f"🖥️ Origem: {self.server_name} ({self.server_ip})\n"
            f"✅ Alvo: {dest}\n"
            f"🕟 Horário do resolvido: {resolved_time_brt}\n"
            f"⏱️ Tempo de indisponibilidade: {duration}"
        )

    def _format_tcp_alert(self, item: dict[str, object], err: TestResult) -> str:
        typed_item: dict[str, Any] = dict(item)
        label = self._tcp_check_label(typed_item)
        family = self._tcp_family_mode(typed_item)
        if family == "v4":
            stack = self._stack_label("v4")
        elif family == "v6":
            stack = self._stack_label("v6")
        else:
            stack = self._stack_label(err.family, dualstack=True)
        dest = self._dest_label(label, err.resolved_ip)
        return self._fmt_alert("TCP", stack, dest, err.error, err.resolved_ip)

    def _format_tcp_resolved(self, item: dict[str, object], start_ts: float | None = None, resolved_ip: str | None = None) -> str:
        typed_item: dict[str, Any] = dict(item)
        family_hint: str | None = None
        if resolved_ip and is_ipv4_literal(resolved_ip):
            family_hint = "v4"
        elif resolved_ip and is_ipv6_literal(resolved_ip):
            family_hint = "v6"
        else:
            mode = self._tcp_family_mode(typed_item)
            family_hint = mode if mode in ("v4", "v6") else None

        host = self._tcp_display_host(typed_item, family_hint)
        label = self._tcp_check_label(typed_item)
        if resolved_ip is None:
            if is_ipv4_literal(host) or is_ipv6_literal(host):
                resolved_ip = host
            elif family_hint == "v6":
                resolved_ip = self._quick_resolve(host, "v6")
            elif family_hint == "v4":
                resolved_ip = self._quick_resolve(host, "v4")
            else:
                host_v4 = self._tcp_host_for_family(typed_item, "v4") or host
                host_v6 = self._tcp_host_for_family(typed_item, "v6") or host
                resolved_ip = (
                    self._quick_resolve(host_v4, "v4")
                    or self._quick_resolve(host_v6, "v6")
                )
        dest = self._dest_label(label, resolved_ip)
        return self._fmt_resolved("TCP", dest, self._human_duration(start_ts))

    def _test_tcp_target_for_family(self, host: str | None, port: int, family: str) -> TestResult:
        if not host:
            return self._tcp_no_address_result("<missing-host>", port, family)
        if family == "v4" and is_ipv4_literal(host):
            return self._test_tcp(host, port, "v4", host)
        if family == "v6" and is_ipv6_literal(host):
            return self._test_tcp(host, port, "v6", host)
        return self._test_tcp(host, port, family)

    def _test_tcp_check(self, item: dict[str, Any]) -> tuple[str, dict[str, TestResult | None], TestResult | None, dict[str, Any]]:
        port = int(item["port"])
        label = self._tcp_check_label(item)
        family_mode = self._tcp_family_mode(item)

        tcp4 = None
        tcp6 = None

        if family_mode == "v4":
            tcp4 = self._test_tcp_target_for_family(
                self._tcp_host_for_family(item, "v4"), port, "v4"
            )
        elif family_mode == "v6":
            tcp6 = self._test_tcp_target_for_family(
                self._tcp_host_for_family(item, "v6"), port, "v6"
            )
        else:
            tcp4 = self._test_tcp_target_for_family(
                self._tcp_host_for_family(item, "v4"), port, "v4"
            )
            tcp6 = self._test_tcp_target_for_family(
                self._tcp_host_for_family(item, "v6"), port, "v6"
            )

        bundle = {"tcp4": tcp4, "tcp6": tcp6}
        errors = [result for result in (tcp4, tcp6) if result and not result.ok]
        err = errors[0] if errors else None
        return label, bundle, err, item

    def _tcp_max_fails(self) -> int:
        return max(1, int(self.cfg.get("tcp_max_fails", self.cfg.get("domain_max_fails", self.cfg.get("max_fails", 3)))))


    def _icmp_count(self) -> int:
        return max(1, int(self.cfg.get("icmp_count", 1)))

    def _icmp_timeout(self) -> float:
        """Timeout do subprocess escala com icmp_count: 1s/pacote + 1.5s de margem."""
        return self._icmp_count() * 1.0 + 1.5

    def _test_icmp(self, ip: str, label: str, family: str) -> TestResult:
        ping_bin = self._ping_bin_v4 if family == "v4" else self._ping_bin_v6
        count = self._icmp_count()
        # "--" impede que IPs/hosts iniciados por "-" sejam interpretados como flags.
        ping_cmd = [ping_bin, "-c", str(count), "-W", "1", "--", ip]
        if family == "v6" and ping_bin == "ping":
            ping_cmd.insert(1, "-6")
        code, out = _run(ping_cmd, timeout=self._icmp_timeout())
        transmitted, received, loss = self._parse_ping_stats(out)
        if code != 0:
            return TestResult(
                False,
                f"{label}-{family} FAIL",
                f"ICMP {family} fail on {label} ({ip})",
                label,
                ip,
                family,
                ping_count=transmitted,
                packet_loss_pct=loss,
            )

        m = self._RE_TIME_MS.search(out)
        if not m:
            return TestResult(
                False,
                f"{label}-{family} FAIL",
                f"ICMP {family} parse fail on {label} ({ip})",
                label,
                ip,
                family,
                ping_count=transmitted,
                packet_loss_pct=loss,
            )

        latency = float(m.group(1))
        max_ms = self.cfg["max_latency_ms"]
        if latency > max_ms:
            return TestResult(
                False,
                f"{label}-{family} {latency:.1f}ms",
                f"ICMP {family} latency {latency:.1f}ms > {max_ms}ms",
                label,
                ip,
                family,
                ping_count=transmitted,
                packet_loss_pct=loss,
            )
        return TestResult(
            True,
            f"{label}-{family} {latency:.1f}ms",
            "",
            label,
            ip,
            family,
            ping_count=transmitted,
            packet_loss_pct=loss,
        )

    def _test_gateway(self, family: str) -> TestResult:
        route_cmd = ["ip", "route", "show", "default"] if family == "v4" else ["ip", "-6", "route", "show", "default"]
        code, out = _run(route_cmd, timeout=2.0)
        if code != 0:
            return TestResult(False, f"GW-{family} FAIL", f"Gateway {family} not found", "gateway", family=family)

        gw = None
        for line in out.splitlines():
            tokens = line.split()
            if not tokens:
                continue
            # Accept lines that begin with "default" or "nexthop" (ECMP hops)
            if tokens[0] not in ("default", "nexthop"):
                continue
            try:
                via_idx = tokens.index("via")
                gw = tokens[via_idx + 1]
                break
            except (ValueError, IndexError):
                continue
        if not gw:
            return TestResult(False, f"GW-{family} FAIL", f"Gateway {family} not found", "gateway", family=family)

        ping_bin = self._ping_bin_v4 if family == "v4" else self._ping_bin_v6
        count = self._icmp_count()
        ping_cmd = [ping_bin, "-c", str(count), "-W", "1", "--", gw]
        if family == "v6" and ping_bin == "ping":
            ping_cmd.insert(1, "-6")
        code, out = _run(ping_cmd, timeout=self._icmp_timeout())
        transmitted, received, loss = self._parse_ping_stats(out)
        if code != 0:
            return TestResult(
                False,
                f"GW-{family} FAIL",
                f"Gateway {family} unreachable ({gw})",
                gw,
                gw,
                family,
                ping_count=transmitted,
                packet_loss_pct=loss,
            )
        m = self._RE_TIME_MS.search(out)
        latency = float(m.group(1)) if m else 0.0
        latency_text = f"{latency:.1f}ms" if m else "n/a"
        return TestResult(
            True,
            f"GW-{family} {latency_text}",
            "",
            "gateway",
            gw,
            family,
            ping_count=transmitted,
            packet_loss_pct=loss,
        )

    def _resolve_gchat_host_redundant(self, url: str) -> str:
        """Tenta resolver o host do GChat via DNS externo se o local falhar."""
        parts = urlsplit(url)
        hostname = parts.hostname
        if not hostname:
            self._log_warn("GChat URL sem hostname; pulando resolução redundante.")
            return url
        hostname = hostname.replace("\n", " ").replace("\r", " ")

        # Se o cache ainda for válido (5 minutos), usamos ele para evitar novos comandos dig.
        # Lock garante leitura consistente de ip+expiry entre múltiplos workers do _alert_executor.
        with self._gchat_cache_lock:
            cached_ip = self._gchat_ip_cache["ip"] if time.time() < self._gchat_ip_cache["expiry"] else None
        if cached_ip:
            return self._build_redundant_url(parts, cached_ip)

        # Tenta resolução local via dig (mais rápido e controlável que socket se o DNS falhar)
        code, out = _run(["dig", hostname, "+short", "+time=1", "+tries=1"], timeout=1.5)
        local_has_ip = False
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                candidate = line.strip()
                if is_valid_ip(candidate, "v4") or is_valid_ip(candidate, "v6"):
                    local_has_ip = True
                    break
        if local_has_ip:
            # DNS local recuperado: descarta cache redundante para voltar a usar SNI/cert correto
            with self._gchat_cache_lock:
                if self._gchat_ip_cache["ip"]:
                    self._log_debug("DNS local recuperado; invalidando cache de IP redundante do GChat.")
                    self._gchat_ip_cache = {"ip": None, "expiry": 0}
            return url

        self._log_warn(f"DNS local falhou para {hostname}. Tentando redundância via 8.8.8.8/1.1.1.1...")
        for dns_server in ["8.8.8.8", "1.1.1.1"]:
            code, out = _run(["dig", f"@{dns_server}", hostname, "+short", "+time=1", "+tries=1"], timeout=1.5)
            if code != 0 or not out.strip():
                continue
            ip = None
            for line in out.strip().splitlines():
                candidate = line.strip()
                if is_valid_ip(candidate, "v4") or is_valid_ip(candidate, "v6"):
                    ip = candidate
                    break
            if not ip:
                continue
            self._log(f"Redundância DNS OK: {hostname} -> {ip} via {dns_server}. Cache por 5min — alertas continuam sendo enviados.")
            with self._gchat_cache_lock:
                self._gchat_ip_cache = {"ip": ip, "expiry": time.time() + 300}
            return self._build_redundant_url(parts, ip)
        return url

    @staticmethod
    def _build_redundant_url(parts: Any, ip: str) -> str:
        """Reconstrói URL substituindo hostname por IP. IPv6 vai entre colchetes."""
        new_parts = list(parts)
        netloc_host = f"[{ip}]" if ":" in ip else ip
        if parts.port:
            netloc_host = f"{netloc_host}:{parts.port}"
        new_parts[1] = netloc_host
        result = urlunsplit(new_parts)
        if isinstance(result, bytes):
            return result.decode()
        return result

    @staticmethod
    def _parse_retry_after(value: str | None) -> int:
        """Retorna segundos de espera a partir do header Retry-After.
        Aceita formato inteiro (segundos) ou HTTP-date (RFC 7231).
        Mínimo: 30s. Máximo: _RETRY_AFTER_MAX_SECONDS.
        Fallback (sem header ou parse falhou): 30s."""
        if not value:
            return 30
        try:
            return max(30, min(_RETRY_AFTER_MAX_SECONDS, int(value)))
        except ValueError:
            pass
        try:
            dt = parsedate_to_datetime(value)
            if dt is None:
                return 30
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = (dt - datetime.now(timezone.utc)).total_seconds()
            return max(30, min(_RETRY_AFTER_MAX_SECONDS, int(delta)))
        except (TypeError, ValueError):
            return 30

    def _in_cooldown(self) -> bool:
        """True se ainda dentro do cooldown imposto pelo último 429 do GChat."""
        with self._queue_lock:
            return time.time() < self._queue_cooldown_until

    def _allow_insecure_tls_fallback(self) -> bool:
        """Break-glass: exige flag em config e variável de ambiente explícita."""
        if not self.cfg.get("allow_insecure_redundant_tls", False):
            return False
        allow_env = str(os.environ.get(_INSECURE_TLS_ENV_FLAG, "")).strip().lower() in {"1", "true", "yes", "on"}
        if allow_env:
            return True
        self._log_warn(
            "GCHAT fallback TLS inseguro bloqueado sem %s=1 (modo break-glass).",
            _INSECURE_TLS_ENV_FLAG,
        )
        return False

    def _gchat_post_once(
        self,
        webhook_url: str,
        payload_data: bytes,
        timeout: float,
        forced_ip: str | None = None,
        insecure_tls: bool = False,
    ) -> tuple[int, dict[str, str], str]:
        """POST único ao webhook do GChat.

        - forced_ip: conecta no IP informado mas mantém SNI no hostname original.
        - insecure_tls: desabilita verificação TLS (último recurso, opcional).
        """
        parts = urlsplit(webhook_url)
        if parts.scheme.lower() != "https":
            raise ValueError("webhook_url deve usar HTTPS")
        host = parts.hostname
        if not host:
            raise ValueError("webhook_url sem hostname")
        port = parts.port or 443
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        if insecure_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context()

        if forced_ip:
            conn: http.client.HTTPSConnection = _ForcedIPHTTPSConnection(
                host=host,
                forced_ip=forced_ip,
                port=port,
                timeout=timeout,
                context=context,
            )
        else:
            conn = http.client.HTTPSConnection(
                host=host,
                port=port,
                timeout=timeout,
                context=context,
            )

        try:
            conn.request(
                "POST",
                path,
                body=payload_data,
                headers={
                    "Content-Type": "application/json; charset=UTF-8",
                    "Host": host,
                },
            )
            response = conn.getresponse()
            body = response.read(_MAX_GCHAT_RESPONSE_BYTES).decode("utf-8", errors="replace")
            headers = {k: v for (k, v) in response.getheaders()}
            return int(response.status), headers, body
        finally:
            conn.close()

    def _post_gchat(self, text: str, thread_key: str | None = None, thread_name: str | None = None, is_retry: bool = False) -> str | None:
        """Envia para GChat com redundância de DNS, cooldown 429 e fila offline.

        Retorna:
        - thread_name (str): sucesso
        - "DRY_RUN": modo dry-run, suprimido
        - "FAILED_FATAL": rejeição permanente (400/401/403/404/410)
        - None: erro de rede/timeout/429; alerta enfileirado se não for retry
        """
        clean_text = self._sanitize_alert_text(text)
        clean_thread_key = self._sanitize_thread_ref(thread_key)
        clean_thread_name = self._sanitize_thread_ref(thread_name)

        if not self.alerts_enabled:
            self._log("Dry-run: alerta suprimido. Mensagem não enviada ao Google Chat.")
            return "DRY_RUN"

        # Cooldown 429 vale para TODOS os envios (não só drain).
        # Sem isso, novos alertas durante outage massiva geram cascata de 429
        # e Google pode revogar o webhook.
        if not is_retry and self._in_cooldown():
            self._log_warn("GChat em cooldown 429: alerta novo enviado direto à fila offline.")
            self._enqueue_alert(clean_text, clean_thread_key, clean_thread_name)
            return None

        actual_text = clean_text
        if is_retry:
            actual_text = f"⚠️ *[ALERTA COM DELAY]* (Enviado seguindo a fila)\n{clean_text}"
        actual_text = self._sanitize_alert_text(actual_text)

        # Ordem de fallback sem recursão: mantém contexto de thread quando possível
        # e degrada em até duas tentativas adicionais.
        attempts: list[tuple[str | None, str | None]]
        clean_name = clean_thread_name if clean_thread_name and clean_thread_name != "FAILED_FATAL" else None
        if clean_name and clean_thread_key:
            attempts = [(clean_name, clean_thread_key), (None, clean_thread_key), (None, None)]
        elif clean_name:
            attempts = [(clean_name, None), (None, None)]
        elif clean_thread_key:
            attempts = [(None, clean_thread_key), (None, None)]
        else:
            attempts = [(None, None)]

        target_url = self._resolve_gchat_host_redundant(self.webhook_url)
        is_redundant = target_url != self.webhook_url
        forced_ip = urlsplit(target_url).hostname if is_redundant else None

        for idx, (attempt_name, attempt_key) in enumerate(attempts):
            thread: dict[str, str] = {}
            if attempt_name:
                thread["name"] = attempt_name
            elif attempt_key:
                thread["threadKey"] = attempt_key

            payload: dict[str, object] = {"text": actual_text}
            if thread:
                payload["thread"] = thread

            data = json.dumps(payload).encode("utf-8")
            timeout = _GCHAT_TIMEOUT_SHUTDOWN if self._stop_event.is_set() else _GCHAT_TIMEOUT_NORMAL

            try:
                status_code = 0
                headers: dict[str, str] = {}
                response_text = ""

                if forced_ip:
                    try:
                        status_code, headers, response_text = self._gchat_post_once(
                            self.webhook_url,
                            data,
                            timeout,
                            forced_ip=forced_ip,
                            insecure_tls=False,
                        )
                    except ssl.SSLError as secure_exc:
                        if not self._allow_insecure_tls_fallback():
                            raise
                        self._log_warn(
                            "GCHAT redundante seguro falhou (%s). Tentando modo inseguro por compatibilidade.",
                            _redact_credentials(secure_exc),
                        )
                        status_code, headers, response_text = self._gchat_post_once(
                            self.webhook_url,
                            data,
                            timeout,
                            forced_ip=forced_ip,
                            insecure_tls=True,
                        )
                        self._log_warn("GCHAT: usando fallback redundante com TLS inseguro permitido por configuração.")
                else:
                    status_code, headers, response_text = self._gchat_post_once(
                        self.webhook_url,
                        data,
                        timeout,
                        forced_ip=None,
                        insecure_tls=False,
                    )

                if 200 <= status_code < 300:
                    # Alerta já entregue. Parse do body em try próprio para que
                    # JSONDecodeError (proxy/WAF com body não-JSON) não propague
                    # até o except externo e re-enfileire uma mensagem já enviada.
                    response_obj: dict = {}
                    if response_text:
                        try:
                            parsed_obj = loads_json_strict(response_text)
                            if isinstance(parsed_obj, dict):
                                response_obj = parsed_obj
                            else:
                                self._log_warn(
                                    "GCHAT resposta 2xx com JSON não-objeto (%s). Prosseguindo sem thread.name.",
                                    type(parsed_obj).__name__,
                                )
                        except (json.JSONDecodeError, DuplicateKeyError, RecursionError, ValueError) as exc:
                            self._log_warn(
                                "GCHAT resposta 2xx com body não-JSON (body ignorado): %s", exc
                            )
                    response_thread_name = ""
                    thread_obj = response_obj.get("thread")
                    if isinstance(thread_obj, dict):
                        thread_name_obj = thread_obj.get("name")
                        if isinstance(thread_name_obj, str):
                            response_thread_name = thread_name_obj.replace("\n", " ").replace("\r", " ")[:512]
                    elif thread_obj is not None:
                        self._log_warn(
                            "GCHAT resposta 2xx com campo 'thread' inválido (%s).",
                            type(thread_obj).__name__,
                        )
                    msg_fingerprint = hashlib.sha256(actual_text.encode("utf-8", errors="replace")).hexdigest()[:16]
                    self._log(
                        "GCHAT OK | Thread: %s | MsgFingerprint: %s | MsgLen: %d",
                        response_thread_name,
                        msg_fingerprint,
                        len(actual_text),
                    )
                    return response_thread_name

                action = self._handle_gchat_http_error(
                    status_code,
                    headers,
                    attempt_name,
                    attempt_key,
                    idx,
                    len(attempts),
                )
                if action == "retry_next":
                    continue
                if action == "failed_fatal":
                    return "FAILED_FATAL"
                # "enqueue_or_drop": cai no fluxo padrão abaixo.
                break
            except (
                http.client.HTTPException,
                socket.timeout,
                ssl.SSLError,
                OSError,
                json.JSONDecodeError,
                DuplicateKeyError,
                RecursionError,
                TypeError,
                ValueError,
            ) as e:
                self._log_warn(f"GCHAT ATTEMPT FAIL: {_redact_credentials(e)}")
                break

        # Falha de rede: guarda na fila se for o envio original.
        if not is_retry:
            self._enqueue_alert(clean_text, clean_thread_key, clean_thread_name)
        return None

    def _handle_gchat_http_error(
        self,
        status_code: int,
        headers: dict[str, str],
        attempted_thread_name: str | None,
        attempted_thread_key: str | None,
        attempt_idx: int,
        total_attempts: int,
    ) -> Literal["retry_next", "failed_fatal", "enqueue_or_drop"]:
        """Classifica status HTTP do GChat para o fluxo iterativo de _post_gchat."""
        if status_code == 400:
            has_fallback = attempt_idx < (total_attempts - 1)
            if has_fallback:
                if attempted_thread_name:
                    self._log_warn("GCHAT 400: thread.name inválida. Tentando fallback de thread.")
                elif attempted_thread_key:
                    self._log_warn("GCHAT 400: threadKey inválida. Tentando envio sem thread.")
                else:
                    self._log_error("GCHAT 400: payload rejeitado. Sem mais fallback.")
                return "retry_next"
            self._log_error("GCHAT 400 FATAL: Mensagem rejeitada permanentemente pelo Google (corpo inválido). Removendo da fila.")
            return "failed_fatal"
        if status_code in (401, 403, 404, 410):
            self._log_error(
                "GCHAT %s FATAL: webhook inválido/revogado. Descartando alerta. Verifique NETWATCHER_WEBHOOK_URL.",
                status_code,
            )
            return "failed_fatal"
        if status_code == 413:
            self._log_error("GCHAT 413 FATAL: payload excedeu limite. Removendo alerta da fila.")
            return "failed_fatal"
        if status_code == 429:
            retry_after = self._parse_retry_after(headers.get("Retry-After") or headers.get("retry-after"))
            with self._queue_lock:
                self._queue_cooldown_until = time.time() + retry_after
            self._log_warn(f"GCHAT 429: rate limited. Envio suspenso por {retry_after}s.")
            return "enqueue_or_drop"
        self._log_warn("GCHAT ATTEMPT FAIL (HTTP %s).", status_code)
        return "enqueue_or_drop"

    def _enqueue_alert(self, text: str, thread_key: str | None, thread_name: str | None) -> None:
        """Enfileira alerta na fila offline de forma thread-safe."""
        clean_text = self._sanitize_alert_text(text)
        clean_thread_key = self._sanitize_thread_ref(thread_key)
        clean_thread_name = self._sanitize_thread_ref(thread_name)

        fingerprint = self._alert_fingerprint(clean_text, clean_thread_key, clean_thread_name)
        if not self._should_enqueue_alert(fingerprint):
            self._log_warn(
                "Fila offline: alerta duplicado suprimido na janela de %.1fs.",
                self._alert_dedupe_window_seconds,
            )
            return
        alert = {
            "text": clean_text,
            "thread_key": clean_thread_key,
            "thread_name": clean_thread_name,
            "timestamp": time.time()
        }
        self.alert_queue.enqueue(alert)

    @staticmethod
    def _alert_fingerprint(text: str, thread_key: str | None, thread_name: str | None) -> str:
        material = f"{thread_key or ''}\x1f{thread_name or ''}\x1f{text}"
        return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _sanitize_alert_text(text: object) -> str:
        suffix = "\n\n... (mensagem cortada por excesso de caracteres)"
        if text is None:
            clean = ""
        else:
            clean = str(text)
        clean = clean.replace("\x00", "")
        if not clean.strip():
            clean = "[mensagem vazia]"
        if len(clean) <= _MAX_ALERT_TEXT_CHARS:
            return clean
        keep = max(0, _MAX_ALERT_TEXT_CHARS - len(suffix))
        return clean[:keep] + suffix

    @staticmethod
    def _sanitize_thread_ref(value: str | None) -> str | None:
        if value is None:
            return None
        clean = (
            str(value)
            .replace("\x00", "")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("\t", " ")
        )
        clean = " ".join(clean.split())
        if not clean:
            return None
        if len(clean) > _MAX_THREAD_REF_CHARS:
            clean = clean[:_MAX_THREAD_REF_CHARS]
        return clean

    def _should_enqueue_alert(self, fingerprint: str) -> bool:
        window = self._alert_dedupe_window_seconds
        if window <= 0:
            return True
        now = time.monotonic()
        cutoff = now - window
        with self._alert_dedupe_lock:
            while self._recent_alert_fingerprint_order and self._recent_alert_fingerprint_order[0][0] < cutoff:
                ts, key = self._recent_alert_fingerprint_order.popleft()
                current = self._recent_alert_fingerprints.get(key)
                if current is not None and current == ts:
                    del self._recent_alert_fingerprints[key]
            last_ts = self._recent_alert_fingerprints.get(fingerprint)
            if last_ts is not None and (now - last_ts) < window:
                return False
            self._recent_alert_fingerprints[fingerprint] = now
            self._recent_alert_fingerprint_order.append((now, fingerprint))
            return True

    def _track_future(self, future: Future, kind: Literal["alert", "trace"]) -> None:
        bucket = self._active_alert_futures if kind == "alert" else self._active_trace_futures
        with self._active_futures_lock:
            bucket.add(future)

        def _cleanup(done: Future) -> None:
            with self._active_futures_lock:
                bucket.discard(done)

        future.add_done_callback(_cleanup)

    def _probe_failure_result(self, meta: ProbeFutureMeta, exc: BaseException) -> TestResult:
        err_cls = type(exc).__name__
        err_msg = _redact_credentials(exc)
        if meta.kind == "domain":
            return TestResult(
                False,
                "DOMAIN PROBE FAIL",
                f"Probe domain worker exception ({err_cls}): {err_msg}",
                meta.label,
            )
        if meta.kind == "tcp":
            item = meta.item or self._tcp_item_by_label.get(meta.label, {})
            mode = self._tcp_family_mode(item)
            family = mode if mode in ("v4", "v6") else None
            host = self._tcp_display_host(item, family)
            return TestResult(
                False,
                "TCP PROBE FAIL",
                f"Probe tcp worker exception ({err_cls}): {err_msg}",
                host,
                family=family,
            )
        target_ip = str((meta.item or {}).get("ip", ""))
        return TestResult(
            False,
            f"INFRA-{meta.family or 'ip'} PROBE FAIL",
            f"Probe infra worker exception ({err_cls}): {err_msg}",
            meta.label,
            resolved_ip=target_ip or None,
            family=meta.family,
        )

    def _synthetic_domain_bundle(self, dom: str) -> dict[str, TestResult]:
        return {
            "dns4": self._domain_skip_result(dom, "DNS", "v4", "probe-exception"),
            "dns6": self._domain_skip_result(dom, "DNS", "v6", "probe-exception"),
            "tcp80_4": self._domain_skip_result(dom, "TCP80", "v4", "probe-exception"),
            "tcp80_6": self._domain_skip_result(dom, "TCP80", "v6", "probe-exception"),
            "tcp443_4": self._domain_skip_result(dom, "TCP443", "v4", "probe-exception"),
            "tcp443_6": self._domain_skip_result(dom, "TCP443", "v6", "probe-exception"),
        }

    def _append_synthetic_probe_result(
        self,
        meta: ProbeFutureMeta,
        exc: BaseException,
        domain_results: list[tuple[str, dict[str, TestResult], TestResult | None]],
        tcp_results: list[tuple[str, dict[str, TestResult | None], TestResult | None, dict[str, Any]]],
        infra_raw_results: list[TestResult],
    ) -> None:
        synthetic_err = self._probe_failure_result(meta, exc)
        if meta.kind == "domain":
            domain_results.append((meta.label, self._synthetic_domain_bundle(meta.label), synthetic_err))
            return
        if meta.kind == "tcp":
            tcp_item = meta.item or self._tcp_item_by_label.get(meta.label) or {
                "label": meta.label,
                "hostva": meta.label,
                "port": 0,
                "family": "dualstack",
            }
            tcp_results.append((meta.label, {"tcp4": None, "tcp6": None}, synthetic_err, tcp_item))
            return
        infra_raw_results.append(synthetic_err)

    def _log_future_error(self, future: Future) -> None:
        """Callback para Futures: surfacing de exceções que de outra forma seriam silenciosamente engolidas.

        Sem isso, qualquer KeyError/AttributeError/etc. dentro de um worker submetido
        ao ThreadPoolExecutor desaparece e o operador nunca sabe por que o alerta não saiu.
        """
        try:
            exc = future.exception()
        except (RuntimeError, OSError):
            return
        if exc:
            self._log_error(f"WORKER ASYNC FALHOU: {_redact_credentials(exc)}")


    def _process_alert_queue(self) -> None:
        """Processa fila offline, enviando alertas pendentes para o GChat.

        Drena até um limite por ciclo para evitar starvation do loop principal.
        Em falha transitória durante retry, re-enfileira no fim da fila para
        evitar head-of-line blocking.
        """
        max_drain = max(1, int(self.cfg.get("max_queue_drain_per_cycle", 50)))
        drained = 0
        while drained < max_drain and not self._stop_event.is_set():
            if self._in_cooldown():
                break
            raw_alert = self.alert_queue.dequeue()
            if not raw_alert:
                break
            if not isinstance(raw_alert, dict):
                self._log_warn("Fila offline: item inválido (não-dict) descartado.")
                drained += 1
                continue
            text = raw_alert.get("text")
            if not isinstance(text, str) or not text.strip():
                self._log_warn("Fila offline: item inválido (campo 'text' ausente/vazio) descartado.")
                drained += 1
                continue
            thread_key_obj = raw_alert.get("thread_key")
            thread_name_obj = raw_alert.get("thread_name")
            thread_key = self._sanitize_thread_ref(None if thread_key_obj is None else str(thread_key_obj))
            thread_name = self._sanitize_thread_ref(None if thread_name_obj is None else str(thread_name_obj))
            clean_text = self._sanitize_alert_text(text)
            alert = {
                "text": clean_text,
                "thread_key": thread_key,
                "thread_name": thread_name,
                "timestamp": raw_alert.get("timestamp", time.time()),
            }
            result = self._post_gchat(
                alert["text"],
                alert["thread_key"],
                alert["thread_name"],
                is_retry=True,
            )
            if result == "FAILED_FATAL":
                drained += 1
                continue
            if result is None:
                self.alert_queue.requeue_back(alert)
                break
            drained += 1

    def _handle_incident_async(
        self,
        kind: Literal["domain", "tcp", "infra"],
        target: str,
        is_resolved: bool,
        bundle: dict | None = None,
        err: TestResult | None = None,
        state_snapshot: dict | None = None,
        item: dict | None = None,
        incident_key: str | None = None,
    ) -> Future:
        """Processa incidentes em background para não travar o loop de monitoramento.

        incident_key: thread_key gerada SINCRONAMENTE no loop principal e já armazenada
        em self.X_incident_thread[target] antes do submit. Garante que uma resolução
        rápida (flapping) tenha acesso à key correta mesmo se o worker ainda não rodou.

        Retorna o Future submetido para que o caller possa rastreá-lo e o ciclo
        de resolução possa aguardar a conclusão do incidente antes de enviar a
        mensagem de RESOLVIDO (evita perda de agrupamento de thread no GChat).
        """
        def worker() -> None:
            _item = item or {"host": target, "port": "?", "family": "dualstack"}
            if kind == "domain":
                self._dispatch_incident(
                    target, is_resolved,
                    states=self.dom_states,
                    fmt_alert_fn=lambda: self._format_domain_alert(target, bundle, err),
                    fmt_resolved_fn=lambda t0, tr: self._format_domain_resolved(
                        target, t0, trace_family=tr.family
                    ),
                    trace_fn=self._domain_trace_target,
                    state_snapshot=state_snapshot,
                    incident_key=incident_key,
                    err=err,
                )
            elif kind == "tcp":
                self._dispatch_incident(
                    target, is_resolved,
                    states=self.tcp_states,
                    fmt_alert_fn=lambda: self._format_tcp_alert(_item, err),
                    fmt_resolved_fn=lambda t0, tr: self._format_tcp_resolved(
                        _item, t0, resolved_ip=tr.target if tr else None
                    ),
                    trace_fn=lambda tgt, e: self._tcp_trace_target(_item, e),
                    state_snapshot=state_snapshot,
                    incident_key=incident_key,
                    err=err,
                    traceroute_guard=(item is not None),
                )
            else:
                self._dispatch_incident(
                    target, is_resolved,
                    states=self.infra_states,
                    fmt_alert_fn=lambda: self._format_infra_alert(target, err),
                    fmt_resolved_fn=lambda t0, tr: self._format_infra_resolved(
                        target, t0, resolved_ip=tr.target if tr else None
                    ),
                    trace_fn=self._infra_trace_target,
                    state_snapshot=state_snapshot,
                    incident_key=incident_key,
                    err=err,
                )

        fut = self._alert_executor.submit(worker)
        fut.add_done_callback(self._log_future_error)
        self._track_future(fut, "alert")
        return fut

    def _dispatch_incident(
        self,
        target: str,
        is_resolved: bool,
        states: dict[str, MonitorState],
        fmt_alert_fn: Callable[[], str],
        fmt_resolved_fn: Callable[[float | None, TraceTarget], str],
        trace_fn: Callable[[str, TestResult], TraceTarget],
        state_snapshot: "dict | None",
        incident_key: "str | None",
        err: "TestResult | None" = None,
        traceroute_guard: bool = True,
    ) -> None:
        """Padrão comum de incidente/resolução: posta mensagem, atualiza estado, dispara traceroute."""
        traceroute_enabled = self.cfg.get("enable_traceroute_on_fail", True)
        if is_resolved:
            snap = state_snapshot or {}
            key = snap.get("thread_key")
            name = snap.get("thread_name")
            outage_t0 = snap.get("outage_t0")
            trace = snap.get("trace_target") or TraceTarget(target)
            self._post_gchat(fmt_resolved_fn(outage_t0, trace), key, name)
            if traceroute_enabled:
                self._send_traceroute_async(trace, "✅ Traceroute Pós-Resolução:", key or "", name)
            return
        trace = trace_fn(target, err) if err else TraceTarget(target)
        thread_name = self._post_gchat(fmt_alert_fn(), incident_key)
        with states[target].lock:
            states[target].trace_target = trace
            states[target].incident_thread_name = thread_name
        if traceroute_enabled and traceroute_guard:
            self._send_traceroute_async(trace, "🚨 Traceroute na Falha:", incident_key or "", thread_name)

    def _new_thread_key(self, prefix: str, label: str) -> str:
        safe_host = self._RE_SAFE_CHARS.sub("_", self.server_name.lower())
        safe_label = self._RE_SAFE_CHARS.sub("_", label.lower())
        return f"{prefix}_{safe_host}_{safe_label}_{int(time.time())}_{secrets.token_hex(4)}"

    def _trace_cmd(self, target: str, family: str | None) -> list[str]:
        cmd = list(self.cfg.get("traceroute_cmd", ["mtr", "-n", "-r", "-c", "3", "-w"]))
        bin_name = os.path.basename(cmd[0])
        fam = family if family else "v4"
        family_flag = {"v4": "-4", "v6": "-6"}.get(fam)
        supports_family_flag = bin_name in {"mtr", "traceroute", "tracepath"}
        has_family_flag = any(arg in {"-4", "-6"} for arg in cmd)
        if family_flag and supports_family_flag and not has_family_flag:
            cmd.append(family_flag)
        return cmd + [target]

    def _send_traceroute_async(
        self,
        trace_target: TraceTarget,
        title: str,
        thread_key: str,
        thread_name: str | None = None,
    ) -> None:
        if self._stop_event.is_set():
            return

        def worker():
            family_suffix = f" ({self._family_name(trace_target.family)})" if trace_target.family else ""
            display_title = f"{title.rstrip(':')}{family_suffix}:"
            trace_time_brt = datetime.now(self._alert_tz).strftime("%H:%M:%S")
            if trace_target.skip_reason:
                self._post_gchat(
                    f"*{display_title}*\n"
                    f"🕟 *Horário:* {trace_time_brt}\n"
                    f"{trace_target.skip_reason}",
                    thread_key,
                    thread_name,
                )
                return

            cmd = self._trace_cmd(trace_target.target, trace_target.family)
            timeout_normal = float(self.cfg.get("traceroute_timeout_seconds", _TRACE_TIMEOUT_NORMAL))
            timeout_shutdown = float(self.cfg.get("traceroute_timeout_shutdown_seconds", _TRACE_TIMEOUT_SHUTDOWN))
            timeout = timeout_shutdown if self._stop_event.is_set() else timeout_normal
            code, out = _run(cmd, timeout=timeout)
            if out.strip():
                safe_out = out.strip().replace("```", "'''")
                self._post_gchat(
                    f"*{display_title}*\n"
                    f"🕟 *Horário:* {trace_time_brt}\n"
                    f"```\n{safe_out}\n```",
                    thread_key,
                    thread_name,
                )
            elif code != 0:
                self._post_gchat(
                    f"*{display_title}*\n"
                    f"🕟 *Horário:* {trace_time_brt}\n"
                    f"⚠️ Traceroute sem saída (código {code}) para {trace_target.target}.",
                    thread_key,
                    thread_name,
                )

        fut = self._traceroute_executor.submit(worker)
        fut.add_done_callback(self._log_future_error)
        self._track_future(fut, "trace")

    def _domain_destination_label(self, dom: str, err: TestResult, resolved_ips: dict[str, list[str]]) -> str:
        if err.resolved_ip:
            return self._dest_label(dom, err.resolved_ip)
        family_ips = resolved_ips.get(err.family or "", [])
        if family_ips:
            return self._dest_label(dom, family_ips[0])
        if err.family:
            return f"{dom} (sem IP resolvido)"
        return dom

    def _domain_trace_target(self, dom: str, err: TestResult) -> TraceTarget:
        if err.resolved_ip:
            return TraceTarget(err.resolved_ip, err.family)
        if err.family == "v6" and "DNS resolution failed" in err.error:
            return TraceTarget(
                dom,
                err.family,
                f"⚠️ Traceroute IPv6 não executado: {dom} não possui IP IPv6 resolvido para esta falha.",
            )
        return TraceTarget(dom, err.family)

    def _infra_trace_target(self, label: str, err: TestResult) -> TraceTarget:
        if err.resolved_ip:
            return TraceTarget(err.resolved_ip, err.family)
        if err.family == "v6" and "DNS resolution failed" in err.error:
            return TraceTarget(
                label,
                err.family,
                f"⚠️ Traceroute IPv6 não executado: {label} não possui IP IPv6 resolvido para esta falha.",
            )
        # Casos onde err.target é o próprio label (ex.: "gateway" quando a rota default não foi encontrada)
        # ou está vazio: não temos um destino real para traceroute, então pulamos com mensagem amigável
        # em vez de chamar mtr com um nome irresolvível (gera "Failed to resolve host: gateway").
        candidate = err.target or label
        family_candidates = [err.family] if err.family in ("v4", "v6") else ["v4", "v6"]
        is_ip = any(is_valid_ip(candidate, fam) for fam in family_candidates)
        if candidate == label or not is_ip:
            return TraceTarget(
                candidate,
                err.family,
                f"⚠️ Traceroute não executado: destino do {label} indisponível (sem IP/rota resolvida).",
            )
        return TraceTarget(candidate, err.family)

    def _format_domain_alert(self, dom: str, bundle: dict[str, TestResult], err: TestResult) -> str:
        service = self._alert_service_type(err)
        stack = self._stack_label(err.family, dualstack=True)
        resolved_ips = self._resolve_domain_ips(dom)
        dest = self._domain_destination_label(dom, err, resolved_ips)
        return self._fmt_alert(service, stack, dest, err.error, err.resolved_ip)

    def _format_domain_resolved(self, dom: str, start_ts: float | None = None, trace_family: str | None = None) -> str:
        # Resolve o IP atual da família que estava falhando; tenta ambas se família desconhecida
        if trace_family:
            ip = self._quick_resolve(dom, trace_family)
        else:
            ip4 = self._quick_resolve(dom, "v4")
            ip6 = self._quick_resolve(dom, "v6")
            ip = ip4 or ip6
        dest = self._dest_label(dom, ip)
        return self._fmt_resolved("Conectividade", dest, self._human_duration(start_ts))


    def _format_infra_alert(self, label: str, err: TestResult) -> str:
        service = "Gateway" if label == "gateway" else "ICMP"
        stack = self._stack_label(err.family)
        dest = self._dest_label(label, err.resolved_ip or (err.target if err.target != label else None))
        return self._fmt_alert(service, stack, dest, err.error, err.resolved_ip)

    def _format_infra_resolved(self, label: str, start_ts: float | None = None, resolved_ip: str | None = None) -> str:
        service = "Gateway" if label == "gateway" else "ICMP"
        dest = self._dest_label(label, resolved_ip)
        return self._fmt_resolved(service, dest, self._human_duration(start_ts))

    def _domain_skip_result(self, dom: str, test_prefix: str, family: str, reason: str | None = None) -> TestResult:
        """Gera um TestResult SKIP para testes desabilitados (por domain_test_mode ou ports)."""
        label = reason or f"modo {self._domain_test_mode()}"
        return TestResult(True, f"{test_prefix}-{family} SKIP ({label})", "", dom, family=family, state="SKIP")

    _DOMAIN_TEST_MODE_ALIASES = {"ipv4": "v4", "ipv6": "v6", "dual": "dualstack"}

    def _domain_test_mode(self) -> str:
        raw = str(self.cfg.get("domain_test_mode", "dualstack")).lower()
        return self._DOMAIN_TEST_MODE_ALIASES.get(raw, raw)

    def _test_domain_stack(self, dom: str) -> tuple[str, dict[str, TestResult], TestResult | None]:
        mode = self._domain_test_mode()
        test_v4 = mode in ("v4", "dualstack")
        test_v6 = mode in ("v6", "dualstack")
        dom_ports = self._domain_ports.get(dom, self._DOMAIN_DEFAULT_PORTS)
        test_80 = 80 in dom_ports
        test_443 = 443 in dom_ports

        if test_v4:
            dns4 = self._test_dns(dom, "v4")
            v4_target_ip = dns4.resolved_ip if not self.cfg.get("dns_random_subdomain", False) else None
            tcp80_4 = self._test_tcp(dom, 80, "v4", v4_target_ip) if test_80 else self._domain_skip_result(dom, "TCP80", "v4", "porta não configurada")
            tcp443_4 = self._test_tcp(dom, 443, "v4", v4_target_ip) if test_443 else self._domain_skip_result(dom, "TCP443", "v4", "porta não configurada")
        else:
            dns4 = self._domain_skip_result(dom, "DNS", "v4")
            tcp80_4 = self._domain_skip_result(dom, "TCP80", "v4")
            tcp443_4 = self._domain_skip_result(dom, "TCP443", "v4")

        if test_v6:
            dns6 = self._test_dns(dom, "v6")
            v6_target_ip = dns6.resolved_ip if not self.cfg.get("dns_random_subdomain", False) else None
            tcp80_6 = self._test_tcp(dom, 80, "v6", v6_target_ip) if test_80 else self._domain_skip_result(dom, "TCP80", "v6", "porta não configurada")
            tcp443_6 = self._test_tcp(dom, 443, "v6", v6_target_ip) if test_443 else self._domain_skip_result(dom, "TCP443", "v6", "porta não configurada")
        else:
            dns6 = self._domain_skip_result(dom, "DNS", "v6")
            tcp80_6 = self._domain_skip_result(dom, "TCP80", "v6")
            tcp443_6 = self._domain_skip_result(dom, "TCP443", "v6")

        bundle = {
            "dns4": dns4,
            "dns6": dns6,
            "tcp80_4": tcp80_4,
            "tcp80_6": tcp80_6,
            "tcp443_4": tcp443_4,
            "tcp443_6": tcp443_6,
        }

        errors = [
            tcp80_4,
            tcp443_4,
            tcp80_6,
            tcp443_6,
        ]
        if self.cfg.get("alert_on_dns_failure", True):
            errors = [dns4, dns6] + errors
        errors = [v for v in errors if not v.ok]
        err = errors[0] if errors else None
        return dom, bundle, err

    def _human_duration(self, start_ts: float | None) -> str:
        if start_ts is None:
            return "0 s"
        sec = int(time.time() - start_ts)
        m, s = divmod(sec, 60)
        return f"{m} min {s} s" if m else f"{s} s"

    def _domain_max_fails(self) -> int:
        return max(1, int(self.cfg.get("domain_max_fails", self.cfg.get("max_fails", 3))))

    def _ping_max_fails(self) -> int:
        return max(1, int(self.cfg.get("ping_max_fails", self.cfg.get("max_fails", 3))))

    def _install_signal_handlers(self) -> None:
        """Instala handlers para SIGTERM/SIGINT para shutdown gracioso.
        Evita perda de alertas em flight ao receber 'systemctl stop' ou Ctrl+C."""
        def _handler(signum, _frame):
            self._log(f"Sinal {signum} recebido. Iniciando shutdown gracioso...")
            self._stop_event.set()
        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)
        except (ValueError, OSError):
            # signal.signal só funciona na thread principal; em testes pode falhar.
            pass

    def _await_incident_future(self, future: Future | None) -> None:
        """Aguarda o worker async do incidente concluir (com timeout) antes de
        coletar snapshot para resolução. Garante que thread_name esteja presente,
        evitando perda de agrupamento no GChat em recuperações rápidas (flapping).
        """
        if future is None or future.done():
            return
        try:
            future.result(timeout=_INCIDENT_FUTURE_JOIN_TIMEOUT)
        except FuturesTimeoutError:
            self._log("Incidente async ainda pendente após %.1fs; seguindo com resolução.", _INCIDENT_FUTURE_JOIN_TIMEOUT)
        except CancelledError:
            pass
        except (RuntimeError, OSError) as exc:
            self._log("Falha ao aguardar incidente async: %s", _redact_credentials(exc))

    def _shutdown(self) -> None:
        """Desliga executores e persiste fila offline antes de sair.
        Usa deadline compartilhado de 20s para todos os futures (respeita TimeoutStopSec=30).
        """
        self._log("Shutdown iniciado: aguardando workers pendentes...")
        deadline = time.monotonic() + 20.0
        for states in (self.dom_states, self.tcp_states, self.infra_states):
            for state in states.values():
                with state.lock:
                    fut = state.incident_future
                if fut is not None and not fut.done():
                    remaining = max(0.05, deadline - time.monotonic())
                    try:
                        fut.result(timeout=remaining)
                    except FuturesTimeoutError:
                        self._log_warn("Timeout aguardando incidente pendente durante shutdown.")
                    except CancelledError:
                        pass
                    except (RuntimeError, OSError) as exc:
                        self._log_warn("Falha aguardando future durante shutdown: %s", _redact_credentials(exc))

        with self._active_futures_lock:
            active_alert = list(self._active_alert_futures)
            active_trace = list(self._active_trace_futures)
        if active_alert:
            remaining = max(0.05, deadline - time.monotonic())
            done, not_done = wait(active_alert, timeout=remaining)
            if not_done:
                self._log_warn("Shutdown: %d futuros de alerta ainda pendentes.", len(not_done))
        if active_trace:
            remaining = max(0.05, deadline - time.monotonic())
            done, not_done = wait(active_trace, timeout=remaining)
            if not_done:
                self._log_warn("Shutdown: %d futuros de traceroute ainda pendentes.", len(not_done))

        for name, executor in (
            ("probe", self._probe_executor),
            ("alert", self._alert_executor),
            ("traceroute", self._traceroute_executor),
        ):
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except (RuntimeError, OSError) as exc:
                self._log_warn("Erro ao desligar executor %s: %s", name, _redact_credentials(exc))
        self.alert_queue.save()
        self._log("NetWatcher encerrado.")

    def run(self, once: bool = False) -> None:
        self._install_signal_handlers()
        self._log(f"NetWatcher iniciado em {self.server_name} ({self.server_ip})")
        self._log(f"Modo: {'dry-run' if self.dry_run else 'produção'}; ciclo único: {once}")
        self._log(f"Configuração carregada. Ciclos de {self.cfg.get('domains_per_cycle')} domínios.")

        try:
            while not self._stop_event.is_set():
                t_cycle_start = time.time()
                _log_context.cycle_id = secrets.token_hex(4)

                self._process_alert_queue() # Tenta descarregar mensagens pendentes

                domains = self._flat_domains
                domains_per_cycle = max(1, int(self.cfg.get("domains_per_cycle", 1)))
                domains_per_cycle = min(domains_per_cycle, len(domains))

                cycle_domains = []
                for i in range(domains_per_cycle):
                    idx = (self.domain_index + i) % len(domains)
                    cycle_domains.append(domains[idx])
                cycle_domain_order = {dom: pos for pos, dom in enumerate(cycle_domains)}

                domain_results = []
                infra_tasks = []
                infra_raw_results = []
                tcp_tasks = []
                tcp_results = []
                probe_meta: dict[Future, ProbeFutureMeta] = {}

                # Pool reutilizado entre ciclos (criado em __init__) para evitar
                # overhead de spinup/teardown a cada loop_interval_seconds.
                pool = self._probe_executor
                # Submete testes de domínio
                dom_futures = {}
                for dom in cycle_domains:
                    fut = pool.submit(self._test_domain_stack, dom)
                    dom_futures[fut] = dom
                    probe_meta[fut] = ProbeFutureMeta("domain", dom)

                # Submete testes de infra (Gateway v4 + v6 + ICMP Targets)
                if self.cfg.get("enable_gateway_test", True):
                    gw4f = pool.submit(self._test_gateway, "v4")
                    gw6f = pool.submit(self._test_gateway, "v6")
                    infra_tasks.append(gw4f)
                    infra_tasks.append(gw6f)
                    probe_meta[gw4f] = ProbeFutureMeta("infra", "gateway", family="v4")
                    probe_meta[gw6f] = ProbeFutureMeta("infra", "gateway", family="v6")

                for item in self.cfg["icmp_targets"]:
                    if item.get("ip_v4"):
                        fut = pool.submit(self._test_icmp, item["ip_v4"], item["label"], "v4")
                        infra_tasks.append(fut)
                        probe_meta[fut] = ProbeFutureMeta("infra", item["label"], family="v4", item={"ip": item["ip_v4"]})
                    if item.get("ip_v6"):
                        fut = pool.submit(self._test_icmp, item["ip_v6"], item["label"], "v6")
                        infra_tasks.append(fut)
                        probe_meta[fut] = ProbeFutureMeta("infra", item["label"], family="v6", item={"ip": item["ip_v6"]})

                for item in self.tcp_checks:
                    fut = pool.submit(self._test_tcp_check, item)
                    tcp_tasks.append(fut)
                    probe_meta[fut] = ProbeFutureMeta("tcp", self._tcp_check_label(item), item=item)

                _all_probe_futures = list(dom_futures.keys()) + infra_tasks + tcp_tasks
                probe_timeout = int(self.cfg.get("probe_timeout_seconds", 60))
                try:
                    for fut in as_completed(_all_probe_futures, timeout=probe_timeout):
                        try:
                            res = fut.result()
                            if isinstance(res, tuple):
                                if len(res) == 4:
                                    tcp_results.append(res)
                                else:
                                    domain_results.append(res)
                            else:
                                infra_raw_results.append(res)
                        except CancelledError:
                            meta = probe_meta.get(fut)
                            if meta is not None:
                                self._log_warn("Probe cancelado: kind=%s label=%s", meta.kind, meta.label)
                                if not self._stop_event.is_set():
                                    self._append_synthetic_probe_result(
                                        meta,
                                        CancelledError("probe cancelled"),
                                        domain_results,
                                        tcp_results,
                                        infra_raw_results,
                                    )
                        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as e:
                            meta = probe_meta.get(fut)
                            if meta is None:
                                self._log_warn("ERRO conhecido no teste: %s", _redact_credentials(e))
                                continue
                            self._log_warn(
                                "ERRO conhecido no worker de probe: kind=%s label=%s error=%s",
                                meta.kind,
                                meta.label,
                                _redact_credentials(e),
                            )
                            self._append_synthetic_probe_result(
                                meta,
                                e,
                                domain_results,
                                tcp_results,
                                infra_raw_results,
                            )
                        except Exception as e:
                            # Boundary defensivo: uma falha inesperada em worker não derruba o daemon.
                            meta = probe_meta.get(fut)
                            if meta is None:
                                self.logger.exception("ERRO inesperado no worker de probe: %s", _redact_credentials(e))
                                continue
                            self.logger.exception(
                                "ERRO inesperado no worker de probe: kind=%s label=%s error=%s",
                                meta.kind,
                                meta.label,
                                _redact_credentials(e),
                            )
                            self._append_synthetic_probe_result(
                                meta,
                                e,
                                domain_results,
                                tcp_results,
                                infra_raw_results,
                            )
                except FuturesTimeoutError:
                    pending_futures = [f for f in _all_probe_futures if not f.done()]
                    cancelled = 0
                    for pf in pending_futures:
                        if pf.cancel():
                            cancelled += 1
                    self._log_error(
                        "PROBE TIMEOUT: um ou mais probes não concluíram em %ss. "
                        "Pendentes=%d, cancelados=%d. Ciclo continua com resultados parciais.",
                        probe_timeout,
                        len(pending_futures),
                        cancelled,
                    )

                # Índice O(1) para evitar varreduras O(n) repetidas por alvo.
                infra_index: dict[tuple[str, str], TestResult] = {
                    (r.target, r.family or ""): r for r in infra_raw_results
                }

                # Pega gateway v4 e v6 (se habilitado). Default = SKIP quando desabilitado.
                gw4 = infra_index.get(
                    ("gateway", "v4"),
                    TestResult(True, "GW-v4 SKIP", "", "gateway", family="v4", state="SKIP"),
                )
                gw6 = infra_index.get(
                    ("gateway", "v6"),
                    TestResult(True, "GW-v6 SKIP", "", "gateway", family="v6", state="SKIP"),
                )

                icmp_results = []
                for item in self.cfg["icmp_targets"]:
                    r4 = infra_index.get(
                        (item["label"], "v4"),
                        TestResult(True, "SKIP (sem IP)", "", item["label"], family="v4", state="SKIP"),
                    )
                    r6 = infra_index.get(
                        (item["label"], "v6"),
                        TestResult(True, "SKIP (sem IP)", "", item["label"], family="v6", state="SKIP"),
                    )
                    icmp_results.append((item, r4, r6))


                for dom, bundle, err in sorted(domain_results, key=lambda x: cycle_domain_order[x[0]]):
                    dns4 = bundle["dns4"]
                    dns6 = bundle["dns6"]
                    tcp80_4 = bundle["tcp80_4"]
                    tcp80_6 = bundle["tcp80_6"]
                    tcp443_4 = bundle["tcp443_4"]
                    tcp443_6 = bundle["tcp443_6"]

                    v4_ip = self._tested_ip(tcp80_4, tcp443_4)
                    v6_ip = self._tested_ip(tcp80_6, tcp443_6)
                    state = self.dom_states[dom]
                    with state.lock:
                        v4_line = (
                            f"[DOM={dom},status={'FAIL' if err else 'OK'},fails={state.fail_count + (1 if err else 0)}/{self._domain_max_fails()}] "
                            f"v4=[{dns4.metric} {tcp80_4.metric} {tcp443_4.metric}] "
                            f"IP testado=v4:{v4_ip}"
                        )
                        v6_line = (
                            f"[DOM={dom},status={'FAIL' if err else 'OK'},fails={state.fail_count + (1 if err else 0)}/{self._domain_max_fails()}] "
                            f"v6=[{dns6.metric} {tcp80_6.metric} {tcp443_6.metric}] "
                            f"IP testado=v6:{v6_ip}"
                        )
                        _dom_log = self._log_warn if (state.fail_count + (1 if err else 0)) > 0 else self._log_debug
                        _dom_log(v4_line)
                        _dom_log(v6_line)
                    self._process_check_result("domain", dom, err, bundle)

                for label, bundle, err, item in sorted(tcp_results, key=lambda x: x[0]):
                    res4 = bundle.get("tcp4")
                    res6 = bundle.get("tcp6")
                    state = self.tcp_states[label]
                    with state.lock:
                        status = "FAIL" if err else "OK"
                        next_fails = state.fail_count + 1 if err else state.fail_count
                        family_mode = self._tcp_family_mode(item)
                        line = (
                            f"[TCPCHK={label},status={status},fails={next_fails}/{self._tcp_max_fails()}] "
                            f"family={family_mode} "
                        )
                        if res4 is not None:
                            line += f"v4=[{res4.metric}] "
                        if res6 is not None:
                            line += f"v6=[{res6.metric}]"
                        _tcp_log = self._log_warn if next_fails > 0 else self._log_debug
                        _tcp_log(line.strip())
                    self._process_check_result("tcp", label, err, bundle)

                ping_max = self._ping_max_fails()
                log_infra_each_domain = bool(self.cfg.get("log_infra_each_domain", True))
                for item, res4, res6 in icmp_results:
                    label = item["label"]
                    infra_err = res4 if not res4.ok else (res6 if not res6.ok else None)
                    with self.infra_states[label].lock:
                        next_fails = self.infra_states[label].fail_count + (1 if infra_err else 0)
                    if log_infra_each_domain or infra_err:
                        _icmp_log = self._log_warn if next_fails > 0 else self._log_debug
                        _icmp_log(
                            f"[ICMPv4[{label}],fails={next_fails}/{ping_max}] "
                            f"{res4.metric} | status={res4.state or ('OK' if res4.ok else 'FAIL')}"
                        )
                        _icmp_log(
                            f"[ICMPv6[{label}],fails={next_fails}/{ping_max}] "
                            f"{res6.metric} | status={res6.state or ('OK' if res6.ok else 'FAIL')}"
                        )
                    self._process_check_result("infra", label, infra_err)

                # Gateway tratado como label "gateway" no mesmo state-machine que ICMP.
                # Falha em qualquer família (v4/v6) conta como falha do gateway.
                gw_err = None
                if self.cfg.get("enable_gateway_test", True):
                    gw_err = gw4 if not gw4.ok else (gw6 if not gw6.ok else None)
                with self.infra_states["gateway"].lock:
                    gw_next_fails = self.infra_states["gateway"].fail_count + (1 if gw_err else 0)
                if log_infra_each_domain or gw_err:
                    _gw_log = self._log_warn if gw_next_fails > 0 else self._log_debug
                    _gw_log(
                        f"[GWv4,fails={gw_next_fails}/{ping_max}] "
                        f"{gw4.metric} | status={gw4.state or ('OK' if gw4.ok else 'FAIL')}"
                    )
                    _gw_log(
                        f"[GWv6,fails={gw_next_fails}/{ping_max}] "
                        f"{gw6.metric} | status={gw6.state or ('OK' if gw6.ok else 'FAIL')}"
                    )
                if self.cfg.get("enable_gateway_test", True):
                    self._process_check_result("infra", "gateway", gw_err)

                self.domain_index = (self.domain_index + domains_per_cycle) % len(domains)

                duration = time.time() - t_cycle_start
                _total_fail = (
                    sum(1 for _, _, err in domain_results if err)
                    + sum(1 for _, _, err, _ in tcp_results if err)
                    + sum(1 for _, r4, r6 in icmp_results if not (r4.ok and r6.ok))
                    + (0 if gw4.ok and gw6.ok else 1)
                )
                if _total_fail:
                    self._log_warn("--- Ciclo FAIL: dur=%.2fs ---", duration)
                else:
                    self._log("--- Ciclo OK: dur=%.2fs ---", duration)

                if once:
                    break

                # Sleep interruptível por SIGTERM/SIGINT
                if self._stop_event.wait(self.cfg.get("loop_interval_seconds", 0.5)):
                    break
        finally:
            self._shutdown()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatcher - monitor de conectividade")
    parser.add_argument("--config", default="netwatcher_config.json", help="Caminho para o arquivo de configuração JSON")
    parser.add_argument("--once", action="store_true", help="Executa apenas um ciclo de monitoramento e sai")
    parser.add_argument("--dry-run", action="store_true", help="Executa testes sem enviar alertas ao Google Chat")
    args = parser.parse_args()

    watcher = NetWatcher(args.config, dry_run=args.dry_run)
    watcher.run(once=args.once)
