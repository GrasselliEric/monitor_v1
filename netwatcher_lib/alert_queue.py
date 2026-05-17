import json
import logging
import math
import os
import threading
import time
from collections import deque
from typing import TypedDict
from netwatcher_lib.json_utils import DuplicateKeyError, load_json_strict


class AlertEntry(TypedDict, total=False):
    text: str
    thread_key: str | None
    thread_name: str | None
    timestamp: float


class AlertQueue:
    """Fila persistente de alertas offline, com TTL e cap, thread-safe."""
    _MAX_TEXT_CHARS = 3800
    _MAX_THREAD_REF_CHARS = 512

    def __init__(
        self,
        path: str,
        ttl: int,
        cap: int,
        save_every_ops: int = 1,
        save_interval_seconds: float = 0.0,
    ):
        self.path = path
        self.ttl = ttl
        self.cap = cap
        self.lock = threading.Lock()
        self.logger = logging.getLogger("NetWatcher.AlertQueue")
        self.queue: deque[AlertEntry] = deque()
        self.save_every_ops = max(1, int(save_every_ops))
        self.save_interval_seconds = max(0.0, float(save_interval_seconds))
        self._ops_since_save = 0
        self._last_save_monotonic = time.monotonic()
        self._load()

    _MAX_QUEUE_FILE_BYTES = 20 * 1024 * 1024  # 20 MB

    def _load(self) -> None:
        with self.lock:
            try:
                size = os.path.getsize(self.path)
                if size > self._MAX_QUEUE_FILE_BYTES:
                    self.logger.warning(
                        "Fila offline (%s) excede limite de 20 MB (%d bytes); descartando.",
                        self.path,
                        size,
                    )
                    self.queue = deque()
                else:
                    with open(self.path, "r", encoding="utf-8") as f:
                        payload = load_json_strict(f)
                        if isinstance(payload, list):
                            self.queue = deque(payload)
                        else:
                            self.logger.warning(
                                "Fila offline (%s) inválida: raiz JSON deve ser lista; descartando.",
                                self.path,
                            )
                            self.queue = deque()
            except FileNotFoundError:
                self.queue = deque()
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError, RecursionError) as exc:
                self.logger.warning("Falha ao carregar fila offline (%s): %s", self.path, exc)
                self.queue = deque()
            self._trim_locked()
            try:
                self._save_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir fila offline após load (%s): %s", self.path, exc)

    def _save_locked(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(list(self.queue), f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._ops_since_save = 0
            self._last_save_monotonic = time.monotonic()
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def _should_save_locked(self) -> bool:
        if self._ops_since_save >= self.save_every_ops:
            return True
        if self.save_interval_seconds > 0.0:
            elapsed = time.monotonic() - self._last_save_monotonic
            if elapsed >= self.save_interval_seconds:
                return True
        return False

    def _mark_mutation_locked(self) -> None:
        self._ops_since_save += 1
        if self._should_save_locked():
            self._save_locked()

    def save(self) -> None:
        """Persiste a fila imediatamente. Chamado pelo shutdown do NetWatcher."""
        with self.lock:
            try:
                self._save_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir fila offline em save(%s): %s", self.path, exc)

    def enqueue(self, alert: AlertEntry) -> None:
        with self.lock:
            self.queue.append(alert)
            self._trim_locked()
            try:
                self._mark_mutation_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir enqueue da fila offline (%s): %s", self.path, exc)

    def requeue_front(self, alert: AlertEntry) -> None:
        with self.lock:
            self.queue.appendleft(alert)
            self._trim_locked()
            try:
                self._mark_mutation_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir requeue da fila offline (%s): %s", self.path, exc)

    def requeue_back(self, alert: AlertEntry) -> None:
        """Reenfileira no fim para evitar head-of-line blocking persistente."""
        with self.lock:
            self.queue.append(alert)
            self._trim_locked()
            try:
                self._mark_mutation_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir requeue-back da fila offline (%s): %s", self.path, exc)

    def dequeue(self) -> "AlertEntry | None":
        with self.lock:
            self._trim_locked()
            if not self.queue:
                return None
            alert = self.queue.popleft()
            try:
                self._mark_mutation_locked()
            except OSError as exc:
                self.logger.warning("Falha ao persistir dequeue da fila offline (%s): %s", self.path, exc)
            return alert

    def _trim_locked(self) -> None:
        """Remove itens expirados e excedentes de cap. Chamar apenas com lock."""
        now = time.time()
        trimmed: deque[AlertEntry] = deque()
        for alert in self.queue:
            if not isinstance(alert, dict):
                continue
            text_obj = alert.get("text")
            if not isinstance(text_obj, str):
                continue
            text = text_obj.replace("\x00", "")
            if not text.strip():
                continue
            if len(text) > self._MAX_TEXT_CHARS:
                text = text[: self._MAX_TEXT_CHARS]
            ts_obj = alert.get("timestamp", now)
            try:
                ts = float(ts_obj)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(ts):
                continue
            if now - ts < self.ttl:
                sanitized: AlertEntry = {"text": text, "timestamp": ts}
                thread_key = self._sanitize_ref(alert.get("thread_key"))
                if thread_key is not None:
                    sanitized["thread_key"] = thread_key
                thread_name = self._sanitize_ref(alert.get("thread_name"))
                if thread_name is not None:
                    sanitized["thread_name"] = thread_name
                trimmed.append(sanitized)
        self.queue = trimmed
        excess = len(self.queue) - self.cap
        if excess > 0:
            for _ in range(excess):
                self.queue.popleft()

    def _sanitize_ref(self, value: object) -> str | None:
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
        if len(clean) > self._MAX_THREAD_REF_CHARS:
            clean = clean[: self._MAX_THREAD_REF_CHARS]
        return clean

    def __len__(self) -> int:
        with self.lock:
            return len(self.queue)
