import logging
import logging.handlers
import os
import sys
from datetime import datetime, timedelta


class DailyRotatingFileHandler(logging.handlers.BaseRotatingHandler):
    def __init__(
        self,
        directory: str,
        prefix: str = "monitor",
        date_format: str = "%Y-%m-%d",
        backup_count: int = 7,
        encoding: str | None = "utf-8",
    ):
        self.directory = directory
        self.prefix = prefix
        self.date_format = date_format
        self.backup_count = backup_count
        self.current_date = datetime.now().date()
        super().__init__(self._current_filename(), mode="a", encoding=encoding)

    def _current_filename(self) -> str:
        return os.path.join(
            self.directory,
            f"{self.prefix}_{self.current_date.strftime(self.date_format)}.log",
        )

    def shouldRollover(self, record: logging.LogRecord) -> bool:
        return datetime.now().date() != self.current_date

    def doRollover(self) -> None:
        if self.stream:
            self.stream.flush()
            self.stream.close()
            self.stream = None
        self.current_date = datetime.now().date()
        self.baseFilename = self._current_filename()
        self.stream = self._open()
        self._remove_old_logs()

    def _remove_old_logs(self) -> None:
        try:
            cutoff = datetime.now() - timedelta(days=self.backup_count)
            for fname in os.listdir(self.directory):
                if not fname.startswith(self.prefix) or not fname.endswith(".log"):
                    continue
                fpath = os.path.join(self.directory, fname)
                if datetime.fromtimestamp(os.path.getmtime(fpath)) < cutoff:
                    os.remove(fpath)
        except OSError as exc:
            sys.stderr.write(f"Erro ao limpar logs antigos: {exc}\n")
