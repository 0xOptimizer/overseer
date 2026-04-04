import os
import sys
import time
import signal
import json
from pathlib import Path
from mysql.connector.pooling import MySQLConnectionPool

from overseer.config import Config
from overseer.database import insert_rows
from overseer.detector import BotDetector
from overseer.parser import parse_line

_running = True
STATE_FILE = Path("/states/watcher_state.json")

FLUSH_INTERVAL = 2.0
MAX_PENDING = 500
MAX_PARTIAL_LINE_BYTES = 65536
INSERT_RETRIES = 3
INSERT_RETRY_DELAY = 2.0


def _signal_handler(sig, frame) -> None:
    global _running
    _running = False


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


class LogFile:
    def __init__(self, path: str, detector: BotDetector) -> None:
        self.path = path
        self.detector = detector
        self.fh = None
        self.inode: int | None = None
        self.offset: int = 0
        self._partial: str = ""
        self._error_logged: bool = False

    def open(self, offset: int = 0, inode: int | None = None) -> bool:
        try:
            fh = open(self.path, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.path)
            current_inode = stat.st_ino
            current_size = stat.st_size

            if inode is not None and inode == current_inode and 0 <= offset <= current_size:
                fh.seek(offset)
                self.offset = offset
            else:
                fh.seek(0)
                self.offset = 0

            self.fh = fh
            self.inode = current_inode
            self._partial = ""
            self._error_logged = False
            sys.stdout.write(
                f"[overseer] opened {self.path} "
                f"(inode={current_inode}, offset={self.offset})\n"
            )
            sys.stdout.flush()
            return True
        except FileNotFoundError:
            if not self._error_logged:
                sys.stderr.write(f"[overseer] file not found: {self.path}\n")
                self._error_logged = True
            return False
        except PermissionError:
            sys.stderr.write(
                f"[overseer] FATAL: permission denied reading {self.path}. "
                f"Check that the overseer user has read access.\n"
            )
            sys.stderr.flush()
            return False

    def close(self) -> None:
        if self.fh:
            try:
                self.fh.close()
            except Exception:
                pass
            self.fh = None

    def check_rotation(self) -> bool:
        try:
            stat = os.stat(self.path)
            if stat.st_ino != self.inode:
                sys.stdout.write(f"[overseer] inode change detected: {self.path}\n")
                sys.stdout.flush()
                return True
            if stat.st_size < self.offset:
                sys.stdout.write(f"[overseer] truncation detected: {self.path}\n")
                sys.stdout.flush()
                return True
            return False
        except FileNotFoundError:
            sys.stdout.write(f"[overseer] file disappeared: {self.path}\n")
            sys.stdout.flush()
            return True

    def read_lines(self) -> list[str]:
        if not self.fh:
            return []

        complete_lines = []
        try:
            while True:
                line = self.fh.readline()
                if not line:
                    break

                if not line.endswith("\n"):
                    if len(self._partial) + len(line) > MAX_PARTIAL_LINE_BYTES:
                        sys.stderr.write(
                            f"[overseer] partial line exceeded {MAX_PARTIAL_LINE_BYTES} "
                            f"bytes on {self.path}, discarding.\n"
                        )
                        self._partial = ""
                    else:
                        self._partial += line
                    break

                full_line = self._partial + line
                self._partial = ""
                complete_lines.append(full_line.strip())

            self.offset = self.fh.tell()
        except OSError as exc:
            sys.stderr.write(f"[overseer] read error on {self.path}: {exc}\n")

        return [l for l in complete_lines if l]

    def parse_rows(self, lines: list[str]) -> list[tuple]:
        rows = []
        for line in lines:
            parsed = parse_line(line, self.detector)
            rows.extend(parsed)
        return rows


class Watcher:
    def __init__(self, config: Config, pool: MySQLConnectionPool) -> None:
        self._config = config
        self._pool = pool
        self._detector = BotDetector(config)
        self._logs: dict[str, LogFile] = {}
        self._state: dict = self._load_state()
        self._pending: list[tuple] = []
        self._last_flush = time.monotonic()

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except (json.JSONDecodeError, OSError) as exc:
                sys.stderr.write(f"[overseer] state load failed: {exc}, starting fresh.\n")
        return {}

    def _save_state(self) -> None:
        try:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = STATE_FILE.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(self._state, f, indent=2)
            os.replace(tmp, STATE_FILE)
        except OSError as exc:
            sys.stderr.write(f"[overseer] state save failed: {exc}\n")

    def _update_state(self, lf: LogFile) -> None:
        self._state[lf.path] = {
            "inode": lf.inode,
            "offset": lf.offset,
        }

    def _init_logs(self) -> None:
        for path in self._config.log_files:
            saved = self._state.get(path, {})
            lf = LogFile(path, self._detector)
            lf.open(
                offset=saved.get("offset", 0),
                inode=saved.get("inode"),
            )
            self._logs[path] = lf

    def _flush(self, force: bool = False) -> None:
        now = time.monotonic()
        elapsed = now - self._last_flush
        should_flush = force or elapsed >= FLUSH_INTERVAL or len(self._pending) >= MAX_PENDING

        if not should_flush or not self._pending:
            if not self._pending:
                self._last_flush = now
            return

        rows_to_insert = self._pending[:]
        attempt = 0
        while attempt < INSERT_RETRIES:
            success = insert_rows(self._pool, rows_to_insert)
            if success:
                self._pending.clear()
                self._save_state()
                self._last_flush = time.monotonic()
                return
            attempt += 1
            sys.stderr.write(
                f"[overseer] insert failed, attempt {attempt}/{INSERT_RETRIES}. "
                f"Retrying in {INSERT_RETRY_DELAY}s\n"
            )
            time.sleep(INSERT_RETRY_DELAY)

        sys.stderr.write(
            f"[overseer] FATAL: insert failed after {INSERT_RETRIES} attempts. "
            f"{len(rows_to_insert)} rows dropped. Check DB connection.\n"
        )
        self._pending.clear()
        self._last_flush = time.monotonic()

    def _process(self, lf: LogFile) -> None:
        if not lf.fh:
            if os.path.exists(lf.path):
                saved = self._state.get(lf.path, {})
                lf.open(
                    offset=saved.get("offset", 0),
                    inode=saved.get("inode"),
                )
            return

        if lf.check_rotation():
            lf.close()
            opened = lf.open(offset=0, inode=None)
            if opened:
                self._update_state(lf)
                self._save_state()
            return

        lines = lf.read_lines()
        if not lines:
            return

        rows = lf.parse_rows(lines)
        if rows:
            self._pending.extend(rows)

        self._update_state(lf)

    def _close_all(self) -> None:
        for lf in self._logs.values():
            lf.close()

    def run(self) -> None:
        self._init_logs()
        sys.stdout.write("Overseer is watching.\n")
        sys.stdout.flush()

        while _running:
            for lf in self._logs.values():
                self._process(lf)
            self._flush()
            time.sleep(self._config.poll_interval)

        self._flush(force=True)
        self._close_all()
        sys.stdout.write("Overseer shut down cleanly.\n")
        sys.stdout.flush()