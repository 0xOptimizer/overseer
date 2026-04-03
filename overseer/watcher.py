import os
import sys
import time
import signal

from mysql.connector.pooling import MySQLConnectionPool

from overseer.config import Config
from overseer.database import insert_rows
from overseer.detector import BotDetector
from overseer.parser import parse_line

_running = True


def _signal_handler(sig, frame) -> None:
    global _running
    _running = False


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


class Watcher:
    def __init__(self, config: Config, pool: MySQLConnectionPool) -> None:
        self._config = config
        self._pool = pool
        self._detector = BotDetector(config)
        self._handles: dict[str, dict] = {}

    def _open_file(self, path: str) -> dict:
        try:
            fh = open(path, "r")
            fh.seek(0, 2)
            return {"fh": fh, "inode": os.stat(path).st_ino}
        except FileNotFoundError:
            return {"fh": None, "inode": None}

    def _init_handles(self) -> None:
        for path in self._config.log_files:
            self._handles[path] = self._open_file(path)

    def _reopen_if_rotated(self, path: str, entry: dict) -> dict:
        try:
            current_inode = os.stat(path).st_ino
        except FileNotFoundError:
            if entry["fh"]:
                entry["fh"].close()
            return {"fh": None, "inode": None}

        if current_inode != entry["inode"]:
            if entry["fh"]:
                entry["fh"].close()
            try:
                fh = open(path, "r")
                return {"fh": fh, "inode": current_inode}
            except Exception:
                return {"fh": None, "inode": None}

        return entry

    def _process_path(self, path: str) -> None:
        entry = self._handles[path]

        if entry["fh"] is None:
            if os.path.exists(path):
                self._handles[path] = self._open_file(path)
            return

        self._handles[path] = self._reopen_if_rotated(path, entry)
        entry = self._handles[path]

        if entry["fh"] is None:
            return

        lines = entry["fh"].readlines()
        if not lines:
            return

        rows = [
            r for r in (
                parse_line(line, self._detector) for line in lines
            )
            if r is not None
        ]

        insert_rows(self._pool, rows)

    def _close_all(self) -> None:
        for entry in self._handles.values():
            if entry.get("fh"):
                entry["fh"].close()

    def run(self) -> None:
        self._init_handles()
        sys.stdout.write("Overseer is watching.\n")
        sys.stdout.flush()

        while _running:
            for path in self._config.log_files:
                self._process_path(path)
            time.sleep(self._config.poll_interval)

        self._close_all()
        sys.stdout.write("Overseer shut down cleanly.\n")
        sys.stdout.flush()