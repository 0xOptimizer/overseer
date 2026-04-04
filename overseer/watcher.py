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
        self._state: dict[str, dict] = self._load_state()

    def _load_state(self) -> dict:
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_state(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._state, f, indent=2)
        os.replace(tmp, STATE_FILE)

    def _update_state(self, path: str, inode: int, offset: int) -> None:
        self._state[path] = {"inode": inode, "offset": offset}
        self._save_state()

    def _open_file(self, path: str) -> dict:
        try:
            fh = open(path, "r")
            stat = os.stat(path)
            current_inode = stat.st_ino
            current_size = stat.st_size

            saved = self._state.get(path)
            if saved and saved.get("inode") == current_inode:
                offset = saved.get("offset", 0)
                if offset <= current_size:
                    fh.seek(offset)
                else:
                    fh.seek(0)
                    offset = 0
                    self._update_state(path, current_inode, offset)
            else:
                fh.seek(0)
                offset = 0
                self._update_state(path, current_inode, offset)

            sys.stdout.write(f"[debug] opened {path} at offset {fh.tell()}\n")
            sys.stdout.flush()
            return {"fh": fh, "inode": current_inode}
        except FileNotFoundError:
            sys.stdout.write(f"[debug] file not found: {path}\n")
            sys.stdout.flush()
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
            self._state.pop(path, None)
            self._save_state()
            return {"fh": None, "inode": None}

        if current_inode != entry["inode"]:
            if entry["fh"]:
                entry["fh"].close()
            try:
                fh = open(path, "r")
                fh.seek(0)
                self._update_state(path, current_inode, 0)
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
        sys.stdout.write(f"[debug] {path}: read {len(lines)} lines\n")
        sys.stdout.flush()
        if not lines:
            return

        rows = [
            row
            for line in lines
            for row in parse_line(line, self._detector)
        ]

        sys.stdout.write(f"[debug] {path}: parsed {len(rows)} rows\n")
        sys.stdout.flush()

        if rows:
            sys.stdout.write(f"[debug] inserting {len(rows)} rows\n")
            sys.stdout.flush()
            insert_rows(self._pool, rows)

        current_offset = entry["fh"].tell()
        self._update_state(path, entry["inode"], current_offset)

    def _close_all(self) -> None:
        for entry in self._handles.values():
            if entry.get("fh"):
                entry["fh"].close()
        self._save_state()

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