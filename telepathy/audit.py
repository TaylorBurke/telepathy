"""Append-only JSONL audit log."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable


class FileSink:
    """Append one line per event to a file of mode 0600.

    Guarantees: each record is one os.write under a lock, so records from
    different threads never interleave. If a write fails or is short and cannot
    be finished, a newline is appended (or queued for the next write) so the
    next record starts on its own line, and OSError is raised; the fragment
    stays visible as one unparsable line, never glued to a good record.

    `reopen()` (wired to SIGHUP by the daemon) lets logrotate move the file
    away. The open, the swap and the close of the old fd all happen under the
    write lock, so each record goes whole to exactly one of the two files. If
    the open fails, the old fd stays in use and OSError is raised.
    `close()` is idempotent and a `reopen()` after it does nothing.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._fd: int | None = self._open()
        self._need_newline = False

    def _open(self) -> int:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)  # a file created by something else stays private
        except OSError:
            pass
        return fd

    def __call__(self, line: str) -> None:
        data = line.encode("utf-8")
        with self._lock:
            if self._fd is None:
                raise ValueError("audit sink is closed")
            if self._need_newline:
                os.write(self._fd, b"\n")  # may raise; then nothing is written
                self._need_newline = False
            written = 0
            try:
                while written < len(data):
                    written += os.write(self._fd, data[written:])
            except OSError:
                if written:
                    try:
                        os.write(self._fd, b"\n")
                    except OSError:
                        self._need_newline = True
                raise

    def reopen(self) -> None:
        with self._lock:
            if self._fd is None:
                return
            new_fd = self._open()  # on failure the old fd stays in place
            old, self._fd = self._fd, new_fd
            try:
                os.close(old)
            except OSError:
                pass  # already on the new file: the reopen succeeded

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                fd, self._fd = self._fd, None
                os.close(fd)


class AuditLog:
    def __init__(self, sink: Callable[[str], None] | None = None, clock=time.time):
        self._sink = sink
        self._clock = clock

    def write(self, event: str, **fields) -> None:
        if self._sink is None:
            return
        rec = {"ts": self._clock(), "event": event, **fields}
        self._sink(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
