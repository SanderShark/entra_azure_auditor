"""Run blocking work (Graph calls, sign-in, a change flow step) on a thread pool.

The UI thread must never wait on the network. ``TaskRunner.submit(fn, on_done, on_error)`` runs ``fn``
on a worker and calls ``on_done(result)`` or ``on_error(exception)`` back on the UI thread.

Why the relay: a Qt signal connected to a plain Python callable runs that callable in the thread that
emitted it, which would touch widgets from a worker. Workers emit on a relay object instead, and the
runner (a QObject living on the UI thread) receives through a queued connection and dispatches.
"""

from __future__ import annotations

import itertools
import logging
from typing import Any, Callable, Optional

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

log = logging.getLogger(__name__)


class _Relay(QObject):
    finished = Signal(int, bool, object)


class _Job(QRunnable):
    def __init__(self, job_id: int, fn: Callable[[], Any], relay: _Relay) -> None:
        super().__init__()
        # The pool must not delete the C++ object when run() returns: Python owns this job (the runner keeps
        # it until its result has been delivered). With auto-delete on, the pool's delete could race with
        # Python collecting the same object and crash the process now and then.
        self.setAutoDelete(False)
        self._job_id, self._fn, self._relay = job_id, fn, relay

    def run(self) -> None:  # worker thread
        try:
            value, ok = self._fn(), True
        except BaseException as exc:  # noqa: BLE001 - every failure must reach the UI, not vanish
            value, ok = exc, False
        self._relay.finished.emit(self._job_id, ok, value)


def _log_error(exc: BaseException) -> None:
    log.error("background task failed: %s", exc)


class TaskRunner(QObject):
    """Owns a thread pool. Callbacks always run on the thread that created the runner (the UI thread)."""

    def __init__(self, parent: Optional[QObject] = None, *, max_threads: int = 4) -> None:
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(max_threads)
        self._relay = _Relay()
        self._relay.finished.connect(self._deliver)   # receiver is self: queued onto the UI thread
        self._callbacks: dict[int, tuple[Optional[Callable], Callable]] = {}
        self._jobs: dict[int, _Job] = {}        # keeps each job alive until _deliver has run for it
        self._ids = itertools.count(1)

    def submit(self, fn: Callable[[], Any], on_done: Optional[Callable[[Any], None]] = None,
               on_error: Optional[Callable[[BaseException], None]] = None) -> int:
        job_id = next(self._ids)
        self._callbacks[job_id] = (on_done, on_error or _log_error)
        job = _Job(job_id, fn, self._relay)
        self._jobs[job_id] = job
        self._pool.start(job)
        return job_id

    @property
    def busy(self) -> bool:
        return bool(self._callbacks)

    def wait(self, msecs: int = 30_000) -> bool:
        """Block until every job has finished (shutdown and tests). Callbacks still need the event loop."""
        return self._pool.waitForDone(msecs)

    @Slot(int, bool, object)
    def _deliver(self, job_id: int, ok: bool, value: Any) -> None:
        on_done, on_error = self._callbacks.pop(job_id, (None, _log_error))
        self._jobs.pop(job_id, None)            # run() has returned: the job can go
        if ok:
            if on_done is not None:
                on_done(value)
        else:
            on_error(value)
