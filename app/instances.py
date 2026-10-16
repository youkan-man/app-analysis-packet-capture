"""Private, leased analysis instances. No durable store or enumerable capture catalog.

Each instance owns a temporary directory, an opaque capability, a subprocess and
one serial job queue. Blocking TShark work never runs on the HTTP event loop.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

CAPABILITY = re.compile(r'^[0-9a-f]{64}$')
MAX_REPLY = 80 * 1024 * 1024


class MissingInstance(Exception):
    pass


class CapacityError(Exception):
    pass


class Instance:
    def __init__(self, root: Path, token: str):
        self.id = uuid.uuid4().hex
        self.root = root / self.id
        self.root.mkdir(mode=0o700)
        self.path = self.root / 'capture.bin'
        self.digest = hashlib.sha256(token.encode()).digest()
        self.touched = time.monotonic()
        self.process: subprocess.Popen | None = None
        self.executor: ThreadPoolExecutor | None = None
        self.jobs: dict[str, Future] = {}
        self.lock = threading.RLock()
        self.closed = False
        self.format = ''

    def authenticates(self, token: str) -> bool:
        return hmac.compare_digest(self.digest, hashlib.sha256(token.encode()).digest())

    def start(self, fmt: str) -> None:
        with self.lock:
            if self.closed:
                raise MissingInstance()
            self.format = fmt
            self.process = subprocess.Popen(
                [sys.executable, '-m', 'app.analysis_worker', str(self.path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding='utf-8', bufsize=1, start_new_session=True,
                env={**os.environ, 'TMPDIR': str(self.root)},
            )
            self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='capture-analysis')

    def _execute(self, command: dict) -> dict:
        process = self.process
        if self.closed or process is None or process.poll() is not None:
            raise MissingInstance()
        # Only this instance's serial executor touches its protocol pipes.
        process.stdin.write(json.dumps(command, ensure_ascii=False) + '\n')
        process.stdin.flush()
        reply = process.stdout.readline(MAX_REPLY + 1)
        if not reply or len(reply) > MAX_REPLY or not reply.endswith('\n'):
            raise MissingInstance()
        return json.loads(reply)

    def submit(self, command: dict) -> str:
        with self.lock:
            if self.closed or self.executor is None or self.process.poll() is not None:
                raise MissingInstance()
            if len(self.jobs) >= 32:
                raise CapacityError('処理待ちが多すぎます。完了後に再実行してください')
            job = uuid.uuid4().hex
            self.jobs[job] = self.executor.submit(self._execute, command)
            return job

    def result(self, job: str) -> dict:
        with self.lock:
            future = self.jobs.get(job)
            if future is None or self.closed:
                raise MissingInstance()
            if not future.done():
                return {'state': 'running' if future.running() else 'queued'}
            try:
                outcome = future.result()
            except Exception as exc:
                # Do not expose subprocess arguments, payloads, or runtime paths.
                raise MissingInstance() from exc
            return ({'state': 'done', 'result': outcome['result']} if outcome['ok'] else
                    {'state': 'error', 'error': outcome['error']})

    def discard(self, job: str) -> None:
        with self.lock:
            future = self.jobs.pop(job, None)
            if future is None:
                raise MissingInstance()
            future.cancel()  # Already-running work finishes without retaining its result.

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            process = self.process
            for future in self.jobs.values():
                future.cancel()
            self.jobs.clear()
        if process is not None:
            # The worker is a session leader; also stop its TShark descendants.
            try:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout):
                if pipe:
                    pipe.close()
        if self.executor:
            self.executor.shutdown(wait=True, cancel_futures=True)
        shutil.rmtree(self.root, ignore_errors=True)


class Instances:
    def __init__(self, runtime_dir: Path | None = None, idle_seconds: float = 900,
                 maximum: int = 32):
        if runtime_dir is not None:
            runtime_dir.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='pcana-analysis-', dir=runtime_dir)
        self.root = Path(self.temp.name)
        self.idle_seconds, self.maximum = idle_seconds, maximum
        self.items: dict[str, Instance] = {}
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.reaper = threading.Thread(target=self._reap, daemon=True, name='analysis-expiry')
        self.reaper.start()

    def allocate(self, token: str) -> Instance:
        with self.lock:
            if self.stopped.is_set():
                raise MissingInstance()
            if len(self.items) >= self.maximum:
                raise CapacityError('解析インスタンスが使用中です。不要なファイルを閉じてください')
            instance = Instance(self.root, token)
            self.items[instance.id] = instance
            return instance

    def get(self, identifier: str, token: str) -> Instance:
        with self.lock:
            instance = self.items.get(identifier)
            if not instance or not instance.authenticates(token) or instance.closed:
                raise MissingInstance()
            if time.monotonic() - instance.touched > self.idle_seconds:
                self.items.pop(identifier, None)
            else:
                instance.touched = time.monotonic()
                return instance
        instance.close()
        raise MissingInstance()

    def remove(self, instance: Instance) -> None:
        with self.lock:
            self.items.pop(instance.id, None)
        instance.close()

    def expire(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self.lock:
            stale = [item for item in self.items.values()
                     if now - item.touched > self.idle_seconds]
            for item in stale:
                self.items.pop(item.id, None)
        for item in stale:
            item.close()

    def _reap(self) -> None:
        while not self.stopped.wait(max(.1, min(30, self.idle_seconds / 2))):
            self.expire()

    def close(self) -> None:
        self.stopped.set()
        self.reaper.join()
        with self.lock:
            values = list(self.items.values())
            self.items.clear()
        for value in values:
            value.close()
        self.temp.cleanup()
