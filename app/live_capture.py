"""Bounded, capability-owned dumpcap sessions. Only the capture sidecar imports this.

Native interfaces only: no remote capture URLs, pipes, shell, or extcap helpers.
Capture files are transient; the browser acknowledges them only after local commit.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from .instances import MissingInstance, CapacityError


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class Options:
    interface: str
    expression: str
    duration: int
    size_mib: int
    packets: int
    snaplen: int


def options(value: object, interfaces: set[str]) -> Options:
    if not isinstance(value, dict) or set(value) - {
        'interface', 'protocol', 'host', 'port', 'direction', 'bpf',
        'duration', 'size_mib', 'packets', 'snaplen',
    }:
        raise CaptureError('取得条件が不正です')
    interface = value.get('interface')
    if not isinstance(interface, str) or interface not in interfaces:
        raise CaptureError('利用可能なインターフェースを選択してください')
    protocol = value.get('protocol', 'any')
    direction = value.get('direction', 'any')
    if protocol not in ('any', 'tcp', 'udp', 'icmp', 'arp') or direction not in ('any', 'src', 'dst'):
        raise CaptureError('プロトコルまたは方向が不正です')
    parts = []
    if protocol != 'any':
        parts.append('(icmp or icmp6)' if protocol == 'icmp' else protocol)
    host = value.get('host', '')
    if not isinstance(host, str):
        raise CaptureError('IPアドレスを指定してください')
    if host.strip():
        try:
            address = str(ipaddress.ip_address(host.strip()))
        except ValueError as exc:
            raise CaptureError('IPアドレスを指定してください') from exc
        prefix = '' if direction == 'any' else direction + ' '
        parts.append(prefix + 'host ' + address)
    port = value.get('port')
    if port is not None:
        if type(port) is not int or not 1 <= port <= 65535 or protocol in ('icmp', 'arp'):
            raise CaptureError('ポートはTCP/UDPで1〜65535を指定してください')
        parts.append('port ' + str(port))
    raw = value.get('bpf', '')
    if not isinstance(raw, str) or len(raw) > 1024 or any(ord(c) < 32 for c in raw):
        raise CaptureError('取得フィルターは1024文字以内で指定してください')
    if raw.strip():
        parts.append(raw.strip())
    limits = {'duration': (1, 3600, 60), 'size_mib': (1, 64, 32),
              'packets': (1, 1000000, 100000), 'snaplen': (64, 262144, 262144)}
    numbers = {}
    for name, (low, high, default) in limits.items():
        number = value.get(name, default)
        if type(number) is not int or not low <= number <= high:
            raise CaptureError(f'{name} は {low}〜{high} で指定してください')
        numbers[name] = number
    return Options(interface=interface, expression=' and '.join(f'({p})' for p in parts), **numbers)


def interfaces() -> list[dict]:
    """Do not accept anything outside the host's native interface name set."""
    executable = os.getenv('DUMPCAP_BIN', 'dumpcap')
    native = {name for _, name in socket.if_nameindex()} | {'any'}
    allowed = {v.strip() for v in os.getenv('CAPTURE_INTERFACES', '').split(',') if v.strip()}
    try:
        result = subprocess.run([executable, '-D'], capture_output=True, text=True, timeout=5,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError('取得サービスでdumpcapを実行できません') from exc
    if result.returncode:
        raise CaptureError('インターフェースを取得できません。取得サービスの権限を確認してください')
    items = []
    for line in result.stdout.splitlines():
        match = re.fullmatch(r'\d+\. (\S+)(?: \((.*)\))?', line.strip())
        if match and match[1] in native and (not allowed or match[1] in allowed):
            items.append({'name': match[1], 'label': match[1] + (f' — {match[2]}' if match[2] else '')})
    return items


class Session:
    def __init__(self, root: Path, token: str, config: Options):
        self.id = uuid.uuid4().hex
        self.digest = hashlib.sha256(token.encode()).digest()
        self.options = config
        self.root = root / self.id
        self.root.mkdir(mode=0o700)
        self.path = self.root / 'capture.pcapng'
        self.path.touch(mode=0o600)
        self.log = self.root / 'dumpcap.log'
        self.lock = threading.RLock()
        self.process: subprocess.Popen | None = None
        self.stopped = False
        self.closed = False
        self.touched = time.monotonic()
        self.error = ''

    def authenticates(self, token: str) -> bool:
        return hmac.compare_digest(self.digest, hashlib.sha256(token.encode()).digest())

    def start(self):
        cfg = self.options
        command = [os.getenv('DUMPCAP_BIN', 'dumpcap'), '-q', '-n', '-p', '-i', cfg.interface,
                   '-s', str(cfg.snaplen), '-a', f'duration:{cfg.duration}',
                   '-a', f'filesize:{cfg.size_mib * 1024}', '-c', str(cfg.packets),
                   '-w', str(self.path)]
        if cfg.expression:
            command += ['-f', cfg.expression]
        try:
            with self.log.open('wb') as log:
                self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
        except OSError as exc:
            raise CaptureError('dumpcapを開始できません。取得サービスを確認してください') from exc

    def status(self) -> dict:
        with self.lock:
            if self.closed:
                raise MissingInstance()
            code = self.process.poll() if self.process else None
            size = self.path.stat().st_size if self.path.exists() else 0
            if code is None:
                state = 'recording' if size >= 28 else 'starting'
            else:
                state = 'complete' if (code == 0 or (self.stopped and code == -signal.SIGINT)) and size >= 28 else 'failed'
                if state == 'failed' and not self.error:
                    # Bound and scrub the diagnostic; never publish runtime paths.
                    text = self.log.read_bytes()[-2048:].decode('utf-8', 'replace') if self.log.exists() else ''
                    text = text.replace(str(self.root), '<capture>')
                    self.error = ('取得に失敗しました。権限・インターフェース・取得フィルターを確認してください。 ' + text.strip())[:900]
            return {'id': self.id, 'state': state, 'interface': self.options.interface,
                    'bytes': size, 'filter': self.options.expression, 'error': self.error}

    def stop(self) -> dict:
        with self.lock:
            if self.closed:
                raise MissingInstance()
            if self.process and self.process.poll() is None:
                self.stopped = True
                try:
                    self.process.send_signal(signal.SIGINT)
                    self.process.wait(timeout=5)
                except ProcessLookupError:
                    pass
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
                    self.error = '取得プロセスが停止に応答しませんでした。データは確定していません'
            return self.status()

    def read(self):
        with self.lock:
            if self.status()['state'] != 'complete':
                raise CaptureError('取得を停止してから保存してください')
            # Opening while locked keeps the descriptor valid even if the lease expires.
            return self.path.open('rb')

    def close(self):
        with self.lock:
            if self.closed:
                return
            try:
                self.stop()
            finally:
                self.closed = True
                shutil.rmtree(self.root, ignore_errors=True)


class Captures:
    def __init__(self, root: Path | None = None, idle_seconds: float = 120, maximum: int = 4):
        self.temp = tempfile.TemporaryDirectory(prefix='pcana-live-', dir=root)
        self.root = Path(self.temp.name)
        self.idle_seconds, self.maximum = idle_seconds, maximum
        self.retention_seconds = float(os.getenv('CAPTURE_RETENTION_SECONDS', '900'))
        self.items: dict[str, Session] = {}
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.reaper = threading.Thread(target=self._reap, daemon=True, name='capture-expiry')
        self.reaper.start()

    def start(self, token: str, config: Options) -> Session:
        with self.lock:
            for item in self.items.values():
                if item.authenticates(token):
                    if item.options != config:
                        raise CaptureError('前の取得を停止・保存または破棄してから条件を変更してください')
                    item.touched = time.monotonic()
                    return item  # Retrying a lost response never starts a second capture.
            if self.stopped.is_set():
                raise MissingInstance()
            if len(self.items) >= self.maximum:
                raise CapacityError('取得セッションが使用中です。不要な取得を終了してください')
            item = Session(self.root, token, config)
            try:
                item.start()
            except BaseException:
                item.close()
                raise
            self.items[item.id] = item
            return item

    def ttl(self, item: Session) -> float:
        return self.retention_seconds if item.process and item.process.poll() is not None else self.idle_seconds

    def get(self, identifier: str, token: str) -> Session:
        with self.lock:
            item = self.items.get(identifier)
            if not item or not item.authenticates(token) or item.closed:
                raise MissingInstance()
            if time.monotonic() - item.touched <= self.ttl(item):
                item.touched = time.monotonic()
                return item
            self.items.pop(identifier, None)
        item.close()
        raise MissingInstance()

    def remove(self, item: Session):
        with self.lock:
            self.items.pop(item.id, None)
        item.close()

    def expire(self):
        with self.lock:
            stale = [s for s in self.items.values() if time.monotonic() - s.touched > self.ttl(s)]
            for item in stale:
                self.items.pop(item.id, None)
        for item in stale:
            item.close()

    def _reap(self):
        while not self.stopped.wait(min(10, self.idle_seconds / 2)):
            self.expire()

    def close(self):
        self.stopped.set()
        self.reaper.join()
        with self.lock:
            items = list(self.items.values())
            self.items.clear()
        for item in items:
            item.close()
        self.temp.cleanup()
