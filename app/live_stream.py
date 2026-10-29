"""Incremental PCAPNG tail and one streaming TShark decoder per capture.

Only complete, trailer-verified blocks enter the browser-visible snapshot. The
summary decoder consumes each byte once; on-demand detail queries use a frozen
copy so a concurrent append cannot produce a truncated dissection.
"""
from __future__ import annotations

import bisect
import csv
import io
import struct
import subprocess
import tempfile
import threading
from pathlib import Path
from . import engine
from .relationships import analyze
from .filters import parse_filter_groups


class BlockTail:
    def __init__(self):
        self.offset = 0
        self.endian = '<'

    def read(self, source):
        source.seek(self.offset)
        header = source.read(12)
        if len(header) < 12:
            return None
        if header[:4] == b'\x0a\x0d\x0d\x0a':
            if header[8:12] == b'\x4d\x3c\x2b\x1a':
                self.endian = '<'
            elif header[8:12] == b'\x1a\x2b\x3c\x4d':
                self.endian = '>'
            else:
                raise ValueError('取得ファイルの形式が不正です')
        size = struct.unpack(self.endian + 'I', header[4:8])[0]
        if size < 12 or size % 4 or size > 16 * 1024 * 1024:
            raise ValueError('取得ブロックの長さが不正です')
        source.seek(self.offset)
        block = source.read(size)
        if len(block) != size:
            return None
        if struct.unpack(self.endian + 'I', block[-4:])[0] != size:
            raise ValueError('取得ブロックの終端が不正です')
        self.offset += size
        return block, struct.unpack(self.endian + 'I', header[:4])[0]


class LiveStream:
    def __init__(self, source: Path, root: Path, capture_process):
        self.source = source
        self.path = root / 'complete.pcapng'
        self.path.touch(mode=0o600)
        self.capture_process = capture_process
        self.lock = threading.RLock()
        self.query_lock = threading.Lock()
        self.stopping = threading.Event()
        self.done = threading.Event()
        self.rows: list[dict] = []
        self.boundaries = [0]
        self.counts = [0]
        self.error = ''
        self.process = subprocess.Popen(
            [engine.TSHARK, '-n', '-l', '-r', '-', *engine._field_args()],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0, start_new_session=True)
        self.reader = threading.Thread(target=self._decode, daemon=True, name='capture-rows')
        self.writer = threading.Thread(target=self._tail, daemon=True, name='capture-blocks')
        self.reader.start()
        self.writer.start()

    def _decode(self):
        try:
            text = io.TextIOWrapper(self.process.stdout, encoding='utf-8', errors='replace', newline='')
            for values in csv.reader(text, delimiter='\t', quotechar='"'):
                row = engine.row_from_values(values)
                if row:
                    with self.lock:
                        self.rows.append(row)
        except (OSError, ValueError):
            if not self.stopping.is_set():
                self.error = '取得したパケットを解析できませんでした'

    def _tail(self):
        tail = BlockTail()
        packets = 0
        try:
            with self.source.open('rb') as source, self.path.open('ab', buffering=0) as target:
                while not self.stopping.is_set():
                    item = tail.read(source)
                    if item is None:
                        if self.capture_process.poll() is not None:
                            # dumpcap has flushed and closed: a partial block is corruption.
                            if self.source.stat().st_size != tail.offset:
                                self.error = '取得ファイルの末尾が未確定です'
                            break
                        self.stopping.wait(.1)
                        continue
                    block, kind = item
                    packets += kind in (2, 3, 6)
                    with self.lock:
                        target.write(block)
                        self.boundaries.append(tail.offset)
                        self.counts.append(packets)
                    pending=memoryview(block)
                    while pending:
                        written=self.process.stdin.write(pending)
                        if not written:raise OSError('Decoder pipe closed')
                        pending=pending[written:]
                    self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            if not self.stopping.is_set():
                self.error = str(exc) if isinstance(exc, ValueError) else '取得データの読み込みが中断しました'
        finally:
            try:
                self.process.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                if not self.stopping.is_set():
                    self.error = '取得データの解析が完了しませんでした'
            self.reader.join(timeout=2)
            if self.process.returncode and not self.stopping.is_set() and not self.error:
                self.error = '取得データの解析に失敗しました'
            self.done.set()

    def chunk(self, offset: int) -> tuple[bytes, int]:
        with self.lock:
            current=bisect.bisect_left(self.boundaries,offset)
            if current>=len(self.boundaries) or self.boundaries[current]!=offset:
                raise ValueError('取得位置が一致しません。ファイルを開き直してください')
            index = bisect.bisect_right(self.boundaries, offset + 1024 * 1024) - 1
            end = self.boundaries[index]
            if end == offset and offset != self.boundaries[-1]:
                end = self.boundaries[current + 1]
            with self.path.open('rb') as file:
                file.seek(offset)
                return file.read(end - offset), self.boundaries[-1]

    def query(self, operation: str, payload: dict):
        through = payload.get('through')
        # Serialize dissections for this capture only, never the HTTP event loop.
        with self.query_lock:
            with self.lock:
                size = self.boundaries[-1] if through is None else through
                if size not in self.boundaries:
                    raise ValueError('保存済みの取得位置を指定してください')
                count = self.counts[bisect.bisect_right(self.boundaries, size) - 1]
                total=min(count,len(self.rows))
                # The common live path copies only new rows and no capture bytes.
                if operation=='packets' and not payload.get('raw') and not parse_filter_groups(payload.get('view','')):
                    after=payload.get('after',0)
                    return {'packets':[dict(row,is_match=True,context_distance=0) for row in self.rows[after:total]],
                            'total':total,'matched':total,'displayed':total,'filtered':False,'context':0,
                            'incremental':'after' in payload}
                rows = list(self.rows[:total])
                if not size:
                    if operation != 'packets':
                        raise ValueError('パケットを受信していません')
                    return engine.project_rows([], self.path)
                # Hard links would grow too; freeze the published prefix instead.
                frozen = tempfile.NamedTemporaryFile(dir=self.path.parent, suffix='.pcapng', delete=False)
                path = Path(frozen.name)
                with self.path.open('rb') as file, frozen:
                    remaining = size
                    while remaining:
                        chunk = file.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError('取得データを読み取れません')
                        frozen.write(chunk)
                        remaining -= len(chunk)
            try:
                if operation == 'packets':
                    result = engine.project_rows(rows, path, payload.get('raw', ''),
                        parse_filter_groups(payload.get('view', '')), payload.get('context', 0))
                    if not result['filtered'] and 'after' in payload:
                        result['packets'] = [p for p in result['packets'] if p['number'] > payload['after']]
                        result['incremental'] = True
                    return result
                if operation == 'detail':
                    return engine.packet_detail(path, payload['number'])
                if operation == 'relations':
                    return analyze(path, payload['number'])
                raise ValueError('未対応の処理です')
            finally:
                path.unlink(missing_ok=True)

    def close(self):
        self.stopping.set()
        if self.process.poll() is None:
            self.process.kill()
        self.writer.join(timeout=12)
        self.reader.join(timeout=2)
