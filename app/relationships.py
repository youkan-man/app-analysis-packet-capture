"""Selected-record conversation and evidenced dependency analysis.

No adjacent-packet guessing: application response and transport ACK links are
only taken from TShark's explicit frame references after a two-pass dissection.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
from .engine import DissectionError, get_fields, run_tshark

BASE = ('frame.number', 'frame.time_relative', '_ws.col.Protocol', '_ws.col.Info', 'frame.protocols')
OPTIONAL = (
    'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'eth.src', 'eth.dst',
    'tcp.stream', 'udp.stream', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
    'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset', 'tcp.len',
    'tcp.seq', 'tcp.ack', 'tcp.analysis.acks_frame', 'tcp.analysis.ack_rtt',
    'tcp.analysis.retransmission', 'tcp.analysis.fast_retransmission',
    'tcp.analysis.duplicate_ack_frame', 'tcp.reassembled_in',
    'dns.response_in', 'dns.response_to', 'dns.time', 'dns.flags.response', 'dns.id',
    'http.response_in', 'http.request_in', 'http.time',
    'icmp.resp_in', 'icmp.resp_to', 'icmp.resptime',
    'icmpv6.resp_in', 'icmpv6.resp_to', 'icmpv6.resptime',
)
LINKS = {
    'dns.response_in': ('response', 'DNS応答', True),
    'dns.response_to': ('response', 'DNS応答', False),
    'http.response_in': ('response', 'HTTP応答', True),
    'http.request_in': ('response', 'HTTP応答', False),
    'icmp.resp_in': ('response', 'ICMP応答', True),
    'icmp.resp_to': ('response', 'ICMP応答', False),
    'icmpv6.resp_in': ('response', 'ICMPv6応答', True),
    'icmpv6.resp_to': ('response', 'ICMPv6応答', False),
    'tcp.analysis.acks_frame': ('ack', 'TCP ACK', False),
    'tcp.analysis.duplicate_ack_frame': ('duplicate_ack', '重複ACK', False),
    'tcp.reassembled_in': ('reassembly', 'TCP再構成', True),
}


def read_rows(path: Path, expression: str, fields: tuple[str, ...]) -> list[dict]:
    args = ['-2', '-r', str(path), '-Y', expression, '-T', 'fields', '-E', 'separator=/t',
            '-E', 'quote=d', '-E', 'occurrence=a', '-E', 'aggregator=|']
    for field in fields:
        args.extend(['-e', field])
    text = run_tshark(args)
    return [dict(zip(fields, row)) for row in csv.reader(io.StringIO(text), delimiter='\t')
            if row and row[0].isdigit()]


def first(row: dict, *fields: str) -> str:
    return next((str(row.get(field, '')).split('|')[0] for field in fields if row.get(field)), '')


def endpoint(row: dict, side: str) -> dict:
    return {'address': first(row, 'ip.' + side, 'ipv6.' + side, 'eth.' + side),
            'port': first(row, 'tcp.' + side + 'port', 'udp.' + side + 'port')}


def project(rows: list[dict], anchor: int, stream: dict | None, warnings: list[str]) -> dict:
    indexed = {int(row['frame.number']): row for row in rows}
    seed = indexed.get(anchor)
    if seed is None:
        raise DissectionError('選択レコードが解析結果にありません')
    origin, peer = endpoint(seed, 'src'), endpoint(seed, 'dst')
    edges: dict[tuple, dict] = {}
    packets = []
    for number, row in sorted(indexed.items()):
        src, dst = endpoint(row, 'src'), endpoint(row, 'dst')
        direction = 'tx' if src == origin and dst == peer else (
            'rx' if src == peer and dst == origin else 'other')
        flags = [name.upper() for name in ('syn', 'ack', 'fin', 'reset')
                 if first(row, 'tcp.flags.' + name) in {'1', 'True'}]
        packets.append({'number': number, 'time': first(row, 'frame.time_relative'),
            'source': src, 'destination': dst, 'direction': direction,
            'protocol': first(row, '_ws.col.Protocol'), 'info': first(row, '_ws.col.Info'),
            'flags': flags, 'seq': first(row, 'tcp.seq'), 'ack': first(row, 'tcp.ack'),
            'payload_length': first(row, 'tcp.len'),
            'retransmission': bool(row.get('tcp.analysis.retransmission') or
                                   row.get('tcp.analysis.fast_retransmission'))})
        for field, (kind, label, invert) in LINKS.items():
            for value in str(row.get(field, '')).split('|'):
                if not value.isdigit():
                    continue
                ref = int(value)
                parent, child = (number, ref) if invert else (ref, number)
                if parent == child:
                    continue
                key = (parent, child, kind, label)
                edge = edges.setdefault(key, {'parent': parent, 'child': child,
                    'kind': kind, 'label': label, 'evidence': [],
                    'available': parent in indexed and child in indexed})
                edge['evidence'].append(field)
    for edge in edges.values():
        if not edge['available']:
            continue
        try:
            edge['delta_ms'] = round((float(indexed[edge['child']]['frame.time_relative']) -
                                      float(indexed[edge['parent']]['frame.time_relative'])) * 1000, 6)
        except (ValueError, KeyError):
            edge['delta_ms'] = None
    if not any(edge['kind'] == 'response' for edge in edges.values()):
        warnings.append('要求／応答の対応は未特定です。逆方向の通信やTCP ACKをアプリケーション応答とは断定しません。')
    return {'anchor': anchor, 'stream': stream, 'origin': origin, 'peer': peer,
            'protocol_stack': first(seed, 'frame.protocols').split(':'),
            'packets': packets, 'relations': list(edges.values()), 'warnings': warnings,
            'counts': {'total': len(packets), 'tx': sum(p['direction'] == 'tx' for p in packets),
                       'rx': sum(p['direction'] == 'rx' for p in packets)}}


def analyze(path: Path, number: int) -> dict:
    available = {item['name'] for item in get_fields()}
    fields = BASE + tuple(field for field in OPTIONAL if field in available)
    seed_rows = read_rows(path, f'frame.number == {number}', fields)
    if not seed_rows:
        raise DissectionError('指定したパケットが見つかりません')
    seed = seed_rows[0]
    stream = None
    for transport in ('tcp', 'udp'):
        value = first(seed, transport + '.stream')
        if value.isdigit():
            stream = {'transport': transport, 'index': int(value),
                      'field': transport + '.stream'}
            break
    warnings = []
    if stream:
        expression = f"{stream['field']} == {stream['index']}"
        rows = read_rows(path, expression, fields)
    else:
        numbers = {number}
        for field in LINKS:
            numbers.update(int(v) for v in seed.get(field, '').split('|') if v.isdigit())
        expression = 'frame.number in {' + ' '.join(map(str, sorted(numbers))) + '}'
        rows = read_rows(path, expression, fields) if len(numbers) > 1 else seed_rows
        warnings.append('TCP/UDPストリームはありません。フレーム参照で確認できる関係のみ表示します。')
    return project(rows, number, stream, warnings)
