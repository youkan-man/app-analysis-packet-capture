"""Bounded offline TShark adapter and packet-view filter execution."""
from __future__ import annotations

import csv
from functools import lru_cache
import io
import json
import os
from pathlib import Path
import re
import subprocess

from .inspection import parse_pdml
from .filters import FilterGroups, compile_native_rules, match_column_rules, split_group

TSHARK = os.getenv("TSHARK_BIN", "tshark")
DISPLAY_FIELDS = (
    "frame.number", "frame.time_relative", "_ws.col.Source",
    "_ws.col.Destination", "_ws.col.Protocol", "frame.len", "_ws.col.Info",
)
CONTEXT_FIELDS = (
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "eth.src", "eth.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
)
FIELDS = DISPLAY_FIELDS + CONTEXT_FIELDS
MAX_LIST_BYTES = 32 * 1024 * 1024
MAX_DETAIL_BYTES = 8 * 1024 * 1024
MAX_CONTEXT = 50


class DissectionError(ValueError):
    pass


def run_tshark(args: list[str], timeout: int = 90, limit: int = MAX_LIST_BYTES) -> str:
    """Execute TShark without a shell or live-interface privileges."""
    try:
        process = subprocess.Popen(
            [TSHARK, "-n", *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise DissectionError("TShark がインストールされていません") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise DissectionError("解析が制限時間を超えました") from exc
    if len(stdout) > limit:
        raise DissectionError("解析結果が上限を超えました。条件を絞ってください")
    if process.returncode:
        lines = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
        headline = next((line for line in lines if line.lower().startswith("tshark:")), "")
        if not headline and lines:
            headline = next((line for line in lines if "invalid" in line.lower() or "error" in line.lower()), lines[0])
        clean = re.sub(r"/(?:data|tmp)/[^\s:]+", "<capture>", headline)
        raise DissectionError((clean or "TShark で解析できませんでした")[:450])
    return stdout.decode("utf-8", "replace")


def _field_args() -> list[str]:
    args = ["-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        args.extend(["-e", field])
    return args


def decoded_rows(path: Path) -> list[dict]:
    content = run_tshark(["-r", str(path), *_field_args()])
    rows: list[dict] = []
    reader = csv.reader(io.StringIO(content), delimiter="\t", quotechar='"')
    for values in reader:
        if len(values) < len(DISPLAY_FIELDS) or not values[0].strip().isdigit():
            continue
        extra = {
            field: values[index]
            for index, field in enumerate(CONTEXT_FIELDS, start=len(DISPLAY_FIELDS))
            if len(values) > index and values[index]
        }
        rows.append({
            "number": int(values[0]),
            "time": values[1],
            "source": values[2],
            "destination": values[3],
            "protocol": values[4],
            "length": int(values[5]) if values[5].isdigit() else values[5],
            "info": values[6],
            "fields": extra,
        })
    return rows


def matching_frame_numbers(path: Path, expression: str) -> frozenset[int]:
    if not expression:
        return frozenset()
    content = run_tshark([
        "-r", str(path), "-Y", expression, "-T", "fields",
        "-E", "occurrence=f", "-e", "frame.number",
    ])
    return frozenset(int(line.strip()) for line in content.splitlines() if line.strip().isdigit())


def packet_list(path: Path, raw_expression: str = "", groups: FilterGroups = (), context: int = 0) -> dict:
    """Return a continuous filtered view plus translucent neighbouring records."""
    if not (0 <= context <= MAX_CONTEXT):
        raise DissectionError("前後表示は0〜50件で指定してください")
    rows = decoded_rows(path)
    all_numbers = frozenset(row["number"] for row in rows)
    filtered = bool(raw_expression or groups)
    if not filtered:
        matching = all_numbers
    elif not groups:
        matching = matching_frame_numbers(path, raw_expression)
    else:
        matching_set: set[int] = set()
        native_cache: dict[str, frozenset[int]] = {}
        for group in groups:
            column_rules, native_rules = split_group(group)
            group_native = compile_native_rules(native_rules)
            expressions = [part for part in (raw_expression.strip(), group_native) if part]
            expression = " && ".join(f"({part})" for part in expressions)
            if expression:
                frames = native_cache.get(expression)
                if frames is None:
                    frames = matching_frame_numbers(path, expression)
                    native_cache[expression] = frames
            else:
                frames = all_numbers
            for row in rows:
                if row["number"] in frames and match_column_rules(row, column_rules):
                    matching_set.add(row["number"])
        matching = frozenset(matching_set)
    matching_indexes = {index for index, row in enumerate(rows) if row["number"] in matching}
    if filtered and context and matching_indexes:
        included_indexes: set[int] = set()
        for index in matching_indexes:
            included_indexes.update(range(max(0, index - context), min(len(rows), index + context + 1)))
    else:
        included_indexes = matching_indexes
    packets: list[dict] = []
    for index in sorted(included_indexes):
        row = dict(rows[index])
        is_match = index in matching_indexes
        row["is_match"] = is_match
        row["context_distance"] = 0 if is_match else min(abs(index - match) for match in matching_indexes)
        packets.append(row)
    return {
        "packets": packets, "total": len(rows), "matched": len(matching_indexes),
        "displayed": len(packets), "filtered": filtered, "context": context, "raw_filter": raw_expression,
    }


def _find_raw(data: object) -> str:
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "frame_raw":
                candidate = value[0] if isinstance(value, list) and value else value
                if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F]+", candidate):
                    return candidate.lower()
        for value in data.values():
            found = _find_raw(value)
            if found:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find_raw(value)
            if found:
                return found
    return ""


def packet_detail(path: Path, number: int) -> dict:
    selector = f"frame.number == {number}"
    content = run_tshark(["-2", "-r", str(path), "-Y", selector, "-T", "json", "-x"], timeout=45, limit=MAX_DETAIL_BYTES)
    try:
        packets = json.loads(content)
        if not isinstance(packets, list) or not packets:
            raise DissectionError("指定したパケットが見つかりません")
        layers = packets[0].get("_source", {}).get("layers", {})
        if not isinstance(layers, dict):
            raise DissectionError("プロトコルツリーを取得できません")
        raw = _find_raw(layers)
        if not raw:
            raw = _find_raw(json.loads(run_tshark(
                ["-r", str(path), "-Y", selector, "-T", "jsonraw"], timeout=45, limit=MAX_DETAIL_BYTES,
            )))
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, DissectionError):
            raise
        raise DissectionError("TShark の詳細解析結果を読み取れません") from exc
    try:
        pdml = run_tshark(["-2", "-r", str(path), "-Y", selector, "-T", "pdml"], timeout=45, limit=MAX_DETAIL_BYTES)
        fields = parse_pdml(pdml, raw, {f["name"]: f["type"] for f in get_fields()})
    except ValueError as exc:
        raise DissectionError("詳細項目の位置情報を解析できません") from exc
    return {"number": number, "layers": layers, "hex": raw, "fields": fields}


@lru_cache(maxsize=1)
def get_fields() -> tuple[dict, ...]:
    try:
        data = run_tshark(["-G", "fields"], timeout=45, limit=48 * 1024 * 1024)
    except DissectionError:
        return ()
    results = []
    for row in data.splitlines():
        columns = row.split("\t")
        if len(columns) >= 4 and columns[0] == "F":
            results.append({"label": columns[1], "name": columns[2], "type": columns[3]})
    return tuple(results)


def search_fields(query: str, limit: int = 50) -> list[dict]:
    query = query.lower().strip()
    if not query:
        popular = {
            "ip.src", "ip.dst", "ip.addr", "ipv6.addr", "tcp.port", "udp.port",
            "tcp.flags.syn", "dns.qry.name", "http.host", "http.request.method",
            "tls.handshake.type", "frame.len",
        }
        return [item for item in get_fields() if item["name"] in popular]
    exact: list[dict] = []
    partial: list[dict] = []
    for item in get_fields():
        name = item["name"].lower()
        label = item["label"].lower()
        if name == query or name.startswith(query + "."):
            exact.append(item)
        elif query in name or query in label:
            partial.append(item)
    return (exact + partial)[:limit]
