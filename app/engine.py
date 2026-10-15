"""Bounded, non-shell TShark adapter. This is the only module invoking Wireshark."""
from __future__ import annotations

import csv
import io
import json
import os
from functools import lru_cache
from pathlib import Path
import re
import subprocess

TSHARK = os.getenv("TSHARK_BIN", "tshark")
FIELDS = (
    "frame.number", "frame.time_relative", "_ws.col.Source",
    "_ws.col.Destination", "_ws.col.Protocol", "frame.len", "_ws.col.Info",
)
MAX_LIST_BYTES = 32 * 1024 * 1024
MAX_DETAIL_BYTES = 8 * 1024 * 1024


class DissectionError(ValueError):
    pass


def run_tshark(args: list[str], timeout: int = 90, limit: int = MAX_LIST_BYTES) -> str:
    """No shell and no interface/privilege access; TShark reads uploaded files only."""
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
        raise DissectionError("解析結果が上限を超えました。フィルターを絞ってください")
    if process.returncode:
        lines = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
        headline = next((line for line in lines if line.lower().startswith("tshark:")), "")
        if not headline and lines:
            headline = next((line for line in lines if "invalid" in line.lower() or "error" in line.lower()), lines[0])
        # Strip private capture paths from diagnostics, preserving the useful error line.
        clean = re.sub(r"/(?:data|tmp)/[^\s:]+", "<capture>", headline)
        raise DissectionError((clean or "TShark で解析できませんでした")[:450])
    return stdout.decode("utf-8", "replace")


def packet_list(path: Path, expression: str = "", page: int = 1, limit: int = 200) -> dict:
    args = ["-r", str(path), "-T", "fields", "-E", "separator=/t",
            "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        args.extend(["-e", field])
    if expression:
        args.extend(["-Y", expression])
    content = run_tshark(args)
    rows = []
    reader = csv.reader(io.StringIO(content), delimiter="\t", quotechar='"')
    for fields in reader:
        if len(fields) < len(FIELDS):
            continue
        if not fields[0].strip().isdigit():
            continue
        rows.append({
            "number": int(fields[0]), "time": fields[1],
            "source": fields[2], "destination": fields[3],
            "protocol": fields[4], "length": fields[5],
            "info": fields[6],
        })
    start = (page - 1) * limit
    return {"packets": rows[start:start + limit], "total": len(rows),
            "page": page, "page_size": limit, "filter": expression}


def _find_raw(data: object) -> str:
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "frame_raw":
                if isinstance(value, list) and value and isinstance(value[0], str):
                    candidate = value[0]
                else:
                    candidate = value
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
    args = ["-r", str(path), "-Y", selector, "-T", "json", "-x"]
    content = run_tshark(args, timeout=45, limit=MAX_DETAIL_BYTES)
    try:
        packets = json.loads(content)
        if not isinstance(packets, list) or not packets:
            raise DissectionError("指定したパケットが見つかりません")
        layers = packets[0].get("_source", {}).get("layers", {})
        if not isinstance(layers, dict):
            raise DissectionError("プロトコルツリーを取得できません")
        raw = _find_raw(layers)
        if not raw:
            raw_content = run_tshark(
                ["-r", str(path), "-Y", selector, "-T", "jsonraw"],
                timeout=45, limit=MAX_DETAIL_BYTES,
            )
            raw = _find_raw(json.loads(raw_content))
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, DissectionError):
            raise
        raise DissectionError("TShark の詳細解析結果を読み取れません") from exc
    return {"number": number, "layers": layers, "hex": raw}


@lru_cache(maxsize=1)
def get_fields() -> tuple[dict, ...]:
    """Fetch actual field identifiers/types supported by the installed TShark."""
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
        popular = ("ip.src", "ip.dst", "ip.addr", "ipv6.addr", "tcp.port",
                   "udp.port", "tcp.flags.syn", "dns.qry.name", "http.host",
                   "http.request.method", "tls.handshake.type", "frame.len")
        selected = set(popular)
        return [item for item in get_fields() if item["name"] in selected]
    exact = []
    partial = []
    for item in get_fields():
        name = item["name"].lower()
        label = item["label"].lower()
        if name == query or name.startswith(query + "."):
            exact.append(item)
        elif query in name or query in label:
            partial.append(item)
    return (exact + partial)[:limit]
