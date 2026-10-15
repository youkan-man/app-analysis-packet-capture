"""HTTP API, capture ownership, filter validation and static frontend."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
import uuid

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine import DissectionError, packet_detail, packet_list, search_fields
from .filters import FilterError, parse_filter_groups

ROOT = Path(__file__).resolve().parent.parent
STORE = Path(os.getenv("CAPTURE_DIR", "/tmp/packet-workbench"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(256 * 1024 * 1024)))
MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap", b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap", b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}
IDENTIFIER = re.compile(r"^[0-9a-f]{32}$")
guard = threading.RLock()
app = FastAPI(title="Packet Capture Workbench", version="0.2.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class CaptureStore:
    """A capture owns its data and metadata; IDs never become arbitrary paths."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def paths(self, capture_id: str) -> tuple[Path, Path]:
        if not IDENTIFIER.fullmatch(capture_id):
            raise HTTPException(status_code=404, detail="キャプチャが見つかりません")
        return self.root / f"{capture_id}.capture", self.root / f"{capture_id}.json"

    def get(self, capture_id: str) -> tuple[Path, dict]:
        raw, meta = self.paths(capture_id)
        if not raw.is_file() or not meta.is_file():
            raise HTTPException(status_code=404, detail="キャプチャが見つかりません")
        try:
            return raw, json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=500, detail="キャプチャ情報が破損しています") from exc

    def list(self) -> list[dict]:
        captures = []
        for entry in self.root.glob("*.json"):
            try:
                _, data = self.get(entry.stem)
                captures.append(data)
            except (HTTPException, OSError):
                continue
        return sorted(captures, key=lambda item: item.get("added", ""), reverse=True)

    async def add(self, upload: UploadFile) -> dict:
        capture_id = uuid.uuid4().hex
        data_path, meta_path = self.paths(capture_id)
        filename = Path((upload.filename or "capture.pcap").replace("\\", "/")).name
        size = 0
        first = b""
        try:
            with data_path.open("xb") as target:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    if not first:
                        first = chunk[:4]
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail="ファイルサイズの上限を超えました")
                    target.write(chunk)
            fmt = MAGICS.get(first)
            if not fmt:
                raise HTTPException(status_code=422, detail="PCAP / PCAPNG ファイルではありません")
            data = {
                "id": capture_id, "filename": filename, "format": fmt, "size": size,
                "added": datetime.now(timezone.utc).isoformat(),
            }
            meta_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            return data
        except BaseException:
            data_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            raise
        finally:
            await upload.close()

    def delete(self, capture_id: str) -> None:
        self.get(capture_id)
        data_path, meta_path = self.paths(capture_id)
        data_path.unlink()
        meta_path.unlink()


store = CaptureStore(STORE)


@app.exception_handler(DissectionError)
async def handle_dissector_error(_request, exc: DissectionError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.get("/api/captures")
async def list_captures():
    with guard:
        return {"items": store.list()}


@app.post("/api/captures", status_code=201)
async def upload_capture(file: UploadFile = File(...)):
    return await store.add(file)


@app.delete("/api/captures/{capture_id}", status_code=204)
async def delete_capture(capture_id: str):
    with guard:
        store.delete(capture_id)


@app.get("/api/captures/{capture_id}/packets")
async def list_packets(
    capture_id: str,
    raw: str = Query("", max_length=2048),
    view: str = Query("", max_length=16384),
    context: int = Query(0, ge=0, le=50),
):
    try:
        groups = parse_filter_groups(view)
    except FilterError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with guard:
        file_path, _ = store.get(capture_id)
        return packet_list(file_path, raw, groups, context)


@app.get("/api/captures/{capture_id}/packets/{number}")
async def get_packet(capture_id: str, number: int):
    if number < 1:
        raise HTTPException(status_code=422, detail="パケット番号が不正です")
    with guard:
        file_path, _ = store.get(capture_id)
        return packet_detail(file_path, number)


@app.get("/api/fields")
async def suggest_fields(q: str = Query("", max_length=100)):
    return {"items": search_fields(q)}
