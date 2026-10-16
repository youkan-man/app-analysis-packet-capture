"""Static UI plus capability-protected, transient background analysis API."""
from contextlib import asynccontextmanager
import asyncio
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from .filters import FilterError, parse_filter_groups
from .instances import CAPABILITY, CapacityError, Instances, MissingInstance

ROOT = Path(__file__).resolve().parent.parent
MAGICS = {b'\xd4\xc3\xb2\xa1':'pcap', b'\xa1\xb2\xc3\xd4':'pcap',
          b'\x4d\x3c\xb2\xa1':'pcap', b'\xa1\xb2\x3c\x4d':'pcap',
          b'\x0a\x0d\x0d\x0a':'pcapng'}


def capability(request: Request) -> str:
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or not CAPABILITY.fullmatch(value[7:]):
        raise MissingInstance()
    return value[7:]


def validate_command(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {'operation', 'payload'}:
        raise ValueError('処理指定が不正です')
    op, payload = value['operation'], value['payload']
    if not isinstance(payload, dict):
        raise ValueError('処理指定が不正です')
    if op == 'packets':
        if set(payload) - {'raw', 'view', 'context'}:
            raise ValueError('不明なフィルター指定です')
        for name, size in [('raw', 2048), ('view', 16384)]:
            if not isinstance(payload.get(name, ''), str) or len(payload.get(name, '')) > size:
                raise ValueError('フィルターが長すぎます')
        if type(payload.get('context', 0)) is not int or not 0 <= payload.get('context', 0) <= 50:
            raise ValueError('前後表示は0〜50件で指定してください')
        parse_filter_groups(payload.get('view', ''))
    elif op in {'detail', 'relations'}:
        if set(payload) != {'number'} or type(payload['number']) is not int or payload['number'] < 1:
            raise ValueError('パケット番号が不正です')
    else:
        raise ValueError('未対応の処理です')
    return value


def create_app(runtime_dir: Path | None = None, idle_seconds: float | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application):
        application.state.instances = Instances(
            runtime_dir or Path(os.getenv('ANALYSIS_RUNTIME_DIR', '/tmp')),
            idle_seconds if idle_seconds is not None else float(os.getenv('ANALYSIS_IDLE_SECONDS', '900')),
            int(os.getenv('MAX_ANALYSIS_INSTANCES', '32')))
        try:
            yield
        finally:
            await asyncio.to_thread(application.state.instances.close)

    app = FastAPI(title='Packet Capture Workbench', version='0.4.0', lifespan=lifespan)
    app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

    @app.middleware('http')
    async def private_responses(request: Request, call_next):
        origin = request.headers.get('origin')
        try:
            cross_origin = origin and urlsplit(origin).netloc != request.headers.get('host')
        except ValueError:
            cross_origin = True
        if request.url.path.startswith('/api/') and cross_origin:
            return JSONResponse({'detail': '異なるオリジンからは操作できません'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.exception_handler(MissingInstance)
    async def missing(_request, _error):
        return JSONResponse({'detail': '解析インスタンスまたは処理が見つかりません'}, status_code=404)

    @app.exception_handler(CapacityError)
    async def full(_request, error):
        return JSONResponse({'detail': str(error)}, status_code=429)

    @app.get('/', include_in_schema=False)
    def home():
        return FileResponse(ROOT / 'static' / 'index.html')

    @app.get('/healthz')
    def health():
        return {'status': 'ok'}

    @app.post('/api/instances', status_code=201)
    async def open_instance(request: Request):
        registry = request.app.state.instances
        item = registry.allocate(capability(request))
        size, prefix = 0, b''
        maximum = int(os.getenv('MAX_UPLOAD_BYTES', str(256 * 1024 * 1024)))
        try:
            with item.path.open('xb') as target:
                os.chmod(item.path, 0o600)
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > maximum:
                        raise HTTPException(413, 'ファイルサイズの上限を超えました')
                    prefix = (prefix + chunk[:4])[:4]
                    item.touched = time.monotonic()
                    await asyncio.to_thread(target.write, chunk)
            if prefix not in MAGICS:
                raise HTTPException(422, 'PCAP / PCAPNG ファイルではありません')
            await asyncio.to_thread(item.start, MAGICS[prefix])
            return {'id': item.id, 'state': 'ready', 'format': item.format}
        except BaseException:
            await asyncio.to_thread(registry.remove, item)
            raise

    def owned(request: Request, identifier: str):
        return request.app.state.instances.get(identifier, capability(request))

    @app.get('/api/instances/{identifier}')
    def instance_status(identifier: str, request: Request):
        item = owned(request, identifier)
        return {'id': item.id, 'state': 'ready', 'format': item.format}

    @app.delete('/api/instances/{identifier}', status_code=204)
    def close_instance(identifier: str, request: Request):
        request.app.state.instances.remove(owned(request, identifier))

    @app.post('/api/instances/{identifier}/jobs', status_code=202)
    async def submit(identifier: str, request: Request):
        item = owned(request, identifier)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 65536:
                raise HTTPException(413, '処理指定が大きすぎます')
        try:
            command = validate_command(json.loads(body))
        except (ValueError, FilterError, TypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {'id': item.submit(command), 'state': 'queued'}

    @app.get('/api/instances/{identifier}/jobs/{job}')
    def result(identifier: str, job: str, request: Request):
        return JSONResponse(owned(request, identifier).result(job))

    @app.delete('/api/instances/{identifier}/jobs/{job}', status_code=204)
    def discard(identifier: str, job: str, request: Request):
        owned(request, identifier).discard(job)

    return app


app = create_app()
