"""Capture-only sidecar API. Deploy on a shared Unix socket, never a TCP port."""
from contextlib import asynccontextmanager
import asyncio
import json
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from .instances import CAPABILITY, CapacityError, MissingInstance
from .live_capture import CaptureError, Captures, interfaces, options


def token(request: Request):
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or not CAPABILITY.fullmatch(value[7:]):
        raise MissingInstance()
    return value[7:]


def create_agent(root: Path | None = None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.captures = Captures(root, float(os.getenv('CAPTURE_IDLE_SECONDS', '120')),
                                     int(os.getenv('MAX_LIVE_CAPTURES', '4')))
        try:
            yield
        finally:
            await asyncio.to_thread(app.state.captures.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(MissingInstance)
    async def missing(_request, _error):
        return JSONResponse({'detail': '取得セッションが見つかりません'}, status_code=404)

    @app.exception_handler(CaptureError)
    async def invalid(_request, error):
        return JSONResponse({'detail': str(error)}, status_code=422)

    @app.exception_handler(CapacityError)
    async def full(_request, error):
        return JSONResponse({'detail': str(error)}, status_code=429)

    @app.get('/config')
    def config(request: Request):
        token(request)
        return {'enabled': True, 'interfaces': interfaces(), 'source': 'Dockerホスト',
                'defaults': {'duration': 60, 'size_mib': 32, 'packets': 100000, 'snaplen': 262144}}

    @app.post('/sessions', status_code=201)
    async def start(request: Request):
        key = token(request)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 8192:
                raise HTTPException(413, '取得条件が大きすぎます')
        try:
            value = json.loads(body)
        except ValueError as exc:
            raise CaptureError('取得条件が不正です') from exc
        names = await asyncio.to_thread(interfaces)
        cfg = options(value, {item['name'] for item in names})
        item = await asyncio.to_thread(app.state.captures.start, key, cfg)
        return item.status()

    def owned(request, identifier):
        return app.state.captures.get(identifier, token(request))

    @app.get('/sessions/{identifier}')
    def status(identifier: str, request: Request):
        return owned(request, identifier).status()

    @app.post('/sessions/{identifier}/stop')
    def stop(identifier: str, request: Request):
        return owned(request, identifier).stop()

    @app.get('/sessions/{identifier}/data')
    def data(identifier: str, request: Request):
        file = owned(request, identifier).read()
        def chunks():
            try:
                while chunk := file.read(65536):
                    yield chunk
            finally:
                file.close()
        return StreamingResponse(chunks(), media_type='application/octet-stream',
                                 headers={'Cache-Control': 'no-store'})

    @app.delete('/sessions/{identifier}', status_code=204)
    def remove(identifier: str, request: Request):
        app.state.captures.remove(owned(request, identifier))

    return app


app = create_agent()
