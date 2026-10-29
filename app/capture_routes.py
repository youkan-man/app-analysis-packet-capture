"""Live capture routes on the existing application's lifecycle and HTTP server."""
import asyncio
import json
import re
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from .instances import CAPABILITY, MissingInstance
from .live_capture import CaptureError, interfaces, options

router = APIRouter(prefix='/api/live')
IDENTIFIER = re.compile(r'^[0-9a-f]{32}$')


def key(request: Request) -> str:
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or not CAPABILITY.fullmatch(value[7:]):
        raise MissingInstance()
    return value[7:]


def owned(request: Request, identifier: str):
    if not IDENTIFIER.fullmatch(identifier):
        raise MissingInstance()
    return request.app.state.captures.get(identifier, key(request))


@router.get('/config')
def config(request: Request):
    key(request)
    try:
        # No cached startup catalog, interface allowlist or deployment profile.
        items = interfaces()
        return {'enabled': bool(items), 'interfaces': items,
                'reason': '' if items else '利用可能なネットワークがありません。更新して確認してください'}
    except CaptureError as error:
        return {'enabled': False, 'interfaces': [], 'reason': str(error)}


@router.post('/sessions', status_code=201)
async def start(request: Request):
    token = key(request)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(413, '取得条件が大きすぎます')
    try:
        value = json.loads(body)
    except ValueError as exc:
        raise CaptureError('取得条件が不正です') from exc
    # Recheck at the moment of use: a selected adapter can disappear meanwhile.
    names = await asyncio.to_thread(interfaces)
    cfg = options(value, {item['name'] for item in names})
    item = await asyncio.to_thread(request.app.state.captures.start, token, cfg)
    return item.status()


@router.get('/sessions/{identifier}')
def status(identifier: str, request: Request):
    return owned(request, identifier).status()


@router.post('/sessions/{identifier}/stop')
def stop(identifier: str, request: Request):
    return owned(request, identifier).stop()


@router.get('/sessions/{identifier}/data')
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


@router.delete('/sessions/{identifier}', status_code=204)
def remove(identifier: str, request: Request):
    request.app.state.captures.remove(owned(request, identifier))
