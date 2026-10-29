"""Capture routes owned by the same app as file analysis. No proxy/service config."""
import asyncio
import json
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from .instances import CAPABILITY, MissingInstance
from .live_capture import CaptureError, interfaces, options

router = APIRouter(prefix='/api/live')


def token(request):
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or not CAPABILITY.fullmatch(value[7:]):
        raise MissingInstance()
    return value[7:]


def owned(request, identifier):
    return request.app.state.captures.get(identifier, token(request))


async def body(request):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 65536:
            raise HTTPException(413, '取得条件が大きすぎます')
    try:
        return json.loads(data)
    except ValueError as exc:
        raise CaptureError('取得条件が不正です') from exc


@router.get('/config')
def config(request: Request):
    token(request)
    return {'enabled': True, 'interfaces': interfaces(),
            'defaults': {'duration': 60, 'size_mib': 32, 'packets': 100000, 'snaplen': 262144}}


@router.post('/sessions', status_code=201)
async def start(request: Request):
    key = token(request)
    value = await body(request)
    names = await asyncio.to_thread(interfaces)
    cfg = options(value, {item['name'] for item in names})
    item = await asyncio.to_thread(request.app.state.captures.start, key, cfg)
    return item.status()


@router.get('/sessions/{identifier}')
def status(identifier: str, request: Request):
    return owned(request, identifier).status()


@router.post('/sessions/{identifier}/stop')
def stop(identifier: str, request: Request):
    return owned(request, identifier).stop()


@router.get('/sessions/{identifier}/data')
def data(identifier: str, request: Request, offset: int = Query(0, ge=0)):
    item = owned(request, identifier)
    if not item.stream:
        raise CaptureError('取得の準備中です')
    try:
        chunk, available = item.stream.chunk(offset)
    except ValueError as exc:
        raise CaptureError(str(exc)) from exc
    return Response(chunk, media_type='application/octet-stream', headers={
        'X-Capture-Offset': str(offset), 'X-Capture-End': str(offset + len(chunk)),
        'X-Capture-Available': str(available), 'Cache-Control': 'no-store'})


@router.post('/sessions/{identifier}/query')
async def query(identifier: str, request: Request):
    item = owned(request, identifier)
    value = await body(request)
    if not isinstance(value, dict) or set(value) != {'operation', 'payload'}:
        raise CaptureError('処理指定が不正です')
    payload = value['payload']
    if not isinstance(payload, dict):
        raise CaptureError('処理指定が不正です')
    # Reuse the file API's validation; these two cursors belong only to a live file.
    from .main import validate_command
    check = dict(payload)
    for name in ('through', 'after'):
        if name in check:
            cursor = check.pop(name)
            if type(cursor) is not int or cursor < 0:
                raise CaptureError('取得位置が不正です')
    try:
        validate_command({'operation': value['operation'], 'payload': check})
        return await asyncio.to_thread(item.stream.query, value['operation'], payload)
    except ValueError as exc:
        raise CaptureError(str(exc)) from exc


@router.delete('/sessions/{identifier}', status_code=204)
def remove(identifier: str, request: Request):
    request.app.state.captures.remove(owned(request, identifier))
