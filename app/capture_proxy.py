"""Fixed Unix-socket transport to the optional capture sidecar, not a generic proxy."""
import os
import re
import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from .instances import CAPABILITY, MissingInstance

router = APIRouter(prefix='/api/live')
IDENTIFIER = re.compile(r'^[0-9a-f]{32}$')


async def forward(request: Request, path: str, binary: bool = False):
    value = request.headers.get('authorization', '')
    if not value.startswith('Bearer ') or not CAPABILITY.fullmatch(value[7:]):
        raise MissingInstance()
    address = os.getenv('CAPTURE_SOCKET', '')
    if not address:
        if path == '/config':
            return {'enabled': False, 'interfaces': [], 'reason': '取得サービスが未接続です。キャプチャ用のCompose設定で起動してください'}
        raise HTTPException(503, '取得サービスが未接続です')
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(413, '取得条件が大きすぎます')
    client = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=address),
                              base_url='http://capture', timeout=15)
    try:
        upstream = await client.send(client.build_request(request.method, path,
            headers={'Authorization': value, 'Content-Type': 'application/json'}, content=bytes(body)), stream=True)
    except (httpx.HTTPError, OSError) as exc:
        await client.aclose()
        raise HTTPException(503, '取得サービスに接続できません。capture-agentの起動状態を確認してください') from exc
    if binary and upstream.status_code == 200:
        async def chunks():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()
        return StreamingResponse(chunks(), media_type='application/octet-stream',
                                 headers={'Cache-Control': 'no-store'})
    try:
        data = await upstream.aread()
        return Response(data, status_code=upstream.status_code, media_type='application/json')
    finally:
        await upstream.aclose()
        await client.aclose()


@router.get('/config')
async def config(request: Request):
    return await forward(request, '/config')


@router.post('/sessions', status_code=201)
async def start(request: Request):
    return await forward(request, '/sessions')


@router.api_route('/sessions/{identifier}', methods=['GET', 'DELETE'])
async def session(identifier: str, request: Request):
    if not IDENTIFIER.fullmatch(identifier):
        raise MissingInstance()
    return await forward(request, '/sessions/' + identifier)


@router.post('/sessions/{identifier}/stop')
async def stop(identifier: str, request: Request):
    if not IDENTIFIER.fullmatch(identifier):
        raise MissingInstance()
    return await forward(request, '/sessions/' + identifier + '/stop')


@router.get('/sessions/{identifier}/data')
async def data(identifier: str, request: Request):
    if not IDENTIFIER.fullmatch(identifier):
        raise MissingInstance()
    return await forward(request, '/sessions/' + identifier + '/data', binary=True)
