"""Pure validation and real process/HTTP lifecycle with a deterministic dumpcap boundary.
Real dumpcap + host-loopback capture is additionally required in browser_live.js CI.
"""
import json
import secrets
import sys
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.live_capture import CaptureError, Captures, interfaces, options
from app.capture_agent import create_agent
from app.main import create_app
from app.instances import CapacityError, MissingInstance
from tests.sample_capture import pcapng


@pytest.fixture
def fake_dumpcap(tmp_path, monkeypatch):
    script = tmp_path / 'dumpcap'
    sample = tmp_path / 'source.pcapng'
    sample.write_bytes(pcapng())
    script.write_text(f'''#!{sys.executable}
import sys,signal,time
from pathlib import Path
if '-D' in sys.argv:
    print('1. lo (Loopback)\\n2. any (All interfaces)\\n3. rpcap://bad (Remote)\\n4. extcap (External)')
    sys.exit(0)
if '-f' in sys.argv and 'invalid' in sys.argv[sys.argv.index('-f')+1]:
    print('Invalid capture filter',file=sys.stderr)
    sys.exit(1)
signal.signal(signal.SIGINT,lambda *_:sys.exit(0))
Path(sys.argv[sys.argv.index('-w')+1]).write_bytes(Path({str(sample)!r}).read_bytes())
time.sleep(60)
''')
    script.chmod(0o755)
    monkeypatch.setenv('DUMPCAP_BIN', str(script))
    monkeypatch.setenv('CAPTURE_INTERFACES', 'lo')
    monkeypatch.setattr('app.live_capture.socket.if_nameindex', lambda: [(1, 'lo')])
    return tmp_path


def headers():
    return {'Authorization': 'Bearer ' + secrets.token_hex(32)}


def wait_for(fn, expected):
    for _ in range(200):
        result = fn()
        if result['state'] == expected:
            return result
        time.sleep(.01)
    raise AssertionError(result)


def test_native_interfaces_only_and_allowlist(fake_dumpcap, monkeypatch):
    assert [i['name'] for i in interfaces()] == ['lo']
    monkeypatch.delenv('CAPTURE_INTERFACES')
    assert [i['name'] for i in interfaces()] == ['lo', 'any']


def test_screen_filter_compilation():
    cfg = options({'interface': 'lo', 'protocol': 'udp', 'host': '192.0.2.1',
                   'direction': 'src', 'port': 53, 'bpf': 'not port 123'}, {'lo'})
    assert cfg.expression == '(udp) and (src host 192.0.2.1) and (port 53) and (not port 123)'
    assert cfg.duration == 60 and cfg.size_mib == 32
    assert options({'interface': 'lo', 'protocol': 'icmp', 'host': '::1'}, {'lo'}).expression == '((icmp or icmp6)) and (host ::1)'


@pytest.mark.parametrize('patch', [
    {'interface': 'rpcap://remote'}, {'interface': '-'}, {'interface': '/tmp/fifo'},
    {'protocol': 'exec'}, {'host': '127.0.0.1; touch /tmp/no'}, {'direction': 'outbound'},
    {'port': 0}, {'port': 65536}, {'port': True}, {'protocol': 'arp', 'port': 80},
    {'duration': 0}, {'duration': 3601}, {'size_mib': 65}, {'packets': 0},
    {'snaplen': 1}, {'bpf': 'tcp\n' }, {'bpf': 'x'*1025}, {'path': '/tmp/output'},
])
def test_invalid_capture_options(patch):
    with pytest.raises(CaptureError):
        options({'interface': 'lo', **patch}, {'lo'})


def test_capture_api_isolation_stop_retry_and_download(fake_dumpcap):
    with TestClient(create_agent(fake_dumpcap)) as client:
        a, b = headers(), headers()
        assert client.get('/config').status_code == 404
        assert client.get('/config', headers=a).json()['enabled']
        assert client.get('/sessions', headers=a).status_code == 405
        result = client.post('/sessions', headers=a, json={'interface': 'lo'})
        assert result.status_code == 201, result.text
        identifier = result.json()['id']
        url = '/sessions/' + identifier
        repeat = client.post('/sessions', headers=a, json={'interface': 'lo'})
        assert repeat.json()['id'] == identifier
        assert len(client.app.state.captures.items) == 1
        for endpoint in [url, url + '/data']:
            assert client.get(endpoint, headers=b).status_code == 404
            assert client.get(endpoint).status_code == 404
        assert client.post(url + '/stop', headers=b).status_code == 404
        assert client.delete(url, headers=b).status_code == 404
        assert client.get(url + '/data', headers=a).status_code == 422
        state = wait_for(lambda: client.get(url, headers=a).json(), 'recording')
        assert state['bytes'] == len(pcapng())
        assert client.post('/sessions', headers=a, json={'interface': 'lo', 'duration': 1}).status_code == 422
        item = client.app.state.captures.items[identifier]
        assert (item.path.stat().st_mode & 0o777) == 0o600
        assert client.post(url + '/stop', headers=a).json()['state'] == 'complete'
        assert client.post(url + '/stop', headers=a).json()['state'] == 'complete'
        assert client.get(url + '/data', headers=a).content == pcapng()
        assert client.get(url + '/data', headers=a).content == pcapng()  # Saving may retry.
        assert item.path.exists()  # Download alone never acknowledges durable browser storage.
        assert client.delete(url, headers=a).status_code == 204
        assert item.process.poll() is not None and not item.root.exists()
        assert client.get(url, headers=a).status_code == 404


def test_capture_start_failure_is_visible_and_disposable(fake_dumpcap):
    with TestClient(create_agent(fake_dumpcap)) as client:
        key = headers()
        response = client.post('/sessions', headers=key, json={'interface': 'lo', 'bpf': 'invalid filter'})
        url = '/sessions/' + response.json()['id']
        state = wait_for(lambda: client.get(url, headers=key).json(), 'failed')
        assert 'Invalid capture filter' in state['error']
        assert str(fake_dumpcap) not in state['error']
        assert client.get(url + '/data', headers=key).status_code == 422
        assert client.delete(url, headers=key).status_code == 204


def test_capture_expiry_and_capacity(fake_dumpcap):
    pool = Captures(fake_dumpcap, maximum=1)
    try:
        key = secrets.token_hex(32)
        item = pool.start(key, options({'interface': 'lo'}, {'lo'}))
        wait_for(item.status, 'recording')
        with pytest.raises(CapacityError):
            pool.start(secrets.token_hex(32), item.options)
        with pytest.raises(MissingInstance):
            pool.get(item.id, secrets.token_hex(32))
        item.touched -= 121
        pool.expire()
        assert item.process.poll() is not None and not item.root.exists()
        assert not pool.items
    finally:
        pool.close()


def test_web_default_remains_unprivileged_and_capture_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv('CAPTURE_SOCKET', raising=False)
    with TestClient(create_app(runtime_dir=tmp_path)) as client:
        key = headers()
        assert client.get('/api/live/config').status_code == 404
        assert client.get('/api/live/config', headers=key).json()['enabled'] is False
        assert client.post('/api/live/sessions', headers=key, json={'interface': 'lo'}).status_code == 503
        assert client.post('/api/live/sessions', headers={**key, 'Origin': 'https://other.example'}, json={}).status_code == 403
        monkeypatch.setenv('CAPTURE_SOCKET', str(tmp_path / 'missing.sock'))
        assert client.get('/api/live/config', headers=key).status_code == 503
        assert client.get('/api/live/sessions/invalid', headers=key).status_code == 404
