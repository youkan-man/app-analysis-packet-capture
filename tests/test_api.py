import json
import secrets
import shutil
from fastapi.testclient import TestClient
import pytest
from app.main import create_app
from tests.sample_capture import pcap, pcapng
from tests.instance_client import upload, query


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(runtime_dir=tmp_path)) as value:
        yield value
    assert not list(tmp_path.iterdir())


def test_old_shared_routes_are_absent(client):
    assert client.get('/healthz').json() == {'status': 'ok'}
    assert client.get('/api/captures').status_code == 404
    assert client.post('/api/captures', files={'file': ('old.pcap', pcap())}).status_code == 404
    assert client.get('/api/instances').status_code == 405
    assert client.get('/api/captures/' + 'a'*32 + '/packets').status_code == 404
    assert client.post('/api/instances', content=pcap()).status_code == 404


def test_upload_validation_does_not_retain_data(client, monkeypatch):
    headers = {'Authorization': 'Bearer ' + secrets.token_hex(32)}
    assert client.post('/api/instances', content=b'not a capture', headers=headers).status_code == 422
    assert not list(client.app.state.instances.root.iterdir())
    monkeypatch.setenv('MAX_UPLOAD_BYTES', '10')
    assert client.post('/api/instances', content=pcap(), headers=headers).status_code == 413
    assert not list(client.app.state.instances.root.iterdir())
    assert client.post('/api/instances', content=pcap(), headers={**headers,'Origin':'https://other.test'}).status_code == 403


@pytest.mark.parametrize('data,fmt',[(pcap(),'pcap'),(pcapng(),'pcapng')])
def test_uploads_create_private_disposable_processes(client, data, fmt):
    base, headers = upload(client, data)
    status = client.get(base, headers=headers)
    assert status.status_code == 200
    assert status.json()['format'] == fmt
    assert status.headers['cache-control'] == 'no-store'
    instance = client.app.state.instances.items[base.split('/')[-1]]
    assert instance.process.pid != __import__('os').getpid()
    assert instance.path.read_bytes() == data
    assert (instance.path.stat().st_mode & 0o777) == 0o600
    assert client.get(base).status_code == 404
    assert client.get(base, headers={'Authorization':'Bearer '+'0'*64}).status_code == 404
    assert client.get(base, params={'token':headers['Authorization'][7:]}).status_code == 404
    assert client.delete(base, headers=headers).status_code == 204
    assert not instance.root.exists()
    assert instance.process.poll() is not None
    assert client.get(base, headers=headers).status_code == 404


def test_job_schema_and_cross_instance_isolation(client):
    a, ah = upload(client, pcap())
    b, bh = upload(client, pcapng())
    pool = client.app.state.instances
    assert pool.items[a.split('/')[-1]].process.pid != pool.items[b.split('/')[-1]].process.pid
    for method in ('get','delete'):
        assert getattr(client, method)(a, headers=bh).status_code == 404
    bad = [{'operation':'shell','payload':{}}, {'operation':'detail','payload':{'number':0}},
           {'operation':'detail','payload':{'number':True}}, {'operation':'packets','payload':{'view':'{'}},
           {'operation':'packets','payload':{'context':51}}]
    for command in bad:
        assert client.post(a+'/jobs',headers=ah,json=command).status_code == 422
    assert client.post(a+'/jobs',headers=bh,json={'operation':'packets','payload':{}}).status_code == 404
    posted=client.post(a+'/jobs',headers=ah,json={'operation':'packets','payload':{}})
    assert posted.status_code == 202
    job=posted.json()['id']
    assert client.get(a+'/jobs/'+job,headers=bh).status_code == 404
    assert client.get(b+'/jobs/'+job,headers=bh).status_code == 404
    assert client.delete(a+'/jobs/'+job,headers=bh).status_code == 404
    assert client.get(b,headers=bh).status_code == 200


def test_idle_expiry_and_close_only_remove_owned_runtime(client):
    a, ah=upload(client,pcap()); b,bh=upload(client,pcap())
    pool=client.app.state.instances
    first=pool.items[a.split('/')[-1]]; second=pool.items[b.split('/')[-1]]
    first.touched -= pool.idle_seconds + 1
    pool.expire()
    assert client.get(a,headers=ah).status_code == 404
    assert not first.root.exists()
    assert second.root.exists()
    assert client.get(b,headers=bh).status_code == 200


@pytest.mark.skipif(shutil.which('tshark') is None, reason='TShark is required in CI')
def test_continuous_rows_visual_native_and_neighbour_queries(client):
    handle=upload(client,pcap())
    def packets(**kw):
        state=query(client,handle,payload=kw)
        assert state['state']=='done',state
        return state['result']
    def view(*groups):return json.dumps({'groups':list(groups)})
    def column(field,value,operator='equals'):
        return {'scope':'column','field':field,'operator':operator,'value':value,'case_sensitive':False}
    data=packets()
    assert data['total']==data['matched']==7 and 'page' not in data
    assert [p['number'] for p in data['packets']]==list(range(1,8))
    for name,value in [('source','192.0.2.10'),('info','query')]:
        filtered=packets(view=view([column(name,value,'contains')]))
        assert [p['number'] for p in filtered['packets']]==[1,5]
    assert [p['number'] for p in packets(raw='tcp')['packets']]==[2,4,6]
    union=packets(view=view([column('source','192.0.2.10')],[column('destination','192.0.2.14')]))
    assert [p['number'] for p in union['packets']]==[1,5,7]
    native={'scope':'wireshark','field':'ip.src','operator':'equals','value':'203.0.113.3','kind':'address'}
    assert [p['number'] for p in packets(view=view([native]))['packets']]==[6]
    nearby=packets(view=view([column('number','4')]),context=1)
    assert [p['number'] for p in nearby['packets']]==[3,4,5]
    assert [p['is_match'] for p in nearby['packets']]==[False,True,False]
    assert query(client,handle,payload={'raw':'tcp && ('})['state']=='error'
    # An invalid operation result must not poison this instance or another browser.
    assert packets()['total']==7
    second=upload(client,pcapng())
    assert query(client,second)['result']['total']==7
