import shutil
import pytest
from fastapi.testclient import TestClient
import app.main as main
from app.inspection import parse_pdml
from app.relationships import project
from tests.inspection_capture import pcap


def flatten(fields):
    for field in fields:
        yield field
        yield from flatten(field['children'])


def test_pdml_distinguishes_value_display_repetition_and_verified_ranges():
    xml = '''<pdml><packet><proto name="geninfo"/><proto name="tcp" pos="0" size="4" showname="TCP">
      <field name="tcp.port" pos="0" size="2" show="80" showname="Source Port: 80" value="0050"/>
      <field name="tcp.port" pos="2" size="2" show="2" showname="Flags: SYN" value="2" unmaskedvalue="5002"/>
      <field name="tcp.stream" pos="0" size="0" show="4" showname="Stream index: 4"/>
      <field name="transformed" pos="0" size="2" show="decoded" value="9999"/>
      <field name="truncated" pos="3" size="9" value="11"/>
    </proto></packet></pdml>'''
    fields = list(flatten(parse_pdml(xml, '00505002', {'tcp.port':'FT_UINT16'})))
    assert fields[1]['value'] == '80' and fields[1]['display_value'] == 'Source Port: 80'
    assert fields[1]['byte_range'] == {'offset':0,'length':2}
    assert fields[2]['byte_range'] == {'offset':2,'length':2}
    assert fields[1]['id'] != fields[2]['id']
    assert fields[1]['kind'] == 'number'
    assert fields[3]['generated'] and fields[3]['byte_range'] is None
    assert fields[4]['byte_range'] is None and fields[5]['byte_range'] is None


@pytest.mark.parametrize('xml', ['bad', '<pdml/>', '<!DOCTYPE x [<!ENTITY x "oops">]><pdml/>'])
def test_invalid_pdml_rejected(xml):
    with pytest.raises(ValueError):
        parse_pdml(xml, '')


def test_flow_does_not_guess_application_pairs_from_reverse_direction():
    rows=[{'frame.number':'1','frame.time_relative':'0','ip.src':'a','ip.dst':'b','tcp.srcport':'1','tcp.dstport':'2'},
          {'frame.number':'2','frame.time_relative':'1','ip.src':'b','ip.dst':'a','tcp.srcport':'2','tcp.dstport':'1','tcp.analysis.acks_frame':'1'}]
    result = project(rows,1,None,[])
    assert result['counts'] == {'total':2,'tx':1,'rx':1}
    assert result['relations'][0]['kind'] == 'ack'
    assert not any(edge['kind']=='response' for edge in result['relations'])
    assert result['warnings']


@pytest.mark.skipif(shutil.which('tshark') is None, reason='TShark is required in CI')
def test_inspection_and_evidenced_dns_http_and_ack_links(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'store', main.CaptureStore(tmp_path))
    with TestClient(main.app) as client:
        cid=client.post('/api/captures',files={'file':('inspect.pcap',pcap())}).json()['id']
        base=f'/api/captures/{cid}/packets'
        detail=client.get(base+'/1')
        assert detail.status_code==200, detail.text
        fields=list(flatten(detail.json()['fields']))
        src=next(field for field in fields if field['name']=='ip.src')
        assert src['value']=='192.0.2.10'
        assert src['byte_range']=={'offset':26,'length':4}
        assert detail.json()['hex'][52:60]=='c000020a'
        assert next(f for f in fields if f['name']=='frame.number')['byte_range'] is None
        dns=client.get(base+'/1/relations')
        assert dns.status_code==200, dns.text
        dns=dns.json()
        assert [p['number'] for p in dns['packets']]==[1,3]
        assert any(e['parent']==1 and e['child']==3 and e['kind']=='response' for e in dns['relations'])
        http=client.get(base+'/7/relations')
        assert http.status_code==200, http.text
        http=http.json()
        assert [p['number'] for p in http['packets']]==list(range(4,10))
        assert any(e['parent']==7 and e['child']==8 and e['kind']=='response' for e in http['relations'])
        assert any(e['kind']=='ack' for e in http['relations'])
        assert client.get(base+'/999/relations').status_code==422
        assert client.get(base+'/0/relations').status_code==422
