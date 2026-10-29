import io
import struct
from app.live_stream import BlockTail
from app.engine import project_rows
from pathlib import Path


def block(kind, payload=b'', endian='<'):
    size=12+len(payload)
    return struct.pack(endian+'II',kind,size)+payload+struct.pack(endian+'I',size)


def test_tail_does_not_publish_partial_blocks_or_repeat_prefix():
    header=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    packet=block(6,b'\0'*20)
    file=io.BytesIO(header+packet[:14]);tail=BlockTail()
    assert tail.read(file)[0]==header
    assert tail.read(file) is None and tail.offset==len(header)
    file.seek(0,2);file.write(packet[14:])
    assert tail.read(file)==(packet,6)
    assert tail.read(file) is None


def test_big_endian_and_trailer_validation():
    import pytest
    header=block(0x0a0d0d0a,struct.pack('>IHHq',0x1a2b3c4d,1,0,-1),'>')
    assert BlockTail().read(io.BytesIO(header))==(header,0x0a0d0d0a)
    broken=header[:-4]+b'\0'*4
    with pytest.raises(ValueError):BlockTail().read(io.BytesIO(broken))


def test_incremental_rows_use_existing_column_filters_and_context():
    from app.filters import parse_filter_groups
    import json
    rows=[{'number':i,'protocol':'UDP' if i==2 else 'TCP'} for i in range(1,5)]
    groups=parse_filter_groups(json.dumps({'groups':[[{'scope':'column','field':'protocol','operator':'equals','value':'UDP'}]]}))
    result=project_rows(rows,Path('unused'),groups=groups,context=1)
    assert [p['number'] for p in result['packets']]==[1,2,3]
    assert [p['is_match'] for p in result['packets']]==[False,True,False]
