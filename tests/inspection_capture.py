"""Deterministic DNS request/response and TCP/HTTP conversation; no real traffic."""
import struct
from .sample_capture import ethernet, ipv4, udp, dns_query


def tcp(sport, dport, seq, ack, flags, payload=b''):
    return struct.pack('!HHIIHHHH', sport, dport, seq, ack, 0x5000 | flags, 8192, 0, 0) + payload


def frames():
    query = dns_query('example.test', 1, 0x1234)
    response = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + query[12:]
    response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([192,0,2,55])
    request = b'GET /status HTTP/1.1\r\nHost: example.test\r\n\r\n'
    reply = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
    payloads = [
        (udp(53000,53,query),17,'192.0.2.10','198.51.100.1'),
        (udp(6400,6401,b'unrelated'),17,'192.0.2.12','192.0.2.13'),
        (udp(53,53000,response),17,'198.51.100.1','192.0.2.10'),
        (tcp(40000,80,100,0,2),6,'192.0.2.20','192.0.2.30'),
        (tcp(80,40000,500,101,0x12),6,'192.0.2.30','192.0.2.20'),
        (tcp(40000,80,101,501,0x10),6,'192.0.2.20','192.0.2.30'),
        (tcp(40000,80,101,501,0x18,request),6,'192.0.2.20','192.0.2.30'),
        (tcp(80,40000,501,101+len(request),0x18,reply),6,'192.0.2.30','192.0.2.20'),
        (tcp(40000,80,101+len(request),501+len(reply),0x10),6,'192.0.2.20','192.0.2.30'),
        (tcp(40001,80,9000,0,2),6,'192.0.2.20','192.0.2.30'),
    ]
    return [ethernet(ipv4(p,proto,src,dst,i+1)) for i,(p,proto,src,dst) in enumerate(payloads)]


def pcap():
    data = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i,frame in enumerate(frames()):
        data += struct.pack('<IIII', 1700000000, i * 10000, len(frame), len(frame)) + frame
    return data


if __name__ == '__main__':
    from pathlib import Path
    import sys
    Path(sys.argv[1]).write_bytes(pcap())
