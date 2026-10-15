"""Create deterministic PCAP and PCAPNG samples for integration tests."""
from __future__ import annotations

import ipaddress
import struct


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack("!" + "H" * (len(data) // 2), data)
    acc = sum(words)
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def ethernet(payload: bytes) -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + payload


def ipv4(payload: bytes, protocol: int, source: str, destination: str) -> bytes:
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         1, 0, 64, protocol, 0, src, dst)
    digest = checksum(header)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                       1, 0, 64, protocol, digest, src, dst) + payload


def packets() -> list[bytes]:
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    udp = struct.pack("!HHHH", 53642, 53, 8 + len(dns), 0) + dns
    tcp = struct.pack("!HHIIHHHH", 52340, 443, 1, 0, 0x5002, 8192, 0, 0)
    return [
        ethernet(ipv4(udp, 17, "192.0.2.10", "8.8.8.8")),
        ethernet(ipv4(tcp, 6, "203.0.113.2", "198.51.100.42")),
    ]


def pcap() -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = [
        struct.pack("<IIII", 1700000000 + index, 0, len(pkt), len(pkt)) + pkt
        for index, pkt in enumerate(packets())
    ]
    return header + b"".join(records)


def pcapng() -> bytes:
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    blocks = []
    for index, pkt in enumerate(packets()):
        padded = pkt + b"\0" * ((-len(pkt)) % 4)
        length = 32 + len(padded)
        blocks.append(
            struct.pack("<IIIIIII", 6, length, 0, 0, 1000000 * (index + 1),
                        len(pkt), len(pkt))
            + padded + struct.pack("<I", length)
        )
    return section + interface + b"".join(blocks)


if __name__ == "__main__":
    from pathlib import Path
    import sys

    Path(sys.argv[1]).write_bytes(pcap())
