"""Create deterministic multi-record PCAP/PCAPNG samples for integration tests."""
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


def ipv4(payload: bytes, protocol: int, source: str, destination: str, ident: int) -> bytes:
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, 64, protocol, 0, src, dst)
    digest = checksum(header)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, 64, protocol, digest, src, dst) + payload


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def tcp(source_port: int, destination_port: int, flags: int, sequence: int = 1, ack: int = 0) -> bytes:
    return struct.pack("!HHIIHHHH", source_port, destination_port, sequence, ack, 0x5000 | flags, 8192, 0, 0)


def packets() -> list[bytes]:
    payloads = [
        (udp(53642, 53, dns_query("example.com", 1, 0x1001)), 17, "192.0.2.10", "8.8.8.8"),
        (tcp(52340, 443, 0x002), 6, "203.0.113.2", "198.51.100.42"),
        (udp(40000, 5000, b"alpha-context"), 17, "192.0.2.11", "192.0.2.12"),
        (tcp(443, 52340, 0x010, sequence=10, ack=2), 6, "198.51.100.42", "203.0.113.2"),
        (udp(53643, 53, dns_query("api.example.com", 28, 0x1002)), 17, "192.0.2.10", "1.1.1.1"),
        (tcp(60000, 80, 0x002), 6, "203.0.113.3", "198.51.100.43"),
        (udp(41000, 6000, b"omega-context"), 17, "192.0.2.13", "192.0.2.14"),
    ]
    return [ethernet(ipv4(payload, protocol, source, destination, index + 1)) for index, (payload, protocol, source, destination) in enumerate(payloads)]


def pcap() -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = [struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet)) + packet for index, packet in enumerate(packets())]
    return header + b"".join(records)


def pcapng() -> bytes:
    section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    blocks = []
    for index, packet in enumerate(packets()):
        padded = packet + b"\0" * ((-len(packet)) % 4)
        length = 32 + len(padded)
        blocks.append(struct.pack("<IIIIIII", 6, length, 0, 0, 1000000 * (index + 1), len(packet), len(packet)) + padded + struct.pack("<I", length))
    return section + interface + b"".join(blocks)


if __name__ == "__main__":
    from pathlib import Path
    import sys
    Path(sys.argv[1]).write_bytes(pcap())
