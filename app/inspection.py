"""PDML projection retaining occurrence identity, display values and verified byte ranges.

A PDML offset alone does not prove a field belongs to the captured frame:
reassembled/decrypted sources can use a different coordinate system. Only ranges
whose unmasked bytes equal the frame slice are linked. Generated fields remain
visible/copyable without inventing a byte location.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping

HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def parse_pdml(text: str, frame_hex: str, field_types: Mapping[str, str] | None = None) -> list[dict]:
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('PDML entity declarations are not accepted')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError('Invalid PDML') from exc
    packet = root.find('packet')
    if packet is None:
        raise ValueError('PDML packet is missing')
    types = field_types or {}
    frame_hex = frame_hex.lower()
    size = len(frame_hex) // 2
    count = 0

    def integer(value: str | None) -> int | None:
        try:
            result = int(value)
            return result if result >= 0 else None
        except (ValueError, TypeError):
            return None

    def visit(source: ET.Element, path: str, depth: int) -> dict:
        nonlocal count
        count += 1
        if depth > 64 or count > 20000:
            raise ValueError('PDML tree exceeds inspection limits')
        a = source.attrib
        name = a.get('name', '')
        start, length = integer(a.get('pos')), integer(a.get('size'))
        raw = a.get('unmaskedvalue', a.get('value', '')).lower()
        candidate = bool(start is not None and length and start + length <= size)
        linked = bool(candidate and HEX.fullmatch(raw) and len(raw) == length * 2
                      and frame_hex[start * 2:(start + length) * 2] == raw)
        children = [visit(child, f'{path}.{index}', depth + 1)
                    for index, child in enumerate(source) if child.tag in {'field', 'proto'}]
        if source.tag == 'proto' and candidate:
            verified = [child for child in children if child['byte_range'] is not None]
            linked = name == 'frame' or (bool(verified) and all(
                start <= child['byte_range']['offset'] and
                child['byte_range']['offset'] + child['byte_range']['length'] <= start + length
                for child in verified))
        ftype = types.get(name, '')
        if ftype in {'FT_IPv4', 'FT_IPv6', 'FT_ETHER', 'FT_EUI64'}:
            kind = 'address'
        elif re.match(r'^FT_(U?INT|BOOLEAN|FLOAT|DOUBLE|FRAMENUM|RELATIVE_TIME)', ftype):
            kind = 'number'
        else:
            kind = 'string'
        value = a.get('show', a.get('value', ''))
        label = a.get('showname') or (f'{name}: {value}' if value else name) or 'Data'
        return {
            'id': path, 'name': name, 'label': label, 'value': value,
            'display_value': label, 'raw_value': a.get('value', ''),
            'kind': kind, 'field_type': ftype, 'protocol': source.tag == 'proto',
            'hidden': a.get('hide') == 'yes', 'generated': length == 0,
            'byte_range': {'offset': start, 'length': length} if linked else None,
            'range_status': 'frame' if linked else ('generated' if not length else 'unmapped'),
            'children': children,
        }

    return [visit(proto, f'f{index}', 0) for index, proto in enumerate(packet)
            if proto.tag in {'proto', 'field'} and proto.get('name') != 'geninfo']
