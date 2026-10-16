"""Test-only synthetic traffic for a populated UI review; not an app fixture."""
from pathlib import Path
import struct
import sys
from tests.sample_capture import packets


def capture() -> bytes:
    header = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frames = packets()
    output = [header]
    for index in range(84):
        frame = frames[index % len(frames)]
        output.append(struct.pack('<IIII', 1700000000, index * 10000, len(frame), len(frame)) + frame)
    return b''.join(output)


if __name__ == '__main__':
    Path(sys.argv[1]).write_bytes(capture())
