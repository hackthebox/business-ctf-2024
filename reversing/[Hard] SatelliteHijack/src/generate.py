#!/usr/bin/env python3
import sys
import os

inp = sys.argv[1]
out = sys.argv[2]

import tempfile

# Copy .text and .rodata out
with tempfile.NamedTemporaryFile() as tempf:
    assert os.system(f"objcopy -O binary --only-section=.text {inp} {tempf.name}") == 0
    text_segment = tempf.read()

with tempfile.NamedTemporaryFile() as tempf:
    assert os.system(f"objcopy -O binary --only-section=.rodata {inp} {tempf.name}") == 0
    rodata_segment = tempf.read()

rounded_up = (len(text_segment) & ~0xfff) + 0x1000
text_segment = text_segment.ljust(rounded_up, b'\x00')
segment = text_segment + rodata_segment

# encrypt
segment = bytes([x ^ 42 for x in segment])

with open(out, 'wb') as f:
    f.write(segment)
