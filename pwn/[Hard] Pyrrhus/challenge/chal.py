#!/usr/bin/env python3
import sys
import subprocess
import tempfile

MAX_SIZE = 30000
TIMEOUT = 60

try:
    script_size = int(input(f"Script size (has to be less than {MAX_SIZE + 1} bytes): "))
except ValueError:
    print("Invalid size", flush=True)
    sys.exit(1)

if script_size > MAX_SIZE:
    print("Invalid size", flush=True)
    sys.exit(1)

print("Script:", flush=True)
script = sys.stdin.read(script_size)
print(f"Received:\n{script}\n\n", flush=True)

with tempfile.NamedTemporaryFile(buffering=0) as f:
    f.write(script.encode("utf-8"))
    print(f"Running script with a {TIMEOUT} second timeout", flush=True)
    res = subprocess.run(["./d8", f.name], timeout=TIMEOUT, stdout=subprocess.PIPE)
    print(f"Finished running", flush=True)
    print(f"Stdout:\n{res.stdout.decode()}", flush=True)
