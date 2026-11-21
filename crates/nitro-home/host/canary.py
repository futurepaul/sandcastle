#!/usr/bin/env python3
"""What the parent reads of the home's disks (docs/nitro-home.md, "What the
parent can still see or do"), on the parent, as root, with the home up:

  sudo ./canary.py <run dir> <data disk> <scratch disk>

A fresh canary is written inside the home three times over, through
sandcastle's agent (the parent's own exec, leak 2): to the encrypted data
disk, to the home's tmpfs, and, as the control, to the root's plain upper
layer (the scratch disk). Each disk file on the parent is then read whole
(its holes skipped, every read checked) and the canary counted. Prints one
JSON object. Python, as the spike's study harnesses are.
"""
import json
import os
import secrets
import subprocess
import sys

run_dir, data, scratch = sys.argv[1:4]
canary = "NITRO-HOME-CANARY-" + secrets.token_hex(8)
block = (canary + "\n") * 4096  # about 140 KB, several blocks of each disk
places = {"data_disk": "/var/lib/fragment-home/canary", "tmpfs": "/run/fragment-home/canary", "scratch_control": "/root/canary"}
script = "C=$(cat); " + "; ".join(f"printf '%s' \"$C\" > {p}" for p in places.values()) + "; sync"
stdin = f"/run/nitro-home/canary-{os.getpid()}"
with open(stdin, "w") as f:
    f.write(block)
try:
    out = subprocess.run(["/usr/local/bin/nitro-home", "exec", "--dir", run_dir, "--stdin", stdin, "--", "/bin/sh", "-c", script], capture_output=True, text=True, check=True)
finally:
    os.remove(stdin)
assert json.loads(out.stdout)["code"] == 0, out.stdout


def count(path, needle):
    """The needle's matches in a file's data, its holes skipped."""
    n, f = 0, os.open(path, os.O_RDONLY)
    try:
        end, pos, tail = os.fstat(f).st_size, 0, b""
        while pos < end:
            try:
                start = os.lseek(f, pos, os.SEEK_DATA)
            except OSError:
                break
            stop = os.lseek(f, start, os.SEEK_HOLE)
            os.lseek(f, start, os.SEEK_SET)
            left = stop - start
            while left > 0:
                chunk = os.read(f, min(left, 8 << 20))
                if not chunk:
                    raise IOError(f"{path}: a short read at {stop - left}")
                buf = tail + chunk
                n += buf.count(needle)
                tail = buf[-(len(needle) - 1):]
                left -= len(chunk)
            pos = stop
    finally:
        os.close(f)
    return n


needle = canary.encode()
row = {"canary_bytes_each": len(block), "data_disk": {"file": "data", "found": count(data, needle)}, "scratch_disk": {"file": "scratch", "found": count(scratch, needle)}}
print(json.dumps(row))
