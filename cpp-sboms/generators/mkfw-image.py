#!/usr/bin/env python3
"""mkfw-image.py - wrap a squashfs rootfs in the sample vendor image format (64-byte header, 0xFF pad to 4 MiB).
usage: mkfw-image.py <rootfs.squashfs> <out.bin> [name] [build]"""
import struct, sys, zlib
sq = open(sys.argv[1], "rb").read()
name = (sys.argv[3] if len(sys.argv) > 3 else "sensorhub-fw").encode()
build = (sys.argv[4] if len(sys.argv) > 4 else "3.1.0+build.2026.11.26").encode()
hdr = struct.pack("<4sII16s32sI", b"SNFW", 1, len(sq), name, build, zlib.crc32(sq)).ljust(64, b"\0")
img = (hdr + sq).ljust(4 << 20, b"\xff")
open(sys.argv[2], "wb").write(img)
print(f"{sys.argv[2]}: {len(img)} bytes, rootfs {len(sq)} bytes at offset 64")
