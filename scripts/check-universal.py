#!/usr/bin/env python3
"""Check that Timbre's executable runs on both kinds of Mac (Intel and Apple Silicon).

Usage: python3 -I scripts/check-universal.py <timbre executable | Timbre.app | .mcpb | .zip>...

0.7.3 was published for Apple Silicon only and could not start on an Intel
Mac: nothing is packaged or published without this check.
"""
import os
import struct
import sys
import zipfile

NAMES = {0x01000007: "x86_64", 0x0100000C: "arm64"}
NEEDED = {"x86_64", "arm64"}


def archs(head: bytes) -> set[str]:
    """The architectures a Mach-O file holds, from its first bytes."""
    if head[:4] == b"\xca\xfe\xba\xbe":  # several, big-endian
        (count,) = struct.unpack(">I", head[4:8])
        return {
            NAMES.get(struct.unpack(">I", head[8 + 20 * i : 12 + 20 * i])[0], "other")
            for i in range(min(count, 16))
        }
    if head[:4] == b"\xcf\xfa\xed\xfe":  # one, 64-bit, little-endian
        return {NAMES.get(struct.unpack("<I", head[4:8])[0], "other")}
    return set()


def executable(path: str) -> bytes:
    """The first bytes of Timbre's executable, wherever `path` holds it."""
    if os.path.isdir(path):
        path = os.path.join(path, "Contents", "MacOS", "timbre")
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            inside = [n for n in z.namelist() if n.endswith("Timbre.app/Contents/MacOS/timbre")]
            if len(inside) != 1:
                sys.exit(f"{path}: no Timbre.app inside")
            with z.open(inside[0]) as f:
                return f.read(4096)
    with open(path, "rb") as f:
        return f.read(4096)


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        found = archs(executable(path))
        if not NEEDED <= found:
            sys.exit(
                f"{path}: built for {', '.join(sorted(found)) or 'no Mac'} only; "
                "a release needs both x86_64 and arm64 (see RELEASING.md)"
            )
        print(f"{path}: universal ({', '.join(sorted(found))})")


if __name__ == "__main__":
    main()
