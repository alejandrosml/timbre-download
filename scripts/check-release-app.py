#!/usr/bin/env python3
"""Check that a release file holds the Timbre.app that was signed and notarized.

Usage: python3 -I scripts/check-release-app.py <version X.Y.Z> <Timbre-X.Y.Z.zip | timbre-X.Y.Z.mcpb>...

An installed Timbre updates itself from the page (`src/updates.rs`). It takes
`Timbre-X.Y.Z.zip` only if the app inside is Timbre, of that version, signed
with a Developer ID of the same Apple team as itself, and notarized;
otherwise it leaves the file aside, tries again the next day, and nobody is
told. The Release workflow's dry run signs the app ad hoc, and the package
in its `timbre-dry-run` artifact has the very name a release's has:
published by mistake, an app signed ad hoc would stop every update without
a sign. So the files of a release are not made
(`scripts/package-extras.sh`), and the page is not built
(`scripts/build-site.py`), unless this check passes.

It refuses a Timbre.app:
- without a stapled notarization ticket, or with one that is not for this
  executable;
- of which a slice is not signed with the Developer ID: no CMS signature,
  the ad-hoc flag, no hardened runtime, another team or another kind of
  certificate;
- whose identifier, in the signature or in Info.plist, is not Timbre's;
- whose version is not the one expected;
- that does not hold both x86_64 and arm64.

This is a guard against publishing the wrong file, NOT a cryptographic
verification: it reads what the signature says and verifies none of it, so
a file made to deceive it would pass. The real verification is the one the
installed Timbre makes on the Mac, with `codesign` and `spctl`. This check
needs nothing but Python and also runs on Linux, where the page is built.
A file that is not ours may be given to it: what it reads, unpacks and
writes out is bounded by the sizes below (with every one of them reached at
once: about 180 MB of memory and a second, which the tests measure), and a
damaged file is refused, not crashed on.
"""

import hashlib
import json
import os
import plistlib
import re
import struct
import sys
import zipfile

BUNDLE_ID = "io.github.alejandrosml.timbre"
# The Apple team of the Developer ID that signs the published versions, as
# read in the published 0.7.4 (`codesign -dv` shows it as TeamIdentifier, and
# README.md names it). An installed Timbre only takes an update signed by
# the team that signed it: a release signed by another team updates no one.
TEAM = "4FQA525DB9"
CPUS = {0x01000007: "x86_64", 0x0100000C: "arm64"}
NEEDED = {"x86_64", "arm64"}

MAX_ARCHIVE = 300_000_000  # an installed Timbre downloads no more (src/updates.rs)
MAX_DIRECTORY = 1 << 20  # the archive's list of files; Timbre's is about 1 KB
MAX_EXECUTABLE = 128 << 20  # unpacked; 0.7.4's is 29 MB
MAX_SMALL = 1 << 20  # manifest.json, the ticket
MAX_PLIST = 64 << 10  # Info.plist; 0.7.4's is 1 KB
MAX_SIGNATURE = 4 << 20  # one slice's signature; 0.7.4's largest is 137 KB


class Refused(Exception):
    """The file is not a release's; each argument is one reason."""


def show(value: object) -> str:
    """A value read in the file, short enough for a message. Only a text or
    a number is written out: a list or a dictionary of a few bytes in the
    file can hold itself many times over, and be gigabytes as text."""
    if isinstance(value, (str, bytes)):
        return repr(value[:77]) + ("..." if len(value) > 77 else "")
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)[:80]
    kind = type(value).__name__
    return f"a{'n' if kind[0] in 'aeiou' else ''} {kind}"


def bounded(path: str) -> None:
    """Refuse an archive too large to be Timbre's, before `zipfile` reads its
    whole list of files into memory."""
    try:
        size = os.path.getsize(path)
        if size > MAX_ARCHIVE:
            raise Refused(f"larger than {MAX_ARCHIVE} bytes: an installed Timbre would not download it")
        # zipfile looks for the end record in the last 22 + 65536 bytes (a
        # comment may follow it), and for a zip64 locator in the 20 bytes
        # before that record: those 20 bytes are read too, wherever it is.
        window = max(0, size - 22 - 65536)
        start = max(0, window - 20)
        with open(path, "rb") as f:
            f.seek(start)
            tail = f.read(size - start)
    except OSError as e:
        raise Refused(f"cannot be read ({e.strerror or e})") from None
    # The end record, found as zipfile finds it: the last 22 bytes when the
    # archive has no comment, the last one in its window otherwise.
    if tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\0\0":
        at = len(tail) - 22
    else:
        at = tail.rfind(b"PK\x05\x06", window - start)
    if at < 0 or at + 22 > len(tail):
        raise Refused("not a zip archive, or a truncated one (no end record)")
    (directory,) = struct.unpack_from("<I", tail, at + 12)
    if directory > MAX_DIRECTORY or tail[max(0, at - 20) : at].startswith(b"PK\x06\x07"):
        raise Refused(
            f"not Timbre's archive: its list of files is larger than {MAX_DIRECTORY} bytes, or in the zip64 form"
        )


def member(z: zipfile.ZipFile, name: str, limit: int, needed: bool = True):
    """The bytes of the one file called `name`, `limit` bytes at most; None
    if there is none and it is not `needed`."""
    found = [i for i in z.infolist() if i.filename == name]
    if not found and not needed:
        return None
    if len(found) != 1:
        raise Refused(f"no {name} inside" if not found else f"{len(found)} files named {name} inside")
    if (found[0].external_attr >> 16) & 0o170000 not in (0, 0o100000):
        raise Refused(f"{name} is not a regular file")
    # Stored or deflated, as Timbre's files are. zipfile unpacks these two
    # up to the size asked and no further; the other ways of packing it
    # knows (bzip2, LZMA) it unpacks whole, whatever size the member says.
    if found[0].compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise Refused(f"{name} is packed in a way Timbre's files are not")
    if found[0].file_size > limit:
        raise Refused(f"{name} is larger than {limit} bytes")
    # Read by pieces into one buffer of the size the member says: read in
    # one go, zipfile holds a member about three times over.
    data, got = bytearray(found[0].file_size), 0
    with z.open(found[0]) as f, memoryview(data) as view:
        while got < len(data):
            piece = f.read(min(1 << 20, len(data) - got))
            if not piece:
                raise Refused(f"{name} is shorter than it says")
            view[got : got + len(piece)] = piece
            got += len(piece)
    return data


def slices(exe: bytearray) -> list:
    """The executable's slices: (architecture, CPU type, bytes) for each."""
    view = memoryview(exe)
    if len(exe) >= 8 and exe[:4] == b"\xcf\xfa\xed\xfe":  # one, 64-bit, little-endian
        (cpu,) = struct.unpack_from("<I", exe, 4)
        return [(CPUS.get(cpu, f"CPU type {cpu:#x}"), cpu, view)]
    if len(exe) < 8 or exe[:4] != b"\xca\xfe\xba\xbe":  # several, big-endian
        raise Refused("Contents/MacOS/timbre is not a Mac executable")
    (count,) = struct.unpack_from(">I", exe, 4)
    if not 1 <= count <= 16 or 8 + 20 * count > len(exe):
        raise Refused("Contents/MacOS/timbre: damaged list of architectures")
    found = []
    for i in range(count):
        cpu, _sub, offset, size, _align = struct.unpack_from(">5I", exe, 8 + 20 * i)
        if offset + size > len(exe):
            raise Refused("Contents/MacOS/timbre: an architecture runs past the end of the file (truncated?)")
        found.append((CPUS.get(cpu, f"CPU type {cpu:#x}"), cpu, view[offset : offset + size]))
    return found


def code_signature(cpu: int, mach: memoryview):
    """What one slice holds as a signature: its code directories by slot, and
    the bytes of its CMS signature (None without one)."""
    damaged = Refused("damaged Mach-O header")
    if len(mach) < 32:
        raise damaged
    magic, own_cpu, _sub, _type, commands, commands_size = struct.unpack_from("<6I", mach, 0)
    if magic != 0xFEEDFACF or own_cpu != cpu or commands > 1024 or 32 + commands_size > len(mach):
        raise damaged
    at, end, where = 32, 32 + commands_size, None
    for _ in range(commands):
        if at + 8 > end:
            raise damaged
        command, size = struct.unpack_from("<II", mach, at)
        if size < 8 or at + size > end:
            raise damaged
        if command == 0x1D:  # LC_CODE_SIGNATURE
            if size < 16:
                raise damaged
            where = struct.unpack_from("<II", mach, at + 8)
        at += size
    if where is None:
        return {}, None
    damaged = Refused("damaged signature")
    offset, size = where
    if size < 12 or size > MAX_SIGNATURE or offset + size > len(mach):
        raise damaged
    blob = mach[offset : offset + size]
    magic, total, count = struct.unpack_from(">3I", blob, 0)
    if magic != 0xFADE0CC0 or total > size or count > 64 or 12 + 8 * count > total:
        raise damaged
    directories, cms = {}, None
    for k in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + 8 * k)
        if start + 8 > total:
            raise damaged
        kind, length = struct.unpack_from(">II", blob, start)
        if length < 8 or start + length > total:
            raise damaged
        # The code directory, and those in other hashes that may come with it.
        if kind == 0xFADE0C02 and (slot == 0 or 0x1000 <= slot <= 0x1005):
            directories[slot] = bytes(blob[start : start + length])
        elif kind == 0xFADE0B01 and slot == 0x10000:
            cms = bytes(blob[start + 8 : start + length])
    return directories, cms


def text_at(blob: bytes, at: int):
    """The NUL-terminated text at `at` in a code directory, if there is one."""
    end = blob.find(b"\0", at, at + 256) if 44 <= at < len(blob) else -1
    return blob[at:end].decode("utf-8", "replace") if end >= 0 else None


def code_directory(blob: bytes):
    """What a code directory says: (flags, identifier, team, its hash as the
    notarization ticket lists it)."""
    if len(blob) < 44:
        raise Refused("damaged signature")
    version, flags, _hashes, identifier_at = struct.unpack_from(">4I", blob, 8)
    team_at = struct.unpack_from(">I", blob, 48)[0] if version >= 0x20200 and len(blob) >= 52 else 0
    digest = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256, 4: hashlib.sha384}.get(blob[37])
    return flags, text_at(blob, identifier_at), text_at(blob, team_at), digest(blob).digest()[:20] if digest else None


def slice_problems(arch: str, cpu: int, mach: memoryview, ticket) -> list:
    """Why one slice is not the signed, notarized one; nothing if it is."""
    try:
        directories, cms = code_signature(cpu, mach)
        said = [code_directory(directories[slot]) for slot in sorted(directories)]
    except Refused as e:
        return [f"{arch}: {reason}" for reason in e.args]
    if 0 not in directories:
        return [f"{arch}: not signed"]
    problems = []
    flags = said[0][0]
    if any(f & 0x2 for f, _, _, _ in said):
        problems.append(f"signed ad hoc (flags {flags:#x}), as the package of the Release workflow's dry run is")
    if not all(f & 0x10000 for f, _, _, _ in said):
        problems.append(f"signed without the hardened runtime (flags {flags:#x})")
    identifiers = {i for _, i, _, _ in said}
    if identifiers != {BUNDLE_ID}:
        problems.append(f"signed as {', '.join(sorted(map(show, identifiers)))}, not {BUNDLE_ID}")
    teams = {t for _, _, t, _ in said}
    if teams != {TEAM}:
        named = sorted(show(t) for t in teams if t is not None)
        problems.append(f"signed for {'team ' + ', '.join(named) if named else 'no team'}, not for team {TEAM}")
    if not cms:
        problems.append("no Developer ID signature (no CMS signature: ad hoc, or not signed)")
    elif b"Developer ID Application: " not in cms or TEAM.encode() not in cms:
        problems.append(f"not signed with a Developer ID Application certificate of team {TEAM}")
    if ticket and not any(h and h in ticket for _, _, _, h in said):
        problems.append("the stapled ticket is not for this executable (signed again after notarization?)")
    return [f"{arch}: {p}" for p in problems]


def check(path: str, version: str) -> str:
    """What `path` holds, in a line, if it is a release's; raises Refused."""
    kind = os.path.splitext(path)[1].lower()
    if kind not in (".zip", ".mcpb"):
        raise Refused("neither a Timbre-X.Y.Z.zip nor a timbre-X.Y.Z.mcpb")
    # Where each kind of file holds the app: an installed Timbre unpacks the
    # zip and takes Timbre.app at its top, nowhere else.
    app = "server/Timbre.app/" if kind == ".mcpb" else "Timbre.app/"
    bounded(path)
    try:
        with zipfile.ZipFile(path) as z:
            exe = member(z, app + "Contents/MacOS/timbre", MAX_EXECUTABLE)
            info = member(z, app + "Contents/Info.plist", MAX_PLIST)
            ticket = member(z, app + "Contents/CodeResources", MAX_SMALL, needed=False)
            manifest = member(z, "manifest.json", MAX_SMALL) if kind == ".mcpb" else None
            sealed = any(i.filename == app + "Contents/_CodeSignature/CodeResources" for i in z.infolist())
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 (zipfile and zlib raise many kinds on a damaged archive)
        raise Refused(f"damaged, or not a zip archive ({type(e).__name__}: {str(e)[:200]})") from None

    problems = []
    try:
        plist = plistlib.loads(info)
    except Exception as e:  # noqa: BLE001 (plistlib raises many kinds on a damaged file)
        problems.append(f"Info.plist cannot be read ({type(e).__name__})")
    else:
        if not isinstance(plist, dict):
            plist = {}
        if plist.get("CFBundleIdentifier") != BUNDLE_ID:
            problems.append(f"Info.plist names {show(plist.get('CFBundleIdentifier'))}, not {BUNDLE_ID}")
        for key in ("CFBundleShortVersionString", "CFBundleVersion"):
            if plist.get(key) != version:
                problems.append(f"Info.plist is version {show(plist.get(key))} ({key}), not {version}")
    if manifest is not None:
        try:
            # Numbers are kept as their text: none is turned into a number,
            # which takes long for one of a million digits.
            said = json.loads(manifest, parse_int=str, parse_float=str, parse_constant=str)
            said = said.get("version") if isinstance(said, dict) else None
        except (ValueError, RecursionError):
            said = None
        if said != version:
            problems.append(f"manifest.json is version {show(said)}, not {version}")
    if not sealed:
        problems.append("no Contents/_CodeSignature/CodeResources: not a signed app")
    if not ticket:
        problems.append("no stapled ticket (Contents/CodeResources): not notarized, or the ticket was not stapled")
    try:
        found = slices(exe)
    except Refused as e:
        problems.extend(e.args)
        found = []
    archs = {arch for arch, _, _ in found}
    if found and not NEEDED <= archs:
        problems.append(f"built for {', '.join(sorted(archs))} only: a release needs both x86_64 and arm64")
    for arch, cpu, mach in found:
        problems.extend(slice_problems(arch, cpu, mach, ticket))
    if problems:
        raise Refused(*problems)
    return (
        f"Timbre {version}, signed with a Developer ID (team {TEAM}), "
        f"ticket stapled, universal ({', '.join(sorted(archs))})"
    )


def main() -> None:
    if len(sys.argv) < 3 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sys.argv[1]):
        sys.stderr.write(__doc__)
        sys.exit(2)
    version, refused = sys.argv[1], False
    for path in sys.argv[2:]:
        try:
            print(f"{path}: {check(path, version)}")
        except Refused as e:
            refused = True
            for reason in e.args:
                print(f"{path}: refused: {reason}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 (never a Python trace on a file that is not ours)
            refused = True
            reason = f"{type(e).__name__}: {str(e)[:200]}"
            print(f"{path}: refused: cannot be read as a release file ({reason})", file=sys.stderr)
    if refused:
        print(
            "A release holds the files scripts/package-extras.sh makes from the package "
            "Timbre Signer signed, never the package of the timbre-dry-run artifact (RELEASING.md).",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
