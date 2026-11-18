"""Dates every entry of a zip or tar archive of this evening at 20:07, Paris
time, keeping everything else: names and their order, contents, modes, a
zip's comment (a source archive names its commit there). The files of a
version show then no hour of the work that made them: git archive dates
them of the commit, mcpb of the hour of packing, the maintainer's Mac of
the build. Used by the Daily workflow.

Usage: python3 -I scripts/redate.py zip|tar <in> <out>
"""
import datetime
import struct
import sys
import tarfile
import zipfile
import zoneinfo

EVENING = datetime.datetime.now(zoneinfo.ZoneInfo("Europe/Paris")).replace(hour=20, minute=7, second=0, microsecond=0)
STAMP = int(EVENING.timestamp())


def kind(i):
    # An entry made by MS-DOS (git archive makes all but the executables so)
    # has no Unix mode: zipfile writes one, which unzip does not read.
    return i.filename, i.create_system, i.external_attr if i.create_system == 3 else i.external_attr & 0xFFFF


def redate_zip(source, out):
    # Each entry is dated twice: the DOS date, and an "UT" field (Unix time).
    ut = b"UT\x05\x00\x01" + struct.pack("<I", STAMP)
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(out, "w") as zout:
        zout.comment = zin.comment
        for info in zin.infolist():
            new = zipfile.ZipInfo(info.filename, date_time=EVENING.timetuple()[:6])
            new.compress_type = zipfile.ZIP_DEFLATED
            new.create_system = info.create_system
            new.external_attr = info.external_attr
            new.extra = ut
            zout.writestr(new, zin.read(info))
    with zipfile.ZipFile(source) as a, zipfile.ZipFile(out) as b:
        assert a.comment == b.comment
        assert [kind(i) for i in a.infolist()] == [kind(i) for i in b.infolist()]
        assert all(a.read(i) == b.read(i.filename) for i in a.infolist())
        assert all(i.date_time == EVENING.timetuple()[:6] and i.extra == ut for i in b.infolist())


def redate_tar(source, out):
    with tarfile.open(source) as tin, tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tout:
        for member in tin.getmembers():
            if not (member.isfile() or member.isdir() or member.issym()):
                raise SystemExit(f"{member.name}: neither a file, a folder nor a link")
            new = tarfile.TarInfo(member.name)
            new.type, new.mode, new.size, new.linkname = member.type, member.mode, member.size, member.linkname
            new.uid = new.gid = 0
            new.uname = new.gname = ""
            new.mtime = STAMP
            tout.addfile(new, tin.extractfile(member) if member.isfile() else None)
    with tarfile.open(source) as a, tarfile.open(out) as b:
        old, new = a.getmembers(), b.getmembers()
        assert [(m.name, m.type, m.mode, m.size, m.linkname) for m in old] == [(m.name, m.type, m.mode, m.size, m.linkname) for m in new]
        assert all(a.extractfile(m).read() == b.extractfile(m.name).read() for m in old if m.isfile())
        assert all(m.mtime == STAMP for m in new)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("zip", "tar"):
        raise SystemExit(__doc__)
    (redate_zip if sys.argv[1] == "zip" else redate_tar)(sys.argv[2], sys.argv[3])
    print(f"{sys.argv[3]}: dated {EVENING.isoformat()}")
