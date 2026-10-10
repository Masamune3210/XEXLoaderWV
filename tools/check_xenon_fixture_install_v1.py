#!/usr/bin/env python3
r"""Check Xenon fixture freshness and compare compiled/packaged/installed .sla.

Run from the repository root:
  python tools/check_xenon_fixture_install_v1.py
Optional:
  python tools/check_xenon_fixture_install_v1.py --installed-sla "C:\path\xenon_64_be.sla"

This script only reads files and never modifies a Ghidra database.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANG = ROOT / "XEXLoaderWV" / "data" / "languages"
OUT = ROOT / "build" / "xenon-isa-audit"
MANIFEST = OUT / "xenon_isa_fixture_v1.tsv"
FIXTURE = OUT / "xenon_isa_fixture_v1.bin"
SLEIGH = LANG / "xenon_vector_v1.sinc"
BUILT = LANG / "xenon_64_be.sla"
DIST = ROOT / "XEXLoaderWV" / "dist"
EXPECTED = {
    "lvsl128": "opaque-userop",
    "lvsr128": "opaque-userop",
    "lvewx128": "native-pcode",
    "stvewx128": "native-pcode",
    "dcbz128": "native-pcode",
    "stvlx": "native-pcode",
    "lvlxl": "native-pcode",
    "lvrxl": "native-pcode",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def describe(path: Path) -> str:
    return "%s (%d bytes, sha256=%s)" % (
        path, path.stat().st_size, digest(path.read_bytes()))


def installed_candidates() -> list[Path]:
    home = Path.home()
    roots = [home / ".ghidra", home / "AppData" / "Roaming" / "ghidra",
             home / "AppData" / "Local" / "ghidra"]
    found = []
    for base in roots:
        if not base.is_dir():
            continue
        try:
            for path in base.glob("*/Extensions/**/xenon_64_be.sla"):
                if path.is_file():
                    found.append(path)
        except OSError as error:
            print("Could not inspect %s: %s" % (base, error))
    return sorted(set(found))


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--installed-sla", type=Path,
                      help="Explicit installed xenon_64_be.sla to compare")
    opt = args.parse_args()
    print("Repository:", ROOT)
    if not SLEIGH.is_file() or not MANIFEST.is_file() or not FIXTURE.is_file():
        print("ERROR: missing current source or fixture. Run:")
        print("  python tools/audit_xenon_isa_coverage_v1.py")
        return 2

    from audit_xenon_isa_coverage_v1 import parse_sleigh
    source_status, unused_ops = parse_sleigh(SLEIGH.read_text(encoding="utf-8"))
    with MANIFEST.open(encoding="utf-8", newline="") as f:
        records = list(csv.DictReader(f, delimiter="\t"))
    if len(records) != 336:
        print("ERROR: expected exactly 336 fixture rows; got", len(records))
        return 2
    data = FIXTURE.read_bytes()
    if len(data) != 1344:
        print("ERROR: fixture is not 1344 bytes:", len(data))
        return 2
    labels = {}
    errors = []
    for row in records:
        name, status = row["expected_mnemonic"], row["sleigh_status"]
        expected_status = source_status.get(name, "missing")
        if expected_status != status:
            errors.append("%s: manifest=%s, source=%s" %
                          (name, status, expected_status))
        old = labels.setdefault(name, status)
        if old != status:
            errors.append("%s: manifest has inconsistent status values" % name)
        offset = int(row["offset"], 16)
        word = int(row["word_be"], 16)
        if offset < 0 or offset + 4 > len(data) or data[offset:offset+4] != word.to_bytes(4, "big"):
            errors.append("%s: fixture bytes mismatch at %s" % (name, row["offset"]))
    print("Current source SLEIGH SHA-256:", digest(SLEIGH.read_bytes()))
    print("Fixture:", describe(FIXTURE))
    print("Manifest:", describe(MANIFEST))
    print("Classification checks:")
    for name, expected_status in EXPECTED.items():
        actual = labels.get(name, "<not found>")
        print("  %s: %s (expected at least %s)" % (name, actual, expected_status))
        if actual != expected_status:
            errors.append("%s: required status %s but found %s" %
                          (name, expected_status, actual))
    if errors:
        print("ERROR: fixture/manifest stale or inconsistent:")
        for issue in dict.fromkeys(errors):
            print("  " + issue)
        print("Regenerate the fixture and select that exact TSV in Ghidra.")
        return 2
    print("PASS: fixture and manifest agree with the working-tree SLEIGH source.")

    built_hash = digest(BUILT.read_bytes()) if BUILT.is_file() else None
    if built_hash is not None:
        print("Built SLA:", describe(BUILT))
    else:
        print("WARNING: built SLA absent:", BUILT)

    archives = sorted(DIST.glob("*.zip"), key=lambda f: f.stat().st_mtime, reverse=True) if DIST.is_dir() else []
    for archive in archives[:5]:
        with zipfile.ZipFile(archive) as z:
            members = [n for n in z.namelist()
                       if n.replace("\\", "/").lstrip("/").endswith("data/languages/xenon_64_be.sla")]
            if not members:
                print("WARNING: archive missing Xenon SLA:", archive)
                continue
            for member in members:
                archive_hash = digest(z.read(member))
                print("Archive SLA:", archive, "::", member, "SHA-256:", archive_hash)
                if built_hash and archive_hash != built_hash:
                    print("WARNING: archive does NOT contain the current built SLA")

    installed = [opt.installed_sla] if opt.installed_sla else installed_candidates()
    installed = [p for p in installed if p.is_file()]
    if not installed:
        print("WARNING: no installed Xenon SLA located automatically.")
        print("Pass --installed-sla with the actual installed file path.")
    for path in installed:
        actual_hash = digest(path.read_bytes())
        print("Installed SLA:", describe(path))
        if built_hash is not None:
            print("SLA checksum match:", "YES" if built_hash == actual_hash else "NO")
            if built_hash != actual_hash:
                print("WARNING: installed Xenon language is not the current build.")
    print("NOTE: matching files do not prove the running Ghidra JVM has reloaded")
    print("the language. Restart Ghidra and import into a NEW Program.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
