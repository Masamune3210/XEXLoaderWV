#!/usr/bin/env python3
r"""Check Xenon fixture freshness and compare compiled/packaged/installed .sla.

Run from the XEXLoaderWV Gradle extension project directory:
  python tools/check_xenon_fixture_install_v1.py
Optional:
  python tools/check_xenon_fixture_install_v1.py --installed-sla "C:\path\xenon_64_be.sla"

This script only reads files and never modifies a Ghidra database.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANG = ROOT / "data" / "languages"
OUT = ROOT / "build" / "xenon-isa-audit"
MANIFEST = OUT / "xenon_isa_fixture_v1.tsv"
REPORT = OUT / "xenon_isa_coverage_v1.md"
COVERAGE = OUT / "xenon_isa_coverage_v1.tsv"
FIXTURE = OUT / "xenon_isa_fixture_v1.bin"
SLEIGH = LANG / "xenon_vector_v1.sinc"
BUILT = LANG / "xenon_64_be.sla"
DIST = ROOT / "dist"
EXPECTED = {
    "lvsl128": "native-pcode",
    "lvsr128": "native-pcode",
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
    if any(not p.is_file() for p in
           (SLEIGH, MANIFEST, FIXTURE, REPORT, COVERAGE)):
        print("ERROR: missing current source or fixture. Run:")
        print("  python tools/audit_xenon_isa_coverage_v1.py")
        return 2

    from audit_xenon_isa_coverage_v1 import (
        FILLS, INVENTORY, EXTRA_INVENTORY, parse_sleigh, read_inventory,
        read_sleigh_source,
    )
    combined_source = read_sleigh_source(SLEIGH)
    source_status, unused_ops = parse_sleigh(combined_source)
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
    report = REPORT.read_text(encoding="utf-8")
    fingerprints = (
        ("SLEIGH SHA-256", digest(combined_source.encode("utf-8"))),
        ("Inventory SHA-256", digest(INVENTORY.read_bytes())),
        ("Extra inventory SHA-256", digest(EXTRA_INVENTORY.read_bytes())),
        ("Language specification SHA-256", digest(
            (LANG / "xenon_64_be.slaspec").read_bytes())),
        ("Generator SHA-256", digest(
            (ROOT / "tools/audit_xenon_isa_coverage_v1.py").read_bytes())),
    )
    for label, current_hash in fingerprints:
        line = re.search(
            r"(?m)^" + re.escape(label) + r": " + chr(96) +
            r"([0-9a-f]{64})" + chr(96) + r"$", report)
        if line is None or line.group(1) != current_hash:
            errors.append("%s: audit report is stale or missing fingerprint" %
                          label)

    # Check the entire pinned manifest against BOTH inventories, not just
    # name classifications. The fixture words remain unchanged when only
    # p-code semantics change; the report fingerprint catches those edits.
    source_rows = (read_inventory(INVENTORY) +
                   read_inventory(EXTRA_INVENTORY))
    expected_samples = []
    for item in source_rows:
        for variant, fill in FILLS:
            word = item["value"] | (fill & (~item["mask"] & 0xFFFFFFFF))
            expected_samples.append((
                f"0x{len(expected_samples) * 4:08X}", f"{word:08X}",
                item["mnemonic"],
                source_status.get(item["mnemonic"], "missing"),
                variant,
            ))
    fields = ("offset", "word_be", "expected_mnemonic", "sleigh_status",
              "variant")
    for index, (actual, expected) in enumerate(zip(records, expected_samples)):
        if tuple(actual[field] for field in fields) != expected:
            errors.append("manifest sample %d does not match current inputs" %
                          index)
    if len(records) != len(expected_samples):
        errors.append("manifest sample count does not match pinned inventories")

    with COVERAGE.open(encoding="utf-8", newline="") as coverage_file:
        coverage_rows = list(csv.DictReader(coverage_file, delimiter="\t"))
    if len(coverage_rows) != len(source_rows):
        errors.append("coverage TSV row count differs from inventories")
    else:
        for index, (actual, item) in enumerate(zip(coverage_rows, source_rows)):
            expected = (
                item["mnemonic"], str(item["primary"]),
                f"0x{item['mask']:08X}", f"0x{item['value']:08X}",
                str(item["xenia_line"]),
                source_status.get(item["mnemonic"], "missing"),
            )
            keys = ("mnemonic", "primary", "mask", "value",
                    "xenia_line", "sleigh_status")
            if tuple(actual[k] for k in keys) != expected:
                errors.append("coverage TSV row %d differs from inputs" % index)
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
    print("Combined Xenon SLEIGH SHA-256:", digest(combined_source.encode("utf-8")))
    print("Fixture:", describe(FIXTURE))
    print("Manifest:", describe(MANIFEST))
    print("Coverage report:", describe(REPORT))
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
        print("Run gradle buildExtension to refresh fixture, manifest and SLA.")
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
