#!/usr/bin/env python3
"""Audit 76 VMX128 and 8 non-suffixed Xenon vector selectors against SLEIGH.

Generate a big-endian instruction fixture plus manifest for Ghidra runtime tests.
This source-level audit NEVER treats a matching name as proof of decode correctness.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "tools/data/xenia_vmx128_opcode_inventory_20261009.tsv"
EXTRA_INVENTORY = ROOT / "tools/data/xenia_xform_vector_opcode_inventory_20261009.tsv"
EXTRA_NAMES = frozenset(("lvlx", "lvrx", "stvlx", "stvrx",
                         "lvlxl", "lvrxl", "stvlxl", "stvrxl"))
SLEIGH = ROOT / "data/languages/xenon_vector_v1.sinc"
ADDITIONAL_SLEIGH = ROOT / "data/languages/xenon_vector_remaining_v1.sinc"
OUTPUT = ROOT / "build/xenon-isa-audit"
FILLS = (("zero", 0), ("ones", 0xFFFFFFFF),
         ("55", 0x55555555), ("aa", 0xAAAAAAAA))
XENIA_COMMIT = "95a5c3ee250f80c3b9d139658649d9ffb6db3eec"


def read_inventory(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(
            (line for line in f if not line.startswith("#")), delimiter="\t"))
    names = set()
    if not rows:
        raise ValueError("Empty inventory")
    for r in rows:
        name = r["mnemonic"]
        if name in names or not (name.endswith("128") or name in EXTRA_NAMES):
            raise ValueError("Duplicate or unexpected name: " + name)
        names.add(name)
        for key in ("primary", "xenia_line"):
            r[key] = int(r[key])
        for key in ("mask", "value"):
            r[key] = int(r[key], 16)
        if (r["mask"] & 0xFC000000) != 0xFC000000:
            raise ValueError("Missing primary opcode mask: " + name)
        if (r["value"] >> 26) != r["primary"] or (r["value"] & ~r["mask"]):
            raise ValueError("Malformed selector for " + name)
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            if (((a["value"] ^ b["value"]) &
                 (a["mask"] & b["mask"])) == 0):
                raise ValueError("Overlapping selectors: " +
                                 a["mnemonic"] + " / " + b["mnemonic"])
    return rows


def parse_xenia_lookup(source: str) -> dict[str, tuple[int, int, int]]:
    """Reconstruct selectors from Xenia's generated nested ExtractBits switches."""
    primary = None
    selector = None
    found = {}
    for line_num, line in enumerate(source.splitlines(), 1):
        head = re.match(r"^  case (\d+):", line)
        if head:
            primary, selector = int(head[1]), None
        switch = re.match(r"^\s+switch \((.+)\) \{$", line)
        if switch:
            selector = switch[1]
        hit = re.match(r"^\s+case 0b([01]+): PPC_DECODER_HIT\(([^)]+)\)", line)
        if not hit or not (hit[2].endswith("128") or hit[2] in EXTRA_NAMES):
            continue
        if primary is None or selector is None:
            raise ValueError(f"Unsupported decoder switch on line {line_num}")
        fields = [(int(a), int(b), int(s)) for a, b, s in re.findall(
            r"ExtractBits\(code, (\d+), (\d+)\) << (\d+)", selector)]
        if not fields:
            raise ValueError(f"No ExtractBits fields on line {line_num}")
        case, mask, value = int(hit[1], 2), 0xFC000000, primary << 26
        for a, b, shift in fields:
            width, pos = b - a + 1, 31 - b
            mask |= ((1 << width) - 1) << pos
            value |= ((case >> shift) & ((1 << width) - 1)) << pos
        if hit[2] in found:
            raise ValueError("Repeated Xenia opcode " + hit[2])
        found[hit[2]] = (primary, mask, value)
    return found


def read_sleigh_source(path: Path) -> str:
    """Return the actual Xenon vector sources included by its .slaspec.

    A standalone --sleigh override remains a standalone input; the default
    Xenon source is the combination of original and supplementary includes.
    """
    source = path.read_text(encoding="utf-8")
    if path.resolve() == SLEIGH.resolve():
        source += "\n" + ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
    return source


def parse_sleigh(source: str) -> tuple[dict[str, str], list[str]]:
    custom_ops = set(re.findall(r"(?m)^\s*define pcodeop\s+(\w+)\s*;", source))
    families: dict[str, set[str]] = {}
    for m in re.finditer(r"(?m)^\s*:([A-Za-z][A-Za-z0-9_.]*)\s", source):
        start = source.find("{", m.end())
        end = source.find("}", start + 1)
        if start == -1 or end == -1:
            raise ValueError("Invalid SLEIGH constructor: " + m[1])
        calls = set(re.findall(r"\b(\w+)\s*\(", source[start + 1:end]))
        label = "opaque-userop" if custom_ops & calls else "native-pcode"
        families.setdefault(m[1], set()).add(label)
    result = {name: ("opaque-userop" if "opaque-userop" in statuses
                     else "native-pcode") for name, statuses in families.items()}
    return result, sorted(custom_ops)


def write_results(rows: list[dict], sleigh_path: Path, inventory_path: Path,
                  output: Path) -> None:
    source = read_sleigh_source(sleigh_path)
    implemented, custom_ops = parse_sleigh(source)
    output.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    annotated = []
    samples = []
    binary = bytearray()
    for r in rows:
        name, mask, value = r["mnemonic"], r["mask"], r["value"]
        status = implemented.get(name, "missing")
        counts[status] += 1
        annotated.append({**r, "status": status})
        for variant, fill in FILLS:
            word = value | (fill & (~mask & 0xFFFFFFFF))
            hits = [x["mnemonic"] for x in rows
                    if (word & x["mask"]) == x["value"]]
            if hits != [name]:
                raise ValueError(f"Fixture ambiguity: {word:08X} -> {hits}")
            samples.append((f"0x{len(binary):08X}", f"{word:08X}",
                            name, status, variant))
            binary.extend(word.to_bytes(4, "big"))

    def write_tsv(name: str, headings: tuple, items: list) -> None:
        with (output / name).open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(headings)
            writer.writerows(items)

    write_tsv("xenon_isa_fixture_v1.tsv",
              ("offset", "word_be", "expected_mnemonic", "sleigh_status",
               "variant"), samples)
    (output / "xenon_isa_fixture_v1.bin").write_bytes(binary)
    write_tsv("xenon_isa_coverage_v1.tsv",
              ("mnemonic", "primary", "mask", "value",
               "xenia_line", "sleigh_status"),
              [(r["mnemonic"], r["primary"], f"0x{r['mask']:08X}",
                f"0x{r['value']:08X}", r["xenia_line"], r["status"])
               for r in annotated])
    tick = chr(96)
    source_url = ("https://github.com/xenia-project/xenia/blob/" +
                  XENIA_COMMIT +
                  "/src/xenia/cpu/ppc/ppc_opcode_lookup_gen.cc")
    lines = [
        "# Xenon VMX128 source-definition coverage",
        "",
        "Generated from Xenia pinned at " + tick + XENIA_COMMIT + tick,
        "Source: " + source_url,
        "Inventory SHA-256: " + tick + hashlib.sha256(
            inventory_path.read_bytes()).hexdigest() + tick,
        "SLEIGH SHA-256: " + tick + hashlib.sha256(
            source.encode("utf-8")).hexdigest() + tick,
        "",
        f"Families: **{len(rows)}**. Native p-code bodies: "
        f"**{counts['native-pcode']}**. Opaque custom userops: "
        f"**{counts['opaque-userop']}**. Missing: **{counts['missing']}**.",
        f"Fixture: **{len(samples)}** sample words, **{len(binary)}** bytes.",
        "",
        "This is source coverage only, NOT verified runtime decoding, and",
        "native SLEIGH p-code does not necessarily mean correct semantics.",
        "These include 76 *128 families plus eight opcode-31 X-form variants.",
        "Stock AltiVec/PowerPC coverage is outside scope. The inherited",
        "Ghidra PPC language may already decode additional X-form cases.",
        "The implemented opcode-31 lvlx and lvrx are NOT opcode-4",
        "lvlx128 and lvrx128.",
        "",
        "| Primary | Family | Status | Mask / Value |",
        "|---:|---|---|---|",
    ]
    for r in annotated:
        lines.append(f"| {r['primary']} | " + tick + r["mnemonic"] + tick +
                     f" | {r['status']} | " + tick +
                     f"{r['mask']:08X} / {r['value']:08X}" + tick + " |")
    extra = sorted(name for name in implemented
                   if name.endswith("128") and
                   name not in {r["mnemonic"] for r in rows})
    lines.extend(["", "SLEIGH-only *128 names: " +
                  (", ".join(extra) if extra else "none"),
                  "Custom userops declared: " + ", ".join(custom_ops),
                  "Ghidra validation: import the generated .bin as raw",
                  "PowerPC big-endian with XENON-32addr and run",
                  "ghidra_scripts/AuditXenonIsaFixtureV1.java using its TSV.",
                  ""])
    (output / "xenon_isa_coverage_v1.md").write_text(
        "\n".join(lines), encoding="utf-8")
    print(f"Families={len(rows)} native={counts['native-pcode']} "
          f"opaque={counts['opaque-userop']} missing={counts['missing']}; "
          f"fixture={len(samples)} words / {len(binary)} bytes")
    print("Generated:", output)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", type=Path, default=INVENTORY)
    ap.add_argument("--extra-inventory", type=Path, default=EXTRA_INVENTORY)
    ap.add_argument("--sleigh", type=Path, default=SLEIGH)
    ap.add_argument("--out-dir", type=Path, default=OUTPUT)
    ap.add_argument("--xenia-lookup", type=Path,
                    help="Optional local Xenia decoder source to recheck "
                         "every pinned opcode selector")
    args = ap.parse_args()
    rows = read_inventory(args.inventory) + read_inventory(args.extra_inventory)
    if args.xenia_lookup:
        actual = parse_xenia_lookup(args.xenia_lookup.read_text(encoding="utf-8"))
        expected = {r["mnemonic"]: (r["primary"], r["mask"], r["value"])
                    for r in rows}
        if actual != expected:
            missing = sorted(expected.keys() - actual.keys())
            added = sorted(actual.keys() - expected.keys())
            changed = sorted(name for name in actual.keys() & expected.keys()
                             if actual[name] != expected[name])
            raise SystemExit("Upstream selector difference: absent=" +
                             str(missing) + " added=" + str(added) +
                             " changed=" + str(changed))
        print("Verified against Xenia source: " + str(len(actual)) + " selectors")
    write_results(rows, args.sleigh, args.inventory, args.out_dir)


if __name__ == "__main__":
    main()
