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
CORRECTION_INVENTORY = ROOT / "tools/data/xenon_vmx128_unpack_corrections_20261010.tsv"
EXTRA_NAMES = frozenset(("lvlx", "lvrx", "stvlx", "stvrx",
                         "lvlxl", "lvrxl", "stvlxl", "stvrxl"))
SLEIGH = ROOT / "data/languages/xenon_vector_v1.sinc"
ADDITIONAL_SLEIGH = ROOT / "data/languages/xenon_vector_remaining_v1.sinc"
OUTPUT = ROOT / "build/xenon-isa-audit"
FILLS = (("zero", 0), ("ones", 0xFFFFFFFF),
         ("55", 0x55555555), ("aa", 0xAAAAAAAA))
XENIA_COMMIT = "95a5c3ee250f80c3b9d139658649d9ffb6db3eec"


def decode_expectation(name: str, word: int) -> str:
    """Distinguish documented X-form Rc=0 from decoder-permissive Rc=1.

    Cell Vector/SIMD PEM v2.07c documents bit 31 = 0 for the eight
    indexed left/right vector loads/stores. Xenia's opcode lookup masks
    this bit out; include both encodings to test a strict SLEIGH decoder.
    This is a Cell encoding reference, not Xenon hardware validation.
    """
    return ("reserved-rc1" if name in EXTRA_NAMES and (word & 1)
            else "decode")


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
                  output: Path, extra_inventory_path: Path = EXTRA_INVENTORY,
                  correction_inventory_path: Path = CORRECTION_INVENTORY) -> None:
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
            # Xenia's broad byte-unpack masks overlap the independent
            # halfword-unpack aliases. Match the most specific selector;
            # SLEIGH constructors explicitly split VA==0x60 from VA!=0x60.
            matching = [x for x in rows
                        if (word & x["mask"]) == x["value"]]
            specificity = max(x["mask"].bit_count() for x in matching)
            hits = [x["mnemonic"] for x in matching
                    if x["mask"].bit_count() == specificity]
            if hits != [name]:
                raise ValueError(f"Fixture ambiguity: {word:08X} -> {hits}")
            samples.append((f"0x{len(binary):08X}", f"{word:08X}",
                            name, status, variant,
                            decode_expectation(name, word)))
            binary.extend(word.to_bytes(4, "big"))

    def write_tsv(name: str, headings: tuple, items: list) -> None:
        with (output / name).open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            writer.writerow(headings)
            writer.writerows(items)

    write_tsv("xenon_isa_fixture_v1.tsv",
              ("offset", "word_be", "expected_mnemonic", "sleigh_status",
               "variant", "decode_expectation"), samples)
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
        "Language specification SHA-256: " + tick + hashlib.sha256(
            (ROOT / "data/languages/xenon_64_be.slaspec").read_bytes()
        ).hexdigest() + tick,
        "Extra inventory SHA-256: " + tick + hashlib.sha256(
            extra_inventory_path.read_bytes()).hexdigest() + tick,
        "Unpack correction inventory SHA-256: " + tick + hashlib.sha256(
            correction_inventory_path.read_bytes()).hexdigest() + tick,
        "Generator SHA-256: " + tick + hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest() + tick,
        "",
        f"Families: **{len(rows)}**. Native p-code bodies: "
        f"**{counts['native-pcode']}**. Opaque custom userops: "
        f"**{counts['opaque-userop']}**. Missing: **{counts['missing']}**.",
        f"Fixture: **{len(samples)}** sample words, **{len(binary)}** bytes.",
        f"Expected decode: **{sum(row[5] == 'decode' for row in samples)}**; "
        f"reserved Rc=1 expected rejection: "
        f"**{sum(row[5] == 'reserved-rc1' for row in samples)}**.",
        "The Rc=1 distinction follows Cell Vector/SIMD PEM v2.07c",
        "X-form instruction diagrams; Xenon hardware behavior is unverified.",
        "",
        "This is source coverage only, NOT verified runtime decoding, and",
        "native SLEIGH p-code does not necessarily mean correct semantics.",
        "These include 76 pinned Xenia *128 families, eight opcode-31",
        "X-form variants, and two independently documented unpack",
        "halfword aliases missing from Xenia's generated decoder.",
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
    print("Expectations: decode=%d reserved-rc1=%d" % (
        sum(row[5] == "decode" for row in samples),
        sum(row[5] == "reserved-rc1" for row in samples)))
    print("Generated:", output)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", type=Path, default=INVENTORY)
    ap.add_argument("--extra-inventory", type=Path, default=EXTRA_INVENTORY)
    ap.add_argument("--correction-inventory", type=Path,
                    default=CORRECTION_INVENTORY)
    ap.add_argument("--sleigh", type=Path, default=SLEIGH)
    ap.add_argument("--out-dir", type=Path, default=OUTPUT)
    ap.add_argument("--xenia-lookup", type=Path,
                    help="Optional local Xenia decoder source to recheck "
                         "every pinned opcode selector")
    args = ap.parse_args()
    pinned_rows = (read_inventory(args.inventory) +
                   read_inventory(args.extra_inventory))
    # Corrections are NOT in Xenia's pinned generated decoder. Keep them
    # separate from the optional exact Xenia lookup comparison.
    rows = pinned_rows + read_inventory(args.correction_inventory)
    if args.xenia_lookup:
        actual = parse_xenia_lookup(args.xenia_lookup.read_text(encoding="utf-8"))
        expected = {r["mnemonic"]: (r["primary"], r["mask"], r["value"])
                    for r in pinned_rows}
        if actual != expected:
            missing = sorted(expected.keys() - actual.keys())
            added = sorted(actual.keys() - expected.keys())
            changed = sorted(name for name in actual.keys() & expected.keys()
                             if actual[name] != expected[name])
            raise SystemExit("Upstream selector difference: absent=" +
                             str(missing) + " added=" + str(added) +
                             " changed=" + str(changed))
        print("Verified against Xenia source: " + str(len(actual)) + " selectors")
    write_results(rows, args.sleigh, args.inventory, args.out_dir,
                  args.extra_inventory, args.correction_inventory)


if __name__ == "__main__":
    main()
