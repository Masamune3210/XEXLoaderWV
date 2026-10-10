// Audit the generated Xenia VMX128 fixture against the installed Xenon language.
// @category Xbox360
//
// The Gradle extension build regenerates the fixture automatically:
//   gradle buildExtension
//
// Import XEXLoaderWV/build/xenon-isa-audit/xenon_isa_fixture_v1.bin as a flat binary
// with PowerPC:BE:64:XENON-32addr, big endian. Run this script in that
// Program and select the generated xenon_isa_fixture_v1.tsv.
//
// The only database mutation is bounded disassembly of 4-byte instruction
// sites in the disposable fixture Program. No source XEX/kernel files,
// bytes, signatures, or function bodies are changed.

import java.io.BufferedReader;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

public class AuditXenonIsaFixtureV1 extends GhidraScript {

    private static final String XENON = "PowerPC:BE:64:XENON-32addr";
    private static final String FIXTURE_TSV = "xenon_isa_fixture_v1.tsv";
    private static final String COVERAGE_TSV = "xenon_isa_coverage_v1.tsv";
    private static final String FIXTURE_HEADER =
        "offset\tword_be\texpected_mnemonic\tsleigh_status\tvariant\tdecode_expectation";


    private static class Family {
        String status;
        int pass;
        int reservedPass;
        int badBytes;
        int missing;
        int mismatch;
        List<String> problems = new ArrayList<>();
        Family(String status) { this.status = status; }
    }

    @Override
    protected void run() throws Exception {
        String language = currentProgram.getLanguage().getLanguageID().getIdAsString();
        if (!XENON.equals(language)) {
            printerr("Xenon ISA fixture audit requires " + XENON +
                     ", current Program language is " + language);
            return;
        }

        File manifest = askFile("Select " + FIXTURE_TSV, "Open");
        // The generator writes two TSVs next to each other. If the coverage
        // table was selected, use its sibling fixture manifest instead.
        if (COVERAGE_TSV.equals(manifest.getName())) {
            File fixture = new File(manifest.getParentFile(), FIXTURE_TSV);
            if (!fixture.isFile()) {
                printerr("Selected coverage table: " + manifest.getAbsolutePath());
                printerr("Expected sibling fixture manifest was not found: " +
                         fixture.getAbsolutePath());
                return;
            }
            println("Selected the coverage TSV; using sibling fixture manifest: " +
                    fixture.getAbsolutePath());
            manifest = fixture;
        }

        Address base = currentProgram.getMinAddress();
        if (base == null) {
            printerr("Program has no mapped memory");
            return;
        }

        Map<String, Family> families = new LinkedHashMap<>();
        int checks = 0;
        int invalid = 0;
        int passes = 0;
        int reservedPasses = 0;

        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            // Python's csv.writer emits UTF-8 without a BOM, but a TSV
            // saved through another editor can acquire a UTF-8 BOM.
            if (line != null && !line.isEmpty() && line.charAt(0) == '\uFEFF') {
                line = line.substring(1);
            }
            if (!FIXTURE_HEADER.equals(line)) {
                printerr("Invalid Xenon fixture manifest: " +
                         manifest.getAbsolutePath());
                printerr("Expected header: " + FIXTURE_HEADER);
                printerr("Actual header:   " +
                         (line == null ? "<empty file>" : line));
                printerr("Select build/xenon-isa-audit/" + FIXTURE_TSV +
                         " (not " + COVERAGE_TSV + ").");
                return;
            }

            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                if (line.isBlank()) continue;
                String[] p = line.split("\t", -1);
                if (p.length != 6)
                    throw new IllegalArgumentException("Invalid manifest row: " + line);

                long offset = Long.parseUnsignedLong(p[0].replaceFirst("^0x", ""), 16);
                long word = Long.parseUnsignedLong(p[1], 16);
                String name = p[2];
                String status = p[3];
                String variant = p[4];
                String expectation = p[5];
                if (!"decode".equals(expectation) &&
                    !"reserved-rc1".equals(expectation)) {
                    throw new IllegalArgumentException(
                        "Unexpected decode expectation: " + expectation);
                }
                if ("reserved-rc1".equals(expectation) && (word & 1L) == 0) {
                    throw new IllegalArgumentException(
                        "Reserved-rc1 sample has Rc=0: " + line);
                }
                Family family = families.computeIfAbsent(name, key -> new Family(status));
                if (!family.status.equals(status))
                    throw new IllegalArgumentException("Inconsistent family status: " + name);

                checks++;
                Address address = base.add(offset);
                byte[] bytes = new byte[4];
                try {
                    if (currentProgram.getMemory().getBytes(address, bytes) != 4)
                        throw new MemoryAccessException("Short instruction word");
                }
                catch (Exception error) {
                    family.badBytes++;
                    invalid++;
                    family.problems.add(address + " " + variant +
                                        " could not read 4 bytes: " + error);
                    continue;
                }
                long actualWord = ((long) (bytes[0] & 0xff) << 24) |
                                  ((long) (bytes[1] & 0xff) << 16) |
                                  ((long) (bytes[2] & 0xff) << 8) |
                                  (long) (bytes[3] & 0xff);
                if (actualWord != word) {
                    family.badBytes++;
                    invalid++;
                    family.problems.add(String.format(
                        "%s %s incorrect bytes expected=%08X got=%08X",
                        address, variant, word, actualWord));
                    continue;
                }

                Instruction instruction = getInstructionAt(address);
                if (instruction == null) {
                    // Attempt to decode only this fixture address. Missing
                    // SLEIGH constructors are reported, not fabricated.
                    disassemble(address);
                    instruction = getInstructionAt(address);
                }
                if ("reserved-rc1".equals(expectation)) {
                    if (instruction == null) {
                        family.reservedPass++;
                        reservedPasses++;
                    }
                    else {
                        family.mismatch++;
                        family.problems.add(address + " " + variant +
                                            " reserved Rc=1 decoded as " +
                                            instruction.getMnemonicString());
                    }
                }
                else if (instruction == null) {
                    family.missing++;
                    family.problems.add(address + " " + variant +
                                        " no instruction; expected " + name);
                }
                else if (!name.equalsIgnoreCase(instruction.getMnemonicString())) {
                    family.mismatch++;
                    family.problems.add(address + " " + variant + " decoded " +
                                        instruction.getMnemonicString() +
                                        " instead of " + name);
                }
                else {
                    family.pass++;
                    passes++;
                }
            }
        }

        println("");
        println("==============================================================");
        println("XENON ISA FIXTURE AUDIT (Ghidra runtime, 4 variants per family)");
        println("==============================================================");
        println("Language: " + language);
        println("Samples: " + checks + "; correct mnemonic: " + passes +
                "; correctly rejected reserved Rc=1: " + reservedPasses +
                "; unreadable / byte mismatch: " + invalid);
        int full = 0;
        int partial = 0;
        int absent = 0;
        int mismatched = 0;
        for (Map.Entry<String, Family> entry : families.entrySet()) {
            Family f = entry.getValue();
            int success = f.pass + f.reservedPass;
            if (success == 4) full++;
            else if (success != 0) partial++;
            else if (f.mismatch != 0) mismatched++;
            else absent++;
        }
        println("Families: " + families.size() + "; 4/4 expectations met: " + full +
                "; partially met: " + partial +
                "; no expectation met: " + absent +
                "; wrong-mnemonic-only: " + mismatched);
        println("");
        println("==============================================================");
        int unresolved = checks - passes - reservedPasses;
        println("UNRESOLVED / INCORRECT STATES (" + unresolved + " samples)");
        println("==============================================================");
        if (unresolved == 0) {
            println("None (mnemonics only; numerical p-code semantics not audited)");
        }
        else {
            for (Map.Entry<String, Family> entry : families.entrySet()) {
                Family f = entry.getValue();
                if (f.problems.isEmpty()) continue;
                println(entry.getKey() + " [" + f.status + "]" +
                        " correct-decode=" + f.pass + "/4" +
                        " correct-reserved-reject=" + f.reservedPass + "/4");
                for (String problem : f.problems)
                    println("  " + problem);
            }
        }
        println("Reserved Rc=1 expectations follow the Cell X-form encoding;");
        println("Xenon hardware validity remains independently unverified.");
        println("This tests decoding, NOT numerical p-code semantics.");
        println("==============================================================");
    }
}
