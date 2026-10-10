// Audit the generated Xenia VMX128 fixture against the installed Xenon language.
// @category Xbox360
//
// Generate fixture:
//   python tools/audit_xenon_isa_coverage_v1.py
//
// Import build/xenon-isa-audit/xenon_isa_fixture_v1.bin as a flat binary
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

    private static class Family {
        String status;
        int pass;
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

        File manifest = askFile("Select xenon_isa_fixture_v1.tsv", "Open");
        Address base = currentProgram.getMinAddress();
        if (base == null) {
            printerr("Program has no mapped memory");
            return;
        }

        Map<String, Family> families = new LinkedHashMap<>();
        int checks = 0;
        int invalid = 0;
        int passes = 0;

        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null || !line.equals(
                    "offset\tword_be\texpected_mnemonic\tsleigh_status\tvariant")) {
                throw new IllegalArgumentException(
                    "Manifest header does not match fixture generator v1");
            }

            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                if (line.isBlank()) continue;
                String[] p = line.split("\t", -1);
                if (p.length != 5)
                    throw new IllegalArgumentException("Invalid manifest row: " + line);

                long offset = Long.parseUnsignedLong(p[0].replaceFirst("^0x", ""), 16);
                long word = Long.parseUnsignedLong(p[1], 16);
                String name = p[2];
                String status = p[3];
                String variant = p[4];
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
                if (instruction == null) {
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
                "; unreadable / byte mismatch: " + invalid);
        int full = 0;
        int partial = 0;
        int absent = 0;
        int mismatched = 0;
        for (Map.Entry<String, Family> entry : families.entrySet()) {
            Family f = entry.getValue();
            if (f.pass == 4) full++;
            else if (f.pass != 0) partial++;
            else if (f.mismatch != 0) mismatched++;
            else absent++;
        }
        println("Families: " + families.size() + "; 4/4 decoded: " + full +
                "; partially decoded: " + partial +
                "; no expected mnemonic: " + absent +
                "; wrong-mnemonic-only: " + mismatched);
        println("");
        println("==============================================================");
        println("UNRESOLVED / INCORRECT STATES (" + (checks - passes) + " samples)");
        println("==============================================================");
        if (checks == passes) {
            println("None (mnemonics only; numerical p-code semantics not audited)");
        }
        else {
            for (Map.Entry<String, Family> entry : families.entrySet()) {
                Family f = entry.getValue();
                if (f.problems.isEmpty()) continue;
                println(entry.getKey() + " [" + f.status + "]" +
                        " pass=" + f.pass + "/4");
                for (String problem : f.problems)
                    println("  " + problem);
            }
        }
        println("This is a mnemonic decode test, NOT a test of numerical p-code.");
        println("==============================================================");
    }
}
