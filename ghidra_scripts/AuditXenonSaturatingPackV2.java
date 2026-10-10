// Execute representative native VMX128 saturating packs and verify VSCR.SAT.
// @category Xbox360
//
// Import build/xenon-isa-audit/xenon_isa_fixture_v1.bin into a disposable
// PowerPC:BE:64:XENON-32addr Program. Run this script, then select the sibling
// xenon_isa_fixture_v1.tsv manifest. The script does not edit a Ghidra database
// except for bounded disassembly of selected fixture instruction sites.
//
// Unlike AuditXenonIsaFixtureV1, this script executes native p-code and checks
// numerical results. It is NOT an assertion of full Xenon hardware equivalence
// or of unrelated IEEE floating-point behavior.

import java.io.BufferedReader;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class AuditXenonSaturatingPackV2 extends GhidraScript {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final BigInteger MASK128 =
        BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private static class Pack {
        final String name;
        final int inputBits;
        final int outputBits;
        final long positiveInput;
        final long positiveResult;
        final long negativeInput;
        final long negativeResult;

        Pack(String name, int inputBits, int outputBits,
             long positiveInput, long positiveResult,
             long negativeInput, long negativeResult) {
            this.name = name;
            this.inputBits = inputBits;
            this.outputBits = outputBits;
            this.positiveInput = positiveInput;
            this.positiveResult = positiveResult;
            this.negativeInput = negativeInput;
            this.negativeResult = negativeResult;
        }
    }

    private static final Pack[] CASES = {
        new Pack("vpkshss128", 16, 8, 0x0100, 0x7f, 0xfe00, 0x80),
        new Pack("vpkshus128", 16, 8, 0x0100, 0xff, 0xffff, 0x00),
        new Pack("vpkswss128", 32, 16, 0x00010000, 0x7fff,
                 0xfffe0000L, 0x8000),
        new Pack("vpkswus128", 32, 16, 0x00010000, 0xffff,
                 0xffffffffL, 0x0000),
        new Pack("vpkuhus128", 16, 8, 0x0100, 0xff, 0xffff, 0xff),
        new Pack("vpkuwus128", 32, 16, 0x00010000, 0xffff,
                 0xffffffffL, 0xffff),
    };

    private static BigInteger repeated(long lane, int laneBits) {
        BigInteger value = BigInteger.ZERO;
        BigInteger mask = BigInteger.ONE.shiftLeft(laneBits)
            .subtract(BigInteger.ONE);
        BigInteger unit = BigInteger.valueOf(lane).and(mask);
        for (int k = 0; k < 128 / laneBits; k++)
            value = value.shiftLeft(laneBits).or(unit);
        return value;
    }

    private Register operand(Instruction instruction, int index) {
        Object[] objects = instruction.getOpObjects(index);
        for (Object object : objects)
            if (object instanceof Register)
                return (Register) object;
        return null;
    }

    private String execute(Pack pack, Instruction instruction,
                           long sourceUnit, long expectedUnit,
                           long initialVSCR, boolean expectSAT)
            throws Exception {
        Register destination = operand(instruction, 0);
        Register left = operand(instruction, 1);
        Register right = operand(instruction, 2);
        if (destination == null || left == null || right == null) {
            return pack.name + ": missing decoded vector operand(s), "
                + instruction.toString();
        }

        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            BigInteger input = repeated(sourceUnit, pack.inputBits);
            emulator.writeRegister(left, input);
            emulator.writeRegister(right, input);
            emulator.writeRegister("xenonVSCR", initialVSCR);
            emulator.writeRegister(currentProgram.getLanguage().getProgramCounter(),
                                   instruction.getAddress().getOffset());

            if (!emulator.step(monitor))
                return pack.name + ": p-code execution failed at "
                    + instruction.getAddress() + ": "
                    + emulator.getLastError();

            BigInteger actual = emulator.readRegister(destination).and(MASK128);
            BigInteger expected = repeated(expectedUnit, pack.outputBits);
            long vscr = emulator.readRegister("xenonVSCR").longValue()
                        & 0xffffffffL;
            long expectedVSCR = initialVSCR | (expectSAT ? 1L : 0L);
            if (!actual.equals(expected) || vscr != expectedVSCR) {
                return pack.name + " at " + instruction.getAddress()
                    + ": expected vector=" + expected.toString(16)
                    + " vscr=" + Long.toHexString(expectedVSCR)
                    + ", actual vector=" + actual.toString(16)
                    + " vscr=" + Long.toHexString(vscr);
            }
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private static BigInteger laneVector(long[] values, int bits) {
        BigInteger mask = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
        BigInteger vector = BigInteger.ZERO;
        for (long value : values)
            vector = vector.shiftLeft(bits).or(BigInteger.valueOf(value).and(mask));
        return vector;
    }

    // Tests the VA and VB halves independently. Identical repeated operands
    // cannot expose lane permutation or accidental duplicate-source reads.
    private String executePattern(Pack pack, Instruction instruction,
                                  boolean saturating) throws Exception {
        Register destination = operand(instruction, 0);
        Register va = operand(instruction, 1);
        Register vb = operand(instruction, 2);
        if (destination == null || va == null || vb == null || va.equals(vb))
            return pack.name + ": patterned fixture must use distinct VA/VB";

        int half = 128 / pack.inputBits;
        long[] a = new long[half];
        long[] b = new long[half];
        long[] output = new long[2 * half];
        for (int i = 0; i < half; i++) {
            a[i] = i + 1;
            b[i] = i + 11;
            output[i] = a[i];
            output[half + i] = b[i];
        }
        if (saturating) {
            a[0] = pack.positiveInput;
            a[1] = pack.negativeInput;
            b[half - 1] = pack.positiveInput;
            output[0] = pack.positiveResult;
            output[1] = pack.negativeResult;
            output[2 * half - 1] = pack.positiveResult;
        }
        BigInteger expected = laneVector(output, pack.outputBits);
        long initialVSCR = 0x10000L;
        long expectedVSCR = initialVSCR | (saturating ? 1 : 0);
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            emulator.writeRegister(va, laneVector(a, pack.inputBits));
            emulator.writeRegister(vb, laneVector(b, pack.inputBits));
            emulator.writeRegister("xenonVSCR", initialVSCR);
            emulator.writeRegister(currentProgram.getLanguage().getProgramCounter(),
                                   instruction.getAddress().getOffset());
            if (!emulator.step(monitor))
                return pack.name + ": patterned p-code execution failed at "
                    + instruction.getAddress() + ": " + emulator.getLastError();
            BigInteger actual = emulator.readRegister(destination).and(MASK128);
            long vscr = emulator.readRegister("xenonVSCR").longValue()
                & 0xffffffffL;
            if (!expected.equals(actual) || vscr != expectedVSCR)
                return pack.name + " (" + (saturating ? "mixed SAT" : "in-range")
                    + ") at " + instruction.getAddress()
                    + ": expected vector=" + expected.toString(16)
                    + " vscr=" + Long.toHexString(expectedVSCR)
                    + ", actual vector=" + actual.toString(16)
                    + " vscr=" + Long.toHexString(vscr);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    @Override
    protected void run() throws Exception {
        String actualLanguage =
            currentProgram.getLanguage().getLanguageID().getIdAsString();
        if (!LANGUAGE.equals(actualLanguage)) {
            printerr("Expected language " + LANGUAGE + ", got " + actualLanguage);
            return;
        }
        if (currentProgram.getRegister("xenonVSCR") == null) {
            printerr("Installed language lacks xenonVSCR. Rebuild/reinstall "
                + "the current extension; do not interpret this as numeric failure.");
            return;
        }

        File manifest = askFile("Select xenon_isa_fixture_v1.tsv", "Open");
        Map<String, Address> addresses = new LinkedHashMap<>();
        Map<String, Address> patternAddresses = new LinkedHashMap<>();
        Address base = currentProgram.getMinAddress();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String heading = reader.readLine();
            if (heading == null ||
                !heading.startsWith("offset\tword_be\texpected_mnemonic\t")) {
                printerr("Incorrect fixture manifest: " + manifest);
                return;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 || !"decode".equals(columns[5]))
                    continue;
                long offset = Long.parseUnsignedLong(
                    columns[0].replaceFirst("^0x", ""), 16);
                addresses.putIfAbsent(columns[2], base.add(offset));
                if ("55".equals(columns[4]))
                    patternAddresses.putIfAbsent(columns[2], base.add(offset));
            }
        }

        int passed = 0;
        int failed = 0;
        java.util.List<String> problems = new java.util.ArrayList<>();
        for (Pack pack : CASES) {
            monitor.checkCancelled();
            Address address = addresses.get(pack.name);
            if (address == null) {
                problems.add(pack.name + ": no decode fixture entry");
                failed += 5;
                continue;
            }
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            if (instruction == null ||
                !pack.name.equalsIgnoreCase(instruction.getMnemonicString())) {
                problems.add(pack.name + ": fixture decoded incorrectly at " + address);
                failed += 5;
                continue;
            }
            // Positive and negative saturation both set SAT while retaining NJ.
            // An in-range pack never clears a preexisting sticky SAT.
            long[][] values = {
                {pack.positiveInput, pack.positiveResult, 0x10000, 1},
                {pack.negativeInput, pack.negativeResult, 0, 1},
                {1, 1, 1, 0},
            };
            for (long[] test : values) {
                monitor.checkCancelled();
                try {
                    String error = execute(pack, instruction,
                        test[0], test[1], test[2], test[3] != 0);
                    if (error != null) {
                        problems.add(error);
                        failed++;
                    }
                    else {
                        passed++;
                    }
                }
                catch (Exception error) {
                    problems.add(pack.name + " at " + address + ": " + error);
                    failed++;
                }
            }
            Address patternAddress = patternAddresses.get(pack.name);
            Instruction patterned = patternAddress == null
                ? null : getInstructionAt(patternAddress);
            if (patterned == null && patternAddress != null) {
                disassemble(patternAddress);
                patterned = getInstructionAt(patternAddress);
            }
            if (patterned == null ||
                !pack.name.equalsIgnoreCase(patterned.getMnemonicString())) {
                problems.add(pack.name + ": missing patterned fixture at "
                    + patternAddress);
                failed += 2;
                continue;
            }
            for (boolean saturating : new boolean[] {false, true}) {
                monitor.checkCancelled();
                try {
                    String error = executePattern(pack, patterned, saturating);
                    if (error == null) passed++;
                    else {
                        problems.add(error);
                        failed++;
                    }
                }
                catch (Exception error) {
                    problems.add(pack.name + " at " + patternAddress
                        + " (patterned): " + error);
                    failed++;
                }
            }
        }

        println("");
        println("============================================================");
        println("XENON NATIVE PACK NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + actualLanguage);
        println("Cases: " + (passed + failed) + "; passed: " + passed
            + "; failed: " + failed);
        println("Verified: 128-bit clipping, VA/VB lane order, and sticky VSCR SAT / NJ.");
        println("Numerical instruction cases only, not Xenon hardware equivalence.");
        println("");
        println("UNRESOLVED / INCORRECT STATES (" + problems.size() + ")");
        if (problems.isEmpty()) println("None");
        for (String problem : problems) println(problem);
    }
}
