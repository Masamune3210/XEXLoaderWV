// Consolidated Xenon native numerical p-code audit: packs, D3D unpack and guarded FP.
// @category Xbox360
//
// A single stable script name. Run in the disposable Xenon ISA fixture,
// select xenon_isa_fixture_v1.tsv once, and receive all numerical diagnostics.
// Program bytes are never changed; probes use EmulatorHelper private memory.
//
// Run in a disposable PowerPC:BE:64:XENON-32addr Program made from
// build/xenon-isa-audit/xenon_isa_fixture_v1.bin. Select the sibling
// xenon_isa_fixture_v1.tsv when prompted.
//
// 12 scalar packing cases x 2 opcode variants x 4 immediate low bits = 96.
// The existing 344-word mnemonic fixture is verified but its operands alias.
// This audit injects numerical probes only into an EmulatorHelper's private
// instruction memory. The Ghidra Program bytes and original fixture stay intact.
// Types 3, 5, 6 and 7 retain CALL_OTHER: NO numeric result is claimed for them.

import java.io.BufferedReader;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.emulator.DefaultEmulator;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class AuditXenonNumericalPcode extends GhidraScript {
    private final List<String> combinedProblems = new ArrayList<>();
    private int combinedPassed = 0;
    private int combinedFailed = 0;

    private void recordSuite(String suite, int passed, int failed,
                             List<String> problems) {
        combinedPassed += passed;
        combinedFailed += failed;
        for (String problem : problems)
            combinedProblems.add(suite + ": " + problem);
    }

    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final long SELECTOR_MASK = 0xfc0007f0L;
    private static final long SELECTOR_VALUE = 0x180007f0L;
    private static final long FP_SELECTOR_MASK = 0xfc0003d0L;
    private static final int SOURCE_BOUND = 2048;
    private static final int EXACT_BOUND = 1 << 24;
    private static final BigInteger MASK128 =
        BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    private static final BigInteger UPPER64 =
        new BigInteger("1122334455667788", 16);
    private static final BigInteger PADDING32 =
        new BigInteger("a5c3719b", 16);

    private static final class TestCase {
        final String label;
        final int format;
        final long packed;
        final long[] expected;

        TestCase(String label, int format, long packed, long... expected) {
            this.label = label;
            this.format = format;
            this.packed = packed;
            this.expected = expected;
            if (expected.length != 4)
                throw new IllegalArgumentException("expected four 32-bit words");
        }
    }

    // Oracles are fixed IEEE-754 bit patterns from packed integer input,
    // not Java floating-point arithmetic, to retain the exact NaN sentinels.
    // Unpack outputs are ordered from highest to lowest 32-bit vector word.
    private static final TestCase[] CASES = {
        new TestCase("color rgba 01020304", 0, 0x04010203L,
            0x3f800001L, 0x3f800002L, 0x3f800003L, 0x3f800004L),
        new TestCase("color rgba 50607080", 0, 0x80506070L,
            0x3f800050L, 0x3f800060L, 0x3f800070L, 0x3f800080L),
        new TestCase("color all ff", 0, 0xffffffffL,
            0x3f8000ffL, 0x3f8000ffL, 0x3f8000ffL, 0x3f8000ffL),

        new TestCase("short2 positive", 1, 0x00010002L,
            0x40400001L, 0x40400002L, 0L, 0x3f800000L),
        new TestCase("short2 negative and overflow", 1, 0x8000ffffL,
            0x7fc00000L, 0x403fffffL, 0L, 0x3f800000L),
        new TestCase("short2 positive limit and overflow", 1, 0x7fff8000L,
            0x40407fffL, 0x7fc00000L, 0L, 0x3f800000L),

        new TestCase("2101010 positive and alpha3", 2, 0xc0300801L,
            0x40400001L, 0x40400002L, 0x40400003L, 0x3f800003L),
        new TestCase("2101010 negative and alpha2", 2, 0xbfdffbffL,
            0x403fffffL, 0x403ffffeL, 0x403ffffdL, 0x3f800002L),
        new TestCase("2101010 sentinels and signed max", 2, 0x5ff80200L,
            0x7fc00000L, 0x7fc00000L, 0x404001ffL, 0x3f800001L),

        new TestCase("short4 positive", 4, 0x0001000200030004L,
            0x40400001L, 0x40400002L, 0x40400003L, 0x40400004L),
        new TestCase("short4 signed limits", 4, 0xffff80007fff0000L,
            0x403fffffL, 0x7fc00000L, 0x40407fffL, 0x40400000L),
        new TestCase("short4 four NaNs", 4, 0x8000800080008000L,
            0x7fc00000L, 0x7fc00000L, 0x7fc00000L, 0x7fc00000L),
    };

    private static byte[] beWord(long word) {
        return new byte[] {
            (byte) (word >>> 24), (byte) (word >>> 16),
            (byte) (word >>> 8), (byte) word,
        };
    }

    private Register vector(String name) {
        Register register = currentProgram.getRegister(name);
        if (register == null || register.getBitLength() != 128)
            throw new IllegalArgumentException(
                "Missing Xenon 128-bit register " + name);
        return register;
    }

    private static BigInteger expected(TestCase test) {
        BigInteger result = BigInteger.ZERO;
        for (long word : test.expected) {
            if ((word & ~0xffffffffL) != 0)
                throw new IllegalArgumentException(
                    "Expected lane outside 32-bit range: " + test.label);
            result = result.shiftLeft(32).or(BigInteger.valueOf(word));
        }
        return result;
    }

    private static BigInteger source(TestCase test) {
        BigInteger low;
        if (test.format == 4) {
            low = new BigInteger(Long.toHexString(test.packed), 16);
        }
        else {
            low = PADDING32.shiftLeft(32).or(
                BigInteger.valueOf(test.packed & 0xffffffffL));
        }
        return UPPER64.shiftLeft(64).or(low).and(MASK128);
    }

    // Five immediate bits A_BITS occupy bits [16..20] of the PPC word.
    // The D3D type is IMM >> 2. The bottom two immediate bits are not
    // interpreted by the native format implementation.
    //
    // Opcode low bit 3 selects the high destination bank: 0 -> vs33,
    // 1 -> xv65. We keep the source in vs35 and the destination separate.
    private static long syntheticWord(int format, int immediateLow, int bank) {
        long word = SELECTOR_VALUE |
            (1L << 21) | (3L << 11) |
            (((long) ((format << 2) | immediateLow)) << 16) |
            (((long) bank) << 3);
        if ((word & SELECTOR_MASK) != SELECTOR_VALUE)
            throw new IllegalArgumentException(
                "Unpack probe does not preserve opcode selector");
        return word;
    }

    private static String hex128(BigInteger value) {
        String s = value.and(MASK128).toString(16);
        StringBuilder result = new StringBuilder(32);
        for (int i = s.length(); i < 32; i++)
            result.append('0');
        return result.append(s).toString();
    }

    private static String header(TestCase test, int bank, int immediateLow,
                                 long word) {
        return test.label + " fmt=" + test.format +
            " bank=" + bank + " immediateLow=" + immediateLow +
            " instruction=" + String.format("%08X", word);
    }

    private String execute(TestCase test, Address address, int bank,
                           int immediateLow) throws Exception {
        long word = syntheticWord(test.format, immediateLow, bank);
        String label = header(test, bank, immediateLow, word);
        Register destination = vector(bank == 0 ? "vs33" : "xv65");
        Register sourceRegister = vector("vs35");
        BigInteger input = source(test);
        BigInteger wanted = expected(test);
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] bytes = beWord(word);
            emulator.writeMemory(address, bytes);
            if (!Arrays.equals(bytes, emulator.readMemory(address, 4)))
                return label + ": emulator-private instruction mismatch";
            emulator.writeRegister(sourceRegister, input);
            emulator.writeRegister(destination, MASK128);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            if (!emulator.step(monitor))
                return label + ": p-code step failed: " +
                    emulator.getLastError();
            BigInteger actual =
                emulator.readRegister(destination).and(MASK128);
            if (!wanted.equals(actual))
                return label + ": expected=" + hex128(wanted) +
                    " actual=" + hex128(actual) +
                    " source=" + hex128(input);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private boolean originalFixtureMatches(Address address, long word)
            throws Exception {
        byte[] actual = new byte[4];
        if (currentProgram.getMemory().getBytes(address, actual) != 4)
            return false;
        return Arrays.equals(actual, beWord(word));
    }

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

    private static final Pack[] PACK_CASES = {
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

    // Xenon SLEIGH subtable operands display as vsNN/xvNN but Ghidra's
    // getOpObjects() does not necessarily expose their exported Registers.
    // Resolve only exact, existing 128-bit register names from the decoded
    // operand representation. Never infer a register from an opcode field.
    private Register operand(Instruction instruction, int index) {
        if (index < 0 || index >= instruction.getNumOperands())
            return null;
        Object[] objects = instruction.getOpObjects(index);
        if (objects != null) {
            for (Object object : objects) {
                if (object instanceof Register) {
                    Register register = (Register) object;
                    if (register.getBitLength() == 128)
                        return register;
                }
            }
        }
        String rendered = instruction.getDefaultOperandRepresentation(index);
        if (rendered == null)
            return null;
        rendered = rendered.trim();
        if (!rendered.matches("(?:vs|xv)[0-9]{1,3}"))
            return null;
        Register register = currentProgram.getRegister(rendered);
        return register != null && register.getBitLength() == 128
            ? register : null;
    }

    private Register requireVectorRegister(String name) {
        Register register = currentProgram.getRegister(name);
        if (register == null || register.getBitLength() != 128)
            throw new IllegalArgumentException(
                "Missing 128-bit Xenon register " + name);
        return register;
    }

    private static long independentPackWord(long original) {
        return (original & 0xfc0003d0L) |
            (1L << 21) | (2L << 16) | (3L << 11);
    }

    private String execute(Pack pack, Instruction instruction,
                           long sourceUnit, long expectedUnit,
                           long initialVSCR, boolean expectSAT)
            throws Exception {
        Register destination = operand(instruction, 0);
        Register left = operand(instruction, 1);
        Register right = operand(instruction, 2);
        if (destination == null || left == null || right == null) {
            return pack.name + ": unresolved 128-bit operand(s) in "
                + instruction + " [0=" +
                instruction.getDefaultOperandRepresentation(0) +
                ", 1=" + instruction.getDefaultOperandRepresentation(1) +
                ", 2=" + instruction.getDefaultOperandRepresentation(2) +
                "]; getOpObjects() may omit SLEIGH subtable exports";
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
    private String executePattern(Pack pack, Address address,
                                  long sourceWord, boolean saturating)
            throws Exception {
        Register destination = requireVectorRegister("vs33");
        Register va = requireVectorRegister("vs34");
        Register vb = requireVectorRegister("vs35");
        long syntheticWord = independentPackWord(sourceWord);
        if ((syntheticWord & 0xfc0003d0L) != (sourceWord & 0xfc0003d0L))
            return pack.name + ": numerical opcode selector mismatch";

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
            byte[] syntheticBytes = beWord(syntheticWord);
            emulator.writeMemory(address, syntheticBytes);
            if (!java.util.Arrays.equals(
                    syntheticBytes, emulator.readMemory(address, 4)))
                return pack.name + ": emulator-private opcode injection failed "
                    + Long.toHexString(syntheticWord);
            emulator.writeRegister(destination, MASK128);
            emulator.writeRegister(va, laneVector(a, pack.inputBits));
            emulator.writeRegister(vb, laneVector(b, pack.inputBits));
            emulator.writeRegister("xenonVSCR", initialVSCR);
            emulator.writeRegister(currentProgram.getLanguage().getProgramCounter(),
                                   address.getOffset());
            if (!emulator.step(monitor))
                return pack.name + ": patterned p-code execution failed at "
                    + address + " (emulated word "
                    + Long.toHexString(syntheticWord) + "): "
                    + emulator.getLastError();
            BigInteger actual = emulator.readRegister(destination).and(MASK128);
            if (actual.equals(MASK128))
                return pack.name + " at " + address +
                    ": patched instruction did not change destination vs33; " +
                    "check whether this Ghidra emulator decodes its private " +
                    "memory rather than the Program listing; emulated word=" +
                    Long.toHexString(syntheticWord);
            long vscr = emulator.readRegister("xenonVSCR").longValue()
                & 0xffffffffL;
            if (!expected.equals(actual) || vscr != expectedVSCR)
                return pack.name + " (" + (saturating ? "mixed SAT" : "in-range")
                    + ") at " + address + " word="
                    + Long.toHexString(syntheticWord)
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

    // Refuse to execute stale or mismatched fixture manifests. All four
    // instruction bytes must match the word selected by the TSV.
    private boolean fixtureWordMatches(Address address, Long word)
            throws Exception {
        if (address == null || word == null) return false;
        byte[] actual = new byte[4];
        if (currentProgram.getMemory().getBytes(address, actual) != 4)
            return false;
        long decoded = 0;
        for (byte b : actual)
            decoded = (decoded << 8) | (b & 0xffL);
        return decoded == word.longValue();
    }

    private void runSaturatingPacks(File manifest, Address base) throws Exception {
        String actualLanguage = LANGUAGE;
        if (currentProgram.getRegister("xenonVSCR") == null) {
            printerr("Missing xenonVSCR; pack numerical audit skipped.");
            return;
        }
        Map<String, Address> addresses = new LinkedHashMap<>();
        Map<String, Address> patternAddresses = new LinkedHashMap<>();
        Map<Address, Long> fixtureWords = new LinkedHashMap<>();
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
                Address site = base.add(offset);
                fixtureWords.put(site, Long.parseUnsignedLong(columns[1], 16));
                addresses.putIfAbsent(columns[2], site);
                if ("55".equals(columns[4]))
                    patternAddresses.putIfAbsent(columns[2], site);
            }
        }

        int passed = 0;
        int failed = 0;
        java.util.List<String> problems = new java.util.ArrayList<>();
        for (Pack pack : PACK_CASES) {
            monitor.checkCancelled();
            Address address = addresses.get(pack.name);
            if (address == null || !fixtureWordMatches(address, fixtureWords.get(address))) {
                problems.add(pack.name + ": missing/byte-mismatched decode fixture entry");
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
            if (!fixtureWordMatches(patternAddress, fixtureWords.get(patternAddress)) ||
                patterned == null ||
                !pack.name.equalsIgnoreCase(patterned.getMnemonicString())) {
                problems.add(pack.name + ": missing patterned fixture at "
                    + patternAddress);
                failed += 2;
                continue;
            }
            for (boolean saturating : new boolean[] {false, true}) {
                monitor.checkCancelled();
                try {
                    String error = executePattern(pack, patternAddress,
                        fixtureWords.get(patternAddress), saturating);
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
        println("Checked: 128-bit clipping, independent VA/VB lane order, "
            + "and sticky VSCR SAT / NJ (only passed cases are verified).");
        println("Pattern probes patch emulator-private instruction bytes only; "
            + "the Program fixture bytes are unchanged.");
        println("Numerical instruction cases only, not Xenon hardware equivalence.");
        println("");
        println("Unresolved details follow in the combined result below.");
        recordSuite("PACK", passed, failed, problems);
    }

    private static final class Family {
        final String name;
        final long selector;
        final int formula;

        Family(String name, long selector, int formula) {
            this.name = name;
            this.selector = selector;
            this.formula = formula;
        }
    }

    // Pinned Xenia VMX128 semantics:
    // 0: vmaddfp128  -> (A * B) + old D
    // 1: vmaddcfp128 -> (A * old D) + B
    // 2: vnmsubfp128 -> old D - (A * B)
    private static final Family[] FAMILIES = {
        new Family("vmaddfp128", 0x140000d0L, 0),
        new Family("vmaddcfp128", 0x14000110L, 1),
        new Family("vnmsubfp128", 0x14000150L, 2),
    };

    private static final class Pattern {
        final String name;
        final int[] a;
        final int[] b;
        final int[] oldD;

        Pattern(String name, int[] a, int[] b, int[] oldD) {
            this.name = name;
            this.a = a;
            this.b = b;
            this.oldD = oldD;
            if (a.length != 4 || b.length != 4 || oldD.length != 4)
                throw new IllegalArgumentException("Expected four vector lanes");
        }
    }

    // Each four-element array is ordered low-to-high register lanes,
    // corresponding to xenonA(0), xenonA(4), xenonA(8), xenonA(12).
    private static final Pattern[] PATTERNS = {
        new Pattern("mixed-sign",
            new int[] { 2, -3, 4, -5 },
            new int[] { 7, 6, -8, 9 },
            new int[] { 11, 13, -17, 19 }),
        new Pattern("ascending",
            new int[] { 1, 2, 3, 4 },
            new int[] { 5, 6, 7, 8 },
            new int[] { 9, 10, 11, 12 }),
        new Pattern("native-guard-boundaries",
            new int[] { 2048, -2048, 1024, -1024 },
            new int[] { 1, -1, 2, -2 },
            new int[] { 1, 3, -5, 7 }),
        new Pattern("sign-and-limits",
            new int[] { -1, 1, -2048, 2048 },
            new int[] { -2048, 2048, -1, 1 },
            new int[] { 127, -127, 5, -5 }),
        new Pattern("asymmetric",
            new int[] { 31, 17, -23, -47 },
            new int[] { 19, -29, 13, 11 },
            new int[] { -101, 103, 107, -109 }),
        new Pattern("alternating",
            new int[] { -7, 11, 13, -17 },
            new int[] { 19, 23, -29, -31 },
            new int[] { 37, -41, 43, -47 }),
    };

    private static BigInteger vector(int[] lanes) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 3; i >= 0; i--) {
            int input = lanes[i];
            if (input == 0 || Math.abs(input) > SOURCE_BOUND)
                throw new IllegalArgumentException(
                    "Outside nonzero integral native guard: " + input);
            long bits = Float.floatToRawIntBits((float) input) & 0xffffffffL;
            result = result.shiftLeft(32).or(BigInteger.valueOf(bits));
        }
        return result;
    }

    private static BigInteger output(Family family, Pattern pattern) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 3; i >= 0; i--) {
            long a = pattern.a[i], b = pattern.b[i], d = pattern.oldD[i];
            long exact;
            if (family.formula == 0) exact = a * b + d;
            else if (family.formula == 1) exact = a * d + b;
            else if (family.formula == 2) exact = d - a * b;
            else throw new IllegalArgumentException("Unknown formula");
            if (exact == 0 || Math.abs(exact) >= EXACT_BOUND)
                throw new IllegalArgumentException(
                    "Output not guarded exact nonzero integer: " + exact);
            long bits = Float.floatToRawIntBits((float) exact) & 0xffffffffL;
            result = result.shiftLeft(32).or(BigInteger.valueOf(bits));
        }
        return result;
    }

    private Register vectorRegister(String name) {
        Register register = currentProgram.getRegister(name);
        if (register == null || register.getBitLength() != 128)
            throw new IllegalArgumentException(
                "Missing Xenon 128-bit register " + name);
        return register;
    }

    private static byte[] wordBytes(long word) {
        return new byte[] {
            (byte) (word >>> 24), (byte) (word >>> 16),
            (byte) (word >>> 8), (byte) word,
        };
    }

    // BITS_4_5=1/3 and BITS_6_10=3/19 (or 4/20, 5/21).
    // Bits 5 and 10 encode high VA register bits, NOT ignored opcode bits.
    // VD=vs33 and VB=vs35 remain fixed. VA occupies four different banks.
    // These cases test the identical native semantics across all four banks.
    private static String guardedFpSourceAName(int variant) {
        if ((variant & ~3) != 0)
            throw new IllegalArgumentException("Invalid FP variant " + variant);
        // bit 5 = MBH; bit 10 = OE, see xenonA in xenon_vector_v1.sinc.
        String[] names = { "vs34", "xv34", "xv66", "xv98" };
        return names[variant];
    }

    private static long probeWord(Family family, int variant) {
        long word = family.selector | (1L << 21) | (2L << 16) |
            (3L << 11) | ((long) (variant & 1) << 5) |
            ((long) (variant & 2) << 9);
        if ((word & FP_SELECTOR_MASK) != family.selector ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3 ||
                ((word >>> 5) & 1) != (variant & 1) ||
                ((word >>> 10) & 1) != ((variant >>> 1) & 1))
            throw new IllegalArgumentException(
                "FP opcode selector / extended A register fields changed");
        return word;
    }

    private String execute(Family family, Pattern pattern, Address address,
                           int variant) throws Exception {
        long word = probeWord(family, variant);
        String label = family.name + " " + pattern.name +
            " variant=" + variant + " A=" +
            guardedFpSourceAName(variant) +
            " word=" + String.format("%08X", word);
        Register destination = vectorRegister("vs33");
        Register a = vectorRegister(guardedFpSourceAName(variant));
        Register b = vectorRegister("vs35");
        BigInteger inputA = vector(pattern.a);
        BigInteger inputB = vector(pattern.b);
        BigInteger initialD = vector(pattern.oldD);
        BigInteger wanted = output(family, pattern);

        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] op = wordBytes(word);
            emulator.writeMemory(address, op);
            if (!Arrays.equals(op, emulator.readMemory(address, 4)))
                return label + ": emulator-private opcode mismatch";
            emulator.writeRegister(a, inputA);
            emulator.writeRegister(b, inputB);
            emulator.writeRegister(destination, initialD);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            if (!emulator.step(monitor))
                return label + ": emulator step failed: " +
                    emulator.getLastError();
            BigInteger actual =
                emulator.readRegister(destination).and(MASK128);
            BigInteger afterA = emulator.readRegister(a).and(MASK128);
            BigInteger afterB = emulator.readRegister(b).and(MASK128);
            if (!wanted.equals(actual) ||
                    !inputA.equals(afterA) || !inputB.equals(afterB))
                return label +
                    ": expectedD=" + hex128(wanted) +
                    " actualD=" + hex128(actual) +
                    " expectedA=" + hex128(inputA) +
                    " actualA=" + hex128(afterA) +
                    " expectedB=" + hex128(inputB) +
                    " actualB=" + hex128(afterB);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private boolean fixtureMatches(Address address, long word)
            throws Exception {
        byte[] bytes = new byte[4];
        if (currentProgram.getMemory().getBytes(address, bytes) != 4)
            return false;
        return Arrays.equals(bytes, wordBytes(word));
    }

    private void runGuardedFp(File manifest, Address base) throws Exception {
        String language = LANGUAGE;
        Map<String, Address> sites = new LinkedHashMap<>();
        Map<String, Long> sourceWords = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String heading = reader.readLine();
            if (heading == null ||
                    !heading.startsWith("offset\tword_be\texpected_mnemonic\t")) {
                printerr("Invalid Xenon ISA fixture manifest: " + manifest);
                return;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 || !"decode".equals(columns[5]))
                    continue;
                for (Family family : FAMILIES) {
                    if (family.name.equals(columns[2]) &&
                            !sites.containsKey(family.name)) {
                        long offset = Long.parseUnsignedLong(
                            columns[0].replaceFirst("^0x", ""), 16);
                        sites.put(family.name, base.add(offset));
                        sourceWords.put(family.name,
                            Long.parseUnsignedLong(columns[1], 16));
                    }
                }
            }
        }
        for (Family family : FAMILIES) {
            Address address = sites.get(family.name);
            Long word = sourceWords.get(family.name);
            if (address == null || word == null ||
                    (word & FP_SELECTOR_MASK) != family.selector ||
                    !fixtureMatches(address, word)) {
                printerr(family.name +
                    ": missing or incorrect original fixture words");
                return;
            }
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            if (instruction == null ||
                    !family.name.equalsIgnoreCase(
                        instruction.getMnemonicString())) {
                printerr(family.name + ": invalid fixture mnemonic at " +
                    address + ": " + (instruction == null ?
                    "<missing>" : instruction.getMnemonicString()));
                return;
            }
        }

        int passed = 0;
        int failed = 0;
        List<String> problems = new ArrayList<>();
        for (Family family : FAMILIES) {
            Address address = sites.get(family.name);
            for (int variant = 0; variant < 4; variant++) {
                for (Pattern pattern : PATTERNS) {
                    monitor.checkCancelled();
                    try {
                        String error = execute(family, pattern,
                            address, variant);
                        if (error == null) passed++;
                        else {
                            problems.add(error);
                            failed++;
                        }
                    }
                    catch (Exception error) {
                        problems.add(family.name + " " + pattern.name +
                            " variant=" + variant + ": " + error);
                        failed++;
                    }
                }
            }
        }

        println("");
        println("============================================================");
        println("XENON GUARDED FP NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + language);
        println("Cases: " + (passed + failed) +
            "; passed: " + passed + "; failed: " + failed);
        println("Families: vmaddfp128 (A*B+D), vmaddcfp128 (A*D+B), " +
            "vnmsubfp128 (D-A*B).");
        println("Dimensions: four instruction variants; six distinct " +
            "four-lane inputs per family.");
        println("Only exact nonzero integral binary32 paths are tested;");
        println("opaque userop fallback, fused rounding and exceptional " +
            "FP behavior remain unverified.");
        println("Original decoder fixture Program bytes were not changed.");
        println("");
        println("Unresolved details follow in the combined result below.");
        recordSuite("GUARDED-FP", passed, failed, problems);
    }


    // Audits independent byte-accurate oracle implementations for two
    // otherwise untested native Xenon shuffle families. Both operations
    // use bit 5 (MBH) and bit 10 (OE) to extend the VA register index.
    private static BigInteger vectorFromBytes(byte[] bytes) {
        if (bytes.length != 16)
            throw new IllegalArgumentException("Expected a 16-byte vector");
        BigInteger value = BigInteger.ZERO;
        for (byte b : bytes)
            value = value.shiftLeft(8).or(
                BigInteger.valueOf(b & 0xffL));
        return value;
    }

    private static byte[] shuffleInput(int which, int pattern) {
        byte[] bytes = new byte[16];
        int start = pattern == 0 ? (which == 0 ? 0x10 : 0xa0)
                                 : (which == 0 ? 0x80 : 0x05);
        int step = pattern == 0 ? (which == 0 ? 1 : -1)
                                : (which == 0 ? 7 : 11);
        for (int i = 0; i < 16; i++)
            bytes[i] = (byte) (start + i * step);
        return bytes;
    }

    private static byte[] shuffleControl(int pattern) {
        byte[] bytes = new byte[16];
        for (int i = 0; i < 16; i++) {
            int c;
            switch (pattern) {
                case 0: c = i; break;                         // A identity
                case 1: c = 0x10 | i; break;                  // B identity
                case 2: c = 0x20 | ((i & 1) << 4) |
                                (15 - i); break;              // mixed reverse
                case 3: c = 0xf0 | (15 - i); break;            // B reverse
                case 4: c = 0x80 | ((i % 3 == 0) ? 0x10 : 0) |
                                ((i * 7 + 3) & 15); break;    // scattered
                case 5: c = 0x40 | ((i & 1) << 4); break;      // first byte
                case 6: c = 0x6f; break;                     // A last byte
                case 7: c = 0x9f; break;                     // B last byte
                default: throw new IllegalArgumentException(
                    "Invalid control pattern " + pattern);
            }
            bytes[i] = (byte) c;
        }
        return bytes;
    }

    private static BigInteger shiftOracle(byte[] a, byte[] b, int shift) {
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++)
            result[i] = i + shift < 16 ?
                a[i + shift] : b[i + shift - 16];
        return vectorFromBytes(result);
    }

    private static BigInteger permuteOracle(byte[] a, byte[] b,
                                             byte[] control) {
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            int c = control[i] & 0xff;
            result[i] = ((c & 0x10) != 0 ? b : a)[c & 0x0f];
        }
        return vectorFromBytes(result);
    }

    private static long shuffleWord(boolean permute, int variant,
                                    int selector) {
        if ((variant & ~3) != 0)
            throw new IllegalArgumentException("Invalid VA variant");
        if (selector < 0 || selector > (permute ? 7 : 15))
            throw new IllegalArgumentException("Invalid shuffle selector");
        // VD=vs33, VA=vs34/xv34/xv66/xv98, VB=vs35.
        long word = (permute ? 0x14000000L : 0x10000010L) |
            (1L << 21) | (2L << 16) | (3L << 11) |
            (((long) selector) << 6) |
            (((long) (variant & 1)) << 5) |
            (((long) (variant & 2)) << 9);
        long mask = permute ? 0xfc000210L : 0xfc000010L;
        long expected = permute ? 0x14000000L : 0x10000010L;
        if ((word & mask) != expected ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3 ||
                ((word >>> 5) & 1) != (variant & 1) ||
                ((word >>> 10) & 1) != ((variant >>> 1) & 1) ||
                ((word >>> 6) & (permute ? 7 : 15)) != selector)
            throw new IllegalArgumentException("Invalid shuffle opcode");
        return word;
    }

    private String executeShuffle(boolean permute, Address address,
                                  int variant, int pattern, int selector)
            throws Exception {
        String family = permute ? "vperm128" : "vsldoi128";
        long word = shuffleWord(permute, variant, selector);
        String label = family + " variant=" + variant +
            " VA=" + guardedFpSourceAName(variant) +
            " pattern=" + pattern + " selector=" + selector +
            " word=" + String.format("%08X", word);
        Register dest = vectorRegister("vs33");
        Register aReg = vectorRegister(guardedFpSourceAName(variant));
        Register bReg = vectorRegister("vs35");
        Register cReg = permute ? vectorRegister("vs36") : null;
        byte[] a = shuffleInput(0, pattern & 1);
        byte[] b = shuffleInput(1, pattern & 1);
        byte[] c = permute ? shuffleControl(pattern) : null;
        BigInteger va = vectorFromBytes(a);
        BigInteger vb = vectorFromBytes(b);
        BigInteger vc = permute ? vectorFromBytes(c) : BigInteger.ZERO;
        BigInteger wanted = permute ?
            permuteOracle(a, b, c) : shiftOracle(a, b, selector);
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] opcode = wordBytes(word);
            emulator.writeMemory(address, opcode);
            if (!Arrays.equals(opcode, emulator.readMemory(address, 4)))
                return label + ": private opcode mismatch";
            emulator.writeRegister(aReg, va);
            emulator.writeRegister(bReg, vb);
            if (permute)
                emulator.writeRegister(cReg, vc);
            emulator.writeRegister(dest, MASK128);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            // Diagnose the emulator-private decode on precisely one failing
            // example per odd-VA variant. No Program memory is modified.
            String decoded = "";
            boolean checkDecode = !permute && (variant & 1) != 0 &&
                pattern == 0 && selector == 0;
            if (checkDecode) {
                if (emulator.getEmulator() instanceof DefaultEmulator) {
                    List<String> instructions =
                        ((DefaultEmulator) emulator.getEmulator())
                            .disassemble(1);
                    decoded = instructions.isEmpty() ?
                        "<no decoded instruction>" : instructions.get(0);
                }
                else {
                    decoded = "<unexpected emulator implementation>";
                }
            }
            if (!emulator.step(monitor))
                return label + ": emulator step failed: " +
                    emulator.getLastError();
            BigInteger got = emulator.readRegister(dest).and(MASK128);
            BigInteger afterA = emulator.readRegister(aReg).and(MASK128);
            BigInteger afterB = emulator.readRegister(bReg).and(MASK128);
            BigInteger afterC = permute ?
                emulator.readRegister(cReg).and(MASK128) : BigInteger.ZERO;
            if (!wanted.equals(got) || !va.equals(afterA) ||
                    !vb.equals(afterB) ||
                    (permute && !vc.equals(afterC)))
                return label + ": expectedD=" + hex128(wanted) +
                    " actualD=" + hex128(got) +
                    " expectedA=" + hex128(va) +
                    " actualA=" + hex128(afterA) +
                    " expectedB=" + hex128(vb) +
                    " actualB=" + hex128(afterB) +
                    (permute ? " expectedC=" + hex128(vc) +
                     " actualC=" + hex128(afterC) : "") +
                    (checkDecode ? " emulatorDecoded=[" + decoded +
                        "] afterPC=" + emulator.getExecutionAddress() +
                        " alternativeDestRegisters=" +
                        "xv33:" + hex128(
                            emulator.readRegister(
                                vectorRegister("xv33"))) +
                        ",xv65:" + hex128(
                            emulator.readRegister(
                                vectorRegister("xv65"))) +
                        ",xv97:" + hex128(
                            emulator.readRegister(
                                vectorRegister("xv97"))) : "");
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private void runShuffles(File manifest, Address base) throws Exception {
        Map<String, Address> sites = new LinkedHashMap<>();
        Map<String, Long> originalWords = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String heading = reader.readLine();
            if (heading == null ||
                    !heading.startsWith("offset\tword_be\texpected_mnemonic\t"))
                throw new IllegalArgumentException(
                    "Incorrect Xenon shuffle fixture manifest");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 ||
                        !"decode".equals(columns[5]))
                    continue;
                String mnemonic = columns[2];
                if (("vsldoi128".equals(mnemonic) ||
                     "vperm128".equals(mnemonic)) &&
                        !sites.containsKey(mnemonic)) {
                    Address site = base.add(Long.parseUnsignedLong(
                        columns[0].replaceFirst("^0x", ""), 16));
                    sites.put(mnemonic, site);
                    originalWords.put(mnemonic,
                        Long.parseUnsignedLong(columns[1], 16));
                }
            }
        }

        List<String> problems = new ArrayList<>();
        int passed = 0;
        int failed = 0;
        for (int familyIndex = 0; familyIndex < 2; familyIndex++) {
            boolean permute = familyIndex == 1;
            String mnemonic = permute ? "vperm128" : "vsldoi128";
            Address address = sites.get(mnemonic);
            Long original = originalWords.get(mnemonic);
            long mask = permute ? 0xfc000210L : 0xfc000010L;
            long value = permute ? 0x14000000L : 0x10000010L;
            if (address == null || original == null ||
                    (original & mask) != value ||
                    !fixtureMatches(address, original)) {
                problems.add(mnemonic +
                    ": missing/mismatched original fixture bytes");
                failed++;
                continue;
            }
            Instruction inst = getInstructionAt(address);
            if (inst == null) {
                disassemble(address);
                inst = getInstructionAt(address);
            }
            if (inst == null ||
                    !mnemonic.equalsIgnoreCase(inst.getMnemonicString())) {
                problems.add(mnemonic +
                    ": fixture decoded to unexpected mnemonic at " + address);
                failed++;
                continue;
            }
            for (int variant = 0; variant < 4; variant++) {
                for (int pattern = 0; pattern < (permute ? 8 : 2);
                        pattern++) {
                    int casesPerPattern = permute ? 1 : 16;
                    for (int selector = 0; selector < casesPerPattern;
                            selector++) {
                        monitor.checkCancelled();
                        try {
                            String error = executeShuffle(permute,
                                address, variant, pattern,
                                permute ? 4 : selector);
                            if (error == null) passed++;
                            else {
                                problems.add(error);
                                failed++;
                            }
                        }
                        catch (Exception error) {
                            problems.add(mnemonic + " variant=" + variant +
                                " pattern=" + pattern + " selector=" +
                                selector + ": " + error);
                            failed++;
                        }
                    }
                }
            }
        }

        println("");
        println("============================================================");
        println("XENON BYTE SHUFFLE NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + LANGUAGE);
        println("Cases: " + (passed + failed) + "; passed: " +
            passed + "; failed: " + failed);
        println("vsldoi128: four VA banks, all 16 byte shifts, " +
            "two independent source patterns (128 cases).");
        println("vperm128: four VA banks, eight control patterns " +
            "with independent VA/VB/VC (32 cases).");
        println("Source register state and original Program bytes preserved.");
        println("Unresolved details follow in combined result below.");
        recordSuite("SHUFFLE", passed, failed, problems);
    }


    // Exact dot-product paths in the existing native VMX128 SLEIGH.
    // Each output lane contains the same binary32 dot value. Keep this
    // distinct from guarded FMA: these are 3- and 4-term reductions.
    private static final class DotOperation {
        final String name;
        final long opcode;
        final int products;

        DotOperation(String name, long opcode, int products) {
            this.name = name;
            this.opcode = opcode;
            this.products = products;
        }
    }

    private static final DotOperation[] DOT_OPERATIONS = {
        new DotOperation("vmsum3fp128", 0x14000190L, 3),
        new DotOperation("vmsum4fp128", 0x140001d0L, 4),
    };

    private static BigInteger dotOracle(DotOperation operation,
                                         Pattern pattern) {
        // SLEIGH evaluates from high word to low word. All products and
        // intermediate sums in this matrix are exact binary32 integers.
        long dot = 0;
        for (int i = 3; i >= 4 - operation.products; i--)
            dot += (long) pattern.a[i] * pattern.b[i];
        if (dot == 0 || Math.abs(dot) >= EXACT_BOUND)
            throw new IllegalArgumentException(
                "Dot product is not a nonzero exact binary32 integer: " +
                operation.name + " " + pattern.name + " dot=" + dot);
        long bits = Float.floatToRawIntBits((float) dot) & 0xffffffffL;
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < 4; i++)
            result = result.shiftLeft(32).or(BigInteger.valueOf(bits));
        return result;
    }

    private static long dotWord(DotOperation operation, int variant) {
        if ((variant & ~3) != 0)
            throw new IllegalArgumentException(
                "Invalid dot-product VA variant " + variant);
        long word = operation.opcode | (1L << 21) | (2L << 16) |
            (3L << 11) | ((long) (variant & 1) << 5) |
            ((long) (variant & 2) << 9);
        if ((word & FP_SELECTOR_MASK) != operation.opcode ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3 ||
                ((word >>> 5) & 1) != (variant & 1) ||
                ((word >>> 10) & 1) != ((variant >>> 1) & 1))
            throw new IllegalArgumentException(
                "Dot-product opcode selector/register mismatch");
        return word;
    }

    private String executeDot(DotOperation operation, Pattern pattern,
                              Address address, int variant)
            throws Exception {
        long word = dotWord(operation, variant);
        String label = operation.name + " " + pattern.name +
            " variant=" + variant + " VA=" +
            guardedFpSourceAName(variant) + " word=" +
            String.format("%08X", word);
        Register destination = vectorRegister("vs33");
        Register a = vectorRegister(guardedFpSourceAName(variant));
        Register b = vectorRegister("vs35");
        BigInteger inputA = vector(pattern.a);
        BigInteger inputB = vector(pattern.b);
        BigInteger expected = dotOracle(operation, pattern);

        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] opcode = wordBytes(word);
            emulator.writeMemory(address, opcode);
            if (!Arrays.equals(opcode, emulator.readMemory(address, 4)))
                return label + ": emulator-private instruction mismatch";
            emulator.writeRegister(a, inputA);
            emulator.writeRegister(b, inputB);
            emulator.writeRegister(destination, MASK128);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            if (!emulator.step(monitor))
                return label + ": emulator step failed: " +
                    emulator.getLastError();
            BigInteger actual = emulator.readRegister(destination).and(MASK128);
            BigInteger afterA = emulator.readRegister(a).and(MASK128);
            BigInteger afterB = emulator.readRegister(b).and(MASK128);
            if (!expected.equals(actual) ||
                    !inputA.equals(afterA) || !inputB.equals(afterB))
                return label + ": expectedD=" + hex128(expected) +
                    " actualD=" + hex128(actual) +
                    " expectedA=" + hex128(inputA) +
                    " actualA=" + hex128(afterA) +
                    " expectedB=" + hex128(inputB) +
                    " actualB=" + hex128(afterB);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private void runDotProducts(File manifest, Address base)
            throws Exception {
        Map<String, Address> sites = new LinkedHashMap<>();
        Map<String, Long> originalWords = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String header = reader.readLine();
            if (header == null ||
                    !header.startsWith("offset\tword_be\texpected_mnemonic\t"))
                throw new IllegalArgumentException(
                    "Incorrect Xenon dot-product fixture manifest");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 ||
                        !"decode".equals(columns[5]))
                    continue;
                for (DotOperation operation : DOT_OPERATIONS) {
                    if (operation.name.equals(columns[2]) &&
                            !sites.containsKey(operation.name)) {
                        Address addr = base.add(Long.parseUnsignedLong(
                            columns[0].replaceFirst("^0x", ""), 16));
                        sites.put(operation.name, addr);
                        originalWords.put(operation.name,
                            Long.parseUnsignedLong(columns[1], 16));
                    }
                }
            }
        }
        int passed = 0, failed = 0;
        List<String> problems = new ArrayList<>();
        for (DotOperation operation : DOT_OPERATIONS) {
            Address address = sites.get(operation.name);
            Long originalWord = originalWords.get(operation.name);
            if (address == null || originalWord == null ||
                    (originalWord & FP_SELECTOR_MASK) != operation.opcode ||
                    !fixtureMatches(address, originalWord)) {
                failed++;
                problems.add(operation.name +
                    ": missing or invalid original fixture bytes");
                continue;
            }
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            if (instruction == null ||
                    !operation.name.equalsIgnoreCase(
                        instruction.getMnemonicString())) {
                failed++;
                problems.add(operation.name +
                    ": incorrect fixture mnemonic at " + address);
                continue;
            }
            for (int variant = 0; variant < 4; variant++) {
                for (Pattern pattern : PATTERNS) {
                    monitor.checkCancelled();
                    try {
                        String problem = executeDot(operation, pattern,
                            address, variant);
                        if (problem == null) passed++;
                        else {
                            failed++;
                            problems.add(problem);
                        }
                    }
                    catch (Exception ex) {
                        failed++;
                        problems.add(operation.name + " " + pattern.name +
                            " variant=" + variant + ": " + ex);
                    }
                }
            }
        }
        println("");
        println("============================================================");
        println("XENON FP DOT PRODUCT NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + LANGUAGE);
        println("Cases: " + (passed + failed) + "; passed: " +
            passed + "; failed: " + failed);
        println("Families: vmsum3fp128 (top 3 lanes), " +
            "vmsum4fp128 (all 4 lanes).");
        println("Dimensions: four extended VA banks; six four-lane " +
            "independent, nonzero integral binary32 input patterns.");
        println("Only exact finite integer dot products are tested;");
        println("rounding/exceptional paths and hardware equivalence " +
            "are not established.");
        println("Fixture Program bytes unchanged; diagnostics below.");
        recordSuite("DOT", passed, failed, problems);
    }


    // Native vslo128/vsro128 interpret bits [3..6] of the least
    // significant byte of VB as a whole-vector shift in bits.
    // The top bit and low three bits must not change the result.
    private static final class WholeVectorShift {
        final String name;
        final long selector;
        final boolean left;

        WholeVectorShift(String name, long selector, boolean left) {
            this.name = name;
            this.selector = selector;
            this.left = left;
        }
    }

    private static final WholeVectorShift[] WHOLE_VECTOR_SHIFTS = {
        new WholeVectorShift("vslo128", 0x14000390L, true),
        new WholeVectorShift("vsro128", 0x140003d0L, false),
    };

    private static long wholeShiftWord(WholeVectorShift operation,
                                       int variant) {
        if ((variant & ~3) != 0)
            throw new IllegalArgumentException("Invalid VA variant");
        long word = operation.selector |
            (1L << 21) | (2L << 16) | (3L << 11) |
            (((long) (variant & 1)) << 5) |
            (((long) (variant & 2)) << 9);
        if ((word & FP_SELECTOR_MASK) != operation.selector ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3 ||
                ((word >>> 5) & 1) != (variant & 1) ||
                ((word >>> 10) & 1) != ((variant >>> 1) & 1))
            throw new IllegalArgumentException(
                "Wrong whole-vector shift encoding");
        return word;
    }

    private String executeWholeShift(WholeVectorShift operation,
                                     Address address, int variant,
                                     int pattern, int count)
            throws Exception {
        long word = wholeShiftWord(operation, variant);
        String label = operation.name + " variant=" + variant +
            " VA=" + guardedFpSourceAName(variant) +
            " pattern=" + pattern + " count=" + count +
            " word=" + String.format("%08X", word);
        Register dest = vectorRegister("vs33");
        Register aReg = vectorRegister(guardedFpSourceAName(variant));
        Register bReg = vectorRegister("vs35");
        byte[] bytesA = shuffleInput(0, pattern);
        byte[] bytesB = shuffleInput(1, pattern);
        // 0x05 has ignored low bits; 0x87 adds an ignored top bit.
        bytesB[15] = (byte) ((count << 3) |
            (pattern == 0 ? 0x05 : 0x87));
        int encoded = bytesB[15] & 0xff;
        if ((encoded & 0x78) != (count * 8))
            throw new IllegalArgumentException(
                "VB selector test setup did not encode requested shift");
        BigInteger aValue = vectorFromBytes(bytesA);
        BigInteger bValue = vectorFromBytes(bytesB);
        BigInteger expected = operation.left ?
            aValue.shiftLeft(count * 8).and(MASK128) :
            aValue.shiftRight(count * 8);

        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] opcode = wordBytes(word);
            emulator.writeMemory(address, opcode);
            if (!Arrays.equals(opcode, emulator.readMemory(address, 4)))
                return label + ": private opcode mismatch";
            emulator.writeRegister(aReg, aValue);
            emulator.writeRegister(bReg, bValue);
            emulator.writeRegister(dest, MASK128);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            if (!emulator.step(monitor))
                return label + ": emulator step failed: " +
                    emulator.getLastError();
            BigInteger got = emulator.readRegister(dest).and(MASK128);
            BigInteger afterA = emulator.readRegister(aReg).and(MASK128);
            BigInteger afterB = emulator.readRegister(bReg).and(MASK128);
            if (!expected.equals(got) ||
                    !aValue.equals(afterA) ||
                    !bValue.equals(afterB))
                return label + ": encodedControlByte=" +
                    String.format("%02X", encoded) +
                    " expectedD=" + hex128(expected) +
                    " actualD=" + hex128(got) +
                    " expectedA=" + hex128(aValue) +
                    " actualA=" + hex128(afterA) +
                    " expectedB=" + hex128(bValue) +
                    " actualB=" + hex128(afterB);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private void runWholeVectorShifts(File manifest, Address base)
            throws Exception {
        Map<String, Address> sites = new LinkedHashMap<>();
        Map<String, Long> originalWords = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String header = reader.readLine();
            if (header == null ||
                    !header.startsWith("offset\tword_be\texpected_mnemonic\t"))
                throw new IllegalArgumentException(
                    "Incorrect Xenon whole-shift fixture manifest");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 ||
                        !"decode".equals(columns[5]))
                    continue;
                for (WholeVectorShift operation : WHOLE_VECTOR_SHIFTS) {
                    if (operation.name.equals(columns[2]) &&
                            !sites.containsKey(operation.name)) {
                        Address addr = base.add(Long.parseUnsignedLong(
                            columns[0].replaceFirst("^0x", ""), 16));
                        sites.put(operation.name, addr);
                        originalWords.put(operation.name,
                            Long.parseUnsignedLong(columns[1], 16));
                    }
                }
            }
        }

        int passed = 0, failed = 0;
        List<String> problems = new ArrayList<>();
        for (WholeVectorShift operation : WHOLE_VECTOR_SHIFTS) {
            Address address = sites.get(operation.name);
            Long originalWord = originalWords.get(operation.name);
            if (address == null || originalWord == null ||
                    (originalWord & FP_SELECTOR_MASK) != operation.selector ||
                    !fixtureMatches(address, originalWord)) {
                failed++;
                problems.add(operation.name +
                    ": missing/mismatched original fixture bytes");
                continue;
            }
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            if (instruction == null ||
                    !operation.name.equalsIgnoreCase(
                        instruction.getMnemonicString())) {
                failed++;
                problems.add(operation.name +
                    ": unexpected fixture mnemonic at " + address);
                continue;
            }
            for (int variant = 0; variant < 4; variant++) {
                for (int pattern = 0; pattern < 2; pattern++) {
                    for (int count = 0; count < 16; count++) {
                        monitor.checkCancelled();
                        try {
                            String problem = executeWholeShift(operation,
                                address, variant, pattern, count);
                            if (problem == null) passed++;
                            else {
                                failed++;
                                problems.add(problem);
                            }
                        }
                        catch (Exception ex) {
                            failed++;
                            problems.add(operation.name +
                                " variant=" + variant +
                                " pattern=" + pattern + " count=" + count +
                                ": " + ex);
                        }
                    }
                }
            }
        }
        println("");
        println("============================================================");
        println("XENON WHOLE-VECTOR SHIFT NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + LANGUAGE);
        println("Cases: " + (passed + failed) + "; passed: " +
            passed + "; failed: " + failed);
        println("vslo128 / vsro128: four VA banks, all 16 byte shift " +
            "counts, two patterns with ignored top/low control bits.");
        println("Source registers and original fixture bytes unchanged.");
        println("Unresolved details follow in combined result below.");
        recordSuite("WHOLE-SHIFT", passed, failed, problems);
    }


    // Per-word shifts and rotates: each VB lane independently chooses
    // a shift count via its low five bits. Higher control bits are ignored.
    private static final class LaneShift {
        final String name;
        final long opcode;
        final int operation;

        LaneShift(String name, long opcode, int operation) {
            this.name = name;
            this.opcode = opcode;
            this.operation = operation;
        }
    }

    private static final LaneShift[] LANE_SHIFTS = {
        new LaneShift("vrlw128",  0x18000050L, 0),
        new LaneShift("vslw128",  0x180000d0L, 1),
        new LaneShift("vsraw128", 0x18000150L, 2),
        new LaneShift("vsrw128",  0x180001d0L, 3),
    };

    // Across the first eight rows every count 0..31 occurs in one lane;
    // the last two deliberately contain nonzero, ignored high bits.
    private static final int[][] LANE_SHIFT_COUNTS = {
        {  0,  1,  2,  3 }, {  4,  5,  6,  7 },
        {  8,  9, 10, 11 }, { 12, 13, 14, 15 },
        { 16, 17, 18, 19 }, { 20, 21, 22, 23 },
        { 24, 25, 26, 27 }, { 28, 29, 30, 31 },
        { 0x80000000, 0x80000001, 0x8000001f, 0x80000010 },
        { 32, 33, 63, 0xffffffe2 },
    };

    private static final int[][] LANE_SHIFT_SOURCES = {
        { 0x80000001, 0x7ffffffe, 0xdeadbeef, 0x12345678 },
        { 0xf0f0f0f0, 0x01010101, 0xaaaaaaaa, 0x55555555 },
    };

    private static BigInteger vectorWords(int[] words) {
        if (words.length != 4)
            throw new IllegalArgumentException(
                "Expected four 32-bit vector words");
        BigInteger v = BigInteger.ZERO;
        for (int i = 3; i >= 0; i--)
            v = v.shiftLeft(32).or(
                BigInteger.valueOf(words[i] & 0xffffffffL));
        return v;
    }

    private static BigInteger wordShiftOracle(LaneShift operation,
                                               int[] values,
                                               int[] counts) {
        if (values.length != 4 || counts.length != 4)
            throw new IllegalArgumentException("Wrong lane count");
        int[] results = new int[4];
        for (int i = 0; i < 4; i++) {
            int word = values[i];
            int shift = counts[i] & 31;
            switch (operation.operation) {
                case 0:
                    results[i] = (word << shift) |
                        (word >>> ((32 - shift) & 31));
                    break;
                case 1:
                    results[i] = word << shift;
                    break;
                case 2:
                    results[i] = word >> shift;
                    break;
                case 3:
                    results[i] = word >>> shift;
                    break;
                default:
                    throw new IllegalArgumentException(
                        "Unknown lane shift operation");
            }
        }
        return vectorWords(results);
    }

    private static long laneShiftWord(LaneShift operation, int variant) {
        if ((variant & ~3) != 0)
            throw new IllegalArgumentException("Invalid VA variant");
        long word = operation.opcode | (1L << 21) | (2L << 16) |
            (3L << 11) | ((long) (variant & 1) << 5) |
            ((long) (variant & 2) << 9);
        if ((word & FP_SELECTOR_MASK) != operation.opcode ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3 ||
                ((word >>> 5) & 1) != (variant & 1) ||
                ((word >>> 10) & 1) != ((variant >>> 1) & 1))
            throw new IllegalArgumentException(
                "Incorrect lane-shift opcode/register fields");
        return word;
    }

    private String executeLaneShift(LaneShift operation, Address address,
                                    int variant, int sourcePattern,
                                    int countPattern) throws Exception {
        long word = laneShiftWord(operation, variant);
        String label = operation.name + " variant=" + variant +
            " VA=" + guardedFpSourceAName(variant) +
            " source=" + sourcePattern + " controls=" + countPattern +
            " word=" + String.format("%08X", word);
        Register dest = vectorRegister("vs33");
        Register aReg = vectorRegister(guardedFpSourceAName(variant));
        Register bReg = vectorRegister("vs35");
        int[] values = LANE_SHIFT_SOURCES[sourcePattern];
        int[] counts = LANE_SHIFT_COUNTS[countPattern];
        BigInteger inputA = vectorWords(values);
        BigInteger inputB = vectorWords(counts);
        BigInteger expected = wordShiftOracle(operation, values, counts);
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] opcode = wordBytes(word);
            emulator.writeMemory(address, opcode);
            if (!Arrays.equals(opcode, emulator.readMemory(address, 4)))
                return label + ": emulator-private instruction mismatch";
            emulator.writeRegister(aReg, inputA);
            emulator.writeRegister(bReg, inputB);
            emulator.writeRegister(dest, MASK128);
            emulator.writeRegister(
                currentProgram.getLanguage().getProgramCounter(),
                address.getOffset());
            if (!emulator.step(monitor))
                return label + ": emulator step failed: " +
                    emulator.getLastError();
            BigInteger result = emulator.readRegister(dest).and(MASK128);
            BigInteger afterA = emulator.readRegister(aReg).and(MASK128);
            BigInteger afterB = emulator.readRegister(bReg).and(MASK128);
            if (!expected.equals(result) || !inputA.equals(afterA) ||
                    !inputB.equals(afterB))
                return label + ": expectedD=" + hex128(expected) +
                    " actualD=" + hex128(result) +
                    " expectedA=" + hex128(inputA) +
                    " actualA=" + hex128(afterA) +
                    " expectedB=" + hex128(inputB) +
                    " actualB=" + hex128(afterB);
        }
        finally {
            emulator.dispose();
        }
        return null;
    }

    private void runLaneShifts(File manifest, Address base)
            throws Exception {
        Map<String, Address> sites = new LinkedHashMap<>();
        Map<String, Long> originalWords = new LinkedHashMap<>();
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String header = reader.readLine();
            if (header == null ||
                    !header.startsWith("offset\tword_be\texpected_mnemonic\t"))
                throw new IllegalArgumentException(
                    "Incorrect Xenon lane-shift fixture manifest");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 ||
                        !"decode".equals(columns[5]))
                    continue;
                for (LaneShift operation : LANE_SHIFTS) {
                    if (operation.name.equals(columns[2]) &&
                            !sites.containsKey(operation.name)) {
                        Address addr = base.add(Long.parseUnsignedLong(
                            columns[0].replaceFirst("^0x", ""), 16));
                        sites.put(operation.name, addr);
                        originalWords.put(operation.name,
                            Long.parseUnsignedLong(columns[1], 16));
                    }
                }
            }
        }
        int passed = 0, failed = 0;
        List<String> problems = new ArrayList<>();
        for (LaneShift operation : LANE_SHIFTS) {
            Address address = sites.get(operation.name);
            Long originalWord = originalWords.get(operation.name);
            if (address == null || originalWord == null ||
                    (originalWord & FP_SELECTOR_MASK) != operation.opcode ||
                    !fixtureMatches(address, originalWord)) {
                failed++;
                problems.add(operation.name +
                    ": missing/mismatched original fixture bytes");
                continue;
            }
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            if (instruction == null ||
                    !operation.name.equalsIgnoreCase(
                        instruction.getMnemonicString())) {
                failed++;
                problems.add(operation.name +
                    ": unexpected fixture mnemonic at " + address);
                continue;
            }
            for (int variant = 0; variant < 4; variant++) {
                for (int sourcePattern = 0; sourcePattern <
                        LANE_SHIFT_SOURCES.length; sourcePattern++) {
                    for (int countPattern = 0; countPattern <
                            LANE_SHIFT_COUNTS.length; countPattern++) {
                        monitor.checkCancelled();
                        try {
                            String problem = executeLaneShift(operation,
                                address, variant, sourcePattern,
                                countPattern);
                            if (problem == null) passed++;
                            else {
                                failed++;
                                problems.add(problem);
                            }
                        }
                        catch (Exception ex) {
                            failed++;
                            problems.add(operation.name +
                                " variant=" + variant +
                                " source=" + sourcePattern +
                                " controls=" + countPattern + ": " + ex);
                        }
                    }
                }
            }
        }
        println("");
        println("============================================================");
        println("XENON PER-LANE WORD SHIFT NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + LANGUAGE);
        println("Cases: " + (passed + failed) + "; passed: " +
            passed + "; failed: " + failed);
        println("vrlw128, vslw128, vsraw128, vsrw128: four VA banks, " +
            "two independent signed/unsigned source patterns,");
        println("all 32 lane shift counts plus two high-bit-masked " +
            "control patterns; each lane uses its own count.");
        println("Source registers and original fixture bytes unchanged.");
        println("Unresolved details follow in combined result below.");
        recordSuite("LANE-SHIFT", passed, failed, problems);
    }

    @Override
    protected void run() throws Exception {
        String id = currentProgram.getLanguage().getLanguageID()
            .getIdAsString();
        if (!LANGUAGE.equals(id)) {
            printerr("Expected " + LANGUAGE + ", got " + id);
            return;
        }
        // The pinned fixture is generated by prepareXenonIsa in this checkout.
        // Never require a file picker for the known local development path.
        File manifest = new File(
            "C:/Users/Johnny/Downloads/Source Files/testing/XEXLoaderWV/" +
            "XEXLoaderWV/build/xenon-isa-audit/xenon_isa_fixture_v1.tsv");
        if (!manifest.isFile()) {
            printerr("Missing Xenon numerical fixture TSV: " +
                manifest.getAbsolutePath());
            return;
        }
        Address base = currentProgram.getMinAddress();
        if (base == null) {
            printerr("Fixture Program has no memory");
            return;
        }
        Address address = null;
        Long originalWord = null;
        try (BufferedReader reader = Files.newBufferedReader(
                manifest.toPath(), StandardCharsets.UTF_8)) {
            String heading = reader.readLine();
            if (heading == null || !heading.startsWith(
                    "offset\tword_be\texpected_mnemonic\t")) {
                printerr("Incorrect fixture manifest: " + manifest);
                return;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                String[] columns = line.split("\t", -1);
                if (columns.length != 6 ||
                        !"vupkd3d128".equals(columns[2]) ||
                        !"decode".equals(columns[5]))
                    continue;
                long offset = Long.parseUnsignedLong(
                    columns[0].replaceFirst("^0x", ""), 16);
                address = base.add(offset);
                originalWord = Long.parseUnsignedLong(columns[1], 16);
                break;
            }
        }
        if (address == null || originalWord == null ||
                (originalWord & SELECTOR_MASK) != SELECTOR_VALUE ||
                !originalFixtureMatches(address, originalWord)) {
            printerr("Missing/invalid original vupkd3d128 fixture bytes");
            return;
        }
        Instruction instruction = getInstructionAt(address);
        if (instruction == null) {
            disassemble(address);
            instruction = getInstructionAt(address);
        }
        if (instruction == null || !"vupkd3d128".equalsIgnoreCase(
                instruction.getMnemonicString())) {
            printerr("Wrong fixture mnemonic at " + address + ": " +
                (instruction == null ? "<missing>" :
                    instruction.getMnemonicString()));
            return;
        }

        int passed = 0;
        int failed = 0;
        List<String> problems = new ArrayList<>();
        for (TestCase test : CASES) {
            for (int bank = 0; bank < 2; bank++) {
                for (int low = 0; low < 4; low++) {
                    monitor.checkCancelled();
                    try {
                        String error = execute(test, address, bank, low);
                        if (error == null) {
                            passed++;
                        }
                        else {
                            problems.add(error);
                            failed++;
                        }
                    }
                    catch (Exception error) {
                        problems.add(test.label + " bank=" + bank +
                            " low=" + low + ": " + error);
                        failed++;
                    }
                }
            }
        }

        println("");
        println("============================================================");
        println("XENON D3D UNPACK NATIVE NUMERICAL P-CODE AUDIT");
        println("============================================================");
        println("Language: " + id);
        println("Cases: " + (passed + failed) +
            "; passed: " + passed + "; failed: " + failed);
        println("Formats tested: 0 D3DCOLOR, 1 SHORT_2, 2 2_10_10_10, 4 SHORT_4.");
        println("Dimensions: two opcode destination banks, four low immediate bits;");
        println("input carries nonzero upper vector data, with exact signed/NaN oracles.");
        println("Original 344-word fixture Program bytes were not modified.");
        println("Userop formats 3,5,6,7 not numerically tested.");
        println("");
        println("Unresolved details follow in the combined result below.");
        recordSuite("D3D", passed, failed, problems);

        // One script entry point and exactly one manifest selection.
        runSaturatingPacks(manifest, base);
        runGuardedFp(manifest, base);
        runShuffles(manifest, base);
        runDotProducts(manifest, base);
        runWholeVectorShifts(manifest, base);
        runLaneShifts(manifest, base);

        println("");
        println("============================================================");
        println("XENON NUMERICAL P-CODE COMBINED RESULT");
        println("============================================================");
        println("Cases: " + (combinedPassed + combinedFailed) +
            "; passed: " + combinedPassed + "; failed: " + combinedFailed);
        println("UNRESOLVED / INCORRECT STATES (" +
            combinedProblems.size() + ")");
        if (combinedProblems.isEmpty()) println("None");
        for (String issue : combinedProblems) println(issue);
        println("============================================================");
    }
}
