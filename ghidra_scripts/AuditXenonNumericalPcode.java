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
        println("UNRESOLVED / INCORRECT STATES (" + problems.size() + ")");
        if (problems.isEmpty()) println("None");
        for (String problem : problems) println(problem);
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
        println("UNRESOLVED / INCORRECT STATES (" + problems.size() + ")");
        if (problems.isEmpty()) println("None");
        for (String problem : problems) println(problem);
        recordSuite("GUARDED-FP", passed, failed, problems);
    }

    @Override
    protected void run() throws Exception {
        String id = currentProgram.getLanguage().getLanguageID()
            .getIdAsString();
        if (!LANGUAGE.equals(id)) {
            printerr("Expected " + LANGUAGE + ", got " + id);
            return;
        }
        File manifest = askFile(
            "Select existing xenon_isa_fixture_v1.tsv", "Open");
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
        println("UNRESOLVED / INCORRECT STATES (" + problems.size() + ")");
        if (problems.isEmpty()) println("None");
        for (String problem : problems) println(problem);
        recordSuite("D3D", passed, failed, problems);

        // One script entry point and exactly one manifest selection.
        runSaturatingPacks(manifest, base);
        runGuardedFp(manifest, base);

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
