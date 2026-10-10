// Execute native vupkd3d128 D3D unpack formats against independent bit oracles.
// @category Xbox360
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

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class AuditXenonD3DUnpackNumericV1 extends GhidraScript {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final long SELECTOR_MASK = 0xfc0007f0L;
    private static final long SELECTOR_VALUE = 0x180007f0L;
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
    }
}
