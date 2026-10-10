// Verify exact finite-integer native lanes in Xenon's guarded FP arithmetic.
// @category Xbox360
//
// Run in the disposable PowerPC:BE:64:XENON-32addr fixture Program imported
// from build/xenon-isa-audit/xenon_isa_fixture_v1.bin. Select the sibling TSV.
// 3 families x 4 selector variants x 6 independent lane patterns = 72 cases.
//
// Uses only values documented by the SLEIGH native guard: nonzero integral
// binary32 source and accumulator lanes within [-2048, 2048], with every
// output nonzero and exactly representable (< 2^24 absolute magnitude).
// This does NOT test nonintegral, NaN, zero, overflow, signed-zero or fused
// rounding behavior. Those deliberately retain a CALL_OTHER fallback.
//
// Synthetic opcodes are injected into EmulatorHelper PRIVATE memory only;
// the Program bytes and existing decoder fixture are never modified.

import java.io.BufferedReader;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class AuditXenonGuardedFusedFloatNumeric extends GhidraScript {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final long SELECTOR_MASK = 0xfc0003d0L;
    private static final BigInteger MASK128 =
        BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    private static final int SOURCE_BOUND = 2048;
    private static final int EXACT_BOUND = 1 << 24;

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
    // These 4 encodings all select the same mnemonic and low 32 registers.
    // VD=vs33; VA=vs34; VB=vs35. The other three selector variants
    // toggle unmasked opcode bit 5 and/or bit 10.
    private static long probeWord(Family family, int variant) {
        long word = family.selector | (1L << 21) | (2L << 16) |
            (3L << 11) | ((long) (variant & 1) << 5) |
            ((long) (variant & 2) << 9);
        if ((word & SELECTOR_MASK) != family.selector ||
                ((word >>> 21) & 31) != 1 ||
                ((word >>> 16) & 31) != 2 ||
                ((word >>> 11) & 31) != 3)
            throw new IllegalArgumentException(
                "FP opcode selector / register fields changed");
        return word;
    }

    private static String hex128(BigInteger value) {
        String digits = value.and(MASK128).toString(16);
        StringBuilder padded = new StringBuilder(32);
        for (int i = digits.length(); i < 32; i++)
            padded.append('0');
        return padded.append(digits).toString();
    }

    private String execute(Family family, Pattern pattern, Address address,
                           int variant) throws Exception {
        long word = probeWord(family, variant);
        String label = family.name + " " + pattern.name +
            " variant=" + variant + " word=" + String.format("%08X", word);
        Register destination = vectorRegister("vs33");
        Register a = vectorRegister("vs34");
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

    @Override
    protected void run() throws Exception {
        String language = currentProgram.getLanguage().getLanguageID()
            .getIdAsString();
        if (!LANGUAGE.equals(language)) {
            printerr("Expected " + LANGUAGE + ", got " + language);
            return;
        }
        File manifest = askFile(
            "Select existing xenon_isa_fixture_v1.tsv", "Open");
        Address base = currentProgram.getMinAddress();
        if (base == null) {
            printerr("Missing fixture Program memory");
            return;
        }

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
                    (word & SELECTOR_MASK) != family.selector ||
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
    }
}
