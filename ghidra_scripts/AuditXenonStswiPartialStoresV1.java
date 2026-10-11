// Ghidra 12.1.3+ read-only Xenon SLEIGH semantics audit.
//@category Xbox360
//
// Emulates STSWI with synthetic instruction/data in EmulatorHelper state.
// Does NOT write to or reanalyze the current Program's bytes.
// Run on the Xbox 360 kernel Program loaded as PowerPC:BE:64:XENON-32addr.

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.math.BigInteger;
import java.util.Arrays;

public class AuditXenonStswiPartialStoresV1 extends GhidraScript {
    private static final long CODE = 0x80061010L;
    private static final long DEST = 0x80061200L;
    private static final int SENTINEL_LENGTH = 48;
    private static final long R3 = 0x1122334455667788L;
    private static final long R5 = 0x99AABBCCDDEEFF00L;
    private static final long R6 = 0x123456780BADF00DL;

    private static void require(boolean ok, String message) {
        if (!ok) {
            throw new IllegalStateException(message);
        }
    }

    private static byte[] be32(int value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    // Primary opcode 31, RS=r3, RA=r4, NB=n, XO=725, Rc=0.
    private static int stswi(int nb) {
        return (31 << 26) | (3 << 21) | (4 << 16) |
            ((nb & 31) << 11) | (725 << 1);
    }

    private static byte[] expected(int byteCount) {
        byte[] expected = new byte[SENTINEL_LENGTH];
        Arrays.fill(expected, (byte) 0xA5);
        long[] regs = { R3, R5, R6 };
        for (int index = 0; index < byteCount; ++index) {
            int word = index / 4;
            int byteInWord = index % 4;
            require(word < regs.length, "Oracle needs more source registers");
            expected[index] = (byte) (regs[word] >>> (24 - 8 * byteInWord));
        }
        return expected;
    }

    private void runCase(Address code, Address dest, int count) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            int encodedNb = (count == 32) ? 0 : count;
            emu.writeMemory(code, be32(stswi(encodedNb)));
            byte[] sentinel = new byte[SENTINEL_LENGTH];
            Arrays.fill(sentinel, (byte) 0xA5);
            emu.writeMemory(dest, sentinel);
            emu.writeRegister("r3", BigInteger.valueOf(R3));
            emu.writeRegister("r4", BigInteger.valueOf(dest.getOffset()));
            emu.writeRegister("r5", BigInteger.valueOf(R5));
            emu.writeRegister("r6", BigInteger.valueOf(R6));
            emu.writeRegister(emu.getPCRegister(),
                BigInteger.valueOf(code.getOffset()));

            if (!emu.step(monitor)) {
                throw new IllegalStateException(
                    "STSWI NB=" + encodedNb +
                    " emulator step failed: " + emu.getLastError());
            }
            byte[] got = emu.readMemory(dest, SENTINEL_LENGTH);
            byte[] want = expected(count);
            require(got != null && Arrays.equals(got, want),
                "STSWI NB=" + encodedNb +
                " memory mismatch (including bytes beyond requested range)" +
                "\\nExpected: " + Arrays.toString(want) +
                "\\nActual:   " + Arrays.toString(got));
            println("PASS: stswi r3,r4," + encodedNb +
                " stored " + count + " byte(s) without clobber");
        }
        finally {
            emu.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        String id = currentProgram.getLanguageID().toString();
        require("PowerPC:BE:64:XENON-32addr".equals(id),
            "Requires Xenon language, found " + id);
        require(currentProgram.getMemory().isBigEndian(),
            "Program must use big-endian memory");

        Address code = toAddr(CODE);
        Address dest = toAddr(DEST);
        require(currentProgram.getMemory().contains(code) &&
                currentProgram.getMemory().contains(dest),
            "Expected retail kernel 17559 test addresses are unmapped");

        // All partial tails (1/2/3), one full word, two-word cases
        // with partial tails, plus the architectural NB=0 -> 32 case.
        // 32-byte case is checked separately below with enough registers.
        int[] cases = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
        println("XENON STSWI BYTE-STORE AUDIT (emulator state only)");
        for (int count : cases) {
            monitor.checkCancelled();
            runCase(code, dest, count);
        }
        println("STSWI PASS: " + cases.length +
            " numerical cases; source Program unchanged");
    }
}
