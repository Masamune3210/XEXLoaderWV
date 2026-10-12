// Numerically verify Xenon addic. / subic. CR0 low-word semantics.
//@category Xbox360
//
// All synthetic instructions execute in the legacy Ghidra emulator's
// PRIVATE memory. No Program bytes, code units, bookmarks, functions,
// datatypes or signatures are modified.
//
// The native 17559 addic. at 0x80064204 is verified before running the
// synthetic cases at that same address. No extension install is done here.
// Run only after rebuilding/reinstalling the modified Xenon language.
// Ghidra 12.1.3 EmulatorHelper remains deprecated; this script follows the
// emulator-private execution model of the existing numerical audit.

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.DefaultEmulator;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

@SuppressWarnings("removal")
public class AuditXenonAddicRecordWidthV1 extends GhidraScript {
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final long SITE = 0x80064204L;

    private static class Case {
        final String label;
        final int opcode;
        final int immediate;
        final long initial;
        final long fullResult;
        final int expectedCr0;
        Case(String label, int opcode, int immediate,
             long initial, int expectedCr0) {
            this.label = label;
            this.opcode = opcode;
            this.immediate = immediate;
            this.initial = initial;
            this.fullResult = initial + immediate;
            this.expectedCr0 = expectedCr0;
        }
    }

    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private byte[] opcode(int major, int immediate) {
        // D-form: op[0:5], RT=12, RA=11, SIMM (16-bit two's complement).
        int word = (major << 26) | (12 << 21) | (11 << 16) |
            (immediate & 0xffff);
        return new byte[] {
            (byte) (word >>> 24), (byte) (word >>> 16),
            (byte) (word >>> 8), (byte) word
        };
    }

    private static int lowWordCr0(long result) {
        int low32 = (int) result;
        if (low32 < 0) return 8; // CR0.LT
        if (low32 > 0) return 4; // CR0.GT
        return 2; // CR0.EQ
    }

    private void execute(Case test, Address site) throws Exception {
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            byte[] syntheticBytes = opcode(test.opcode, test.immediate);
            emulator.writeMemory(site, syntheticBytes);
            require(java.util.Arrays.equals(
                syntheticBytes, emulator.readMemory(site, 4)),
                test.label + ": synthetic instruction failed private memory roundtrip");
            emulator.writeRegister("r11", BigInteger.valueOf(test.initial));
            emulator.writeRegister("r12", 0x5500550055005500L);
            emulator.writeRegister("xer_so", 0);
            emulator.writeRegister("cr0", 0xa);
            emulator.writeRegister(emulator.getPCRegister(), site.getOffset());
            // The emulator decodes from its private instruction bytes, not
            // Ghidra's persistent Listing instruction at this address.
            ((DefaultEmulator) emulator.getEmulator()).disassemble(1);
            boolean advanced = emulator.step(monitor);
            require(advanced && emulator.getLastError() == null,
                test.label + ": emulator failed: " + emulator.getLastError());
            long result = emulator.readRegister("r12").longValue();
            int cr0 = emulator.readRegister("cr0").intValue() & 0xf;
            require(result == test.fullResult,
                test.label + ": destination result 0x" +
                Long.toHexString(result) + ", expected 0x" +
                Long.toHexString(test.fullResult));
            require(cr0 == test.expectedCr0,
                test.label + ": CR0 0x" + Integer.toHexString(cr0) +
                ", expected 0x" + Integer.toHexString(test.expectedCr0));
            println("PASS " + test.label + " result=0x" +
                Long.toHexString(result) + " CR0=0x" +
                Integer.toHexString(cr0));
        }
        finally {
            emulator.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        require("PowerPC:BE:64:XENON-32addr".equals(
            currentProgram.getLanguageID().toString()),
            "Requires Xenon 64-bit GPR/32-bit address language");
        require(SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "Wrong retail 17559 kernel image");
        Address site = toAddr(SITE);
        Instruction original = currentProgram.getListing()
            .getInstructionAt(site);
        require(original != null &&
            "addic.".equals(original.getMnemonicString()) &&
            java.util.Arrays.equals(original.getBytes(),
                new byte[] {(byte)0x35, (byte)0x6b, 0, 1}),
            "Expected original 0x356B0001 addic. r11,r11,1 " +
            "at 0x80064204");

        // Cases independently calculate the signed low-word CR0 oracle.
        // Destination is deliberately checked as a *full* GPR result:
        // the patch must not accidentally truncate existing arithmetic.
        List<Case> cases = new ArrayList<>();
        cases.add(new Case("addic. ffffffff plus one (EQ)", 13, 1,
            0x00000000ffffffffL, 2));
        cases.add(new Case("addic. 7fffffff plus one (LT)", 13, 1,
            0x000000007fffffffL, 8));
        cases.add(new Case("addic. nonzero high word, zero low (EQ)", 13, 0,
            0x0000000100000000L, 2));
        cases.add(new Case("addic. high word, negative low (LT)", 13, 0,
            0x0000000180000000L, 8));
        cases.add(new Case("addic. ordinary positive (GT)", 13, 1,
            1L, 4));
        cases.add(new Case("subic. 0x100000000 minus one (LT)", 13, -1,
            0x0000000100000000L, 8));
        cases.add(new Case("subic. 1 minus one (EQ)", 13, -1,
            1L, 2));
        cases.add(new Case("subic. 2 minus one (GT)", 13, -1,
            2L, 4));
        cases.add(new Case("subic. wraps negative low", 13, -1,
            0x0000000000000000L, 8));
        // Opcode 12 forms are NON-RECORDING and must leave prior CR0.
        cases.add(new Case("addic nonrecord CR0 untouched", 12, 1,
            0x00000000ffffffffL, 0xa));
        cases.add(new Case("subic nonrecord CR0 untouched", 12, -1,
            1L, 0xa));

        for (Case test : cases) {
            monitor.checkCancelled();
            if (test.opcode == 13) {
                require(lowWordCr0(test.fullResult) == test.expectedCr0,
                    "Broken independent test oracle for " + test.label);
            }
            execute(test, site);
        }
        println("XENON ADDIC RECORD WIDTH: 11/11 PASS (private emulator memory)");
        println("Program unchanged: no byte, type, function, signature, or " +
            "analysis metadata changes.");
    }
}
