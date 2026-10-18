// Verify retail HV 17559 raw bytes and annotate known SRR0/SRR1/return pathways.
//@category Xbox360
//
// Safe to run on an already annotated import.  All edits are labels/comments.
// Existing labels, comments, functions, datatypes, instruction units, and bytes
// are preserved.  No p-code or native-decompiler modifications.
//
// Evidence: directly verified 0x40000-byte retail HV 17559 binary, not
// speculative global decoding of arbitrary raw data.
// Notes: a branch between an SRR1 write and nearby rfid can divert control.
// SF=0 annotations describe explicit register writes, not every possible exit.

import java.security.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class AnnotateXenonHv17559ReturnPaths_20261018_v2 extends GhidraScript {
    private static final long LENGTH = 0x40000L;
    private static final String SHA =
        "225d1c6907651126182e8a2ce74d7df59e7970c0086848114de20c35268609f5";

    // Offset of exact SRR1 write, immediate load, value, and nearby RFID.
    // Nearby is NOT equivalent to a verified straight-line CFG edge.
    private static final long[][] KNOWN_SRR1 = {
        {0x0558, 0x054c, 0x1030, 0x0578},
        {0x0668, 0x065c, 0x1030, 0x0688},
        {0x0758, 0x074c, 0x1030, 0x0778},
        {0x0890, 0x088c, 0x1030, 0x08b0},
        {0x0958, 0x094c, 0x1030, 0x0978},
        {0x0a40, 0x0a3c, 0x1030, 0x0a58},
        {0x0a98, 0x0a94, 0x1030, 0x0bf4},
        {0x0d58, 0x0d4c, 0x1030, 0x0d78},
        {0x0fb0, 0x0fac, 0x1030, 0x0fd0},
        {0x103c, 0x1038, 0x1030, 0x106c},
        {0x1690, 0x168c, 0x1030, 0x16b8},
        {0x1758, 0x174c, 0x1030, 0x1778},
        {0x1aec, 0x1ae4, 0x02003030L, 0x1b0c}
    };

    // Direct code pairs loading 0x80075F90 before writing SRR0.
    private static final long[][] FIXED_SRR0 = {
        {0x0544,0x0548,0x0550},
        {0x0654,0x0658,0x0660},
        {0x0744,0x0748,0x0750},
        {0x087c,0x0880,0x0884},
        {0x0944,0x0948,0x0950},
        {0x0a28,0x0a2c,0x0a30},
        {0x0a84,0x0a88,0x0a8c},
        {0x0d44,0x0d48,0x0d50},
        {0x0f9c,0x0fa0,0x0fa4},
        {0x1680,0x1684,0x1688},
        {0x1744,0x1748,0x1750}
    };

    private static final long[] RFID = {
        0x0578,0x0688,0x0778,0x0848,0x08b0,0x0978,
        0x0a0c,0x0a58,0x0b00,0x0b98,0x0bf4,0x0d78,
        0x0f68,0x0fd0,0x106c,0x11f0,0x16b8,0x1778,0x1b0c
    };

    private void ensure(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private int word(long off) throws Exception {
        byte[] b = new byte[4];
        ensure(currentProgram.getMemory().getBytes(toAddr(off), b) == 4,
            "Cannot read word 0x" + Long.toHexString(off));
        return ((b[0] & 255) << 24) | ((b[1] & 255) << 16) |
            ((b[2] & 255) << 8) | (b[3] & 255);
    }

    private void verifyAll() throws Exception {
        ensure("PowerPC:BE:64:XENON-32addr".equals(
            currentProgram.getLanguageID().toString()),
            "Only the Xenon 64-bit GPR/32-bit offset raw-binary program is supported");
        ensure(currentProgram.getMemory().contains(toAddr(0)) &&
               currentProgram.getMemory().contains(toAddr(LENGTH-1)),
            "Expected full raw HV image at 0x0..0x3FFFF");
        MessageDigest dig = MessageDigest.getInstance("SHA-256");
        byte[] b = new byte[4096];
        for (long off=0; off<LENGTH; off+=b.length) {
            monitor.checkCancelled();
            ensure(currentProgram.getMemory().getBytes(toAddr(off),b)==b.length,
                "Unreadable original image offset " + Long.toHexString(off));
            dig.update(b);
        }
        StringBuilder h = new StringBuilder();
        for (byte v : dig.digest()) h.append(String.format("%02x", v & 0xff));
        ensure(SHA.equals(h.toString()), "Wrong or modified HV 17559 bytes: "+h);
        ensure(word(0x08)==0x100 && word(0x0c)==0x40000 &&
               word(0x100)==0x7c71faa6 &&
               word(0x20000)==0x7d8802a6 && word(0x30000)==0x7d8802a6,
            "Image/header anchors changed");

        for (long[] t : KNOWN_SRR1) {
            int op = t[0]==0x103c ? 0x7cbb03a6 :
                     t[0]==0x1aec ? 0x7c7b03a6 : 0x7c3b03a6;
            ensure(word(t[0])==op, "SRR1 opcode at "+Long.toHexString(t[0]));
            if (t[0]==0x1aec) {
                ensure(word(0x1ae4)==0x3c600200 &&
                       word(0x1ae8)==0x60633030,
                    "Expected SRR1 construction of 0x02003030");
            } else {
                ensure(word(t[1]) == (t[0]==0x103c ? 0x38a01030:0x38201030),
                    "Expected SRR1 immediate 0x1030 at "+Long.toHexString(t[1]));
            }
            ensure(word(t[3]) == 0x4c000024,
                "Expected possible rfid exit at "+Long.toHexString(t[3]));
        }

        for (long[] t : FIXED_SRR0) {
            boolean reg5 = t[2]==0x1688;
            ensure(word(t[0])==(reg5?0x3ca08007:0x3c808007) &&
                   word(t[1])==(reg5?0x38a55f90:0x38845f90) &&
                   word(t[2])==(reg5?0x7cba03a6:0x7c9a03a6),
                "Fixed kernel SRR0 evidence changed at "+Long.toHexString(t[2]));
        }
        ensure(word(0x1ad8)==0x3c608008 &&
               word(0x1adc)==0x38638db0 &&
               word(0x1ae0)==0x7c7a03a6,
               "Expected second fixed kernel SRR0 0x80078DB0");
        for (long off : RFID)
            ensure(word(off)==0x4c000024,
                "Changed rfid instruction at "+Long.toHexString(off));
        ensure(word(0x994)==0x4c000224, "Expected hrfid at 0x994");
        // Dynamic SRR1 writes: not evidence of a fixed 32-bit mode.
        ensure(word(0x144)==0x7d1b03a6 &&
               word(0x838)==0x7c9b03a6 &&
               word(0x9a0)==0x7c3b03a6 &&
               word(0xf58)==0x7c9b03a6,
            "Dynamic SRR1 guard failed");
        // Distinguish the 0xA98 branch to shared epilogue from 0xB00.
        ensure(word(0xa9c)==0x48000100,
            "SRR1 write 0xA98 should branch to shared block 0xB9C");
        ensure(word(0x16000)==0x00002a80 &&
               word(0x16004)==0x00002540 &&
               word(0x16008)==0x0000177c,
               "Observed 0x16000 local address-table prefix changed");
    }

    private void annotate(long off, String symbolName, String note) throws Exception {
        Address address=toAddr(off);
        boolean exists=false;
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(address))
            if (symbol.getName().equals(symbolName)) exists=true;
        if (!exists) createLabel(address, symbolName, false);
        String current=getPreComment(address);
        if (current==null || current.length()==0) setPreComment(address,note);
        else if (!current.contains(note)) setPreComment(address,current+"\n"+note);
    }

    @Override public void run() throws Exception {
        verifyAll();  // All checks complete before first database edit.
        for (long[] t : FIXED_SRR0) {
            long at=t[2];
            annotate(at,String.format("HvKernelTargetSRR0_%04X",at),
                "Native lis/addi -> mtsrr0 sets SRR0=0x80075F90; downstream flow may branch to shared epilogue.");
        }
        annotate(0x1ae0,"HvKernelTargetSRR0_1AE0",
            "Native lis/addi -> mtsrr0 sets SRR0=0x80078DB0.");
        for (long[] t : KNOWN_SRR1) {
            long at=t[0];
            annotate(at,String.format("HvExplicitSF0SRR1_%04X",at),
                String.format("Native immediate -> mtsrr1 sets SRR1=0x%08X (SF=0). Nearby rfid at 0x%04X; a branch may divert to another exit.",t[2],t[3]));
        }
        for (long at : RFID) {
            annotate(at,String.format("HvRfidExit_%04X",at),
                "Native rfid. The actual return target and resulting MSR depend on the reaching SRR0/SRR1 definitions; do not infer SF solely from nearby code.");
        }
        annotate(0x0994,"HvHypervisorReturn_0994",
            "Native hrfid, distinct from rfid. Restores state through hypervisor-return mechanism; no fixed SF conclusion from this instruction alone.");
        annotate(0x0144,"HvDynamicSRR1Write_0144",
            "Native mtsrr1 r8; source is not an immediate 0x1030 assignment.");
        annotate(0x0838,"HvDynamicSRR1Write_0838",
            "Native mfsrr1/OR/mtsrr1 modifies saved MSR dynamically; cannot classify this return as universally SF=0.");
        annotate(0x09a0,"HvDynamicSRR1Write_09A0",
            "Native mtsrr1 r1 after a value loaded from context at [r13+44]; not a constant-SF write.");
        annotate(0x0f58,"HvDynamicSRR1Write_0F58",
            "Native mfsrr1/OR/mtsrr1 modifies saved MSR dynamically; preserve the incoming SF state.");
        annotate(0x0a9c,"HvBranchToSharedReturn_0A9C",
            "Native unconditional branch to 0xB9C. The 0xA98 explicit SF=0 write does not fall through to 0xB00.");
        annotate(0x0bf4,"HvSharedRfidEpilogue_0BF4",
            "Native shared rfid exit. Reaching SRR1 state is path-dependent; 0xA98 can branch to 0xB9C first.");
        annotate(0x16000,"HvObservedLocalOffsetTable_16000",
            "Verified BE32 internal HV offsets start 0x2A80, 0x2540, 0x177C; extent and pointer domain still unresolved. No array length asserted.");
        println("HV17559_RETURNS_V2_APPLIED source_sha256="+SHA+
            " sf0_writes=13 fixed_kernel_srr0_sites=12 rfid_exits=19 hrfid_exits=1"+
            " original bytes and existing metadata preserved");
    }
}
