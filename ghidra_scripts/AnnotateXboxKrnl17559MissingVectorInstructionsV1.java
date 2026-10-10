// @category Xbox360
// Verified retail 17559 xenon instruction metadata.
// Apply only to the original, correctly mapped kernel database.
// Ghidra's stock PowerPC:BE:64:A2ALT-32addr language does not provide all
// Xenon VMX128/extended vector instructions. This script ADDS COMMENTS ONLY.
// It does NOT replace instruction decode/p-code, repair functions, or delete
// bookmarks. The known call-to-KeBugCheckEx padding case is informational.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;

public class AnnotateXboxKrnl17559MissingVectorInstructionsV1 extends GhidraScript {
    private static final String EXPECTED_ORIGINAL =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String EXPECTED_NORMALIZED =
        "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85";
    private static final String EXPECTED_LANGUAGE = "PowerPC:BE:64:A2ALT-32addr";
    private static final long BASE = 0x80040000L;
    private static final String PREFIX = "Xbox 360 Xenon decoded opcode (Xenia): ";
    private static class Opcode {
        final long addr;
        final int word;
        final String mnemonic;
        Opcode(long addr, int word, String mnemonic) {
            this.addr = addr;
            this.word = word;
            this.mnemonic = mnemonic;
        }
    }
    // Extracted from the user's xboxkrnl.exe(4).gzf bookmark messages and
    // verified against the original retail 17559 kernel image SHA-256.
    // Names independently matched against Xenia's ppc_opcode_lookup_gen.cc,
    // not guessed from hexadecimal similarity.
    private static final Opcode[] VECTOR_ERRORS = {
        new Opcode(0x80144DA0L, 0x10EBE8C3, "lvx128"),
        new Opcode(0x80143584L, 0x11A058C3, "lvx128"),
        new Opcode(0x80141E6CL, 0x1140D8C3, "lvx128"),
        new Opcode(0x80141B40L, 0x7DB8540E, "lvlx"),
        new Opcode(0x8013140CL, 0x100048C3, "lvx128"),
        new Opcode(0x80131240L, 0x118048C3, "lvx128"),
        new Opcode(0x8012D3D0L, 0x100018C3, "lvx128"),
        new Opcode(0x8012D080L, 0x100058C3, "lvx128"),
        new Opcode(0x8012CF1CL, 0x7D605C0E, "lvlx"),
        new Opcode(0x800CE9A4L, 0x192467F0, "vupkd3d128"),
        new Opcode(0x800CD580L, 0x7D405C0E, "lvlx"),
        new Opcode(0x800CD3E4L, 0x7C00540E, "lvlx"),
        new Opcode(0x800CC918L, 0x100058C3, "lvx128"),
        new Opcode(0x800CC17CL, 0x112058C3, "lvx128"),
        new Opcode(0x800CBEE0L, 0x1005D8C3, "lvx128"),
        new Opcode(0x800BD030L, 0x7DAB244E, "lvrx"),
    };
    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    private int readWord(long offset) throws Exception {
        Memory memory = currentProgram.getMemory();
        int value = 0;
        Address address = at(offset);
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | (memory.getByte(address.add(i)) & 0xff);
        }
        return value;
    }
    @Override
    protected void run() throws Exception {
        String hash = currentProgram.getExecutableSHA256();
        boolean original = EXPECTED_ORIGINAL.equalsIgnoreCase(hash);
        boolean normalized = EXPECTED_NORMALIZED.equalsIgnoreCase(hash);
        if ((!original && !normalized) ||
                !EXPECTED_LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
                currentProgram.getImageBase().getOffset() != BASE ||
                readWord(0x80061010L) != 0x7D8802A6) {
            printerr("Not a correctly mapped, verified retail 17559 kernel. No changes.");
            return;
        }
        println("Verifying 16 genuinely unsupported Xenon vector instructions.");
        int changed = 0, already = 0, skipped = 0;
        for (Opcode issue : VECTOR_ERRORS) {
            monitor.checkCancelled();
            int found = readWord(issue.addr);
            if (found != issue.word) {
                skipped++;
                println(String.format("SKIP %08X: opcode mismatch %08X != %08X",
                    issue.addr, found, issue.word));
                continue;
            }
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(at(issue.addr));
            if (cu == null) {
                skipped++;
                println(String.format("SKIP %08X: no code unit", issue.addr));
                continue;
            }
            String marker = PREFIX + issue.mnemonic + " (encoding " +
                String.format("%08X", issue.word) +
                "); missing stock Ghidra PowerPC/VMX128 language constructor. " +
                "Informational only; p-code has NOT been recovered.";
            String oldComment = cu.getComment(CommentType.EOL);
            if (oldComment != null && oldComment.contains(marker)) {
                already++;
            }
            else {
                cu.setComment(CommentType.EOL,
                    oldComment == null || oldComment.isBlank()
                        ? marker : oldComment + "\n" + marker);
                changed++;
            }
            println(String.format("%08X: %08X %s", issue.addr, issue.word, issue.mnemonic));
        }
        println("");
        println("The 17th bookmark, 0x80073734, is zero padding after");
        println("0x80073730: bl KeBugCheckEx; do NOT create an instruction there.");
        println("Verify the call terminates flow and KeBugCheckEx has No Return.");
        println("The bookmark may persist after flow metadata is repaired.");
        println("Do not clear any of the 16 genuine unsupported-code bookmarks");
        println("until a Xenon-compatible SLEIGH language actually decodes them.");
        println(String.format("EOL comments added=%d, already present=%d, skipped=%d",
            changed, already, skipped));
        println("No bytes, function bodies, signatures, or bookmarks modified.");
    }
}
