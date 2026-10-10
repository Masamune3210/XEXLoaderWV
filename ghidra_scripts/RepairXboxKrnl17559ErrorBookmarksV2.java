// @category Xbox360
// Apply narrowly verified RETAIL 17559 kernel flow metadata and audit outstanding
// processor decode errors. This script is safe to rerun on an existing Program.
// The caller supplies no names, types, lengths, or memory patches.
//
// Repairs actual Ghidra metadata:
//   0x800716e8 KeBugCheckEx: No Return
//   0x80073730 bl KeBugCheckEx: CALL_RETURN/CALL_TERMINATOR override
//   0x80073734: remove ONLY the old matching "Bad Instruction" error bookmark
//     AFTER validating the caller, instruction bytes and flow metadata.
// The other 16 bookmarks are genuine Xenon ISA decode errors: preserve them,
// and annotate their exact opcode bytes without replacing p-code.
import java.util.Locale;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class RepairXboxKrnl17559ErrorBookmarksV2 extends GhidraScript {
    private static final String ORIGINAL_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String NORMALIZED_SHA =
        "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85";
    private static final String LANG = "PowerPC:BE:64:A2ALT-32addr";
    private static final String PREFIX = "Verified Xenon opcode: ";

    private static class MissingInsn {
        final long address;
        final long encodedWord;
        final String mnemonic;
        MissingInsn(long a, long w, String m) {
            address = a; encodedWord = w; mnemonic = m;
        }
    }

    private static final MissingInsn[] MISSING = {
        new MissingInsn(0x80144DA0L, 0x10EBE8C3L, "lvx128"),
        new MissingInsn(0x80143584L, 0x11A058C3L, "lvx128"),
        new MissingInsn(0x80141E6CL, 0x1140D8C3L, "lvx128"),
        new MissingInsn(0x80141B40L, 0x7DB8540EL, "lvlx"),
        new MissingInsn(0x8013140CL, 0x100048C3L, "lvx128"),
        new MissingInsn(0x80131240L, 0x118048C3L, "lvx128"),
        new MissingInsn(0x8012D3D0L, 0x100018C3L, "lvx128"),
        new MissingInsn(0x8012D080L, 0x100058C3L, "lvx128"),
        new MissingInsn(0x8012CF1CL, 0x7D605C0EL, "lvlx"),
        new MissingInsn(0x800CE9A4L, 0x192467F0L, "vupkd3d128"),
        new MissingInsn(0x800CD580L, 0x7D405C0EL, "lvlx"),
        new MissingInsn(0x800CD3E4L, 0x7C00540EL, "lvlx"),
        new MissingInsn(0x800CC918L, 0x100058C3L, "lvx128"),
        new MissingInsn(0x800CC17CL, 0x112058C3L, "lvx128"),
        new MissingInsn(0x800CBEE0L, 0x1005D8C3L, "lvx128"),
        new MissingInsn(0x800BD030L, 0x7DAB244EL, "lvrx")
    };

    private Address addr(long a) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
    }

    private long readWord(long address) throws Exception {
        Memory memory = currentProgram.getMemory();
        long value = 0;
        for (int i=0; i<4; ++i) {
            value = (value << 8) | (memory.getByte(addr(address).add(i)) & 0xffL);
        }
        return value;
    }

    @Override
    public void run() throws Exception {
        String hash = currentProgram.getExecutableSHA256();
        if (!(ORIGINAL_SHA.equalsIgnoreCase(hash) || NORMALIZED_SHA.equalsIgnoreCase(hash)) ||
            !LANG.equals(currentProgram.getLanguageID().getIdAsString()) ||
            currentProgram.getImageBase().getOffset() != 0x80040000L ||
            readWord(0x80061010L) != 0x7D8802A6L ||
            readWord(0x80089EB0L) != 0x7D8802A6L) {
            printerr("Wrong kernel, language, or section mapping; nothing changed.");
            return;
        }

        final long BUGCHECK = 0x800716E8L;
        final long CALL = 0x80073730L;
        final long PADDING = 0x80073734L;
        if (readWord(CALL) != 0x4BFFDFB9L || readWord(PADDING) != 0L ||
            readWord(0x80073690L) != 0x808D0100L) {
            printerr("KeLeaveUserMode instruction bytes differ; nothing changed.");
            return;
        }

        Function bugcheck = currentProgram.getFunctionManager().getFunctionAt(addr(BUGCHECK));
        Instruction fatalCall = currentProgram.getListing().getInstructionAt(addr(CALL));
        if (bugcheck == null || fatalCall == null ||
            !"bl".equalsIgnoreCase(fatalCall.getMnemonicString())) {
            printerr("KeBugCheckEx function or KeLeaveUserMode fatal call missing; no changes.");
            return;
        }

        boolean noreturnChanged = false, callChanged = false;
        if (!bugcheck.hasNoReturn()) {
            bugcheck.setNoReturn(true);
            noreturnChanged = true;
        }
        if (fatalCall.getFlowOverride() != FlowOverride.CALL_RETURN) {
            fatalCall.setFlowOverride(FlowOverride.CALL_RETURN);
            callChanged = true;
        }

        int bookmarksRemoved = 0;
        BookmarkManager bookmarks = currentProgram.getBookmarkManager();
        for (Bookmark bookmark : bookmarks.getBookmarks(addr(PADDING), BookmarkType.ERROR)) {
            String comment = bookmark.getComment();
            if ("Bad Instruction".equals(bookmark.getCategory()) &&
                comment != null &&
                comment.toLowerCase(Locale.ROOT).contains(
                    "unable to resolve constructor at 80073734 (flow from 80073730)")) {
                bookmarks.removeBookmark(bookmark);
                bookmarksRemoved++;
            }
        }

        int commentsAdded = 0, alreadyPresent = 0, opcodeMismatches = 0;
        for (MissingInsn entry : MISSING) {
            monitor.checkCancelled();
            if (readWord(entry.address) != entry.encodedWord) {
                opcodeMismatches++;
                printerr(String.format("Opcode mismatch at 0x%08X: expected 0x%08X",
                    entry.address, entry.encodedWord));
                continue;
            }
            CodeUnit unit = currentProgram.getListing().getCodeUnitAt(addr(entry.address));
            if (unit == null) {
                opcodeMismatches++;
                printerr(String.format("No code unit at 0x%08X", entry.address));
                continue;
            }
            String text = String.format(
                "%s%s (word 0x%08X; verified with Xenia PPC opcode lookup; " +
                "requires actual Xenon SLEIGH decode/p-code).",
                PREFIX, entry.mnemonic, entry.encodedWord);
            String existing = unit.getComment(CommentType.EOL);
            if (existing != null && existing.contains(text)) {
                alreadyPresent++;
                continue;
            }
            unit.setComment(CommentType.EOL,
                existing == null || existing.isBlank() ? text : existing + "\n" + text);
            commentsAdded++;
        }

        println(String.format("KeBugCheckEx NoReturn changed=%s; 0x80073730 CALL_RETURN changed=%s",
            noreturnChanged, callChanged));
        println("Precisely matched stale padding bookmarks deleted=" + bookmarksRemoved);
        println(String.format("Verified Xenon vector comments added=%d, existing=%d, mismatches=%d",
            commentsAdded, alreadyPresent, opcodeMismatches));
        println("Other 16 true decoder-error bookmarks intentionally retained.");
        println("Program bytes, instruction opcodes/p-code, function bodies and signatures unchanged.");
    }
}
