// @category Xbox360
// Read-only smoke test for the experimental isolated Xenon SLEIGH language.
// Import a COPY of verified retail 17559 xboxkrnl with this variant selected,
// then run Auto Analyze. Do not alter the existing A2ALT kernel Program.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class VerifyXboxKrnl17559XenonDecodeV1 extends GhidraScript {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String ORIGINAL =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String NORMALIZED =
        "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85";
    private static class Expect {
        final long address;
        final int word;
        final String mnemonic;
        Expect(long a, int w, String name) { address=a; word=w; mnemonic=name; }
    }
    private static final Expect[] CASES = {
        new Expect(0x80144DA0L, 0x10EBE8C3, "lvx128"),
        new Expect(0x80143584L, 0x11A058C3, "lvx128"),
        new Expect(0x80141E6CL, 0x1140D8C3, "lvx128"),
        new Expect(0x80141B40L, 0x7DB8540E, "lvlx"),
        new Expect(0x8013140CL, 0x100048C3, "lvx128"),
        new Expect(0x80131240L, 0x118048C3, "lvx128"),
        new Expect(0x8012D3D0L, 0x100018C3, "lvx128"),
        new Expect(0x8012D080L, 0x100058C3, "lvx128"),
        new Expect(0x8012CF1CL, 0x7D605C0E, "lvlx"),
        new Expect(0x800CE9A4L, 0x192467F0, "vupkd3d128"),
        new Expect(0x800CD580L, 0x7D405C0E, "lvlx"),
        new Expect(0x800CD3E4L, 0x7C00540E, "lvlx"),
        new Expect(0x800CC918L, 0x100058C3, "lvx128"),
        new Expect(0x800CC17CL, 0x112058C3, "lvx128"),
        new Expect(0x800CBEE0L, 0x1005D8C3, "lvx128"),
        new Expect(0x800BD030L, 0x7DAB244E, "lvrx")
    };
    private Address addr(long a) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
    }
    private int readWord(long a) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address start = addr(a);
        int value = 0;
        for (int i=0;i<4;i++) value = (value << 8)|(mem.getByte(start.add(i))&255);
        return value;
    }
    @Override
    public void run() throws Exception {
        String sha = currentProgram.getExecutableSHA256();
        if ((!ORIGINAL.equalsIgnoreCase(sha) && !NORMALIZED.equalsIgnoreCase(sha)) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            currentProgram.getImageBase().getOffset()!=0x80040000L ||
            readWord(0x80061010L)!=0x7D8802A6) {
            printerr("Not the verified kernel imported with isolated XENON-32addr; aborting.");
            return;
        }
        int decoded=0, wrong=0, missing=0, errors=0;
        for (Expect test:CASES) {
            monitor.checkCancelled();
            Address address=addr(test.address);
            if (readWord(test.address)!=test.word) {
                println(String.format("CORRUPT BYTES %08X",test.address));
                wrong++;
                continue;
            }
            Instruction insn=currentProgram.getListing().getInstructionAt(address);
            if (insn==null) {
                missing++;
                println(String.format("NOT DECODED %08X %08X %s",test.address,
                    test.word,test.mnemonic));
            }
            else if (!test.mnemonic.equalsIgnoreCase(insn.getMnemonicString())) {
                wrong++;
                println(String.format("WRONG OPCODE %08X expected=%s actual=%s",
                    test.address,test.mnemonic,insn.getMnemonicString()));
            }
            else {
                decoded++;
                println(String.format("DECODED %08X %s",test.address,test.mnemonic));
            }
            for (Bookmark bookmark:currentProgram.getBookmarkManager().getBookmarks(
                address, BookmarkType.ERROR)) {
                errors++;
                println("  remaining error bookmark: " + bookmark.getCategory()
                    + " " + bookmark.getComment());
            }
        }
        println("================================================");
        println(String.format("Xenon decoder test: decoded=%d/16 missing=%d wrong=%d",
            decoded,missing,wrong));
        println("Bad/other error bookmarks at these 16 addresses="+errors);
        println("If decoded<16, preserve database and send this log; no mutation done.");
        println("Decoded instructions are necessary but not proof numeric userop semantics.");
    }
}
