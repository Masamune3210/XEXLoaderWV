// @category Xbox360
// Targeted follow-up for the verified 17559 Xenon-language Ghidra archive.
// Checks 16 original, 13 second-phase, and 8 word-merge VMX128 instructions.
// On a fresh Program, it is a decoder audit; on a Program upgraded to
// the newer SLEIGH .sla, it tries bounded 4-byte disassembly and removes
// ONLY precisely matching stale Bad Instruction bookmarks AFTER checking
// the correct mnemonic. Preserves all program bytes, functions and labels.
import java.util.Locale;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class RepairAuditXboxKrnl17559XenonVmxV3 extends GhidraScript {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String ORIGINAL =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String NORMALIZED =
        "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85";
    private static class Expect {
        final long address;
        final long word;
        final String mnemonic;
        Expect(long a, long w, String name) {address=a; word=w; mnemonic=name;}
    }
    private static final Expect[] CASES = {
        new Expect(0x80144DA0L, 0x10EBE8C3L, "lvx128"),
        new Expect(0x80143584L, 0x11A058C3L, "lvx128"),
        new Expect(0x80141E6CL, 0x1140D8C3L, "lvx128"),
        new Expect(0x80141B40L, 0x7DB8540EL, "lvlx"),
        new Expect(0x8013140CL, 0x100048C3L, "lvx128"),
        new Expect(0x80131240L, 0x118048C3L, "lvx128"),
        new Expect(0x8012D3D0L, 0x100018C3L, "lvx128"),
        new Expect(0x8012D080L, 0x100058C3L, "lvx128"),
        new Expect(0x8012CF1CL, 0x7D605C0EL, "lvlx"),
        new Expect(0x800CE9A4L, 0x192467F0L, "vupkd3d128"),
        new Expect(0x800CD580L, 0x7D405C0EL, "lvlx"),
        new Expect(0x800CD3E4L, 0x7C00540EL, "lvlx"),
        new Expect(0x800CC918L, 0x100058C3L, "lvx128"),
        new Expect(0x800CC17CL, 0x112058C3L, "lvx128"),
        new Expect(0x800CBEE0L, 0x1005D8C3L, "lvx128"),
        new Expect(0x800BD030L, 0x7DAB244EL, "lvrx"),
        new Expect(0x80145000L, 0x196E6290L, "vpermwi128"),
        new Expect(0x80144EFCL, 0x192E6A90L, "vpermwi128"),
        new Expect(0x80144E90L, 0x19AE6A90L, "vpermwi128"),
        new Expect(0x80141ED8L, 0x142C01D0L, "vmsum4fp128"),
        new Expect(0x80141BC4L, 0x17CC01D0L, "vmsum4fp128"),
        new Expect(0x801314A0L, 0x14290090L, "vmulfp128"),
        new Expect(0x801312D0L, 0x14E75890L, "vmulfp128"),
        new Expect(0x8012D3DCL, 0x15A06890L, "vmulfp128"),
        new Expect(0x8012D088L, 0x100759C3L, "stvx128"),
        new Expect(0x800CE9E0L, 0x180417D0L, "vrlimi128"),
        new Expect(0x800CD594L, 0x180467D0L, "vrlimi128"),
        new Expect(0x800CD3F0L, 0x180467D0L, "vrlimi128"),
        new Expect(0x800BD040L, 0x17806ADCL, "vor128"),
        new Expect(0x800BD280L, 0x1918B763L, "vmrglw128"),
        new Expect(0x800BD2B8L, 0x19B8B723L, "vmrghw128"),
        new Expect(0x800BD2C4L, 0x1999BF63L, "vmrglw128"),
        new Expect(0x800BD2CCL, 0x1819BF23L, "vmrghw128"),
        new Expect(0x800BD35CL, 0x193BAF63L, "vmrglw128"),
        new Expect(0x800BD360L, 0x195CD763L, "vmrglw128"),
        new Expect(0x800BD364L, 0x18FBAF23L, "vmrghw128"),
        new Expect(0x800BD368L, 0x191CD723L, "vmrghw128")
    };
    private Address addr(long a) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
    }
    private long readWord(long a) throws Exception {
        Memory mem = currentProgram.getMemory();
        long value = 0;
        for (int i=0; i<4; i++)
            value=(value<<8)|(mem.getByte(addr(a).add(i))&0xffL);
        return value;
    }
    @Override
    public void run() throws Exception {
        String sha = currentProgram.getExecutableSHA256();
        if (!(ORIGINAL.equalsIgnoreCase(sha) || NORMALIZED.equalsIgnoreCase(sha)) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            currentProgram.getImageBase().getOffset()!=0x80040000L ||
            readWord(0x80061010L)!=0x7D8802A6L) {
            printerr("Not the correct mapped retail 17559 Xenon Program; no changes.");
            return;
        }
        int pass=0, missing=0, wrong=0, badBytes=0, retried=0, cleared=0;
        List<String> issues = new ArrayList<>();
        for (Expect test: CASES) {
            monitor.checkCancelled();
            Address a=addr(test.address);
            if (readWord(test.address)!=test.word) {
                badBytes++;
                issues.add(String.format("BAD OPCODE BYTES 0x%08X expected %08X",
                    test.address,test.word));
                continue;
            }
            Instruction instruction=currentProgram.getListing().getInstructionAt(a);
            if (instruction==null &&
                currentProgram.getListing().getInstructionContaining(a)==null &&
                currentProgram.getListing().getDefinedDataContaining(a)==null) {
                DisassembleCommand cmd = new DisassembleCommand(
                    a, new AddressSet(a,a.add(3)), true);
                if (cmd.applyTo(currentProgram, monitor)) retried++;
                instruction=currentProgram.getListing().getInstructionAt(a);
            }
            if (instruction==null) {
                missing++;
                issues.add(String.format("UNDECODED 0x%08X 0x%08X %s",
                    test.address,test.word,test.mnemonic));
                continue;
            }
            if (!test.mnemonic.equalsIgnoreCase(instruction.getMnemonicString())) {
                wrong++;
                issues.add(String.format("WRONG DECODE 0x%08X wanted=%s actual=%s",
                    test.address,test.mnemonic,instruction.getMnemonicString()));
                continue;
            }
            pass++;
            // Delete *only* a pre-existing failed decode record at the same
            // exact bytes, never generic errors or other bookmark categories.
            for (Bookmark mark:currentProgram.getBookmarkManager().getBookmarks(
                    a,BookmarkType.ERROR)) {
                String desc=mark.getComment();
                String expected="unable to resolve constructor at " +
                    String.format("%08x",test.address);
                if ("Bad Instruction".equals(mark.getCategory()) &&
                    desc!=null && desc.toLowerCase(Locale.ROOT).contains(expected)) {
                    currentProgram.getBookmarkManager().removeBookmark(mark);
                    cleared++;
                }
            }
            // Successful sites are counted; leave all actionable issues at the end.
        }
        println("======================================================");
        println(String.format("Xenon 17559 decode: %d/%d correct, %d undecoded, %d wrong, %d opcode mismatches",
            pass,CASES.length,missing,wrong,badBytes));
        println("Newly disassembled instructions=" + retried +
                ", confirmed stale error bookmarks cleared=" + cleared);
        println("A successful decoder audit does not imply complete numerical");
        println("p-code for opaque VMX128 user operations. All bytes, symbols,");
        println("function signatures, and function extents were preserved.");
        println("======================================================");
        println("UNRESOLVED OPCODE/INSTRUCTION STATES (" + issues.size() + ")");
        if (issues.isEmpty()) println("None");
        for (String issue:issues) println(issue);
    }
}
