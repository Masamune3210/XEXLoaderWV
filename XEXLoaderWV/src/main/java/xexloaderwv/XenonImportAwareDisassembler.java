package xexloaderwv;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

/**
 * Xenon disassembler that understands PRE-LINK XEX import thunk relocation
 * records. The first two 32-bit words of a canonical 16-byte thunk are XEX
 * loader tokens, not valid PowerPC instructions. The final mtctr/bctr words
 * are genuine PowerPC code.
 *
 * The XEX loader saves the verified thunk entrypoints in Program options.
 * At every later analysis pass this disassembler excludes those two words
 * from BOTH disassembly seeds and flow-follow destinations. The original
 * bytes and native external thunk function are untouched.
 *
 * On Xbox kernel PE or unrelated Programs without the XEX marker option this
 * behaves identically to the stock Ghidra disassembler. Addresses whose raw
 * bytes have been patched to real PPC code at a later point are not masked.
 */
public class XenonImportAwareDisassembler extends Disassembler {
    public static final String XEX_THUNK_OPTIONS = "XEX Import Thunks";
    public static final String XEX_THUNK_ENTRIES =
        "Pre-link Relocation Token Entrypoints";

    private final Program importProgram;
    private final AddressSet relocationTokens;

    // Required by Ghidra's language-specific disassembler factory.
    public XenonImportAwareDisassembler(Program program, TaskMonitor monitor,
            DisassemblerMessageListener listener) {
        super(program, monitor, listener);
        importProgram = program;
        relocationTokens = identifyRelocationTokens(program);
    }

    public XenonImportAwareDisassembler(Program program,
            boolean markBadInstructions, boolean markUnimplementedPcode,
            boolean restrictToExecuteMemory, TaskMonitor monitor,
            DisassemblerMessageListener listener) {
        super(program, markBadInstructions, markUnimplementedPcode,
            restrictToExecuteMemory, monitor, listener);
        importProgram = program;
        relocationTokens = identifyRelocationTokens(program);
    }

    public XenonImportAwareDisassembler(Language language,
            AddressFactory addressFactory, TaskMonitor monitor,
            DisassemblerMessageListener listener) {
        super(language, addressFactory, monitor, listener);
        importProgram = null; // pseudo-disassembly outside any Program
        relocationTokens = new AddressSet();
    }

    /**
     * Only trust addresses explicitly registered by the XEX loader or repair
     * script, and only while all 16 source bytes remain canonical.
     * Re-resolve on each Disassembler construction so a reopened Program's
     * settings are effective on every analysis rerun.
     */
    private static AddressSet identifyRelocationTokens(Program program) {
        AddressSet result = new AddressSet();
        if (program == null) {
            return result;
        }
        String encoded = program.getOptions(XEX_THUNK_OPTIONS)
            .getString(XEX_THUNK_ENTRIES, "");
        if (encoded.isEmpty()) {
            return result;
        }

        Memory memory = program.getMemory();
        byte[] words = new byte[16];
        for (String item : encoded.split(",")) {
            try {
                long value = Long.parseUnsignedLong(item.strip(), 16);
                Address entry = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(value);
                if (memory.getBytes(entry, words) != words.length ||
                        !isCanonicalTokenPair(words)) {
                    continue;
                }
                // Protect JUST +0..+7. +8 and +12 remain actual PPC code.
                result.add(entry, entry.add(7));
            }
            catch (Exception ignored) {
                // An out-of-range, stale or modified marker is NEVER reason
                // to suppress disassembly at another address.
            }
        }
        return result;
    }

    private static boolean isCanonicalTokenPair(byte[] b) {
        if (b[0] != 0x01 || b[1] != 0x00 ||
                b[4] != 0x02 || b[5] != 0x00 ||
                b[2] != b[6] || b[3] != b[7]) {
            return false;
        }
        final int[] tail = {0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20};
        for (int i = 0; i < tail.length; i++) {
            if ((b[i + 8] & 0xff) != tail[i]) {
                return false;
            }
        }
        return true;
    }

    private AddressSetView withoutTokens(AddressSetView restrictedSet) {
        if (relocationTokens.isEmpty() || importProgram == null) {
            return restrictedSet;
        }
        // 'null' means unrestricted to the generic disassembler. Supplying
        // a concrete set is essential so it won't follow bl targets into
        // the token bytes from another instruction.
        AddressSet allowed = restrictedSet == null
            ? new AddressSet(importProgram.getMemory().getLoadedAndInitializedAddressSet())
            : new AddressSet(restrictedSet);
        allowed.delete(relocationTokens);
        return allowed;
    }

    @Override
    public AddressSet disassemble(Address start,
            AddressSetView restrictedSet, RegisterValue initialContextValue,
            boolean followFlow) {
        if (relocationTokens.contains(start)) {
            return new AddressSet();
        }
        return super.disassemble(start, withoutTokens(restrictedSet),
            initialContextValue, followFlow);
    }

    @Override
    public AddressSet disassemble(AddressSetView starts,
            AddressSetView restrictedSet, RegisterValue initialContextValue,
            boolean followFlow) {
        if (relocationTokens.isEmpty()) {
            return super.disassemble(starts, restrictedSet,
                initialContextValue, followFlow);
        }
        AddressSet seeds = new AddressSet(starts);
        seeds.delete(relocationTokens);
        if (seeds.isEmpty()) {
            return new AddressSet();
        }
        return super.disassemble(seeds, withoutTokens(restrictedSet),
            initialContextValue, followFlow);
    }
}
