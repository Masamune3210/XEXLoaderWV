// Read-only audit of Xbox 360 XEX native import-token thunks and kernel links.
// @category Xbox360
//
// Run on an analyzed XEX Program with the XEXLoaderWV extension installed.
// Does not rewrite original token bytes, create functions, or clear bookmarks.
// The native unresolved token words are data from the XEX loader's perspective;
// Ghidra may report Bad Instruction at those bytes even when a thunk is linked.
//
// For original retail 17559 $flash_xam.xex, the known baseline is 443
// canonical xboxkrnl.exe import thunks, but no fixed count is assumed.

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Library;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalManager;

public class AuditXamImportThunkLinksV1 extends GhidraScript {
    private static final String KERNEL_LIBRARY = "xboxkrnl.exe";
    private static final long MTCTR_R11 = 0x7d6903a6L;
    private static final long BCTR = 0x4e800420L;
    private static final long VENEER_LIS = 0x3d600000L;
    private static final long VENEER_ORI = 0x616b0000L;

    private static final class Site {
        final Address address;
        final int ordinal;
        final boolean rawToken;
        Site(Address address, int ordinal, boolean rawToken) {
            this.address = address;
            this.ordinal = ordinal;
            this.rawToken = rawToken;
        }
    }

    private static long unsignedWord(byte[] bytes, int start) {
        long n = 0;
        for (int i = 0; i < 4; i++)
            n = (n << 8) | (bytes[start + i] & 0xffL);
        return n;
    }

    private static boolean isRawImport(long a, long b, long c, long d) {
        return (a & 0xffff0000L) == 0x01000000L &&
            (b & 0xffff0000L) == 0x02000000L &&
            (a & 0xffffL) == (b & 0xffffL) &&
            c == MTCTR_R11 && d == BCTR;
    }

    private static boolean isVeneer(long a, long b, long c, long d) {
        return a == VENEER_LIS && b == VENEER_ORI &&
            c == MTCTR_R11 && d == BCTR;
    }

    private static boolean isKernelNamespace(Function target) {
        if (target == null || !target.isExternal() ||
            target.getParentNamespace() == null)
            return false;
        return KERNEL_LIBRARY.equalsIgnoreCase(
            target.getParentNamespace().getName());
    }

    private static int countBadInstructionBookmarks(
            BookmarkManager manager, Address address) {
        int count = 0;
        for (Bookmark bookmark : manager.getBookmarks(address)) {
            if ("Error".equalsIgnoreCase(bookmark.getType()) &&
                "Bad Instruction".equalsIgnoreCase(bookmark.getCategory()))
                count++;
        }
        return count;
    }

    @Override
    protected void run() throws Exception {
        String language = currentProgram.getLanguage().getLanguageID()
            .getIdAsString();
        if (!language.startsWith("PowerPC:BE:64:")) {
            printerr("Expected Xbox 360 big-endian PowerPC Program, got "
                + language);
            return;
        }

        Memory memory = currentProgram.getMemory();
        BookmarkManager bookmarks = currentProgram.getBookmarkManager();
        FunctionManager functions = currentProgram.getFunctionManager();
        ExternalManager externals = currentProgram.getExternalManager();
        Library library = externals.getExternalLibrary(KERNEL_LIBRARY);
        String linkedProgram = library == null
            ? null : library.getAssociatedProgramPath();

        // Discover 16-byte native import-token stubs directly from Program
        // bytes, independent of existing function labels or thunk creation.
        Map<Address, Site> rawSites = new HashMap<>();
        int unreadableWords = 0;
        int candidateWords = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute())
                continue;
            long start = (block.getStart().getOffset() + 3L) & ~3L;
            long end = block.getEnd().getOffset();
            if (end - start < 15)
                continue;
            byte[] first = new byte[4];
            byte[] rest = new byte[12];
            for (long offset = start; offset <= end - 15; offset += 4) {
                monitor.checkCancelled();
                Address address = block.getStart().getAddressSpace()
                    .getAddress(offset);
                try {
                    if (memory.getBytes(address, first) != 4) {
                        unreadableWords++;
                        continue;
                    }
                    long word0 = unsignedWord(first, 0);
                    if ((word0 & 0xffff0000L) != 0x01000000L)
                        continue;
                    candidateWords++;
                    if (memory.getBytes(address.add(4), rest) != 12) {
                        unreadableWords++;
                        continue;
                    }
                    long word1 = unsignedWord(rest, 0);
                    long word2 = unsignedWord(rest, 4);
                    long word3 = unsignedWord(rest, 8);
                    if (isRawImport(word0, word1, word2, word3))
                        rawSites.put(address, new Site(address,
                            (int)(word0 & 0xffffL), true));
                }
                catch (ghidra.program.model.mem.MemoryAccessException e) {
                    unreadableWords++;
                }
            }
        }

        int linkedKernel = 0;
        int linkedOther = 0;
        int nonThunk = 0;
        int missing = 0;
        int badAtTokenWords = 0;
        int rawBookmarks = 0;
        List<String> problems = new ArrayList<>();

        for (Site site : rawSites.values()) {
            monitor.checkCancelled();
            Function function = functions.getFunctionAt(site.address);
            if (function == null) {
                missing++;
                problems.add(site.address + " ordinal 0x" +
                    Integer.toHexString(site.ordinal) + ": no function");
            }
            else if (!function.isThunk()) {
                nonThunk++;
                problems.add(site.address + " ordinal 0x" +
                    Integer.toHexString(site.ordinal) +
                    ": function is not a Ghidra thunk (" +
                    function.getName() + ")");
            }
            else {
                Function target = function.getThunkedFunction(true);
                if (isKernelNamespace(target)) {
                    linkedKernel++;
                }
                else {
                    linkedOther++;
                    problems.add(site.address + " ordinal 0x" +
                        Integer.toHexString(site.ordinal) +
                        ": thunk target is " +
                        (target == null ? "(unresolved)" :
                         target.getName(true)));
                }
            }
            int first = countBadInstructionBookmarks(bookmarks, site.address);
            int second = countBadInstructionBookmarks(bookmarks,
                site.address.add(4));
            if (first != 0 || second != 0) {
                badAtTokenWords++;
                rawBookmarks += first + second;
            }
        }

        // Enumerate actual modeled thunks too. The optional EXPERIMENTAL
        // loader veneer replaces the two token words and therefore cannot
        // be found by a raw-token byte-pattern scan. This avoids falsely
        // treating rewritten Program bytes as an absence of thunk functions.
        int allKernelThunks = 0;
        int rawModeledKernel = 0;
        int veneerModeledKernel = 0;
        int otherModeledKernel = 0;
        Set<Address> seen = new HashSet<>();
        FunctionIterator it = functions.getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function function = it.next();
            if (!function.isThunk() ||
                !isKernelNamespace(function.getThunkedFunction(true)))
                continue;
            allKernelThunks++;
            Address entry = function.getEntryPoint();
            if (!seen.add(entry))
                continue;
            byte[] words = new byte[16];
            try {
                if (memory.getBytes(entry, words) != 16) {
                    otherModeledKernel++;
                    problems.add(entry + ": kernel thunk bytes unreadable");
                    continue;
                }
                long a = unsignedWord(words, 0);
                long b = unsignedWord(words, 4);
                long c = unsignedWord(words, 8);
                long d = unsignedWord(words, 12);
                if (isRawImport(a, b, c, d))
                    rawModeledKernel++;
                else if (isVeneer(a, b, c, d))
                    veneerModeledKernel++;
                else {
                    otherModeledKernel++;
                    problems.add(entry + ": kernel thunk has unfamiliar " +
                        String.format(Locale.ROOT,
                            "%08X %08X %08X %08X", a, b, c, d));
                }
            }
            catch (ghidra.program.model.mem.MemoryAccessException e) {
                otherModeledKernel++;
                problems.add(entry + ": kernel thunk byte read failed: " + e);
            }
        }

        println("");
        println("==========================================================");
        println("XEX IMPORT THUNK AND PROJECT KERNEL LINK AUDIT (READ ONLY)");
        println("==========================================================");
        println("Program: " + currentProgram.getName());
        println("Language: " + language);
        println("External library " + KERNEL_LIBRARY + " exists: " +
            (library != null));
        println("Associated project Program path: " +
            (linkedProgram == null ? "(none; namespace alone is not linkage)"
                                   : linkedProgram));
        println("Raw canonical 16-byte import stubs: " + rawSites.size());
        println("Raw candidates with 0x0100 header: " + candidateWords +
            "; unreadable word sites: " + unreadableWords);
        println("Raw stub function state: linked kernel=" + linkedKernel +
            ", linked elsewhere/unresolved=" + linkedOther +
            ", non-thunk=" + nonThunk + ", missing=" + missing);
        println("All modeled kernel thunks: " + allKernelThunks +
            " (raw=" + rawModeledKernel + ", EXPERIMENTAL veneers=" +
            veneerModeledKernel + ", unfamiliar=" + otherModeledKernel + ")");
        println("Raw stub token sites with live Bad Instruction bookmarks: " +
            badAtTokenWords + " (total token-word bookmarks=" +
            rawBookmarks + ")");
        println("A Bad Instruction bookmark on an original unresolved " +
            "token is NOT proof the external Ghidra thunk link failed.");
        println("Original XEX source bytes are not modified by this audit.");
        println("");
        if (library == null)
            problems.add("No " + KERNEL_LIBRARY +
                " external library namespace exists in this Program");
        else if (linkedProgram == null)
            problems.add(KERNEL_LIBRARY + " has no associated Ghidra " +
                "project Program; imports may be named but not linked");
        println("UNRESOLVED / INCORRECT STATES (" + problems.size() + ")");
        if (problems.isEmpty())
            println("None");
        for (String problem : problems)
            println(problem);
    }
}
