// Audit post-reanalysis functions/bookmarks; add only proven provenance comments.
//@category Xbox360
//
// Target: retail 17559 Xbox kernel imported with the Xenon language.
// Safe metadata only: no function creation/deletion, type changes, code
// disassembly, bookmark deletion, p-code edits, or guessed function renames.
// Apply one concise comment to exact Found-Code function entries outside
// every recorded .pdata unwind range. Re-running is idempotent.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AuditAnnotateXboxKrnl17559ReanalysisV1 extends GhidraScript {
    // Change to false to produce a completely read-only report.
    private static final boolean APPLY_SAFE_METADATA = true;
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final Pattern UNWIND = Pattern.compile(
        "Verified retail 17559 \\.pdata extent: 0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)");
    private static final String PROVENANCE =
        "GZF10 reanalysis: Ghidra's 'Found Code' bookmark identifies this " +
        "function entry outside all 3,188 verified 17559 .pdata ranges. " +
        "Potential unwindless/leaf function; not proof of a hardware entrypoint.";
    private static final int MAX_DETAILS = 45;

    private static class Span {
        long start;
        long end;
        Span(long start, long end) {
            this.start = start;
            this.end = end;
        }
    }

    private static Span findSpan(List<Span> spans, long address) {
        int low = 0, high = spans.size() - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            Span s = spans.get(mid);
            if (address < s.start) high = mid - 1;
            else if (address >= s.end) low = mid + 1;
            else return s;
        }
        return null;
    }

    private boolean recognizedSharedEntry(long address, Span unwind) {
        long first;
        String mnemonic;
        String registerPrefix;
        if (unwind.start == 0x8010CB90L &&
            unwind.end == 0x8010CBE0L) {
            first = 0x8010CB90L;
            mnemonic = "std";
            registerPrefix = "r";
        }
        else if (unwind.start == 0x8010D240L &&
                 unwind.end == 0x8010D28CL) {
            first = 0x8010D240L;
            mnemonic = "stfd";
            registerPrefix = "f";
        }
        else if (unwind.start == 0x8010D28CL &&
                 unwind.end == 0x8010D2D8L) {
            first = 0x8010D28CL;
            mnemonic = "lfd";
            registerPrefix = "f";
        }
        else return false;
        long offset = address - first;
        if (offset <= 0 || offset >= 18 * 4 || (offset % 4) != 0)
            return false;
        Instruction i = currentProgram.getListing()
            .getInstructionAt(toAddr(address));
        if (i == null || !mnemonic.equals(i.getMnemonicString()) ||
                i.getRegister(0) == null) return false;
        int n = 14 + (int)(offset / 4);
        String name = i.getRegister(0).getName().toLowerCase(
            java.util.Locale.ROOT);
        return name.equals(registerPrefix + n) ||
            ("f".equals(registerPrefix) && name.equals("fr" + n));
    }

    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    @Override
    public void run() throws Exception {
        require("PowerPC:BE:64:XENON-32addr".equals(
            currentProgram.getLanguageID().toString()),
            "Requires Xenon kernel language");
        require(SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "Unexpected image SHA-256; this script is only for verified 17559");
        require("Xbox 360 Kernel 17559 Memory Image PE".equals(
            currentProgram.getExecutableFormat()),
            "Requires verified memory-image PE import");

        List<Span> spans = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        List<Function> allFunctions = new ArrayList<>();
        FunctionIterator fit =
            currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            monitor.checkCancelled();
            Function f = fit.next();
            allFunctions.add(f);
            String note = f.getRepeatableComment();
            if (note == null) continue;
            Matcher m = UNWIND.matcher(note);
            if (!m.find()) continue;
            long start = Long.parseLong(m.group(1), 16);
            long end = Long.parseLong(m.group(2), 16);
            String key = start + ":" + end;
            if (seen.add(key)) spans.add(new Span(start, end));
        }
        Collections.sort(spans, Comparator.comparingLong(s -> s.start));
        for (int i = 1; i < spans.size(); i++) {
            require(spans.get(i - 1).end <= spans.get(i).start,
                "Overlapping recorded .pdata spans: requires manual inspection");
        }
        println("XBOXKRNL 17559 POST-REANALYSIS AUDIT");
        println("Kernel SHA-256 verified, language and loader verified");
        println("Functions=" + allFunctions.size() +
            " distinct .pdata annotations=" + spans.size());

        int pdataEntry = 0, outside = 0, interior = 0;
        int recognizedHelpers = 0, needsReview = 0;
        int suspiciousPrinted = 0;
        for (Function f : allFunctions) {
            monitor.checkCancelled();
            long at = f.getEntryPoint().getOffset();
            Span s = findSpan(spans, at);
            if (s == null) {
                ++outside;
            }
            else if (s.start == at) {
                ++pdataEntry;
            }
            else {
                ++interior;
                boolean helper = recognizedSharedEntry(at, s);
                if (helper) recognizedHelpers++; else needsReview++;
                if (suspiciousPrinted++ < MAX_DETAILS) {
                    println("  " + (helper ? "MULTI-ENTRY HELPER" : "REVIEW") +
                        ": function " + f.getName() +
                        " at " + f.getEntryPoint() +
                        " starts inside .pdata 0x" +
                        Long.toHexString(s.start) + "..0x" +
                        Long.toHexString(s.end) + " (exclusive)");
                }
            }
        }
        println("Function entries at .pdata start=" + pdataEntry +
            ", outside all spans=" + outside +
            ", inside another .pdata span=" + interior);
        println("Verified GPR/FPR shared helper entries=" + recognizedHelpers +
            ", other nested entries needing review=" + needsReview);
        println("Multiple entrypoints can be intentional; do not merge just for overlap.");

        Listing listing = currentProgram.getListing();
        BookmarkManager bookmarks = currentProgram.getBookmarkManager();
        Iterator<Bookmark> iter = bookmarks.getBookmarksIterator();
        Map<String, Integer> categories = new HashMap<>();
        Set<Long> foundCode = new HashSet<>();
        List<Bookmark> addressTablesInside = new ArrayList<>();
        List<Bookmark> nonReturning = new ArrayList<>();
        List<Bookmark> warnings = new ArrayList<>();
        int totalBookmarks = 0;
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Bookmark b = iter.next();
            ++totalBookmarks;
            String cat = b.getCategory();
            categories.put(cat, categories.getOrDefault(cat, 0) + 1);
            long at = b.getAddress().getOffset();
            if ("Found Code".equals(cat) &&
                    "Found code from operand reference".equals(b.getComment())) {
                foundCode.add(at);
            }
            if ("Address Table".equals(cat) &&
                    findSpan(spans, at) != null) {
                addressTablesInside.add(b);
            }
            if ("Non-Returning Function".equals(cat)) {
                nonReturning.add(b);
            }
            String type = b.getTypeString();
            if ("Error".equalsIgnoreCase(type) ||
                    "Warning".equalsIgnoreCase(type) ||
                    "Bad Instruction".equalsIgnoreCase(cat)) {
                warnings.add(b);
            }
        }
        println("Bookmarks total=" + totalBookmarks +
            ", category totals=" + categories);
        println("Found-Code bookmark addresses=" + foundCode.size() +
            ", address tables within .pdata=" + addressTablesInside.size() +
            ", non-returning bookmarks=" + nonReturning.size());
        int foundInside = 0;
        for (long at : foundCode) {
            if (findSpan(spans, at) != null) foundInside++;
        }
        println("Found-Code bookmarks within a .pdata span=" + foundInside);
        println("Address tables within .pdata (data/code conflicts to review):");
        int n = 0, asInstructions = 0, asDefinedData = 0;
        for (Bookmark b : addressTablesInside) {
            Instruction inst = listing.getInstructionContaining(b.getAddress());
            if (inst != null) asInstructions++;
            if (listing.getDefinedDataContaining(b.getAddress()) != null)
                asDefinedData++;
            if (n++ < MAX_DETAILS) {
                Span s = findSpan(spans, b.getAddress().getOffset());
                println("  " + b.getAddress() + " " + b.getComment() +
                    " unwind=0x" + Long.toHexString(s.start) +
                    " instruction=" +
                    (inst == null ? "none" : inst.getMnemonicString()) +
                    " definedData=" +
                    (listing.getDefinedDataContaining(b.getAddress()) != null));
            }
        }
        println("Address-table locations represented by instructions=" +
            asInstructions + ", by defined data=" + asDefinedData);

        for (Bookmark b : nonReturning) {
            Function f = currentProgram.getFunctionManager()
                .getFunctionAt(b.getAddress());
            println("Non-returning discovery at " + b.getAddress() +
                " entryFunction=" + (f == null ? "<none>" : f.getName()) +
                " (no-return status not modified)");
        }
        println("Warning/error bookmarks=" + warnings.size());
        for (int i = 0; i < Math.min(MAX_DETAILS, warnings.size()); i++) {
            Bookmark b = warnings.get(i);
            println("  " + b.getAddress() + " [" + b.getTypeString() +
                " / " + b.getCategory() + "] " + b.getComment());
        }

        boolean safe = spans.size() == 3188 &&
            allFunctions.size() >= 3188 &&
            foundInside == 0;
        // Only exact Found-Code entrypoints OUTSIDE every verified unwind
        // interval can be annotated. Other functions' overlapping spans
        // are reported independently; they do not compromise this subset.
        if (!safe) {
            println("No annotations: verified unwind or Found-Code " +
                "baseline differs.");
        }
        int annotated = 0, already = 0, notEntry = 0;
        if (APPLY_SAFE_METADATA && safe) {
            List<Long> sorted = new ArrayList<>(foundCode);
            Collections.sort(sorted);
            for (long at : sorted) {
                monitor.checkCancelled();
                Address addr = toAddr(at);
                Function f = currentProgram.getFunctionManager()
                    .getFunctionAt(addr);
                if (f == null) { notEntry++; continue; }
                String old = f.getRepeatableComment();
                if (old != null && old.contains(PROVENANCE)) {
                    already++;
                    continue;
                }
                f.setRepeatableComment(
                    (old == null || old.isEmpty()) ? PROVENANCE :
                    old + "\n" + PROVENANCE);
                annotated++;
            }
        }
        println("Provenance metadata: applied=" + annotated +
            ", already present=" + already +
            ", Found-Code locations without function entry=" + notEntry);
        println("No functions created/merged, bytes changed, errors cleared, " +
            "return types inferred, or calling conventions modified.");
        println("AUDIT COMPLETE");
    }
}
