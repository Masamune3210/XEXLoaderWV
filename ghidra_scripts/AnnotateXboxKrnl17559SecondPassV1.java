// Compare the second 17559 reanalysis snapshot with the first and apply
// only proven, additive Ghidra metadata (no deleted/rewritten parameters).
//@category Xbox360
//
// Source: xboxkrnl.exe(20261011-022926).gzf vs xboxkrnl.exe(10).gzf.
// New in second snapshot: 5 "Found Code" bookmarks at fixed addresses,
// all outside 3188 unchanged .pdata intervals. New function *names*
// at those addresses are NOT established by the archive.
//
// If the allocator still has its 16 original parameters, names for its
// THREE EXISTING GPR inputs can be refined without touching the 13
// unresolved FPR parameters. ExFreePool's signature is left untouched.

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

public class AnnotateXboxKrnl17559SecondPassV1 extends GhidraScript {
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final Pattern PDATA = Pattern.compile(
        "Verified retail 17559 \\.pdata extent: 0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)");
    private static final long[] ADDED_CODE_BOOKMARKS = {
        0x80067A28L, 0x800D91B0L, 0x800EDB80L, 0x800FD830L, 0x80151088L
    };
    private static final String EVIDENCE =
        "Reanalysis delta (2026-10-11): New 'Found Code from operand " +
        "reference' analysis bookmark absent from previous 17559 snapshot. " +
        "Outside all 3,188 verified .pdata intervals. This does not prove " +
        "that the instruction is a distinct function entry.";

    private static class Interval {
        final long start;
        final long end;
        Interval(long a, long b) { start = a; end = b; }
    }
    private static Interval covering(List<Interval> spans, long at) {
        int low = 0, high = spans.size() - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            Interval interval = spans.get(middle);
            if (at < interval.start) high = middle - 1;
            else if (at >= interval.end) low = middle + 1;
            else return interval;
        }
        return null;
    }

    private void require(boolean valid, String detail) {
        if (!valid) throw new IllegalStateException(detail);
    }

    private List<Interval> verifiedPdata() throws Exception {
        List<Interval> spans = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        FunctionIterator iter = currentProgram.getFunctionManager()
            .getFunctions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function f = iter.next();
            String comment = f.getRepeatableComment();
            if (comment == null) continue;
            Matcher m = PDATA.matcher(comment);
            if (!m.find()) continue;
            long start = Long.parseLong(m.group(1), 16);
            long end = Long.parseLong(m.group(2), 16);
            require(start < end, "Invalid verified .pdata annotation");
            String id = start + ":" + end;
            if (seen.add(id)) spans.add(new Interval(start, end));
        }
        Collections.sort(spans, Comparator.comparingLong(x -> x.start));
        require(spans.size() == 3188,
            "Changed verified .pdata interval count: " + spans.size());
        for (int n = 1; n < spans.size(); n++) {
            require(spans.get(n - 1).end <= spans.get(n).start,
                "Overlapping .pdata intervals, aborting annotations");
        }
        return spans;
    }

    private boolean hasExpectedBookmark(Address address) {
        for (Bookmark bookmark : currentProgram.getBookmarkManager()
                .getBookmarks(address)) {
            if ("Found Code".equals(bookmark.getCategory()) &&
                "Found code from operand reference".equals(
                    bookmark.getComment())) return true;
        }
        return false;
    }

    private boolean allocatorCanRename(Function allocator) {
        if (allocator == null || !("ExAllocatePoolTypeWithTag"
                .equals(allocator.getName()))) return false;
        Parameter[] parameters = allocator.getParameters();
        if (parameters.length != 16) return false;
        String[] stores = {"r3:8", "r4:4", "r5:4"};
        String[] names = {"allocationSize", "allocationTag", "poolSelection"};
        for (int k = 0; k < 3; k++) {
            Parameter p = parameters[13 + k];
            String name = p.getName();
            if (!stores[k].equals(p.getVariableStorage().toString()) ||
                !(name.startsWith("param_") || names[k].equals(name))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void run() throws Exception {
        require("PowerPC:BE:64:XENON-32addr".equals(
            currentProgram.getLanguageID().toString()),
            "Not the verified Xenon language");
        require(SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "Different executable SHA-256");
        require("Xbox 360 Kernel 17559 Memory Image PE".equals(
            currentProgram.getExecutableFormat()), "Different kernel loader");

        List<Interval> spans = verifiedPdata();
        List<CodeUnit> commentTargets = new ArrayList<>();
        println("17559 SECOND-PASS REANALYSIS DELTA");
        println("Verified unchanged .pdata intervals=" + spans.size() +
            ", existing functions=" +
            currentProgram.getFunctionManager().getFunctionCount());

        // Preflight ALL five bookmarks and .pdata memberships BEFORE edits.
        // An address can be a bookmark without yet being an instruction.
        for (long address : ADDED_CODE_BOOKMARKS) {
            monitor.checkCancelled();
            Address at = toAddr(address);
            require(covering(spans, address) == null,
                "New code discovery overlaps verified .pdata: " + at);
            require(hasExpectedBookmark(at),
                "Missing expected second-pass analysis bookmark: " + at);
            Instruction instruction = currentProgram.getListing()
                .getInstructionAt(at);
            Function entry = currentProgram.getFunctionManager()
                .getFunctionAt(at);
            Function owner = currentProgram.getFunctionManager()
                .getFunctionContaining(at);
            println("  " + at +
                " instruction=" + (instruction == null ? "<none>" :
                    instruction.getMnemonicString()) +
                " entryFunction=" + (entry == null ? "<none>" :
                    entry.getName()) +
                " containingFunction=" + (owner == null ? "<none>" :
                    owner.getName()));
            if (instruction != null) commentTargets.add(instruction);
        }

        Function allocator = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(0x800644E8L));
        boolean namesSafe = allocatorCanRename(allocator);
        if (!namesSafe) {
            println("Allocator parameter names not changed: the current " +
                "parameter list/storage does not exactly match the " +
                "observed original 16-parameter layout.");
        }

        int commentsApplied = 0;
        for (CodeUnit code : commentTargets) {
            monitor.checkCancelled();
            String old = code.getComment(CommentType.PRE);
            if (old != null && old.contains(EVIDENCE)) continue;
            code.setComment(CommentType.PRE,
                old == null || old.isEmpty() ? EVIDENCE :
                    old + "\n" + EVIDENCE);
            ++commentsApplied;
        }

        int paramsNamed = 0;
        if (namesSafe) {
            String[] names = {"allocationSize", "allocationTag", "poolSelection"};
            Parameter[] p = allocator.getParameters();
            for (int k = 0; k < 3; k++) {
                if (!names[k].equals(p[13 + k].getName())) {
                    p[13 + k].setName(names[k], SourceType.USER_DEFINED);
                    ++paramsNamed;
                }
            }
        }

        println("New-code provenance comments applied=" + commentsApplied +
            " of " + ADDED_CODE_BOOKMARKS.length + " (decoded instructions only)");
        println("Existing allocator GPR parameters named=" + paramsNamed +
            " (out of three; all unresolved FPR parameters retained)");
        println("All function counts, .pdata intervals, return types, " +
            "argument counts/types/storage, calling conventions, and bytes " +
            "left unchanged. No functions or labels invented.");
    }
}
