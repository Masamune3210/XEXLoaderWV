// Third 17559 GZF scan: preserve native annotations, inspect typed metadata,
// and surface three preexisting PPC arithmetic-width concerns for review.
//@category Xbox360
//
// Source: xboxkrnl.exe(20261011-043046).gzf, compared with the previous
// xboxkrnl.exe(20261011-022926).gzf. All 3,188 verified .pdata intervals
// match; the newer archive contains 110 native annotation strings.
//
// This script ONLY conditionally adds missing source-grounded data labels
// and idempotent NOTE bookmarks at functions that already carry explicit
// native annotations about addic./subic. CR0 widths.
// No functions, prototypes, datatypes, code, bytes, comments or unwind
// boundaries are rewritten. In particular, all inferred FPR inputs remain.

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AuditApplyXboxKrnl17559NativeMetadataPassV1 extends GhidraScript {
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String FORMAT = "Xbox 360 Kernel 17559 Memory Image PE";
    private static final Pattern PDATA = Pattern.compile(
        "Verified retail 17559 \\.pdata extent: 0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)");
    private static final String WIDTH_FLAG =
        "Current lift uses 64-bit CR0 for addic./subic.";
    private static final String REVIEW_CATEGORY = "Xenon arithmetic-width review";
    private static final String REVIEW_TEXT =
        "Native kernel annotation flags possible addic./subic. CR0 width " +
        "disagreement at 32-bit counter wraparound. Verify instruction " +
        "semantics against Xenon before changing SLEIGH or function " +
        "prototypes; architecture-level width is not independently proven.";

    // Addresses and names are already recorded in the newly supplied
    // serialized Program. Do not recreate a type if a declaration is absent.
    private static final long[] DATA_ADDRESSES = {
        0x800418E8L, 0x801A561CL, 0x801B0EE0L, 0x801B0EE8L
    };
    private static final String[] DATA_NAMES = {
        "RtlCrc32LookupTable", "IoCancelSpinLockWord",
        "KeInterruptTime100ns", "KeSystemTime100ns"
    };
    private static final int[] DATA_MIN_LENGTHS = {1024, 4, 8, 8};
    private static final Set<String> STRUCT_NAMES = new HashSet<>(Arrays.asList(
        "CriticalSectionObserved28", "ReadWriteLockObserved56",
        "DispatcherPrefix16", "EventPrefix16", "SemaphorePrefix20",
        "MutantObserved29", "TimerObserved40", "TimerPrefix40",
        "DpcObserved28", "DpcPrefix20", "WaitBlockObserved24",
        "DeviceQueueObserved16", "DeviceQueueEntryObserved13",
        "SListHeaderObserved8", "SListEntry32",
        "UnicodeString32", "AnsiString32", "TimeFieldsObserved16",
        "ApcObserved40"
    ));

    private static class Interval {
        final long start, end;
        Interval(long a, long b) { start = a; end = b; }
    }

    private void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private List<Interval> getVerifiedUnwindRanges() throws Exception {
        List<Interval> intervals = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        FunctionIterator functions = currentProgram.getFunctionManager()
            .getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function f = functions.next();
            String comment = f.getRepeatableComment();
            if (comment == null) continue;
            Matcher m = PDATA.matcher(comment);
            if (!m.find()) continue;
            long start = Long.parseLong(m.group(1), 16);
            long end = Long.parseLong(m.group(2), 16);
            check(start < end, "Invalid .pdata annotation at " + f.getEntryPoint());
            String key = start + ":" + end;
            if (seen.add(key)) intervals.add(new Interval(start, end));
        }
        Collections.sort(intervals, Comparator.comparingLong(i -> i.start));
        check(intervals.size() == 3188,
            "Expected 3188 verified retail unwind intervals, got " +
                intervals.size());
        for (int n = 1; n < intervals.size(); n++) {
            check(intervals.get(n - 1).end <= intervals.get(n).start,
                "Overlapping verified .pdata ranges");
        }
        return intervals;
    }

    private void inspectStructures() throws Exception {
        Set<String> found = new HashSet<>();
        Iterator<DataType> types = currentProgram.getDataTypeManager()
            .getAllDataTypes();
        while (types.hasNext()) {
            monitor.checkCancelled();
            DataType datatype = types.next();
            if (!STRUCT_NAMES.contains(datatype.getName()) ||
                !(datatype instanceof Structure)) continue;
            Structure structure = (Structure) datatype;
            found.add(structure.getName());
            println("STRUCT " + structure.getName() +
                " size=" + structure.getLength() +
                " category=" + structure.getCategoryPath());
            for (DataTypeComponent member : structure.getComponents()) {
                if (member.getFieldName() == null) continue;
                println("  +0x" + Integer.toHexString(member.getOffset()) +
                    " " + member.getDataType().getName() +
                    " " + member.getFieldName() +
                    " length=" + member.getLength());
            }
        }
        println("Recognized new native structures=" + found.size() +
            " (missing type names are not fabricated)");
    }

    private int inspectOrRestoreLabels() throws Exception {
        int applied = 0;
        for (int n = 0; n < DATA_ADDRESSES.length; n++) {
            monitor.checkCancelled();
            Address address = toAddr(DATA_ADDRESSES[n]);
            Symbol primary = currentProgram.getSymbolTable()
                .getPrimarySymbol(address);
            Data data = currentProgram.getListing().getDefinedDataAt(address);
            boolean sufficientlyDefined = data != null &&
                data.getLength() >= DATA_MIN_LENGTHS[n];
            String existing = primary == null ? "<none>" : primary.getName();
            println("GLOBAL " + address + " expected=" + DATA_NAMES[n] +
                " actual=" + existing +
                " definedLength=" + (data == null ? 0 : data.getLength()) +
                " definedType=" +
                (data == null ? "<undefined>" : data.getDataType().getName()));
            if (DATA_NAMES[n].equals(existing)) continue;
            if (!sufficientlyDefined) {
                println("  SKIP: exact required defined-data span absent");
                continue;
            }
            if (primary != null &&
                primary.getSource() != SourceType.DEFAULT) {
                println("  SKIP: preserves existing non-default symbol");
                continue;
            }
            currentProgram.getSymbolTable()
                .createLabel(address, DATA_NAMES[n], SourceType.USER_DEFINED);
            ++applied;
            println("  Added missing verified native data label");
        }
        return applied;
    }

    private int flagPreviouslyObservedWidthQuestions() throws Exception {
        BookmarkManager manager = currentProgram.getBookmarkManager();
        FunctionIterator iter = currentProgram.getFunctionManager()
            .getFunctions(true);
        int matched = 0, added = 0;
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function function = iter.next();
            String nativeComment = function.getRepeatableComment();
            if (nativeComment == null || !nativeComment.contains(WIDTH_FLAG))
                continue;
            ++matched;
            Address at = function.getEntryPoint();
            boolean existing = false;
            for (Bookmark bookmark : manager.getBookmarks(at)) {
                if (BookmarkType.NOTE.equals(bookmark.getTypeString()) &&
                    REVIEW_CATEGORY.equals(bookmark.getCategory()) &&
                    REVIEW_TEXT.equals(bookmark.getComment())) {
                    existing = true;
                    break;
                }
            }
            if (!existing) {
                manager.setBookmark(at, BookmarkType.NOTE,
                    REVIEW_CATEGORY, REVIEW_TEXT);
                ++added;
            }
            println("WIDTH REVIEW " + at + " " + function.getName() +
                " source=native annotation; bookmark already present=" +
                existing);
        }
        println("Explicit native width-question functions=" + matched +
            ", new non-destructive NOTE bookmarks=" + added);
        return added;
    }

    @Override
    public void run() throws Exception {
        check(LANGUAGE.equals(currentProgram.getLanguageID().toString()),
            "Wrong PowerPC language");
        check(SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "Wrong retail kernel image");
        check(FORMAT.equals(currentProgram.getExecutableFormat()),
            "Wrong kernel loader");

        List<Interval> ranges = getVerifiedUnwindRanges();
        println("THIRD 17559 NATIVE METADATA SNAPSHOT");
        println("Verified intact .pdata intervals=" + ranges.size());
        println("Function entries=" +
            currentProgram.getFunctionManager().getFunctionCount());
        inspectStructures();

        int labels = inspectOrRestoreLabels();
        int notes = flagPreviouslyObservedWidthQuestions();
        println("Applied missing data labels=" + labels +
            "; new source-backed review bookmarks=" + notes);
        println("No parameter count, datatype, return type, function body, " +
            "calling convention, instruction bytes, or .pdata range changed.");
        println("Native addic./subic. width mismatch remains an UNVERIFIED " +
            "ISA question; this script does not change arithmetic semantics.");
    }
}
