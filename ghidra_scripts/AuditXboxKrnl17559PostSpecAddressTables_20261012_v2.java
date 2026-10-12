// Read-only structural inspection of 85 address-table discoveries after Xenon SLEIGH reanalysis.
// Generated from the user-supplied 2026-10-12 Address Table analysis log.
// Reports mapped absolute-address interpretations; a nonmapped value is not, by itself, an error.
//@category Xbox360

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class AuditXboxKrnl17559PostSpecAddressTables_20261012_v2 extends GhidraScript {
    private static final String SOURCE_SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final long[][] TABLES = {
        {0x80040AA4L, 3},
        {0x80040AB0L, 3},
        {0x80040B24L, 5},
        {0x80042750L, 11},
        {0x800428C4L, 11},
        {0x80042A58L, 12},
        {0x80042CACL, 11},
        {0x80042CE4L, 11},
        {0x80042D88L, 3},
        {0x80042DCCL, 11},
        {0x80042F10L, 11},
        {0x80043048L, 13},
        {0x80043080L, 13},
        {0x800430C4L, 3},
        {0x800430DCL, 3},
        {0x800430ECL, 3},
        {0x80043214L, 3},
        {0x8004322CL, 12},
        {0x80043264L, 12},
        {0x80043294L, 10},
        {0x80043320L, 13},
        {0x80043488L, 5},
        {0x80043D78L, 72},
        {0x80044A0CL, 12},
        {0x80044A5CL, 3},
        {0x80044B1CL, 11},
        {0x80045000L, 5},
        {0x800452C0L, 3},
        {0x80045580L, 3},
        {0x80045E48L, 3},
        {0x8004AA44L, 4},
        {0x8004AADCL, 5},
        {0x8004AB84L, 4},
        {0x8004AC38L, 4},
        {0x8004AD2CL, 4},
        {0x8004AE74L, 4},
        {0x8004AEE8L, 4},
        {0x8004AF6CL, 4},
        {0x8004AFFCL, 4},
        {0x8004B0BCL, 4},
        {0x8004B1BCL, 4},
        {0x8004B25CL, 4},
        {0x8004B30CL, 4},
        {0x8004B3D0L, 4},
        {0x8004B4E4L, 4},
        {0x8004B670L, 4},
        {0x8004B870L, 4},
        {0x8004BD7CL, 5},
        {0x8004BD90L, 10},
        {0x8004BEE0L, 16},
        {0x8004D0D8L, 4},
        {0x8004D0ECL, 8},
        {0x8004D110L, 6},
        {0x8004F188L, 11},
        {0x8004F1CCL, 11},
        {0x8004F204L, 10},
        {0x8004F260L, 11},
        {0x8004F4C8L, 11},
        {0x8004F834L, 4},
        {0x8012FAE0L, 5},
        {0x80142D78L, 16},
        {0x801432F4L, 15},
        {0x8014CA90L, 106},
        {0x8014D24CL, 4},
        {0x8014D294L, 3},
        {0x8014D3D8L, 6},
        {0x80151BD4L, 4},
        {0x8015200CL, 8},
        {0x80152030L, 3},
        {0x80152F60L, 8},
        {0x80153920L, 4},
        {0x801547E8L, 8},
        {0x80155D78L, 4},
        {0x80155E98L, 4},
        {0x80155FA8L, 105},
        {0x80170C74L, 5},
        {0x80172124L, 4},
        {0x80172134L, 6},
        {0x8017232CL, 9},
        {0x80172948L, 3},
        {0x801729E0L, 15},
        {0x8017C2B0L, 14},
        {0x8017C304L, 7},
        {0x8017CBECL, 7},
        {0x8017CCC4L, 7},
    };

    @Override
    public void run() throws Exception {
        if (!LANGUAGE.equals(currentProgram.getLanguageID().toString()) ||
            !SOURCE_SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Expected retail 17559 Xenon kernel; no audit performed");
        }
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        long previousEnd = -1;
        int expectedSlots = 0;
        for (long[] record : TABLES) {
            long start = record[0];
            long end = start + record[1] * 4L;
            if (start < previousEnd || record[1] < 1) {
                throw new IllegalStateException("Overlapping/invalid generated table ranges");
            }
            previousEnd = end;
            expectedSlots += (int) record[1];
        }
        if (TABLES.length != 85 || expectedSlots != 850) {
            throw new IllegalStateException("Unexpected table list; aborting audit");
        }

        int unreadableTotal = 0, unmappedTotal = 0, instructionOverlapTotal = 0;
        int typedTotal = 0, functionTargetTotal = 0, codeTargetTotal = 0;
        int mappedTotal = 0, zeroTotal = 0;
        println("ADDRESS TABLE AUDIT (read-only): 85 nonoverlapping base ranges, 850 BE32 slots");
        println("TABLE start count mapped unmapped zeros unreadable typedCells instructionOverlap functionEntryTargets instructionTargets");
        for (long[] record : TABLES) {
            monitor.checkCancelled();
            long start = record[0];
            int count = (int) record[1];
            int mapped = 0, unmapped = 0, zeros = 0, unreadable = 0;
            int typedCells = 0, instructionOverlap = 0, functionTarget = 0, codeTarget = 0;
            for (int i = 0; i < count; i++) {
                monitor.checkCancelled();
                Address cell = toAddr(start + i * 4L);
                if (listing.getInstructionContaining(cell) != null) instructionOverlap++;
                Data data = listing.getDefinedDataContaining(cell);
                if (data != null) typedCells++;
                try {
                    long value = Integer.toUnsignedLong(memory.getInt(cell, true));
                    if (value == 0) zeros++;
                    Address destination = toAddr(value);
                    if (memory.contains(destination)) {
                        mapped++;
                        if (currentProgram.getFunctionManager().getFunctionAt(destination) != null)
                            functionTarget++;
                        if (listing.getInstructionContaining(destination) != null)
                            codeTarget++;
                    }
                    else {
                        unmapped++;
                    }
                }
                catch (MemoryAccessException error) {
                    unreadable++;
                }
            }
            mappedTotal += mapped; unmappedTotal += unmapped;
            zeroTotal += zeros; unreadableTotal += unreadable;
            typedTotal += typedCells; instructionOverlapTotal += instructionOverlap;
            functionTargetTotal += functionTarget; codeTargetTotal += codeTarget;
            println(String.format(
                "TABLE %08X %d %d %d %d %d %d %d %d %d",
                start, count, mapped, unmapped, zeros, unreadable, typedCells,
                instructionOverlap, functionTarget, codeTarget));
            if (unreadable > 0 || instructionOverlap > 0) {
                println(String.format("REVIEW %08X: unreadable slots=%d; live instruction overlaps=%d",
                    start, unreadable, instructionOverlap));
            }
        }
        int functions = 0, autoFunctions = 0, annotatedPdata = 0;
        int obsoleteCR0 = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            functions++;
            if (function.getName().startsWith("FUN_")) autoFunctions++;
            String comment = function.getRepeatableComment();
            if (comment != null) {
                if (comment.contains("Verified retail 17559 .pdata extent")) annotatedPdata++;
                if (comment.contains("Current lift uses 64-bit CR0 for addic./subic.")) obsoleteCR0++;
            }
        }
        println("SUMMARY tables=85 slots=850 mappedAbsolute=" + mappedTotal +
            " unmappedAbsolute=" + unmappedTotal + " zeros=" + zeroTotal +
            " unreadable=" + unreadableTotal + " typedCells=" + typedTotal +
            " instructionOverlap=" + instructionOverlapTotal +
            " functionEntryTargets=" + functionTargetTotal +
            " instructionTargets=" + codeTargetTotal);
        println("PROGRAM functions=" + functions + " autoNamed=" + autoFunctions +
            " pdataComments=" + annotatedPdata + " staleCR0Comments=" + obsoleteCR0);
        println("INTERPRETATION: unmapped raw32 values may be offsets, sentinel values," +
            " or invalid pointers. No data, symbols, functions, comments, or bookmarks changed.");
    }
}
