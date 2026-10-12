// Read-only target classification for 85 verified address-table discoveries after Xenon SLEIGH reanalysis.
// Generated from the user-supplied 2026-10-12 Address Table analysis log.
// Reports mapped absolute-address interpretations; a nonmapped value is not, by itself, an error.
//@category Xbox360

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;
import java.util.Map;
import java.util.TreeMap;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class AuditXboxKrnl17559PostSpecAddressTableTargets_20261012_v1 extends GhidraScript {
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
            throw new IllegalStateException("Wrong kernel SHA256 or processor language; no audit performed");
        }
        int declaredSlots = 0;
        long previousEnd = -1;
        for (long[] row : TABLES) {
            if (row[1] < 1 || row[0] < previousEnd)
                throw new IllegalStateException("Unexpected table overlap");
            previousEnd = row[0] + row[1] * 4L;
            declaredSlots += (int) row[1];
        }
        if (TABLES.length != 85 || declaredSlots != 850)
            throw new IllegalStateException("Unexpected table inventory; no audit performed");

        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        int entries = 0, codeAtStart = 0, codeMidInstruction = 0;
        int functionEntries = 0, otherInstructionStarts = 0;
        int dataTargets = 0, undefinedTargets = 0, nonCodeInsideFunction = 0;
        int nonMapped = 0, unreadable = 0, undefinedSource = 0;
        int flagged = 0;
        Map<String, Integer> sourceTypes = new TreeMap<>();
        Map<String, Integer> targetTypes = new TreeMap<>();
        println("POST-SPEC TARGET CLASSIFICATION (read only)");
        println("TABLE start slots fnEntry otherCodeStart midInstruction typedNonCode undefinedNonCode nonCodeWithinFunction");
        for (long[] row : TABLES) {
            monitor.checkCancelled();
            long tableBase = row[0];
            int slots = (int) row[1];
            int tableFn = 0, tableOther = 0, tableMid = 0;
            int tableData = 0, tableUndefined = 0, tableFnGap = 0;
            for (int i = 0; i < slots; i++) {
                monitor.checkCancelled();
                Address cell = toAddr(tableBase + (long) i * 4L);
                entries++;
                Data source = listing.getDefinedDataContaining(cell);
                if (source == null) {
                    undefinedSource++;
                } else {
                    String key = source.getDataType().getDisplayName();
                    sourceTypes.put(key, sourceTypes.getOrDefault(key, 0) + 1);
                }
                long raw;
                try {
                    raw = Integer.toUnsignedLong(memory.getInt(cell, true));
                } catch (MemoryAccessException e) {
                    unreadable++;
                    if (flagged++ < 100)
                        println(String.format("REVIEW UNREADABLE source=%s", cell));
                    continue;
                }
                Address destination = toAddr(raw);
                if (!memory.contains(destination)) {
                    nonMapped++;
                    if (flagged++ < 100)
                        println(String.format("REVIEW UNMAPPED source=%s raw=%08X", cell, raw));
                    continue;
                }
                Instruction instruction = listing.getInstructionContaining(destination);
                if (instruction != null) {
                    if (!instruction.getMinAddress().equals(destination)) {
                        codeMidInstruction++;
                        tableMid++;
                        if (flagged++ < 100)
                            println("REVIEW MID_INSTRUCTION source=" + cell + " target=" +
                                destination + " instruction=" + instruction.getMinAddress());
                    } else if (currentProgram.getFunctionManager().getFunctionAt(destination) != null) {
                        functionEntries++;
                        tableFn++;
                    } else {
                        otherInstructionStarts++;
                        tableOther++;
                    }
                    codeAtStart += instruction.getMinAddress().equals(destination) ? 1 : 0;
                    continue;
                }
                Data target = listing.getDefinedDataContaining(destination);
                if (target != null) {
                    dataTargets++;
                    tableData++;
                    String key = target.getDataType().getDisplayName();
                    targetTypes.put(key, targetTypes.getOrDefault(key, 0) + 1);
                } else {
                    undefinedTargets++;
                    tableUndefined++;
                }
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(destination);
                if (owner != null) {
                    nonCodeInsideFunction++;
                    tableFnGap++;
                }
                if (target == null || owner != null) {
                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(destination);
                    if (flagged++ < 100)
                        println("REVIEW NONCODE source=" + cell + " target=" + destination +
                            " type=" + (target == null ? "UNDEFINED" : target.getDataType().getDisplayName()) +
                            " containingFunction=" + (owner == null ? "none" : owner.getName()) +
                            " primarySymbol=" + (symbol == null ? "none" : symbol.getName()));
                }
            }
            println(String.format("TABLE %08X %d %d %d %d %d %d %d",
                tableBase, slots, tableFn, tableOther, tableMid, tableData, tableUndefined, tableFnGap));
        }
        println("SUMMARY slots=" + entries + " instructionStarts=" + codeAtStart +
            " functionEntries=" + functionEntries +
            " nonEntryInstructionStarts=" + otherInstructionStarts +
            " midInstruction=" + codeMidInstruction +
            " typedNonCodeTargets=" + dataTargets +
            " undefinedNonCodeTargets=" + undefinedTargets +
            " nonCodeWithinFunction=" + nonCodeInsideFunction +
            " unmapped=" + nonMapped + " unreadable=" + unreadable +
            " undefinedSourceSlots=" + undefinedSource);
        println("DATA TYPES AT SOURCE CELLS: " + sourceTypes);
        println("DATA TYPES AT NONCODE TARGETS: " + targetTypes);
        if (flagged > 100)
            println("Additional review entries suppressed: " + (flagged - 100));
        println("NO MUTATIONS: no bytes, functions, signatures, labels, datatypes, comments or bookmarks changed.");
    }
}
