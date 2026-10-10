package xexloaderwv;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Early metadata pass for the SHA256-verified retail 17559 Xbox 360 kernel PE.
 *
 * The standard Ghidra PE loader still maps the executable. This analyzer runs
 * before normal disassembly/function discovery, using verified big-endian
 * PowerPC .pdata entries to reserve exact, non-overlapping function bodies.
 * It also adds ordinal-export names and leaf-entry seeds. It never rewrites
 * code/data bytes or fabricates function signatures.
 *
 * Deliberately SHA-256-gated: do not treat RGH, devkit, or other retail builds
 * as having the identical .pdata/export layout.
 */
public class Xbox360RetailKernelPdataAnalyzer extends AbstractAnalyzer {
    private static final long BASE = 0x80040000L;
    private static final String SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:A2ALT-32addr";
    private static final long PDATA_START = BASE + 0xFA00L;
    private static final int PDATA_COUNT = 3188;
    private static final long EXPORT_START = BASE + 0x15E00L;
    private static final long TEXT_START = BASE + 0x21000L;
    private static final long TEXT_END_EXCLUSIVE = TEXT_START + 0x1006C8L;
    private static final int EXPORT_COUNT = 931;
    private static final int CODE_EXPORT_COUNT = 886;
    private static final int DATA_EXPORT_COUNT = 35;
    private static final int PDATA_EXPORT_COUNT = 569;

    private static final class Range {
        final long start;
        final long end; // exclusive
        Range(long start, long end) { this.start = start; this.end = end; }
    }

    private static final class Metadata {
        final List<Range> pdata = new ArrayList<>();
        final Map<Long, List<String>> exportNames = new HashMap<>();
        final Set<Long> codeExportsWithoutPdata = new HashSet<>();
    }

    public Xbox360RetailKernelPdataAnalyzer() {
        super("Xbox 360 Retail Kernel 17559 .pdata",
            "Seeds verified retail 17559 PowerPC kernel function boundaries before generic PE analysis",
            AnalyzerType.BYTE_ANALYZER);
        // PE sections are already mapped when this runs. The normal entry-point
        // disassembler runs at BLOCK_ANALYSIS, after FORMAT_ANALYSIS.
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null &&
            LANGUAGE.equals(program.getLanguageID().getIdAsString()) &&
            program.getImageBase().getOffset() == BASE &&
            SHA256.equalsIgnoreCase(program.getExecutableSHA256()) &&
            "Portable Executable (PE)".equals(program.getExecutableFormat());
    }

    private static Address at(Program program, long value) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private static long readU32(Memory memory, Address address, boolean bigEndian) throws Exception {
        long result = 0;
        for (int i = 0; i < 4; i++) {
            int value = memory.getByte(address.add(i)) & 0xFF;
            if (bigEndian) result = (result << 8) | value;
            else result |= (long) value << (i * 8);
        }
        return result & 0xFFFFFFFFL;
    }

    private static void require(boolean ok, String reason) {
        if (!ok) throw new IllegalStateException(reason);
    }

    /**
     * Read and verify EVERYTHING before changing symbols, instructions, or
     * functions. A wrong PE mapping or malformed table cannot half-annotate.
     */
    private static Metadata readAndValidate(Program program, TaskMonitor monitor) throws Exception {
        Memory memory = program.getMemory();
        MemoryBlock pd = memory.getBlock(at(program, PDATA_START));
        MemoryBlock ex = memory.getBlock(at(program, EXPORT_START));
        MemoryBlock tx = memory.getBlock(at(program, TEXT_START));
        require(pd != null && ".pdata".equals(pd.getName()) &&
                pd.getStart().getOffset() == PDATA_START &&
                pd.getSize() >= 0x63A0L && pd.getSize() <= 0x6400L,
            "Unexpected .pdata mapping");
        require(ex != null && ".edata".equals(ex.getName()) &&
                ex.getStart().getOffset() == EXPORT_START, "Unexpected .edata mapping");
        require(tx != null && ".text".equals(tx.getName()) &&
                tx.isExecute() && tx.getStart().getOffset() == TEXT_START &&
                tx.getSize() >= 0x1006C8L && tx.getSize() <= 0x100800L,
            "Unexpected executable .text mapping");

        Metadata metadata = new Metadata();
        long previousEnd = TEXT_START;
        Set<Long> starts = new HashSet<>();
        for (int i = 0; i < PDATA_COUNT; i++) {
            monitor.checkCancelled();
            Address row = at(program, PDATA_START + (long) i * 8);
            long start = readU32(memory, row, true);
            long packed = readU32(memory, row.add(4), true);
            long size = ((packed >>> 8) & 0x3FFFFFL) * 4;
            long end = start + size;
            require(size >= 4 && (start & 3) == 0 &&
                    start >= TEXT_START && end <= TEXT_END_EXCLUSIVE &&
                    start >= previousEnd && end > start,
                "Invalid/overlapping .pdata range at record " + i);
            starts.add(start);
            metadata.pdata.add(new Range(start, end));
            previousEnd = end;
        }

        Address exportDir = at(program, EXPORT_START);
        long ordinalBase = readU32(memory, exportDir.add(16), false);
        long slots = readU32(memory, exportDir.add(20), false);
        long numNames = readU32(memory, exportDir.add(24), false);
        long funcTableRva = readU32(memory, exportDir.add(28), false);
        require(ordinalBase == 1 && slots == EXPORT_COUNT && numNames == 0 &&
                funcTableRva == 0x15E2CL, "Unexpected kernel export directory");

        int codeCount = 0, dataCount = 0, pdataCount = 0, emptyCount = 0;
        for (int ordinal = 1; ordinal <= EXPORT_COUNT; ordinal++) {
            monitor.checkCancelled();
            long rva = readU32(memory, at(program, BASE + funcTableRva + (ordinal - 1L) * 4), false);
            if (rva == 0) { emptyCount++; continue; }
            long destination = BASE + rva;
            MemoryBlock block = memory.getBlock(at(program, destination));
            require(block != null, "Export " + ordinal + " points outside memory");
            boolean code = block.isExecute();
            if (code) {
                codeCount++;
                require(destination >= TEXT_START && destination < TEXT_END_EXCLUSIVE &&
                        (destination & 3) == 0,
                    "Unexpected code export location at ordinal " + ordinal);
                if (starts.contains(destination)) pdataCount++;
                else {
                    // No .pdata boundary proves a length for this entry.
                    // Mark as a known entrypoint; let Ghidra determine its body.
                    metadata.codeExportsWithoutPdata.add(destination);
                }
            }
            else dataCount++;
            String name = ImportRenamer.Rename("xboxkrnl.exe", ordinal);
            metadata.exportNames.computeIfAbsent(destination, ignored -> new ArrayList<>()).add(name);
        }
        require(codeCount == CODE_EXPORT_COUNT && dataCount == DATA_EXPORT_COUNT &&
                pdataCount == PDATA_EXPORT_COUNT && emptyCount == 10,
            "Kernel export categories do not match verified 17559 layout");
        return metadata;
    }

    private static boolean symbolExists(SymbolTable table, Address address, String name) {
        for (Symbol symbol : table.getSymbols(address)) {
            if (symbol.getName().equals(name)) return true;
        }
        return false;
    }

    private static String firstName(Metadata metadata, long address) {
        List<String> names = metadata.exportNames.get(address);
        return names == null || names.isEmpty() ? null : names.get(0);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) return true;

        final Metadata metadata;
        try {
            metadata = readAndValidate(program, monitor);
        }
        catch (CancelledException ex) { throw ex; }
        catch (Exception ex) {
            log.appendMsg("Xbox 360 kernel 17559 metadata validation failed; no changes: " + ex);
            return false;
        }

        FunctionManager functions = program.getFunctionManager();
        Listing listing = program.getListing();
        SymbolTable symbols = program.getSymbolTable();
        int created = 0, alreadyPresent = 0, skipped = 0, disassemblyFailures = 0;
        int newLabels = 0, leafEntrypoints = 0;
        List<String> failures = new ArrayList<>();

        for (Range record : metadata.pdata) {
            monitor.checkCancelled();
            Address entry = at(program, record.start);
            AddressSet exactBody = new AddressSet(entry, at(program, record.end - 1));
            Function current = functions.getFunctionAt(entry);
            if (current != null) {
                alreadyPresent++;
                continue;
            }
            Iterator<Function> collisions = functions.getFunctionsOverlapping(exactBody);
            if (collisions.hasNext()) {
                skipped++;
                if (failures.size() < 20)
                    failures.add("Overlapping existing function near " + entry);
                continue;
            }

            try {
                // Restrict flow to the proven .pdata range; it is not safe to
                // disassemble through a neighboring function boundary.
                if (listing.getInstructionAt(entry) == null) {
                    DisassembleCommand disassemble = new DisassembleCommand(entry, exactBody, true);
                    disassemble.enableCodeAnalysis(false);
                    disassemble.applyTo(program, monitor);
                }
                if (listing.getInstructionAt(entry) == null) {
                    disassemblyFailures++;
                    if (failures.size() < 20)
                        failures.add("No instruction at .pdata start " + entry);
                    continue;
                }
                Function function = functions.createFunction(firstName(metadata, record.start),
                    entry, exactBody, SourceType.ANALYSIS);
                if (function == null) {
                    skipped++;
                    if (failures.size() < 20)
                        failures.add("Could not create .pdata function at " + entry);
                }
                else created++;
            }
            catch (Exception ex) {
                skipped++;
                if (failures.size() < 20)
                    failures.add("Function " + entry + ": " + ex.getMessage());
            }
        }

        // Export addresses from the PE are real entrypoints, even when they
        // have no .pdata record. Do not guess their function sizes.
        for (long address : metadata.codeExportsWithoutPdata) {
            monitor.checkCancelled();
            Address entry = at(program, address);
            try {
                if (!symbols.isExternalEntryPoint(entry)) {
                    symbols.addExternalEntryPoint(entry);
                    leafEntrypoints++;
                }
            }
            catch (Exception ex) {
                if (failures.size() < 20)
                    failures.add("Leaf entrypoint " + entry + ": " + ex.getMessage());
            }
        }

        // Export aliases are common; keep *every* ordinal name as a symbol
        // rather than discarding all but the first one.
        for (Map.Entry<Long, List<String>> export : metadata.exportNames.entrySet()) {
            monitor.checkCancelled();
            Address entry = at(program, export.getKey());
            for (String name : export.getValue()) {
                if (symbolExists(symbols, entry, name)) continue;
                try {
                    symbols.createLabel(entry, name, SourceType.ANALYSIS);
                    newLabels++;
                }
                catch (Exception ex) {
                    if (failures.size() < 20)
                        failures.add("Symbol " + name + " at " + entry + ": " + ex.getMessage());
                }
            }
        }

        log.appendMsg(String.format(
            "Xbox 360 kernel 17559: .pdata functions created=%d, existing=%d, " +
            "skipped=%d, disassembly failures=%d, export labels=%d, leaf entrypoints=%d",
            created, alreadyPresent, skipped, disassemblyFailures, newLabels, leafEntrypoints));
        for (String failure : failures) log.appendMsg("  " + failure);
        return skipped == 0 && disassemblyFailures == 0;
    }
}
