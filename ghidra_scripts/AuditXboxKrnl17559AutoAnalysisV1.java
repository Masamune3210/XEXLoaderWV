// @category Xbox360
// Read-only post-auto-analysis audit for the retail 17559 kernel.
// Run inside the existing xboxkrnl.exe Ghidra Program. No reimport needed.
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class AuditXboxKrnl17559AutoAnalysisV1 extends GhidraScript {
    private static final long BASE = 0x80040000L;
    private static final long PDATA = 0x8004FA00L;
    private static final long EAT = 0x80055E2CL;
    private static final String SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:A2ALT-32addr";
    private static final int MAX_DETAILS = 200;

    private Address addr(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private long read32(Address at, boolean bigEndian) throws Exception {
        Memory mem = currentProgram.getMemory();
        long value = 0;
        for (int i = 0; i < 4; i++) {
            int b = mem.getByte(at.add(i)) & 0xFF;
            if (bigEndian) value = (value << 8) | b;
            else value |= (long) b << (i * 8);
        }
        return value & 0xFFFFFFFFL;
    }

    private void note(List<String> dest, String message) {
        if (dest.size() < MAX_DETAILS) dest.add(message);
    }

    @Override
    protected void run() throws Exception {
        if (!SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            currentProgram.getImageBase().getOffset() != BASE) {
            printerr("Refusing audit: Program is not the verified retail 17559 kernel.");
            return;
        }
        int exact = 0, missing = 0, changed = 0, undecoded = 0;
        int definedData = 0, middleOfInstruction = 0, undefinedEntry = 0;
        int ordinalCode = 0, ordinalData = 0, ordinalEmpty = 0, ordinalInsideOther = 0;
        int ordinalFunctionEntry = 0, ordinalNoFunction = 0;
        Set<Long> pdataStarts = new HashSet<>();
        List<String> errors = new ArrayList<>();
        List<String> pending = new ArrayList<>();

        for (int i = 0; i < 3188; i++) {
            monitor.checkCancelled();
            long start = read32(addr(PDATA + i * 8L), true);
            long packed = read32(addr(PDATA + i * 8L + 4), true);
            long length = ((packed >>> 8) & 0x3FFFFFL) * 4;
            pdataStarts.add(start);
            Address entry = addr(start);
            Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (f == null) {
                missing++;
                note(errors, String.format("MISSING function: .pdata[%d] %08X length %X", i, start, length));
            }
            else {
                AddressSetView body = f.getBody();
                if (body.getNumAddresses() == length &&
                    body.getMinAddress().equals(entry) &&
                    body.getMaxAddress().equals(addr(start + length - 1))) {
                    exact++;
                }
                else {
                    changed++;
                    note(errors, String.format("CHANGED body: .pdata[%d] %08X expected length %X, actual %X (%s..%s)",
                        i, start, length, body.getNumAddresses(),
                        body.getMinAddress(), body.getMaxAddress()));
                }
            }
            if (currentProgram.getListing().getInstructionAt(entry) == null) {
                undecoded++;
                Data data = currentProgram.getListing().getDefinedDataContaining(entry);
                Instruction containing = currentProgram.getListing().getInstructionContaining(entry);
                String classification;
                if (data != null) {
                    definedData++;
                    classification = "DEFINED DATA " + data.getDataType().getName() + " at " + data.getMinAddress();
                }
                else if (containing != null) {
                    middleOfInstruction++;
                    classification = "INSIDE INSTRUCTION " + containing.getMinAddress();
                }
                else {
                    undefinedEntry++;
                    classification = "UNDEFINED ENTRY";
                }
                note(pending, String.format("UNDECODED .pdata[%d] %08X: %s", i, start, classification));
            }
        }

        for (int ordinal = 1; ordinal <= 931; ordinal++) {
            monitor.checkCancelled();
            long rva = read32(addr(EAT + (ordinal - 1L) * 4), false);
            if (rva == 0) { ordinalEmpty++; continue; }
            Address entry = addr(BASE + rva);
            if (!currentProgram.getMemory().getBlock(entry).isExecute()) {
                ordinalData++;
                continue;
            }
            ordinalCode++;
            Function f = currentProgram.getFunctionManager().getFunctionContaining(entry);
            if (f == null) {
                ordinalNoFunction++;
                note(errors, String.format("EXPORT without function: ordinal %d at %s; pdataStart=%s",
                    ordinal, entry, pdataStarts.contains(entry.getOffset())));
            }
            else if (f.getEntryPoint().equals(entry)) ordinalFunctionEntry++;
            else {
                ordinalInsideOther++;
                note(errors, String.format("EXPORT inside OTHER function: ordinal %d at %s inside %s @ %s",
                    ordinal, entry, f.getName(), f.getEntryPoint()));
            }
        }

        println("===========================================================");
        println("RETAIL 17559 KERNEL: POST-AUTO-ANALYSIS READ-ONLY AUDIT");
        println("===========================================================");
        println("Explicit .pdata function bodies:");
        println(String.format("  Exact=%d  Missing=%d  Changed=%d  Total=%d", exact, missing, changed, 3188));
        println(String.format("  Missing entry instructions=%d (defined data=%d, inside instruction=%d, undefined=%d)",
            undecoded, definedData, middleOfInstruction, undefinedEntry));
        println("PE exports:");
        println(String.format("  Code=%d  Data=%d  Empty=%d", ordinalCode, ordinalData, ordinalEmpty));
        println(String.format("  Code export at function entry=%d  Inside other function=%d  No function=%d",
            ordinalFunctionEntry, ordinalInsideOther, ordinalNoFunction));
        println("Neither the imported bytes nor any Ghidra metadata was modified.");
        println("");
        println("===========================================================");
        println("REMAINING ISSUES (" + errors.size() + " shown; cap " + MAX_DETAILS + ")");
        println("===========================================================");
        if (errors.isEmpty()) println("None");
        else for (String problem : errors) println(problem);
        println("");
        println("===========================================================");
        println("UNDECODED ENTRY DIAGNOSTICS (" + pending.size() + " shown; cap " + MAX_DETAILS + ")");
        println("===========================================================");
        if (pending.isEmpty()) println("None");
        else for (String problem : pending) println(problem);
    }
}
