// @category Xbox360
// Read-only post-analysis verification for the retail 17559 kernel.
// Use after normal Auto Analyze finishes, on the SAME Program.
// A Ghidra function body follows reachable code, not necessarily every byte
// of the contiguous .pdata unwind range. This script measures valid containment
// and entrypoint survival, rather than requiring byte-for-byte body equality.
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class AuditXboxKrnl17559FlowBodiesV2 extends GhidraScript {
    private static final long BASE = 0x80040000L;
    private static final long PDATA = 0x8004FA00L;
    private static final long EAT = 0x80055E2CL;
    private static final int COUNT = 3188;
    private static final int MAX_DETAILS = 200;
    private static final String SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:A2ALT-32addr";

    private Address addr(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private long read32(Address at, boolean bigEndian) throws Exception {
        Memory memory = currentProgram.getMemory();
        long result = 0;
        for (int i = 0; i < 4; i++) {
            int b = memory.getByte(at.add(i)) & 0xff;
            if (bigEndian) result = (result << 8) | b;
            else result |= (long) b << (i * 8);
        }
        return result & 0xffffffffL;
    }

    private static void note(List<String> messages, String message) {
        if (messages.size() < MAX_DETAILS) messages.add(message);
    }

    @Override
    protected void run() throws Exception {
        if (!SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            currentProgram.getImageBase().getOffset() != BASE) {
            printerr("Wrong kernel hash, language, or image base; aborting read-only audit.");
            return;
        }

        int present = 0, missing = 0, contained = 0, escaped = 0;
        int exact = 0, undecoded = 0, undData = 0, undMiddle = 0, undUnknown = 0;
        long totalVerifiedBytes = 0, totalOwnedBytes = 0;
        Set<Long> startAddresses = new HashSet<>();
        List<String> problems = new ArrayList<>();
        List<String> decodeProblems = new ArrayList<>();

        for (int i = 0; i < COUNT; i++) {
            monitor.checkCancelled();
            long start = read32(addr(PDATA + i * 8L), true);
            long packed = read32(addr(PDATA + i * 8L + 4), true);
            long length = ((packed >>> 8) & 0x3fffffL) * 4;
            Address entry = addr(start);
            AddressSet extent = new AddressSet(entry, addr(start + length - 1));
            startAddresses.add(start);
            totalVerifiedBytes += length;

            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null) {
                missing++;
                note(problems, String.format("MISSING .pdata[%d] entry=%08X length=%X", i, start, length));
            }
            else {
                present++;
                AddressSetView body = function.getBody();
                long outside = body.subtract(extent).getNumAddresses();
                totalOwnedBytes += body.getNumAddresses();
                if (outside == 0) contained++;
                else {
                    escaped++;
                    note(problems, String.format("ESCAPED .pdata[%d] entry=%08X: %d body bytes outside [%08X,%08X)",
                        i, start, outside, start, start + length));
                }
                if (body.getNumAddresses() == length &&
                    body.getMinAddress().equals(entry) &&
                    body.getMaxAddress().equals(addr(start + length - 1))) exact++;
            }

            if (currentProgram.getListing().getInstructionAt(entry) == null) {
                undecoded++;
                Data defined = currentProgram.getListing().getDefinedDataContaining(entry);
                Instruction containing = currentProgram.getListing().getInstructionContaining(entry);
                String why;
                if (defined != null) {
                    undData++;
                    why = "defined data " + defined.getDataType().getName();
                }
                else if (containing != null) {
                    undMiddle++;
                    why = "inside instruction " + containing.getMinAddress();
                }
                else {
                    undUnknown++;
                    why = "undefined code unit";
                }
                note(decodeProblems, String.format("UNDECODED .pdata[%d] %08X: %s", i, start, why));
            }
        }

        int empty = 0, code = 0, data = 0;
        int entryCode = 0, insideOther = 0, noFunction = 0;
        int pDataExport = 0, notPDataExport = 0;

        for (int ordinal = 1; ordinal <= 931; ordinal++) {
            monitor.checkCancelled();
            long rva = read32(addr(EAT + (ordinal - 1L) * 4), false);
            if (rva == 0) { empty++; continue; }
            Address address = addr(BASE + rva);
            if (!currentProgram.getMemory().getBlock(address).isExecute()) {
                data++;
                continue;
            }
            code++;
            if (startAddresses.contains(address.getOffset())) pDataExport++;
            else notPDataExport++;
            Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                noFunction++;
                note(problems, String.format("CODE EXPORT NO FUNCTION: ordinal %d at %s", ordinal, address));
            }
            else if (function.getEntryPoint().equals(address)) entryCode++;
            else {
                insideOther++;
                note(problems, String.format("CODE EXPORT INSIDE OTHER FUNCTION: ordinal %d at %s inside %s @ %s",
                    ordinal, address, function.getName(), function.getEntryPoint()));
            }
        }

        println("========================================================");
        println("RETAIL 17559: POST-ANALYSIS FUNCTION FLOW AUDIT (V2)");
        println("========================================================");
        println(String.format(".pdata: total=%d, function entries present=%d, missing=%d", COUNT, present, missing));
        println(String.format("Bodies contained within verified .pdata extent=%d, escaped=%d", contained, escaped));
        println(String.format("Exactly fill extent=%d (informational ONLY, not required)", exact));
        println(String.format("Verified .pdata bytes=%d, current function body bytes=%d",
            totalVerifiedBytes, totalOwnedBytes));
        println(String.format("Undecoded entrypoints=%d (data=%d, inside instruction=%d, undefined=%d)",
            undecoded, undData, undMiddle, undUnknown));
        println(String.format("Exports: code=%d data=%d empty=%d (.pdata-backed code=%d, uncovered code=%d)",
            code, data, empty, pDataExport, notPDataExport));
        println(String.format("Code exports: at function entry=%d, inside other=%d, no function=%d",
            entryCode, insideOther, noFunction));
        println("Read-only: no Program bytes or Ghidra metadata were modified.");
        println("");
        println("========================================================");
        println("FUNCTION BOUNDARY / EXPORT PROBLEMS (up to " + MAX_DETAILS + ")");
        println("========================================================");
        if (problems.isEmpty()) println("None");
        for (String problem : problems) println(problem);
        println("");
        println("========================================================");
        println("UNDECODED FUNCTION ENTRYPOINTS (up to " + MAX_DETAILS + ")");
        println("========================================================");
        if (decodeProblems.isEmpty()) println("None");
        for (String problem : decodeProblems) println(problem);
    }
}
