// Repair 19 already-imported XAM kernel ordinal fallback names for retail 17559.
// Exact SHA256/ISA gated; no kernel Program changes, no bytes/signatures/types touched.
// Existing XAM external locations, thunk function symbols and import-slot labels are renamed
// in one database transaction only after a full 19-entry preflight.
// Names: Xenia xboxkrnl_table.inc; ordinals independently observed in xam.xex GZF.
//@category Xbox360
import java.util.ArrayList;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ApplyXam17559KernelImportOrdinalNames_20261012_v1 extends GhidraScript {
    private static final String SHA256 =
        "78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String LIBRARY = "xboxkrnl.exe";
    private static final int[] ORDINALS = {
        859,
        869,
        871,
        873,
        882,
        883,
        884,
        886,
        887,
        901,
        902,
        904,
        909,
        919,
        922,
        923,
        924,
        925,
        926,
    };
    private static final String[] NAMES = {
        "DrvSetAudioLatencyCallback",
        "VdQueryVideoCapabilities",
        "VdGet3dVideoFormat",
        "VdSet3dVideoFormat",
        "UsbdGetNatalHub",
        "UsbdGetNatalHardwareVersion",
        "UsbdNatalHubRegisterNotificationCallback",
        "KeCallAndWaitForDpcRoutine",
        "TidDeviceRequest",
        "XInputdGetFailedConnectionOrBind",
        "XInputdSetFailedConnectionOrBindCallback",
        "XInputdSetMinMaxAuthDelay",
        "MmResetLowestAvailablePages",
        "XeCryptAesCreateKeySchedule",
        "XeCryptAesCbcEncrypt",
        "XeCryptAesCbcDecrypt",
        "XeCryptAesGcmInitialize",
        "XeCryptAesGcmUpdate",
        "XeCryptAesGcmFinalize",
    };
    private static class Rename {
        final int ordinal;
        final String oldName, newName;
        final ExternalLocation external;
        final List<Symbol> slotSymbols;
        final List<Symbol> thunkSymbols;
        Rename(int ordinal, String oldName, String newName,
               ExternalLocation external, List<Symbol> slotSymbols, List<Symbol> thunkSymbols) {
            this.ordinal = ordinal;
            this.oldName = oldName;
            this.newName = newName;
            this.external = external;
            this.slotSymbols = slotSymbols;
            this.thunkSymbols = thunkSymbols;
        }
    }
    private List<Symbol> globalMemorySymbols(SymbolTable symbols, String name) {
        List<Symbol> result = new ArrayList<>();
        SymbolIterator iterator = symbols.getSymbols(name);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            Address address = symbol.getAddress();
            if (address.isMemoryAddress() &&
                currentProgram.getGlobalNamespace().equals(symbol.getParentNamespace())) {
                result.add(symbol);
            }
        }
        return result;
    }
    @Override
    public void run() throws Exception {
        if (!LANGUAGE.equals(currentProgram.getLanguageID().toString()) ||
            !SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Expected retail 17559 xam.xex SHA256/language; no changes");
        }
        if (ORDINALS.length != 19 || NAMES.length != ORDINALS.length)
            throw new IllegalStateException("Invalid exact-ordinal source list");

        ExternalManager externals = currentProgram.getExternalManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        List<Rename> pending = new ArrayList<>();
        int already = 0, slotCount = 0, thunkCount = 0;

        // Preflight all records and name collisions BEFORE writing to the Program.
        for (int i = 0; i < ORDINALS.length; i++) {
            monitor.checkCancelled();
            String oldName = LIBRARY + "_ord_" + ORDINALS[i];
            String newName = NAMES[i];
            ExternalLocation previous = externals.getUniqueExternalLocation(LIBRARY, oldName);
            ExternalLocation existing = externals.getUniqueExternalLocation(LIBRARY, newName);
            if (previous == null) {
                if (existing != null && existing.isFunction()) {
                    already++;
                    continue;
                }
                throw new IllegalStateException("Missing expected kernel import " + oldName);
            }
            if (!previous.isFunction())
                throw new IllegalStateException("Expected function import for " + oldName);
            if (existing != null && !existing.getExternalSpaceAddress().equals(
                    previous.getExternalSpaceAddress())) {
                throw new IllegalStateException("Conflicting external for " + newName);
            }
            if (newName.equals(previous.getSymbol().getName())) {
                already++;
                continue;
            }
            List<Symbol> slots = globalMemorySymbols(symbols, "__imp__" + oldName);
            List<Symbol> thunks = globalMemorySymbols(symbols, oldName);
            if (!globalMemorySymbols(symbols, "__imp__" + newName).isEmpty() ||
                !globalMemorySymbols(symbols, newName).isEmpty()) {
                throw new IllegalStateException("Already has memory symbol for " + newName);
            }
            if (slots.isEmpty() && thunks.isEmpty())
                throw new IllegalStateException("No matching import slot/thunk memory symbols for " + oldName);
            pending.add(new Rename(ORDINALS[i], oldName, newName, previous, slots, thunks));
        }

        println("PRECHECK xam17559 kernel ordinals=" + ORDINALS.length +
            " pending=" + pending.size() + " already=" + already);
        if (pending.isEmpty()) {
            println("NOOP: all expected names already present; Program unchanged");
            return;
        }
        int transaction = currentProgram.startTransaction("Resolve XAM retail 17559 kernel ordinal names");
        boolean success = false;
        try {
            for (Rename rename : pending) {
                monitor.checkCancelled();
                // The external association is not recreated. Changing its primary name
                // preserves the same ExternalLocation and its original import-name record.
                Symbol original = rename.external.getSymbol();
                rename.external.setName(original.getParentNamespace(), rename.newName, SourceType.USER_DEFINED);
                for (Symbol slot : rename.slotSymbols) {
                    slot.setName("__imp__" + rename.newName, SourceType.IMPORTED);
                    slotCount++;
                }
                for (Symbol thunk : rename.thunkSymbols) {
                    thunk.setName(rename.newName, SourceType.IMPORTED);
                    thunkCount++;
                }
                println("RENAMED ordinal " + rename.ordinal + " -> " + rename.newName +
                    " slots=" + rename.slotSymbols.size() +
                    " thunks=" + rename.thunkSymbols.size());
            }
            success = true;
        } finally {
            currentProgram.endTransaction(transaction, success);
        }
        if (!success) throw new IllegalStateException("Transaction rolled back");
        println("APPLIED externalLocations=" + pending.size() +
            " importSlotSymbols=" + slotCount + " thunkSymbols=" + thunkCount +
            "; unchanged Program bytes, types, signatures, kernel Program and bookmarks");
    }
}
