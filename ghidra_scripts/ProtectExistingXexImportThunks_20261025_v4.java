// ProtectExistingXexImportThunks_20261025_v4.java
// @category Xbox360.Imports
// Reusable protection for existing XEX imports: persist canonical thunk entrypoints.
// The two relocation words must remain undefined at the native thunk entry:
// the earlier "type them as DWord data" approach caused hundreds of Ghidra
// auto-analysis conflicting-data errors. This script adds explanatory comments
// and saves the entrypoints for the Xenon import-aware disassembler to guard on
// EVERY future analysis pass. Only the real PPC tail at +8 is decoded;
// it never changes bytes,
// function entrypoints, function linkage, imports or existing user-defined data.

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.disassemble.Disassembler;

public class ProtectExistingXexImportThunks_20261025_v4 extends GhidraScript {
    private static final int MAX_ROWS = 30;
    private boolean isCanonical(byte[] raw) {
        if (raw.length != 16 || raw[0] != 1 || raw[4] != 2 || raw[1] != raw[5] ||
                raw[2] != raw[6] || raw[3] != raw[7]) return false;
        final int[] suffix = {0x7D, 0x69, 0x03, 0xA6, 0x4E, 0x80, 0x04, 0x20};
        for (int i = 0; i < 8; i++)
            if ((raw[i + 8] & 0xFF) != suffix[i]) return false;
        return true;
    }

    private String appendOnce(String old, String marker, String additional) {
        if (old != null && old.contains(marker)) return old;
        if (old == null || old.isEmpty()) return additional;
        return old + "\n\n" + additional;
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        List<Address> candidates = new ArrayList<>();
        byte[] bytes = new byte[16];
        int checked = 0, ignored = 0, conflicts = 0;
        Set<String> persisted = new LinkedHashSet<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function f = functions.next();
            if (!f.isThunk() || f.getThunkedFunction(false) == null ||
                    !f.getEntryPoint().isMemoryAddress()) continue;
            checked++;
            Address entry = f.getEntryPoint();
            try {
                if (memory.getBytes(entry, bytes) != 16 || !isCanonical(bytes)) {
                    ignored++;
                    continue;
                }
                // Do not clear or rewrite previously defined code/data at
                // relocation tokens. Such entries require separate review.
                if (listing.getInstructionContaining(entry) != null ||
                        listing.getInstructionContaining(entry.add(4)) != null ||
                        listing.getDefinedDataContaining(entry) != null ||
                        listing.getDefinedDataContaining(entry.add(4)) != null) {
                    conflicts++;
                    continue;
                }
                candidates.add(entry);
            } catch (Exception ex) {
                conflicts++;
                if (conflicts <= MAX_ROWS)
                    println("SKIPPED " + entry + ": " + ex.getMessage());
            }
        }
        println("XEX import preflight: native linked thunks=" + checked +
            " canonical untouched tokens=" + candidates.size() +
            " existing code/data conflicts=" + conflicts +
            " other thunks=" + ignored);
        // Protected addresses already persisted by a previous run should
        // survive, but revalidate them against the current 16 raw bytes.
        String previous = currentProgram.getOptions("XEX Import Thunks")
            .getString("Pre-link Relocation Token Entrypoints", "");
        for (String item : previous.split(",")) {
            if (item.isBlank()) continue;
            try {
                long rawAddress = Long.parseUnsignedLong(item.strip(), 16);
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(rawAddress);
                if (memory.getBytes(addr, bytes) == 16 && isCanonical(bytes)) {
                    persisted.add(Long.toUnsignedString(rawAddress, 16));
                }
            } catch (Exception ignoredMarker) {
                // Stale marker cannot block unrelated disassembly.
            }
        }
        for (Address entry : candidates) {
            persisted.add(Long.toUnsignedString(entry.getOffset(), 16));
        }
        if (persisted.isEmpty()) {
            println("No confirmed canonical thunk entries; nothing to protect.");
            return;
        }

        String custom = currentProgram.getLanguage().getProperty(
            GhidraLanguagePropertyKeys.CUSTOM_DISASSEMBLER_CLASS);
        boolean configured = "xexloaderwv.XenonImportAwareDisassembler".equals(custom);
        boolean active = false;
        if (configured) {
            try {
                Disassembler actual = Disassembler.getDisassembler(
                    currentProgram, monitor, null);
                active = "xexloaderwv.XenonImportAwareDisassembler".equals(
                    actual.getClass().getName());
            } catch (RuntimeException ex) {
                println("WARN: Language property configured but custom " +
                    "disassembler could not be instantiated: " + ex.getMessage());
            }
        }
        println("Import-aware Xenon disassembler ACTIVE: " + active);
        if (!active) {
            println("WARNING: Install the updated XEXLoaderWV Xenon language and " +
                "reopen this Program before repeating auto-analysis.");
        }

        int transaction = currentProgram.startTransaction("Annotate Xbox 360 XEX import thunks");
        boolean success = false;
        int updated = 0, tailDecoded = 0;
        try {
            for (Address entry : candidates) {
                monitor.checkCancelled();
                Function thunk = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (thunk == null || !thunk.isThunk())
                    throw new IllegalStateException("Thunk changed since preflight: " + entry);
                int ordinal = (memory.getByte(entry.add(2)) & 0xFF) << 8 |
                    (memory.getByte(entry.add(3)) & 0xFF);
                String plate = String.format(
                    "XEX import relocation tokens (NOT PPC instructions). Ordinal 0x%04X.\n" +
                    "The original 0100OOOO / 0200OOOO token words are replaced " +
                    "at runtime with instructions loading the external target into r11.\n" +
                    "Unpatched bytes +8 through +15 are real PPC: mtctr r11; bctr.\n" +
                    "The tokens intentionally remain undefined because Ghidra " +
                    "attempts disassembly at thunk function entrypoints even when " +
                    "they are declared data. Original bytes and external thunk link preserved.",
                    ordinal);
                CodeUnit firstUnit = listing.getCodeUnitAt(entry);
                String priorPlate = firstUnit.getComment(CommentType.PLATE);
                String revisedPlate = appendOnce(priorPlate,
                    "XEX import relocation tokens", plate);
                if (!revisedPlate.equals(priorPlate))
                    listing.setComment(entry, CommentType.PLATE, revisedPlate);

                CodeUnit secondUnit = listing.getCodeUnitAt(entry.add(4));
                if (firstUnit.getComment(CommentType.EOL) == null)
                    listing.setComment(entry, CommentType.EOL,
                        String.format("XEX high-half relocation token 0100%04X (not code)", ordinal));
                if (secondUnit.getComment(CommentType.EOL) == null)
                    listing.setComment(entry.add(4), CommentType.EOL,
                        String.format("XEX low-half relocation token 0200%04X (not code)", ordinal));

                if (listing.getInstructionAt(entry.add(8)) != null &&
                        listing.getInstructionAt(entry.add(12)) != null) {
                    tailDecoded++;
                } else {
                    DisassembleCommand dis = new DisassembleCommand(entry.add(8), null, true);
                    dis.enableCodeAnalysis(false);
                    if (dis.applyTo(currentProgram, monitor) &&
                            listing.getInstructionAt(entry.add(8)) != null &&
                            listing.getInstructionAt(entry.add(12)) != null)
                        tailDecoded++;
                    else if (updated < MAX_ROWS)
                        println("WARN " + entry + " PPC tail was not fully disassembled");
                }
                Function surviving = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (surviving == null || !surviving.isThunk())
                    throw new IllegalStateException("Thunk relationship lost: " + entry);
                updated++;
                if (updated <= MAX_ROWS)
                    println("ANNOTATED " + entry + " ordinal=0x" +
                        String.format("%04X", ordinal) + " -> " +
                        surviving.getThunkedFunction(false).getName());
            }
            // Persistent per-Program registry consumed by the Xenon custom
            // Disassembler on every fresh disassembly command, including
            // reanalysis after saving and reopening the Ghidra database.
            currentProgram.getOptions("XEX Import Thunks").setString(
                "Pre-link Relocation Token Entrypoints",
                String.join(",", persisted));
            success = true;
        } finally {
            currentProgram.endTransaction(transaction, success);
        }
        println("COMPLETE: guarded token ranges=" + persisted.size() +
            ", annotated=" + updated + ", real PPC tails decoded=" +
            tailDecoded + ", bytes changed=0, native thunk targets retained.");
        if (updated > MAX_ROWS)
            println("Additional per-thunk rows omitted after " + MAX_ROWS + ".");
        if (conflicts > 0)
            println("Existing code/data conflicts were NOT cleared or modified.");
    }
}
