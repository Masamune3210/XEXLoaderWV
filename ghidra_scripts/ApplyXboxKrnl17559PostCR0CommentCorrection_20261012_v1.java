// Correct three obsolete native-analysis comments after verified Xenon
// addic./subic. record-condition semantics. No functions/bytes/types/etc.
//@category Xbox360

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;

public class ApplyXboxKrnl17559PostCR0CommentCorrection_20261012_v1 extends GhidraScript {
    private static final String SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final long[] FUNCTION_ENTRIES = {
        0x800641D8L, // ExAcquireReadWriteLockExclusive
        0x800642B8L, // ExAcquireReadWriteLockShared
        0x800643D8L  // ExReleaseReadWriteLock
    };
    private static final String OBSOLETE =
        "Current lift uses 64-bit CR0 for addic./subic.; native 32-bit " +
        "record conditions must compare low32. Do not trust the lifted " +
        "first-acquire/last-release branch at word wrap until the ISA " +
        "model is corrected.";
    private static final String CORRECTED =
        "Xenon record-condition fix verified 2026-10-11: addic./subic. " +
        "compare signed low32 for CR0.LT/GT/EQ while retaining the full " +
        "64-bit destination GPR. AuditXenonAddicRecordWidthV1 passed " +
        "11/11 private-emulator cases (0xFFFFFFFF+1 yields " +
        "r12=0x100000000 and CR0.EQ). This verifies those p-code cases, " +
        "not physical lock contention or XER carry semantics.";

    private static class Change {
        final Function function;
        final String updatedComment;
        Change(Function f, String updated) {
            function = f;
            updatedComment = updated;
        }
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    @Override
    public void run() throws Exception {
        require(LANGUAGE.equals(currentProgram.getLanguageID().toString()),
            "Wrong processor language; refusing to update kernel comments");
        require(SHA256.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
            "Wrong program SHA256; refusing to update kernel comments");

        Instruction instruction = currentProgram.getListing()
            .getInstructionAt(toAddr(0x80064204L));
        require(instruction != null &&
                "addic.".equals(instruction.getMnemonicString()) &&
                Arrays.equals(instruction.getBytes(), new byte[] {
                    (byte) 0x35, (byte) 0x6b, 0, 1
                }),
            "Native addic. reference opcode at 0x80064204 is not 356B0001");

        Set<Long> expected = new HashSet<>();
        List<Change> changes = new ArrayList<>();
        int alreadyUpdated = 0;
        for (long entry : FUNCTION_ENTRIES) {
            monitor.checkCancelled();
            expected.add(entry);
            Address address = toAddr(entry);
            Function function = currentProgram.getFunctionManager()
                .getFunctionAt(address);
            require(function != null,
                "Required existing function missing at " + address);
            String comment = function.getRepeatableComment();
            require(comment != null,
                "Required native-analysis comment missing for " + address);
            boolean stale = comment.contains(OBSOLETE);
            boolean corrected = comment.contains(CORRECTED);
            require(stale != corrected,
                "Expected exactly one of old/new evidence strings at " + address);
            if (stale) {
                require(comment.indexOf(OBSOLETE) ==
                    comment.lastIndexOf(OBSOLETE),
                    "Multiple obsolete sentences at " + address);
                changes.add(new Change(function,
                    comment.replace(OBSOLETE, CORRECTED)));
            }
            else {
                alreadyUpdated++;
            }
            println("CHECK " + address + " " + function.getName() +
                (stale ? " : obsolete comment to update" :
                         " : already corrected"));
        }

        // Prove we are not silently missing additional copies elsewhere
        // before making the first mutation.
        FunctionIterator iterator = currentProgram.getFunctionManager()
            .getFunctions(true);
        int staleCount = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            String comment = function.getRepeatableComment();
            if (comment == null || !comment.contains(OBSOLETE)) {
                continue;
            }
            staleCount++;
            require(expected.contains(function.getEntryPoint().getOffset()),
                "Obsolete CR0 text also present in unexpected function: " +
                function.getEntryPoint());
        }
        require(staleCount == changes.size(),
            "Stale-comment inventory changed during preflight");
        require(changes.size() + alreadyUpdated == 3,
            "Three-function inventory invariant failed");

        // Ghidra runs this script in its normal script transaction. All
        // preconditions were checked above, before modifying any comment.
        for (Change change : changes) {
            monitor.checkCancelled();
            change.function.setRepeatableComment(change.updatedComment);
            println("UPDATED " + change.function.getEntryPoint() + " " +
                change.function.getName());
        }
        println("POST-CR0 COMMENTS: updated=" + changes.size() +
            " alreadyCorrect=" + alreadyUpdated +
            " unexpectedStale=0; original native-analysis facts retained.");
        println("No instruction bytes, function signatures/bodies, parameters, " +
            "datatypes, .pdata, symbols, or bookmarks changed.");
    }
}