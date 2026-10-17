// Audit and conservatively refine Xbox 360 retail kernel 17559 after Xenon CR0 work.
// @category Xbox360.Kernel
// Requires Ghidra 12.x and the existing PowerPC:BE:64:XENON-32addr program.
// Source evidence: xkrnl-decomp (17489 debug) MiMakePhysicalProtectionMask;
// native identity: 2026-10-15 kernel full-export-final/asm/80080cb0.asm.
// The source identity is cross-version; only the proven matching 17559 body is renamed.

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.HashSet;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class AuditXboxKrnl17559PostCR0Checkpoint_20261017_v2 extends GhidraScript {
    private static final boolean APPLY_VERIFIED_METADATA = true;
    private static final boolean ADD_NEW_CR0_REVIEW_BOOKMARKS = true;
    private static final String BOOKMARK_CATEGORY = "XenonCR0SF0_20261017";
    private static final String EXPECTED_KERNEL_FUNCTION_SHA =
        "aa65bd4ee6b78e0ce6ccdad8e8dd90235f998103e9189d07166f5ac7f6827381";
    // Immediate native instruction and branch bytes, independently archived.
    private static final long[][] RECORD_BRANCHES = {
        {0x80080cb4L, 0x556b05e9L, 0x4182000cL, 0x00000200L},
        {0x80083af0L, 0x556b0499L, 0x4182006cL, 0x00004000L},
        {0x800925e4L, 0x556b075fL, 0x41820010L, 0x00000008L},
        {0x800a81e8L, 0x556b0733L, 0x4082003cL, 0x00000010L},
        {0x8010bf8cL, 0x554a0203L, 0x41820018L, 0x01000000L}
    };
    private static final String[] INTERESTING_SAVED_NAMES = {
        "MiGetPteAddress", "MiGetMappedPteAddress", "MiReadPhysicalMappingTable",
        "EmaExecuteSingle", "EmaExecute", "DecodeMappingProtectionWordObserved",
        "BnDivide128By64Observed", "BnDivideLimbs64Observed",
        "BnAddModularVectorObserved", "BnRandomModularVectorObserved",
        "BnReleaseOperationContextObserved", "RtlpFormatBinary64FixedObserved",
        "VdpSmcReadF0RegisterWordObserved", "QueryPageMappingWordObserved",
        "QueryPageMappingWordTailObserved"
    };

    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(offset);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static String hash(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    private long nativeWord(Address a) throws Exception {
        return currentProgram.getMemory().getInt(a) & 0xffffffffL;
    }

    private String compareWidth(Instruction i) {
        int four = 0, eight = 0, other = 0;
        for (PcodeOp op : i.getPcode(false)) {
            int code = op.getOpcode();
            if (code != PcodeOp.INT_EQUAL &&
                code != PcodeOp.INT_SLESS && code != PcodeOp.INT_SLESSEQUAL) {
                continue;
            }
            if (op.getNumInputs() != 2) continue;
            Varnode a = op.getInput(0), b = op.getInput(1);
            boolean zeroA = a.isConstant() && a.getOffset() == 0;
            boolean zeroB = b.isConstant() && b.getOffset() == 0;
            if (!zeroA && !zeroB) continue;
            int size = zeroA ? b.getSize() : a.getSize();
            if (size == 4) four++;
            else if (size == 8) eight++;
            else other++;
        }
        if (four > 0 && eight == 0 && other == 0)
            return "LOW32_COMPARISONS";
        if (eight > 0 && four == 0 && other == 0)
            return "FULL64_COMPARISONS";
        return "INCONCLUSIVE(four=" + four + ",eight=" + eight + ",other=" + other + ")";
    }

    private int checkCr0Sites() throws Exception {
        int matched = 0, added = 0, failed = 0;
        for (long[] row : RECORD_BRANCHES) {
            monitor.checkCancelled();
            long address = row[0], recordedWord = row[1], branchWord = row[2];
            Address site = at(address);
            try {
                Instruction i = currentProgram.getListing().getInstructionAt(site);
                Instruction branch = currentProgram.getListing().getInstructionAt(site.add(4));
                if (i == null || branch == null || nativeWord(site) != recordedWord ||
                    nativeWord(site.add(4)) != branchWord ||
                    !i.getMnemonicString().startsWith("rlwinm")) {
                    println("CR0_SITE_MISMATCH " + site + " expectedWord=0x" +
                        Long.toHexString(recordedWord));
                    failed++;
                    continue;
                }
                matched++;
                String mode = compareWidth(i);
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(site);
                String ownerText = owner == null ? "none" :
                    owner.getName() + "@" + owner.getEntryPoint();
                println("CR0_SITE " + site + " word=0x" + Long.toHexString(recordedWord) +
                    " next=" + branch.getMnemonicString() +
                    " pcode=" + mode + " owner=" + ownerText);

                // 80080CB4 has already been documented and privately executed.
                // Four other sites have only mathematical model witnesses so far.
                if (address == 0x80080cb4L || !ADD_NEW_CR0_REVIEW_BOOKMARKS ||
                    !APPLY_VERIFIED_METADATA) continue;
                BookmarkManager bm = currentProgram.getBookmarkManager();
                Bookmark old = bm.getBookmark(site, BookmarkType.NOTE, BOOKMARK_CATEGORY);
                if (old != null) continue;
                String msg = "Native bytes verified, wrapping rlwinm. followed by CR0 branch. " +
                    "Fixed-SF0 model witness input low32=0x" +
                    Long.toHexString(row[3]) + ". P-code comparison=" + mode +
                    ". Model witness, NOT proof of runtime input reachability or MSR[SF]. " +
                    "Stock full64 CR0 may yield a different branch. Preserve native GPR64.";
                bm.setBookmark(site, BookmarkType.NOTE, BOOKMARK_CATEGORY, msg);
                println("APPLIED_REVIEW_BOOKMARK " + site);
                added++;
            } catch (Exception ex) {
                println("CR0_SITE_ERROR " + site + " " + ex.getMessage());
                failed++;
            }
        }
        println("CR0_SUMMARY matched=" + matched + " bookmarksAdded=" +
            added + " siteErrors=" + failed);
        return matched;
    }

    private void annotateProtectionMaskFunction() {
        Address entry = at(0x80080cb0L);
        Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (f == null) {
            println("PROTECTION_NO_ENTRY_FUNCTION 80080cb0");
            return;
        }
        try {
            byte[] raw = new byte[0x74];
            if (currentProgram.getMemory().getBytes(entry, raw) != raw.length) {
                println("PROTECTION_BYTES_UNREADABLE 80080cb0");
                return;
            }
            String actual = hash(raw);
            if (!EXPECTED_KERNEL_FUNCTION_SHA.equals(actual)) {
                println("PROTECTION_HASH_MISMATCH 80080cb0 actual=" + actual);
                return;
            }
            if (f.getParameterCount() != 2 || !f.getBody().contains(at(0x80080d20L))) {
                println("PROTECTION_SIGNATURE_OR_BODY_UNEXPECTED 80080cb0" +
                    " name=" + f.getName() + " params=" + f.getParameterCount());
                return;
            }
            Parameter[] params = f.getParameters();
            if (params[0].getLength() != 4 || params[1].getLength() != 4 ||
                !(params[1].getDataType() instanceof Pointer)) {
                println("PROTECTION_PARAMETER_TYPES_CHANGED 80080cb0; preserve");
                return;
            }
            println("PROTECTION_IDENTITY_VERIFIED 80080cb0" +
                " bodySha256=" + actual +
                " originalName=" + f.getName() +
                " return=" + f.getReturnType().getDisplayName() +
                " inputs=" + params[0].getDataType().getDisplayName() + "," +
                params[1].getDataType().getDisplayName());
            if (!APPLY_VERIFIED_METADATA) return;
            if ("FUN_80080cb0".equals(f.getName())) {
                f.setName("MiMakePhysicalProtectionMask", SourceType.ANALYSIS);
                println("APPLIED_FUNCTION_NAME 80080cb0 -> MiMakePhysicalProtectionMask");
            } else {
                println("PRESERVE_FUNCTION_NAME 80080cb0 " + f.getName());
            }
            if (params[0].getName().startsWith("param_") &&
                params[0].getSource() != SourceType.USER_DEFINED) {
                params[0].setName("protectionFlags", SourceType.ANALYSIS);
                println("APPLIED_PARAMETER_NAME 80080cb0 index=0 protectionFlags");
            }
            if (params[1].getName().startsWith("param_") &&
                params[1].getSource() != SourceType.USER_DEFINED) {
                params[1].setName("outPhysicalMask", SourceType.ANALYSIS);
                println("APPLIED_PARAMETER_NAME 80080cb0 index=1 outPhysicalMask");
            }
        } catch (Exception ex) {
            println("PROTECTION_APPLICATION_ERROR " + ex.getMessage());
        }
    }

    private void reportSavedFunctions() throws Exception {
        Set<String> targets = new HashSet<>(Arrays.asList(INTERESTING_SAVED_NAMES));
        int located = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!targets.contains(f.getName())) continue;
            println("PRESERVED_FUNCTION " + f.getEntryPoint() + " " +
                f.getName() + " return=" + f.getReturnType().getDisplayName() +
                " params=" + f.getParameterCount() +
                " signatureSource=" + f.getSignatureSource());
            located++;
        }
        println("PRESERVED_FUNCTION_SUMMARY recognized=" + located +
            "/" + targets.size());
    }

    @Override
    protected void run() throws Exception {
        println("XBOXKRNL_17559_POST_CR0_CHECKPOINT_20261017_v2" +
            " apply=" + APPLY_VERIFIED_METADATA);
        println("Program=" + currentProgram.getName() +
            " language=" + currentProgram.getLanguageID() +
            " executableSha256=" + currentProgram.getExecutableSHA256());
        if (!"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE_WRONG_LANGUAGE");
            return;
        }
        // The GZF cannot attest to the compiled SLA hash. P-code widths are
        // observed from the language actually loaded in this Ghidra session.
        checkCr0Sites();
        annotateProtectionMaskFunction();
        reportSavedFunctions();
        println("DONE: bytes, function bodies, existing datatypes, signatures," +
            " and unrelated bookmarks preserved. New metadata is guarded and repeat-safe.");
    }
}