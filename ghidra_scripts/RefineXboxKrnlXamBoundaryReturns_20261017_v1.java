// Native SHA-guarded correction of five kernel return contracts heavily used by XAM.
// @category Xbox360.Kernel
// Retail 17559 only. No parameter, calling-convention, source byte or datatype edits.
// Ghidra script runs with the *kernel* program open, not xam.xex.
import java.security.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;

public class RefineXboxKrnlXamBoundaryReturns_20261017_v1 extends GhidraScript {
    private static final boolean APPLY_VERIFIED_CHANGES = true;
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String KERNEL_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";

    private static final class Target {
        final long entry;
        final int length, params, xamCalls;
        final String name, sha;
        Target(long entry, int length, int params, int xamCalls, String name, String sha) {
            this.entry = entry;
            this.length = length;
            this.params = params;
            this.xamCalls = xamCalls;
            this.name = name;
            this.sha = sha;
        }
    }
    // Whole-function big-endian native instruction SHA256 from 2026-10-15 exports.
    private static final Target[] TARGETS = {
        new Target(0x800718e0L, 0x14, 0, 460, "KeEnterCriticalRegion",
            "b804cbd2243abdb5c607944ce5de1595e6b9267943aef85e67b893460a439e39"),
        new Target(0x800718f8L, 0x38, 0, 496, "KeLeaveCriticalRegion",
            "b87c0e3f2713fc1a71ec6c77394d08a42d8a807cdbc996f53fc5e30645a1afae"),
        new Target(0x8008b928L, 0x88, 1, 126, "ObDereferenceObject",
            "31379f86f1061492a6be17a9bca7b70f3093e47a5b02bc012dfad87c253a8e34"),
        new Target(0x800750f4L, 0x34, 1, 116, "KfLowerIrql",
            "c1c3c1223ae0cdf60695c9999e6e12877f48b20dba543bc9ee702b6641214a25"),
        new Target(0x8007020cL, 0x10, 1, 112, "KeReleaseSpinLockFromRaisedIrql",
            "8528b6bfa38c3cc6a7c4320b6291ef768e36ec4d8757de3f4a858dfcb79f03e5")
    };

    private Address address(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    private String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }
    @Override
    public void run() throws Exception {
        if (!LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            !KERNEL_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"xboxkrnl.exe".equalsIgnoreCase(currentProgram.getName())) {
            println("REFUSE: expected retail 17559 kernel with exact SHA/language");
            return;
        }
        println("KERNEL_XAM_CONTRACT_RETURNS_20261017_V1 apply=" + APPLY_VERIFIED_CHANGES);
        int matched = 0, applied = 0, already = 0, withheld = 0;
        for (Target target : TARGETS) {
            monitor.checkCancelled();
            Address entry = address(target.entry);
            Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (f == null || f.isThunk() || !target.name.equals(f.getName()) ||
                f.getParameterCount() != target.params ||
                !f.getBody().contains(entry.add(target.length - 4))) {
                println("WITHHELD " + entry + " function/name/body/parameters changed");
                withheld++;
                continue;
            }
            boolean instructionMismatch = false;
            for (int i = 0; i < target.length; i += 4) {
                Instruction ins = currentProgram.getListing().getInstructionAt(entry.add(i));
                if (ins == null || ins.getLength() != 4) {
                    instructionMismatch = true;
                    break;
                }
            }
            if (instructionMismatch) {
                println("WITHHELD " + entry + " noncontiguous/native instruction mismatch");
                withheld++;
                continue;
            }
            byte[] bytes = new byte[target.length];
            int n = currentProgram.getMemory().getBytes(entry, bytes);
            if (n != bytes.length || !target.sha.equals(sha256(bytes))) {
                println("WITHHELD " + entry + " native SHA mismatch");
                withheld++;
                continue;
            }
            matched++;
            String oldReturn = f.getReturnType().getName();
            if ("void".equals(oldReturn)) {
                println("VERIFIED_ALREADY_VOID " + entry + " " + target.name);
                already++;
                continue;
            }
            if (!oldReturn.startsWith("undefined") || f.hasCustomVariableStorage()) {
                println("WITHHELD " + entry + " preserve typed/custom return=" + oldReturn +
                    " customStorage=" + f.hasCustomVariableStorage());
                withheld++;
                continue;
            }
            println("VERIFIED " + entry + " " + target.name + " oldReturn=" + oldReturn +
                " XamBranchReferences=" + target.xamCalls +
                " params=" + f.getParameterCount() +
                " signatureSource=" + f.getSignatureSource());
            if (APPLY_VERIFIED_CHANGES) {
                f.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                if (!"void".equals(f.getReturnType().getName()))
                    throw new IllegalStateException("Return type did not update at " + entry);
                println("APPLIED_VOID_RETURN " + entry + " " + target.name);
                applied++;
            }
        }
        println("SUMMARY matched=" + matched + " changed=" + applied +
            " alreadyVoid=" + already + " withheld=" + withheld +
            " xamBranchReferencesAffected=1310");
        println("PRESERVED instruction bytes, parameter count/types/names/storage, " +
            "calling conventions, all globals, datatypes and bookmarks.");
        println("NOTE: This does NOT update XAM's separate external prototypes.");
    }
}
