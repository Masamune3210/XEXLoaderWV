// Refine the confirmed non-local jump helper in the 1888 dash XEX.
// @category Xbox360.XEX
//
// Applies only if the actual big-endian PPC instruction words match the
// provided dashboard disassembly. Does not modify native bytes, the import
// thunk, the RtlUnwind external, or unknown jump-buffer structure layouts.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

public class RefineXenonLongjmp1888_20261030_v1 extends GhidraScript {
    private static final long LONGJMP = 0x92452420L;
    private static final long CALLER = 0x9242D500L;

    private void requireWord(long address, int expected) throws Exception {
        Address a = toAddr(address);
        int actual = getInt(a);
        if (actual != expected) {
            throw new IllegalStateException(String.format(
                "Unexpected word at %08X: expected %08X, got %08X. " +
                "This is not the identified 1888 dashboard implementation.",
                address, expected, actual));
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open the imported 1888 dashboard Program first.");
            return;
        }
        // The critical control-flow landmarks: second return argument
        // normalized from zero to one; saved LR and SP restored; an alternate
        // unwind branch; caller immediately followed by zero padding.
        requireWord(0x92452420L, 0x7C0802A6); // mflr r0
        requireWord(0x92452430L, 0x2C040000); // cmpwi r4,0
        requireWord(0x92452448L, 0x38C00001); // li r6,1
        requireWord(0x924524F8L, 0x7CA803A6); // mtlr r5
        requireWord(0x92452508L, 0x4E800020); // blr, saved continuation LR
        requireWord(0x92452520L, 0x48001EFD); // bl xboxkrnl::RtlUnwind
        requireWord(0x9242D514L, 0x817F0140); // lwz r11,0x140(r31), optional callback
        requireWord(0x9242D524L, 0x4E800421); // bctrl, optional callback
        requireWord(0x9242D528L, 0x38800001); // li r4,1
        requireWord(0x9242D530L, 0x48024EF1); // bl 92452420
        requireWord(0x9242D534L, 0x00000000); // padding, not PPC

        Function f = getFunctionAt(toAddr(LONGJMP));
        Function caller = getFunctionAt(toAddr(CALLER));
        if (f == null || caller == null) {
            throw new IllegalStateException(
                "Expected Ghidra functions at 92452420 and 9242D500.");
        }

        int tx = currentProgram.startTransaction("Refine Xenon 1888 longjmp");
        boolean success = false;
        try {
            // Keep any specific existing user-defined name rather than
            // overwrite an unrelated manual refinement.
            if (f.getSymbol().getSource() != SourceType.USER_DEFINED ||
                    "longjmp".equals(f.getName())) {
                if (!"longjmp".equals(f.getName())) {
                    f.setName("longjmp", SourceType.USER_DEFINED);
                }
            }
            if (!f.hasNoReturn()) {
                f.setNoReturn(true);
            }
            // This wrapper only invokes an optional callback at +0x140 and
            // then calls longjmp(jumpBuffer, 1). It also cannot return.
            if (caller.getSymbol().getSource() != SourceType.USER_DEFINED ||
                    "LongjmpAfterOptionalCallback".equals(caller.getName())) {
                if (!"LongjmpAfterOptionalCallback".equals(caller.getName())) {
                    caller.setName("LongjmpAfterOptionalCallback",
                        SourceType.USER_DEFINED);
                }
            }
            if (!caller.hasNoReturn()) {
                caller.setNoReturn(true);
            }
            if (caller.getComment() == null || caller.getComment().isBlank()) {
                caller.setComment("Invokes an optional function pointer at " +
                    "jumpBuffer+0x140 (if present), then performs a " +
                    "non-returning longjmp(jumpBuffer, 1). The following " +
                    "zero bytes are intentional alignment padding.");
            }
            // Only refine unresolved ABI details. A pre-existing, manually
            // defined type must not be replaced.
            if (!f.hasCustomVariableStorage() && f.getParameterCount() == 2) {
                if (f.getReturnType().getName().startsWith("undefined")) {
                    f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                }
                Parameter jumpBuffer = f.getParameter(0);
                Parameter returnValue = f.getParameter(1);
                if (jumpBuffer.getName().startsWith("param_")) {
                    jumpBuffer.setName("jumpBuffer", SourceType.USER_DEFINED);
                }
                if (returnValue.getDataType().getName().startsWith("undefined")) {
                    returnValue.setDataType(IntegerDataType.dataType,
                        SourceType.USER_DEFINED);
                }
                if (returnValue.getName().startsWith("param_")) {
                    returnValue.setName("returnValue", SourceType.USER_DEFINED);
                }
            } else {
                println("Prototype not rewritten: parameter storage/count " +
                    "needs review. No Return marker and function identity " +
                    "were still applied.");
            }
            // Add explanatory comments only where there is no prior annotation.
            if (f.getComment() == null || f.getComment().isBlank()) {
                f.setComment("Xenon longjmp: restores saved f14-f31, r13-r31, " +
                    "SP, CR and LR before nonlocal transfer. The alternate " +
                    "path calls xboxkrnl::RtlUnwind. A zero requested " +
                    "returnValue is converted to one. Does not return " +
                    "to its direct caller.");
            }
            Address call = toAddr(0x9242D530L);
            if (getPlateComment(call) == null) {
                setPlateComment(call, "Calls non-returning longjmp(jumpBuffer, 1). " +
                    "The zero word at 9242D534 is padding, not a valid " +
                    "PPC instruction. Do not patch the native bytes.");
            }
            success = true;
        } finally {
            currentProgram.endTransaction(tx, success);
        }
        println("1888 dash longjmp refined at 92452420: " + f.getName() +
            ", No Return=" + f.hasNoReturn() +
            "; wrapper 9242D500 No Return=" + caller.hasNoReturn() +
            "; call at 9242D530 no longer has a valid fallthrough.");
        println("If an old Bad Instruction bookmark remains at 9242D534, " +
            "refresh analysis of the caller; existing bookmarks may persist.");
    }
}
