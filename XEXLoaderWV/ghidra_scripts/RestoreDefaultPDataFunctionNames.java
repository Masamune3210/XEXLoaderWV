// RestoreDefaultPDataFunctionNames.java
// Revert legacy Function_XXXXXXXX symbols manufactured by earlier versions
// of XEXLoaderWV while leaving semantic names, user changes, and prototypes
// intact. The first run is a preview. Explicitly set APPLY_CHANGES = true,
// verify the preview and rerun to apply.
// @category XEXLoaderWV

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RestoreDefaultPDataFunctionNames extends GhidraScript {
    // Defaults to read-only. Change this to true only after reviewing results.
    private static final boolean APPLY_CHANGES = false;
    private static final int MAX_PREVIEW = 40;
    private static final Pattern LEGACY_NAME =
        Pattern.compile("^Function_([0-9a-fA-F]{8})$");

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("No active Ghidra program.");
            return;
        }
        int matching = 0;
        int altered = 0;
        int skipped = 0;
        println((APPLY_CHANGES ? "APPLY" : "PREVIEW") +
            ": legacy XEXLoaderWV Function_ names in " + currentProgram.getName());
        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            Matcher matcher = LEGACY_NAME.matcher(function.getName());
            if (!matcher.matches()) continue;
            long suffix = Long.parseUnsignedLong(matcher.group(1), 16);
            long entry = function.getEntryPoint().getOffset() & 0xffffffffL;
            if (suffix != entry ||
                    function.getSymbol().getSource() != SourceType.ANALYSIS ||
                    function.isThunk()) {
                skipped++;
                continue;
            }
            matching++;
            if (matching <= MAX_PREVIEW) {
                println((APPLY_CHANGES ? "Reset " : "Would reset ") +
                    function.getName() + " @ " + function.getEntryPoint());
            }
            if (APPLY_CHANGES) {
                // Ghidra itself computes FUN_XXXXXXXX. Do NOT rename the
                // function to a hand-generated FUN_ string, which would just
                // create another non-default analysis/user symbol.
                function.setName(null, SourceType.DEFAULT);
                altered++;
            }
        }
        println("Eligible: " + matching + ", skipped different-source/address " +
            "or thunk: " + skipped + ", changed: " + altered);
        if (!APPLY_CHANGES) {
            println("Preview only. To apply, change APPLY_CHANGES to true and rerun.");
        }
    }
}
