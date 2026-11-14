package xexloaderwv;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Ghidra-independent source-regression guard: .pdata function discovery
 * must not manufacture Function_ symbols with SourceType.ANALYSIS.
 *
 * Run from the XEXLoaderWV extension root:
 * javac -d build/pdata-name-test src/test/java/xexloaderwv/PDataDefaultFunctionNamesTest.java
 * java -cp build/pdata-name-test xexloaderwv.PDataDefaultFunctionNamesTest
 *
 * This is a source-contract test, not a replacement for Ghidra integration.
 */
public final class PDataDefaultFunctionNamesTest {
    private static int checks;

    private static void require(boolean condition, String description) {
        checks++;
        if (!condition) throw new AssertionError(description);
    }

    private static String method(String text, String start, String next) {
        int a = text.indexOf(start);
        int b = text.indexOf(next, a + start.length());
        require(a >= 0 && b > a, "method boundary " + start);
        return text.substring(a, b);
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of("").toAbsolutePath();
        String xex = Files.readString(root.resolve(
            "src/main/java/xexloaderwv/XEXHeader.java"));
        String kernel = Files.readString(root.resolve(
            "src/main/java/xexloaderwv/XboxKernelMemoryPeLoader.java"));
        String conventionalPData = method(xex, "public void ProcessPData(",
            "public void ProcessNativeExports(");
        String kernelPData = method(kernel, "private static void importPData(",
            "private static boolean ensureFunction(");

        require(conventionalPData.contains("EnsureFunction(addr, program, monitor)"),
            "XEX .pdata still creates functions");
        require(kernelPData.contains("ensureFunction(program, target, monitor)"),
            "kernel PE .pdata still creates functions");

        for (String part : new String[] {conventionalPData, kernelPData}) {
            require(!part.contains("\"Function_\""),
                ".pdata must not assign a Function_ name");
            require(!part.contains("createPreferredLabelOrFunctionSymbol("),
                ".pdata must not pre-label function entrypoints");
            require(!part.contains(".setName("),
                ".pdata must not name functions merely from their addresses");
        }

        String script = Files.readString(root.resolve(
            "ghidra_scripts/RestoreDefaultPDataFunctionNames.java"));
        require(script.contains("APPLY_CHANGES = false"),
            "legacy database repair must default to preview mode");
        require(script.contains("SourceType.ANALYSIS"),
            "repair must limit itself to analysis-sourced symbols");
        require(script.contains("function.setName(null, SourceType.DEFAULT)"),
            "repair must restore actual Ghidra defaults, not generate FUN_ labels");

        System.out.println("PASS: " + checks +
            " .pdata default-function-name source checks");
    }
}
