package xexloaderwv;

import java.io.IOException;
import java.util.Arrays;

/**
 * Standalone import-table regression tests (no Ghidra runtime required).
 *
 * javac -d build/import-table-test src/main/java/xexloaderwv/ImportFunction.java src/main/java/xexloaderwv/ImportLibrary.java src/main/java/xexloaderwv/XEXImportTableParser.java src/test/java/xexloaderwv/XEXImportTableParserTest.java
 * java -cp build/import-table-test xexloaderwv.XEXImportTableParserTest
 */
public final class XEXImportTableParserTest {
    private static int checks;

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 8);
        data[offset + 1] = (byte) value;
    }

    private static void put32(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }

    private static void expect(boolean condition, String description) {
        checks++;
        if (!condition) {
            throw new AssertionError(description);
        }
    }

    private static void rejects(byte[] table, String description) {
        checks++;
        try {
            XEXImportTableParser.parse(table);
            throw new AssertionError(description + ": malformed table accepted");
        } catch (IOException expected) {
            // Correct rejection.
        }
    }

    // Matches the real aac.xex table's extents and import counts.
    // Only synthesized metadata is used; no XEX payload is embedded here.
    private static byte[] descriptor(int extraNamePadding, int extraRecordPadding,
            int trailingPadding) {
        int nameBytes = 0x18 + extraNamePadding;
        int firstSize = 0x70 + extraRecordPadding;
        int secondSize = 0x60;
        int total = 0x0C + nameBytes + firstSize + secondSize + trailingPadding;
        byte[] table = new byte[total];
        put32(table, 0, total);
        put32(table, 4, nameBytes);
        put32(table, 8, 2);

        byte[] name1 = "xam.xex".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] name2 = "xboxkrnl.exe".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(name1, 0, table, 0x0C, name1.length);
        System.arraycopy(name2, 0, table, 0x14, name2.length);
        // The second name terminates at 0x20. Bytes 0x21..0x23 are arbitrary.
        table[0x21] = 0x12;
        table[0x22] = 0x4E; // Actual observed padding value that failed import.
        table[0x23] = (byte) 0xA5;
        Arrays.fill(table, 0x24, 0x24 + extraNamePadding, (byte) 0xF7);

        int first = 0x0C + nameBytes;
        int second = first + firstSize;
        put32(table, first, firstSize);
        put16(table, first + 0x24, 0);
        put16(table, first + 0x26, 18);
        for (int i = 0; i < 18; i++) {
            put32(table, first + 0x28 + i * 4, 0x91000000 | i);
        }
        Arrays.fill(table, first + 0x70, second, (byte) 0xFE);
        put32(table, second, secondSize);
        put16(table, second + 0x24, 1);
        put16(table, second + 0x26, 14);
        for (int i = 0; i < 14; i++) {
            put32(table, second + 0x28 + i * 4, 0x92000000 | i);
        }
        Arrays.fill(table, second + secondSize, total, (byte) 0x81);
        return table;
    }

    public static void main(String[] args) throws Exception {
        byte[] exactExtents = descriptor(0, 0, 0);
        XEXImportTableParser.Result parsed = XEXImportTableParser.parse(exactExtents);
        expect(parsed.names.size() == 2, "name count");
        expect("xam.xex".equals(parsed.names.get(0)), "first library name");
        expect("xboxkrnl.exe".equals(parsed.names.get(1)), "second library name");
        expect(parsed.libraries.size() == 2, "library record count");
        expect(parsed.libraries.get(0).records.size() == 18, "xam import count");
        expect(parsed.libraries.get(1).records.size() == 14, "kernel import count");
        expect(parsed.libraries.get(1).records.get(13) == 0x9200000D,
                "final import record preserved");

        // Unspecified padding must be skipped at every defined extent:
        // per-name alignment, name-table tail, library-record tail, descriptor tail.
        parsed = XEXImportTableParser.parse(descriptor(4, 4, 3));
        expect(parsed.libraries.size() == 2, "arbitrary padding preserves records");
        expect("xboxkrnl.exe".equals(parsed.libraries.get(1).name),
                "library name index preserved");

        byte[] badIndex = exactExtents.clone();
        put16(badIndex, 0x24 + 0x24, 3);
        rejects(badIndex, "out-of-range name index");

        byte[] badSize = exactExtents.clone();
        put32(badSize, 0x24, 0x20);
        rejects(badSize, "undersized library record");

        byte[] badCount = exactExtents.clone();
        put16(badCount, 0x24 + 0x26, 19);
        rejects(badCount, "import count exceeds record size");

        byte[] badDescriptor = exactExtents.clone();
        put32(badDescriptor, 0, exactExtents.length + 4);
        rejects(badDescriptor, "descriptor exceeds buffer");

        System.out.println("PASS: " + checks + " XEX import table checks");
    }
}
