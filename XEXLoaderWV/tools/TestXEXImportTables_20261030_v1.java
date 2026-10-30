import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import xexloaderwv.XEXImportTableParser;

/**
 * Standalone regression for the original 1888 import crash (0xCDCD index).
 *
 * Compile from XEXLoaderWV/:
 * javac -d build/import-test src/main/java/xexloaderwv/ImportFunction.java src/main/java/xexloaderwv/ImportLibrary.java src/main/java/xexloaderwv/XEXImportTableParser.java tools/TestXEXImportTables_20261030_v1.java
 * java -cp build/import-test TestXEXImportTables_20261030_v1
 */
public final class TestXEXImportTables_20261030_v1 {
	private static int passed;

	private static void putU32(byte[] out, int pos, long value) {
		for (int i = 0; i < 4; i++) {
			out[pos + i] = (byte) (value >> (24 - 8 * i));
		}
	}

	private static void putU16(byte[] out, int pos, int value) {
		out[pos] = (byte) (value >> 8);
		out[pos + 1] = (byte) value;
	}

	private static byte[] fixture() {
		// DWORD-aligned names with CD filler; two libraries.
		// First library has an extra DWORD of CD padding after its imports.
		int strings = 24;
		int firstSize = 0x28 + 2 * 4 + 4;
		int secondSize = 0x28 + 1 * 4;
		int first = 12 + strings;
		int second = first + firstSize;
		byte[] bytes = new byte[second + secondSize];
		Arrays.fill(bytes, (byte) 0xCD);
		putU32(bytes, 0, bytes.length);
		putU32(bytes, 4, strings);
		putU32(bytes, 8, 2);
		byte[] one = "xboxkrnl.exe".getBytes(StandardCharsets.US_ASCII);
		byte[] two = "xam.xex".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(one, 0, bytes, 12, one.length);
		bytes[12 + one.length] = 0;
		System.arraycopy(two, 0, bytes, 12 + 16, two.length);
		bytes[12 + 16 + two.length] = 0;
		putU32(bytes, first, firstSize);
		putU16(bytes, first + 0x24, 0xCD00);
		putU16(bytes, first + 0x26, 2);
		putU32(bytes, first + 0x28, 0x80000120L);
		putU32(bytes, first + 0x2C, 0x80000124L);
		putU32(bytes, second, secondSize);
		putU16(bytes, second + 0x24, 0xCD01);
		putU16(bytes, second + 0x26, 1);
		putU32(bytes, second + 0x28, 0x81000330L);
		return bytes;
	}

	private static void check(boolean value, String description) {
		if (!value) {
			throw new AssertionError(description);
		}
		passed++;
	}

	private static void expectFailure(byte[] bytes, String fragment) throws Exception {
		try {
			XEXImportTableParser.parse(bytes);
			throw new AssertionError("Expected IOException mentioning " + fragment);
		} catch (IOException e) {
			check(e.getMessage().contains(fragment),
				"Error did not mention '" + fragment + "': " + e.getMessage());
		}
	}

	public static void main(String[] args) throws Exception {
		byte[] bytes = fixture();
		var parsed = XEXImportTableParser.parse(bytes);
		check(parsed.names.size() == 2, "Name count");
		check(parsed.names.get(0).equals("xboxkrnl.exe"), "Aligned kernel name");
		check(parsed.names.get(1).equals("xam.xex"), "Aligned XAM name");
		check(parsed.libraries.size() == 2, "Library count");
		check(parsed.libraries.get(0).name.equals("xboxkrnl.exe"), "High-byte 0xCD name_index");
		check(parsed.libraries.get(1).name.equals("xam.xex"), "Second library after padded record");
		check(parsed.libraries.get(0).records.size() == 2, "First record count");
		check(parsed.libraries.get(0).records.get(0) == 0x80000120, "First import address");
		check(parsed.libraries.get(1).records.get(0) == 0x81000330, "Second import address");

		int second = 12 + 24 + 0x34;
		byte[] invalid = bytes.clone();
		putU16(invalid, second + 0x24, 0xCDCD);
		expectFailure(invalid, "name_index=0xcdcd");

		invalid = bytes.clone();
		putU32(invalid, 12 + 24, 0x7FFFFFFFL);
		expectFailure(invalid, "invalid record size");

		invalid = bytes.clone();
		putU16(invalid, 12 + 24 + 0x26, 0xFFFF);
		expectFailure(invalid, "imports but record size");

		invalid = bytes.clone();
		invalid[12 + "xboxkrnl.exe".length()] = 0x41;
		expectFailure(invalid, "non-ASCII library name");

		System.out.println("XEX import table regression: " + passed + " checks passed.");
	}
}
