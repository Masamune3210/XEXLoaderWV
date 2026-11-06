package xexloaderwv;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * Reads the XEX_HEADER_IMPORT_LIBRARIES optional header without depending on
 * decrypted PE bytes. Handles the 4-byte-aligned name table and per-library
 * record lengths used by early (including 1888) and later XEX2 images.
 */
public final class XEXImportTableParser {
	private static final int HEADER_SIZE = 0x0C;
	private static final int LIBRARY_HEADER_SIZE = 0x28;

	public static final class Result {
		public final ArrayList<String> names = new ArrayList<>();
		public final ArrayList<ImportLibrary> libraries = new ArrayList<>();
		public boolean packedNames;
	}

	private XEXImportTableParser() {
	}

	private static long readU32(byte[] bytes, int offset) throws IOException {
		if (offset < 0 || (long) offset + 4 > bytes.length) {
			throw new IOException("XEX import table: truncated 32-bit field at 0x" +
				Integer.toHexString(offset));
		}
		return ((long) (bytes[offset] & 0xFF) << 24) |
			((long) (bytes[offset + 1] & 0xFF) << 16) |
			((long) (bytes[offset + 2] & 0xFF) << 8) |
			(long) (bytes[offset + 3] & 0xFF);
	}

	private static int readU16(byte[] bytes, int offset) throws IOException {
		if (offset < 0 || (long) offset + 2 > bytes.length) {
			throw new IOException("XEX import table: truncated 16-bit field at 0x" +
				Integer.toHexString(offset));
		}
		return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
	}

	/**
	 * Prefer the usual per-name DWORD alignment, but support import tables whose
	 * names are packed together. Both layouts must pass full bounds and library
	 * record validation; a failure is never treated as an empty import table.
	 */
	public static Result parse(byte[] bytes) throws IOException {
		try {
			return parseLayout(bytes, true);
		} catch (IOException alignedFailure) {
			try {
				Result packed = parseLayout(bytes, false);
				packed.packedNames = true;
				return packed;
			} catch (IOException packedFailure) {
				alignedFailure.addSuppressed(packedFailure);
				throw alignedFailure;
			}
		}
	}

	private static boolean isPadding(byte[] bytes, int start, int end) {
		for (int i = start; i < end; i++) {
			int c = bytes[i] & 0xFF;
			if (c != 0 && c != 0xCD) {
				return false;
			}
		}
		return true;
	}

	private static Result parseLayout(byte[] bytes, boolean alignedNames)
			throws IOException {
		if (bytes == null || bytes.length < HEADER_SIZE) {
			throw new IOException("XEX import table: descriptor shorter than 12 bytes");
		}
		long size = readU32(bytes, 0);
		long nameBytes = readU32(bytes, 4);
		long nameCount = readU32(bytes, 8);
		if (size < HEADER_SIZE || size > bytes.length ||
				nameBytes > size - HEADER_SIZE) {
			throw new IOException("XEX import table: invalid descriptor size=" + size +
					" nameBytes=" + nameBytes + " bufferLength=" + bytes.length);
		}
		// +0x08 is the string-table name count, NOT the number of library
		// records. Multiple library records may refer to the same name.
		if (nameCount > nameBytes / 2) {
			throw new IOException("XEX import table: " + nameCount +
					" names cannot fit in " + nameBytes + " string-table bytes");
		}
		int namesEnd = (int) (HEADER_SIZE + nameBytes);
		Result result = new Result();
		int pos = HEADER_SIZE;
		for (long i = 0; i < nameCount; i++) {
			if (pos >= namesEnd) {
				throw new IOException("XEX import table: missing name " + i +
						" before string table end 0x" + Integer.toHexString(namesEnd));
			}
			int begin = pos;
			while (pos < namesEnd && bytes[pos] != 0) {
				int c = bytes[pos] & 0xFF;
				if (c < 0x20 || c > 0x7E) {
					throw new IOException("XEX import table: non-ASCII library name byte 0x" +
							Integer.toHexString(c) + " at 0x" + Integer.toHexString(pos));
				}
				pos++;
			}
			if (pos >= namesEnd || pos == begin) {
				throw new IOException("XEX import table: unterminated or empty library name " +
						i + " at 0x" + Integer.toHexString(begin));
			}
			result.names.add(new String(bytes, begin, pos - begin,
					StandardCharsets.US_ASCII));
			int afterTerminator = pos + 1;
			int aligned = HEADER_SIZE + ((afterTerminator - HEADER_SIZE + 3) & ~3);
			if (alignedNames) {
				if (aligned > namesEnd) {
					throw new IOException("XEX import table: name " + i +
							" alignment exceeds table at 0x" + Integer.toHexString(pos));
				}
				for (pos = afterTerminator; pos < aligned; pos++) {
					int c = bytes[pos] & 0xFF;
					if (c != 0 && c != 0xCD) {
						throw new IOException("XEX import table: invalid alignment byte 0x" +
								Integer.toHexString(c) + " at 0x" + Integer.toHexString(pos));
					}
				}
			} else {
				pos = afterTerminator;
			}
		}
		if (!isPadding(bytes, pos, namesEnd)) {
			throw new IOException("XEX import table: unexpected trailing name bytes at 0x" +
					Integer.toHexString(pos));
		}

		// Import records occupy the rest of the descriptor, each advancing by
		// its declared size, independently of the number of library names.
		long next = namesEnd;
		while (next < size) {
			int base = (int) next;
			if (size - next < LIBRARY_HEADER_SIZE) {
				if (!isPadding(bytes, base, (int) size)) {
					throw new IOException("XEX import table: truncated library header at 0x" +
							Long.toHexString(next));
				}
				break;
			}
			long recordSize = readU32(bytes, base);
			if (recordSize == 0 || recordSize == 0xCDCDCDCDL) {
				if (!isPadding(bytes, base, (int) size)) {
					throw new IOException("XEX import table: non-padding data after library records at 0x" +
							Long.toHexString(next));
				}
				break;
			}
			if (recordSize < LIBRARY_HEADER_SIZE || recordSize > size - next) {
				throw new IOException("XEX import table: library at 0x" +
						Long.toHexString(next) + " has invalid record size 0x" +
						Long.toHexString(recordSize));
			}
			// Upper name_index byte may be 0xCD in early XEXs.
			int rawNameIndex = readU16(bytes, base + 0x24);
			int nameIndex = rawNameIndex & 0xFF;
			int count = readU16(bytes, base + 0x26);
			if (nameIndex >= result.names.size()) {
				throw new IOException("XEX import table: library at 0x" +
						Long.toHexString(next) + " has name_index=0x" +
						Integer.toHexString(rawNameIndex) + " (low-byte index " +
						nameIndex + ", " + result.names.size() + " names)");
			}
			if ((long) count * 4 > recordSize - LIBRARY_HEADER_SIZE) {
				throw new IOException("XEX import table: library at 0x" +
						Long.toHexString(next) + " has " + count +
						" imports but record size is 0x" + Long.toHexString(recordSize));
			}
			ImportLibrary library = new ImportLibrary();
			library.name = result.names.get(nameIndex);
			for (int j = 0; j < count; j++) {
				library.records.add((int) readU32(bytes,
						base + LIBRARY_HEADER_SIZE + j * 4));
			}
			result.libraries.add(library);
			next += recordSize;
		}
		return result;
	}

}
