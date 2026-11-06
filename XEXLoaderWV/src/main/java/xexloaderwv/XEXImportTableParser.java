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

	public static Result parse(byte[] bytes) throws IOException {
		if (bytes == null || bytes.length < HEADER_SIZE) {
			throw new IOException("XEX import table: descriptor shorter than 12 bytes");
		}
		long size = readU32(bytes, 0);
		long nameBytes = readU32(bytes, 4);
		long libraryCount = readU32(bytes, 8);
		if (size < HEADER_SIZE || size > bytes.length ||
				nameBytes > size - HEADER_SIZE) {
			throw new IOException("XEX import table: invalid descriptor size=" + size +
				" nameBytes=" + nameBytes + " bufferLength=" + bytes.length);
		}
		long libraryStart = HEADER_SIZE + nameBytes;
		if (libraryCount > (size - libraryStart) / LIBRARY_HEADER_SIZE) {
			throw new IOException("XEX import table: " + libraryCount +
				" library headers cannot fit inside " + size + " bytes");
		}

		Result result = new Result();
		int namesEnd = (int) libraryStart;
		int pos = HEADER_SIZE;

		// XEX names are individually NUL-terminated and DWORD-aligned.
		// 0xCD is widely used for alignment padding, not a filename character.
		// The number of library names is explicitly specified by the header.
		for (long i = 0; i < libraryCount; i++) {
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
		}
		// The reserved bytes at the end of the table are padding too.
		for (; pos < namesEnd; pos++) {
			int c = bytes[pos] & 0xFF;
			if (c != 0 && c != 0xCD) {
				throw new IOException("XEX import table: unexpected trailing name byte 0x" +
					Integer.toHexString(c) + " at 0x" + Integer.toHexString(pos));
			}
		}

		long next = libraryStart;
		for (long i = 0; i < libraryCount; i++) {
			if (size - next < LIBRARY_HEADER_SIZE) {
				throw new IOException("XEX import table: truncated library " + i +
					" header at 0x" + Long.toHexString(next));
			}
			int base = (int) next;
			long recordSize = readU32(bytes, base);
			if (recordSize < LIBRARY_HEADER_SIZE || recordSize > size - next) {
				throw new IOException("XEX import table: library " + i +
					" at 0x" + Long.toHexString(next) +
					" has invalid record size 0x" + Long.toHexString(recordSize));
			}
			// The high byte of name_index is reserved (some XEXs fill it with
			// 0xCD). Only the low byte selects a string, as in native XEX2.
			int rawNameIndex = readU16(bytes, base + 0x24);
			int nameIndex = rawNameIndex & 0xFF;
			int count = readU16(bytes, base + 0x26);
			if (nameIndex >= result.names.size()) {
				throw new IOException("XEX import table: library " + i +
					" at 0x" + Long.toHexString(next) + " has name_index=0x" +
					Integer.toHexString(rawNameIndex) + " (low-byte index " +
					nameIndex + ", " + result.names.size() + " names)");
			}
			if ((long) count * 4 > recordSize - LIBRARY_HEADER_SIZE) {
				throw new IOException("XEX import table: library " + i +
					" at 0x" + Long.toHexString(next) + " has " + count +
					" imports but record size is 0x" + Long.toHexString(recordSize));
			}
			ImportLibrary library = new ImportLibrary();
			library.name = result.names.get(nameIndex);
			for (int j = 0; j < count; j++) {
				library.records.add((int) readU32(bytes,
					base + LIBRARY_HEADER_SIZE + j * 4));
			}
			result.libraries.add(library);
			// Deliberately use the embedded size, not 0x28 + count*4:
			// some XEXs pad library records and the following header would
			// otherwise be parsed from 0xCD-filled padding.
			next += recordSize;
		}
		for (int posTail = (int) next; posTail < size; posTail++) {
			int c = bytes[posTail] & 0xFF;
			if (c != 0 && c != 0xCD) {
				throw new IOException("XEX import table: unexpected trailing byte 0x" +
					Integer.toHexString(c) + " at 0x" +
					Integer.toHexString(posTail));
			}
		}
		return result;
	}
}
