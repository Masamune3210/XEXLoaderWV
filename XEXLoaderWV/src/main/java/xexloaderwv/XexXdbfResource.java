package xexloaderwv;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Pure-Java, read-only parser for Xbox 360 XEX RESOURCE_INFO (0x2ff) entries
 * containing a big-endian XDBF (usually a title SPA) in the decoded image.
 * Coordinates are virtual RVAs, never PE PointerToRawData file offsets.
 */
final class XexXdbfResource {
    static final int HEADER_SIZE = 0x18;
    static final int ENTRY_SIZE = 0x12;
    static final int FREE_ENTRY_SIZE = 8;

    static final class Record {
        final int namespace;
        final long id, offset, length;

        Record(int namespace, long id, long offset, long length) {
            this.namespace = namespace;
            this.id = id;
            this.offset = offset;
            this.length = length;
        }
    }

    static final class Resource {
        final String name;
        final long address;
        final int rva, length;
        final int version, entryCapacity, entryCount, freeCapacity, freeCount;
        final int freeOffset, dataOffset, dataLength;
        final long highestReferencedPayloadEnd;
        final List<Record> records;

        Resource(String name, long address, int rva, int length,
                int version, int entryCapacity, int entryCount,
                int freeCapacity, int freeCount, int freeOffset, int dataOffset,
                long highestReferencedPayloadEnd, List<Record> records) {
            this.name = name;
            this.address = address;
            this.rva = rva;
            this.length = length;
            this.version = version;
            this.entryCapacity = entryCapacity;
            this.entryCount = entryCount;
            this.freeCapacity = freeCapacity;
            this.freeCount = freeCount;
            this.freeOffset = freeOffset;
            this.dataOffset = dataOffset;
            this.dataLength = length - dataOffset;
            this.highestReferencedPayloadEnd = highestReferencedPayloadEnd;
            this.records = Collections.unmodifiableList(new ArrayList<>(records));
        }
    }

    private XexXdbfResource() {
    }

    static long be32(byte[] bytes, int pos) {
        return ((long) (bytes[pos] & 255) << 24) |
                ((long) (bytes[pos + 1] & 255) << 16) |
                ((long) (bytes[pos + 2] & 255) << 8) |
                (long) (bytes[pos + 3] & 255);
    }

    private static boolean isXdbf(byte[] image, int offset) {
        return image[offset] == 'X' && image[offset + 1] == 'D' &&
                image[offset + 2] == 'B' && image[offset + 3] == 'F';
    }

    static List<Resource> parse(byte[] image, int imageBase, byte[] resourceInfo) {
        if (image == null || resourceInfo == null || resourceInfo.length < 20)
            return Collections.emptyList();
        long size = be32(resourceInfo, 0);
        if (size < 20 || size > resourceInfo.length || (size - 4) % 16 != 0)
            return Collections.emptyList();
        List<Resource> found = new ArrayList<>();
        long unsignedBase = Integer.toUnsignedLong(imageBase);
        for (int p = 4; p + 16 <= size; p += 16) {
            String name = new String(resourceInfo, p, 8, StandardCharsets.US_ASCII);
            boolean readableName = true;
            for (int c = 0; c < 8; c++) {
                int ch = resourceInfo[p + c] & 255;
                if (ch < 0x20 || ch > 0x7e) readableName = false;
            }
            if (!readableName) continue;
            long address = be32(resourceInfo, p + 8);
            long length = be32(resourceInfo, p + 12);
            long rva = address - unsignedBase;
            if (rva < 0 || rva > image.length - HEADER_SIZE ||
                    length < HEADER_SIZE || length > image.length - rva ||
                    length > Integer.MAX_VALUE) continue;
            int offset = (int) rva;
            if (!isXdbf(image, offset)) continue;
            // Retail Xbox 360 XDBF is big endian. The GFWL little-endian
            // variant is intentionally not typed as Xenon BE fields.
            long version = be32(image, offset + 4);
            long entries = be32(image, offset + 8);
            long entryCount = be32(image, offset + 12);
            long frees = be32(image, offset + 16);
            long freeCount = be32(image, offset + 20);
            if (version != 0x10000 || entryCount > entries ||
                    freeCount > frees) continue;
            long freeOffset = HEADER_SIZE + entries * ENTRY_SIZE;
            long dataOffset = freeOffset + frees * FREE_ENTRY_SIZE;
            if (dataOffset > length || entries > Integer.MAX_VALUE / ENTRY_SIZE ||
                    frees > Integer.MAX_VALUE / FREE_ENTRY_SIZE) continue;
            long payloadLength = length - dataOffset;
            // Validate the active entries; unused capacity slots need not
            // contain meaningful values. All offsets are payload-relative.
            boolean valid = true;
            long highestEnd = 0;
            List<Record> records = new ArrayList<>();
            for (int n = 0; n < entryCount; n++) {
                int entry = offset + HEADER_SIZE + n * ENTRY_SIZE;
                int namespace = ((image[entry] & 255) << 8) |
                        (image[entry + 1] & 255);
                long id = (be32(image, entry + 2) << 32) |
                        be32(image, entry + 6);
                long relative = be32(image, entry + 10);
                long bytes = be32(image, entry + 14);
                if (relative > payloadLength ||
                        bytes > payloadLength - relative) {
                    valid = false;
                    break;
                }
                highestEnd = Math.max(highestEnd, relative + bytes);
                records.add(new Record(namespace, id, relative, bytes));
            }
            if (!valid) continue;
            found.add(new Resource(name, address, offset, (int) length,
                    (int) version, (int) entries, (int) entryCount,
                    (int) frees, (int) freeCount, (int) freeOffset,
                    (int) dataOffset, highestEnd, records));
        }
        return found;
    }
}
