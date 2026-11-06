package xexloaderwv;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Dependency-free integration fixtures for XEX resource descriptors and the
 * Xbox 360 big-endian XDBF table layout documented by Free60.
 *
 * javac -d build/xdbf-test src/main/java/xexloaderwv/XexXdbfResource.java src/test/java/xexloaderwv/XexXdbfResourceTest.java
 * java -cp build/xdbf-test xexloaderwv.XexXdbfResourceTest
 */
public final class XexXdbfResourceTest {
    private static int checks;

    private static void check(boolean condition, String description) {
        checks++;
        if (!condition) throw new AssertionError(description);
    }

    private static void be32(byte[] data, int at, long value) {
        data[at] = (byte) (value >>> 24);
        data[at + 1] = (byte) (value >>> 16);
        data[at + 2] = (byte) (value >>> 8);
        data[at + 3] = (byte) value;
    }

    private static void be16(byte[] data, int at, int value) {
        data[at] = (byte) (value >>> 8);
        data[at + 1] = (byte) value;
    }

    private static byte[] fixture(int resourceBytes) {
        byte[] data = new byte[resourceBytes];
        System.arraycopy("XDBF".getBytes(StandardCharsets.US_ASCII),
                0, data, 0, 4);
        be32(data, 4, 0x10000);
        be32(data, 8, 4); // capacity, not active count
        be32(data, 12, 2);
        be32(data, 16, 2);
        be32(data, 20, 1);
        int payloadStart = 0x18 + 4 * 0x12 + 2 * 8;
        be16(data, 0x18, 1);
        be32(data, 0x18 + 2, 0x12345678);
        be32(data, 0x18 + 6, 0x9abcdef0L);
        be32(data, 0x18 + 10, 10);
        be32(data, 0x18 + 14, 8);
        be16(data, 0x18 + 0x12, 2);
        be32(data, 0x18 + 0x12 + 2, 0);
        be32(data, 0x18 + 0x12 + 6, 1);
        be32(data, 0x18 + 0x12 + 10, 50);
        be32(data, 0x18 + 0x12 + 14, 4);
        for (int n = 0; n < 8; n++) data[payloadStart + 10 + n] = (byte) (n + 1);
        for (int n = 0; n < 4; n++) data[payloadStart + 50 + n] = (byte) (n + 1);
        return data;
    }

    private static byte[] descriptor(int imageBase, int rva, int length) {
        byte[] desc = new byte[20];
        be32(desc, 0, 20);
        System.arraycopy("4D5307D2".getBytes(StandardCharsets.US_ASCII),
                0, desc, 4, 8);
        be32(desc, 12, Integer.toUnsignedLong(imageBase) + rva);
        be32(desc, 16, length);
        return desc;
    }

    public static void main(String[] args) {
        int base = 0x82000000, rva = 0xB90000;
        int declared = 0x1000; // includes a long zero-filled tail
        byte[] image = new byte[rva + declared];
        byte[] xdbf = fixture(declared);
        System.arraycopy(xdbf, 0, image, rva, declared);
        byte[] descriptor = descriptor(base, rva, declared);

        List<XexXdbfResource.Resource> found =
                XexXdbfResource.parse(image, base, descriptor);
        check(found.size() == 1, "recognizes only valid resource");
        XexXdbfResource.Resource res = found.get(0);
        check(res.address == 0x82B90000L, "preserves unsigned guest address");
        check(res.length == declared, "declared resource length is not payload length");
        check(res.entryCapacity == 4 && res.entryCount == 2, "entry array capacity/count");
        check(res.freeCapacity == 2 && res.freeCount == 1, "free table capacity/count");
        check(res.dataOffset == 0x18 + 4 * 18 + 2 * 8, "payload starts after capacity-sized tables");
        check(res.highestReferencedPayloadEnd == 54,
                "highest active payload byte separate from resource padding");
        check(res.records.size() == 2 && res.records.get(0).namespace == 1 &&
                res.records.get(1).namespace == 2, "active namespace records");
        check(res.records.get(0).id == 0x123456789abcdef0L, "big endian 64-bit ID");

        // A resource may have padding; the parser must never use final
        // nonzero byte of a decoded XEX as a guessed database boundary.
        check(res.highestReferencedPayloadEnd < res.dataLength,
                "trailing padding distinguished from live records");

        byte[] malformed = image.clone();
        be32(malformed, rva + 0x18 + 14, declared);
        check(XexXdbfResource.parse(malformed, base, descriptor).isEmpty(),
                "reject payload outside declared resource");
        malformed = image.clone();
        be32(malformed, rva + 4, 0x20000);
        check(XexXdbfResource.parse(malformed, base, descriptor).isEmpty(),
                "reject unknown endian/version");
        check(XexXdbfResource.parse(image, base,
                descriptor(base, rva, rva + declared + 1)).isEmpty(),
                "reject resource beyond decoded image");
        check(XexXdbfResource.parse(image, base,
                descriptor(base, rva + declared, 24)).isEmpty(),
                "reject missing resource header");
        check(XexXdbfResource.parse(image, base, new byte[8]).isEmpty(),
                "reject truncated descriptor table");
        System.out.println("PASS: " + checks + " XEX XDBF resource checks");
    }
}
