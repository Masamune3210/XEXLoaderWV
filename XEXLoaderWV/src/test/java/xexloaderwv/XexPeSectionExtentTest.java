package xexloaderwv;

import java.io.IOException;

/**
 * Dependency-free regression tests for decoded-image-backed PE section extents.
 *
 * Run from the extension root with:
 * javac -d build/pe-extent-test src/main/java/xexloaderwv/XexPeSectionExtent.java src/test/java/xexloaderwv/XexPeSectionExtentTest.java
 * java -cp build/pe-extent-test xexloaderwv.XexPeSectionExtentTest
 */
public final class XexPeSectionExtentTest {
    private static int checks;

    private static void expect(String description, int expected, int actual) {
        checks++;
        if (expected != actual) {
            throw new AssertionError(description + ": expected 0x" +
                    Integer.toHexString(expected) + ", got 0x" +
                    Integer.toHexString(actual));
        }
    }

    private static void reject(String description, int rva, int size, int imageSize)
            throws Exception {
        checks++;
        try {
            XexPeSectionExtent.backedSize(description, rva, size, imageSize);
            throw new AssertionError(description + ": unexpectedly accepted invalid extent");
        } catch (IOException expected) {
            if (!expected.getMessage().contains(description)) {
                throw new AssertionError("Missing section name in error", expected);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // Kameo: Elements of Power, retail launch XEX. Its .reloc virtual
        // end is 0xC077C0 but the authenticated XEX image ends at 0xBF0000.
        int imageSize = 0xBF0000;
        int relocRva = 0xBA0200;
        int relocVirtualSize = 0x675C0;
        expect("Kameo .reloc backed bytes", 0x4FE00,
                XexPeSectionExtent.backedSize(".reloc", relocRva,
                        relocVirtualSize, imageSize));
        expect("Kameo .reloc declared end", 0xC077C0,
                relocRva + relocVirtualSize);
        expect("Kameo .reloc unbacked tail", 0x177C0,
                relocVirtualSize - 0x4FE00);

        // A normal, in-bounds section retains its full declared virtual size.
        expect("Kameo .text", 0x61F6BC,
                XexPeSectionExtent.backedSize(".text", 0xB0000,
                        0x61F6BC, imageSize));
        expect("exact image end", 0x100,
                XexPeSectionExtent.backedSize("last", imageSize - 0x100,
                        0x100, imageSize));
        expect("zero virtual size", 0,
                XexPeSectionExtent.backedSize("empty", 0, 0, imageSize));

        // Guard 32-bit arithmetic: the declared end must never wrap and
        // cause a negative array range or synthetic zero-filled bytes.
        expect("overflow-safe subtraction", 0x0F,
                XexPeSectionExtent.backedSize("overflow", 0x7FFFFFF0,
                        Integer.MAX_VALUE, Integer.MAX_VALUE));

        reject("negative RVA", -1, 4, imageSize);
        reject("negative size", 0, -1, imageSize);
        reject("at decoded image end", imageSize, 1, imageSize);
        reject("beyond decoded image end", imageSize + 1, 1, imageSize);
        reject("empty decoded image", 0, 1, 0);

        System.out.println("PASS: " + checks + " XEX PE section extent regression checks");
    }
}
