package xexloaderwv;

import java.util.Arrays;

/**
 * Dependency-free tests for identifying a CF/CG reconstructed Xbox 360
 * kernel PE without interpreting its stale PointerToRawData fields.
 *
 * javac -d build/kernel-rva-test src/main/java/xexloaderwv/XboxKernelMemoryPe.java src/test/java/xexloaderwv/XboxKernelMemoryPeTest.java
 * java -cp build/kernel-rva-test xexloaderwv.XboxKernelMemoryPeTest
 */
public final class XboxKernelMemoryPeTest {
    private static int checks;
    private static void expect(boolean value, String name) {
        checks++;
        if (!value) throw new AssertionError(name);
    }

    private static void le16(byte[] bytes, int off, int value) {
        bytes[off] = (byte) value;
        bytes[off + 1] = (byte) (value >>> 8);
    }

    private static void le32(byte[] bytes, int off, int value) {
        le16(bytes, off, value);
        le16(bytes, off + 2, value >>> 16);
    }

    private static void section(byte[] bytes, int offset, String name,
            int rva, int virtualSize, int raw, int rawSize, int flags) {
        for (int i = 0; i < name.length(); ++i)
            bytes[offset + i] = (byte) name.charAt(i);
        le32(bytes, offset + 8, virtualSize);
        le32(bytes, offset + 12, rva);
        le32(bytes, offset + 16, rawSize);
        le32(bytes, offset + 20, raw);
        le32(bytes, offset + 36, flags);
    }

    private static byte[] kernelImage() {
        byte[] bytes = new byte[0x130000];
        bytes[0] = 'M';
        bytes[1] = 'Z';
        le32(bytes, 0x3c, 0xe8);
        int pe = 0xe8;
        bytes[pe] = 'P';
        bytes[pe + 1] = 'E';
        le16(bytes, pe + 4, 0x1f2);  // Xbox 360 PowerPC PE.
        le16(bytes, pe + 6, 2);
        le16(bytes, pe + 20, 0xe0);
        int opt = pe + 24;
        le16(bytes, opt, 0x10b);
        le32(bytes, opt + 16, 0x20c00);
        le32(bytes, opt + 28, 0x80040000);
        le32(bytes, opt + 56, bytes.length);
        le32(bytes, opt + 60, 0x400);
        le32(bytes, opt + 92, 1);
        le32(bytes, opt + 96, 0xf400);
        le32(bytes, opt + 100, 0xb7f);
        int sec = opt + 0xe0;
        section(bytes, sec, ".rdata", 0x400, 0xa4fc, 0x400, 0xa600, 0x40000040);
        section(bytes, sec + 40, ".text", 0x20c00, 0xbae00,
                0x14200, 0xbae00, 0x60000020);
        byte[] code = {
            0x38, 0x00, 0x00, 0x0d,
            0x44, 0x00, 0x00, 0x02,
            0x4e, (byte) 0x80, 0x00, 0x20,
            0x7d, (byte) 0x88, 0x02, (byte) 0xa6
        };
        System.arraycopy(code, 0, bytes, 0x20c00, code.length);
        // The raw PE offset is just padding in the reconstructed file.
        expect(bytes[0x14200] == 0, "fixture stale raw pointer is blank");
        // This instruction is accidentally imported into 0x80119C00 by
        // Ghidra's conventional PE interpretation. Its destination then
        // appears to be unmapped (0x8011BBF0).
        bytes[0xcd200] = 0x48;
        bytes[0xcd201] = 0;
        bytes[0xcd202] = 0x1f;
        bytes[0xcd203] = (byte) 0xf1;
        return bytes;
    }

    public static void main(String[] args) {
        byte[] source = kernelImage();
        XboxKernelMemoryPe.Image image = XboxKernelMemoryPe.detect(source);
        expect(image != null, "detect reconstructed 6717-like kernel");
        expect(image.imageBase() == 0x80040000L, "kernel image base");
        expect(image.sizeOfImage() == 0x130000, "growth-supported image size");
        expect(image.address(0x20c00) == 0x80060c00L, "virtual text address");
        XboxKernelMemoryPe.Section text = image.sections().stream()
                .filter(s -> s.name().equals(".text")).findFirst().orElseThrow();
        expect(text.virtualAddress() == 0x20c00, "text RVA");
        expect(text.pointerToRawData() == 0x14200, "stale raw pointer");
        expect(source[text.virtualAddress()] == 0x38, "actual text from RVA");
        expect(source[text.pointerToRawData()] == 0, "not raw pointer");
        expect(source[0xcd200] == 0x48 && source[0xd9c00] == 0,
                "bogus 0x80119C00 branch only exists at stale raw offset");

        byte[] diskLayout = kernelImage();
        // A conventional PE's executable bytes reside at PointerToRawData.
        System.arraycopy(diskLayout, 0x20c00, diskLayout, 0x14200, 32);
        Arrays.fill(diskLayout, 0x20c00, 0x20c20, (byte) 0);
        expect(XboxKernelMemoryPe.detect(diskLayout) == null,
                "reject conventional disk layout");

        byte[] noRawDifference = kernelImage();
        int sec = 0xe8 + 24 + 0xe0;
        le32(noRawDifference, sec + 40 + 20, 0x20c00);
        expect(XboxKernelMemoryPe.detect(noRawDifference) == null,
                "reject equal raw pointer/RVA");

        byte[] wrongBase = kernelImage();
        le32(wrongBase, 0xe8 + 24 + 28, 0x82000000);
        expect(XboxKernelMemoryPe.detect(wrongBase) == null,
                "do not hijack other PowerPC PE executables");

        byte[] wrongMachine = kernelImage();
        le16(wrongMachine, 0xe8 + 4, 0x14c);
        expect(XboxKernelMemoryPe.detect(wrongMachine) == null,
                "do not hijack x86 PE files");

        byte[] wrongSize = kernelImage();
        le32(wrongSize, 0xe8 + 24 + 56, 0x140000);
        expect(XboxKernelMemoryPe.detect(wrongSize) == null,
                "reject disk-style length different from SizeOfImage");

        byte[] truncatedSection = kernelImage();
        le32(truncatedSection, sec + 40 + 8, 0x200000);
        expect(XboxKernelMemoryPe.detect(truncatedSection) == null,
                "reject overflowed virtual section extent");

        byte[] corruptNt = kernelImage();
        le32(corruptNt, 0x3c, 0x130000);
        expect(XboxKernelMemoryPe.detect(corruptNt) == null,
                "reject out-of-bounds NT header");

        expect(XboxKernelMemoryPe.detect(new byte[64]) == null,
                "reject non-PE input");
        System.out.println("PASS: " + checks +
                " Xbox 360 reconstructed kernel PE detection checks");
    }
}
