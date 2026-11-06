package xexloaderwv;

import java.io.IOException;

/**
 * Computes the portion of a PE section backed by a decoded XEX image.
 *
 * XEX security metadata, rather than the embedded PE's SizeOfImage, governs
 * the decoded image allocation. Early retail PE section headers can describe
 * virtual tails extending beyond that allocation. Do not synthesize those
 * bytes and never use PointerToRawData against the decoded virtual image.
 */
final class XexPeSectionExtent {
    private XexPeSectionExtent() {
    }

    static int backedSize(String name, int rva, int virtualSize, int imageSize)
            throws IOException {
        // Only a section which actually begins in the decoded image can be
        // partially imported. Invalid starts and negative/overflowed metadata
        // remain fatal; Array.copyOfRange must never silently zero-pad.
        if (rva < 0 || virtualSize < 0 || imageSize <= 0 ||
                (long) rva >= imageSize) {
            throw new IOException("Invalid XEX PE section extent: " + name +
                    " RVA=0x" + Integer.toHexString(rva) +
                    " virtualSize=0x" + Integer.toHexString(virtualSize) +
                    " decodedImageSize=0x" + Integer.toHexString(imageSize));
        }
        return (int) Math.min((long) virtualSize, (long) imageSize - rva);
    }
}
