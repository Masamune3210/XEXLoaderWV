package xexloaderwv;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

/** Standalone delta record and block regressions. */
public final class XEXDeltaPatchTest {
    public static void main(String[] args) throws Exception {
        byte[] records = ByteBuffer.allocate(24)
                .putInt(0).putInt(2).putShort((short) 4).putShort((short) 1)
                .putInt(0).putInt(6).putShort((short) 2).putShort((short) 0)
                .array();
        byte[] block = ByteBuffer.allocate(24 + records.length)
                .position(24).put(records).array();
        byte[] hash = MessageDigest.getInstance("SHA-1").digest(block);
        byte[] base = {1, 2, 3, 4, 5, 6, 7, 8};
        XEXDeltaPatch.applyBlocks(block, block.length, hash, base, 15);
        if (!Arrays.equals(base, new byte[] {1, 2, 1, 2, 3, 4, 0, 0})) {
            throw new AssertionError("overlapping copy must preserve the original source span");
        }

        block[block.length - 1] ^= 1;
        try {
            XEXDeltaPatch.applyBlocks(block, block.length, hash, base, 15);
            throw new AssertionError("corrupted block accepted");
        } catch (IOException expected) {
            if (!expected.getMessage().contains("SHA-1")) {
                throw expected;
            }
        }

        byte[] relocated = XEXDeltaPatch.prepareTarget(
                new byte[] {1, 2, 3, 4, 5, 6}, 4, 2, 3, 1, true);
        if (!Arrays.equals(relocated, new byte[] {1, 3, 4, 5, 0, 0})) {
            throw new AssertionError("relocation and shrinking must clear the discarded tail");
        }
    }
}
