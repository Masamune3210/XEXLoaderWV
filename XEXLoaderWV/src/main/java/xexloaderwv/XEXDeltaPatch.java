package xexloaderwv;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

final class XEXDeltaPatch {
    private static final int BLOCK_HEADER_SIZE = 24;
    private static final int RECORD_HEADER_SIZE = 12;

    private XEXDeltaPatch() {
    }

    static byte[] prepareTarget(byte[] original, int targetSize, int source,
            int length, int destination, boolean clearAfterCopy) throws IOException {
        if (targetSize <= 0) {
            throw new IOException("Invalid XEXP target size: " + targetSize);
        }
        int capacity = Math.max(original.length, targetSize);
        checkRange(destination, length, clearAfterCopy ? capacity : targetSize, "relocation target");
        if (!clearAfterCopy || source != 0) {
            checkRange(source, length, original.length, "relocation source");
        }
        byte[] target = Arrays.copyOf(original, capacity);
        if (source != 0) {
            System.arraycopy(target, source, target, destination, length);
        }
        int retainedEnd = clearAfterCopy ? destination + length : targetSize;
        if (retainedEnd < original.length) {
            Arrays.fill(target, retainedEnd, original.length, (byte) 0);
        }
        return target;
    }

    static void applyBlocks(byte[] payload, int blockSize, byte[] expectedHash,
            byte[] target, int windowBits) throws IOException, NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        ByteBuffer blocks = ByteBuffer.wrap(payload);
        int offset = 0;
        while (blockSize != 0) {
            if (blockSize < BLOCK_HEADER_SIZE || blockSize > payload.length - offset) {
                throw new IOException("Invalid XEXP block size " + blockSize +
                        " at payload offset 0x" + Integer.toHexString(offset));
            }
            sha1.update(payload, offset, blockSize);
            if (!MessageDigest.isEqual(expectedHash, sha1.digest())) {
                throw new IOException("XEXP block SHA-1 mismatch at payload offset 0x" +
                        Integer.toHexString(offset));
            }
            int end = offset + blockSize;
            applyRecords(payload, offset + BLOCK_HEADER_SIZE, end, target, windowBits);
            blockSize = blocks.getInt(offset);
            expectedHash = Arrays.copyOfRange(payload, offset + 4, offset + BLOCK_HEADER_SIZE);
            offset = end;
        }
    }

    static void applyRecords(byte[] data, int start, int end, byte[] target,
            int windowBits) throws IOException {
        ByteBuffer records = ByteBuffer.wrap(data, start, end - start);
        while (records.hasRemaining()) {
            if (records.remaining() < RECORD_HEADER_SIZE) {
                throw new IOException("Truncated XEXP delta record at offset 0x" +
                        Integer.toHexString(records.position()));
            }
            int source = records.getInt();
            int destination = records.getInt();
            int length = Short.toUnsignedInt(records.getShort());
            int compressedLength = Short.toUnsignedInt(records.getShort());
            if (source == 0 && destination == 0 && length == 0 && compressedLength == 0) {
                break;
            }
            checkRange(destination, length, target.length, "record target");
            if (compressedLength == 0) {
                Arrays.fill(target, destination, destination + length, (byte) 0);
                continue;
            }
            checkRange(source, length, target.length, "record source");
            if (compressedLength == 1) {
                System.arraycopy(target, source, target, destination, length);
                continue;
            }
            if (compressedLength > records.remaining() || length > (1 << windowBits)) {
                throw new IOException("XEXP delta record exceeds its block or LZX window");
            }
            byte[] compressed = new byte[compressedLength];
            records.get(compressed);
            byte[] reference = Arrays.copyOfRange(target, source, source + length);
            byte[] decoded = new LzxDecompression().DecompressLZX(
                    compressed, reference, length, windowBits);
            System.arraycopy(decoded, 0, target, destination, length);
        }
    }

    private static void checkRange(int offset, int length, int limit, String field)
            throws IOException {
        if (offset < 0 || length < 0 || offset > limit || length > limit - offset) {
            throw new IOException("XEXP " + field + " outside its buffer");
        }
    }
}
