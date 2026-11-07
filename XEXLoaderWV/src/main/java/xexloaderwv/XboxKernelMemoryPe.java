package xexloaderwv;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects a reconstructed Xbox 360 retail kernel PE that is *already laid out
 * by virtual RVA*. CG patches produce this form, retaining stale PE raw-file
 * offsets. Importing it as an ordinary disk-layout PE shifts .text and turns
 * data into false branches.
 *
 * This classifier deliberately refuses conventional PE files and other MZ
 * binaries. No bytes are modified, and the original embedded headers remain
 * available at RVA 0.
 *
 * Dependency-free so it can be regression tested without a Ghidra install.
 */
final class XboxKernelMemoryPe {
    private XboxKernelMemoryPe() {}

    record Section(String name, int virtualAddress, int virtualSize,
            int pointerToRawData, int rawSize, int characteristics) {
        boolean executable() { return (characteristics & 0x20000000) != 0; }
        boolean readable() { return (characteristics & 0x40000000) != 0; }
        boolean writable() { return (characteristics & 0x80000000) != 0; }
    }

    record Image(long imageBase, int sizeOfImage, int sizeOfHeaders,
            int entryPointRva, int exportDirectoryRva, int exportDirectorySize,
            List<Section> sections) {
        long address(int rva) { return (imageBase + Integer.toUnsignedLong(rva)) & 0xffffffffL; }
    }

    static int u16(byte[] bytes, int offset) {
        return Byte.toUnsignedInt(bytes[offset]) | (Byte.toUnsignedInt(bytes[offset + 1]) << 8);
    }

    static int u32(byte[] bytes, int offset) {
        return u16(bytes, offset) | (u16(bytes, offset + 2) << 16);
    }

    static boolean range(int length, long offset, long bytes) {
        return offset >= 0 && bytes >= 0 && offset <= length && bytes <= length - offset;
    }

    // PPC instruction plausibility, used only to identify whether the
    // executable's start lives at the RVA or the stale raw file pointer.
    private static int ppcScore(byte[] bytes, int offset) {
        if (!range(bytes.length, offset, 32)) return 0;
        int score = 0;
        for (int i = 0; i < 8; ++i) {
            int word = (Byte.toUnsignedInt(bytes[offset + i * 4]) << 24) |
                (Byte.toUnsignedInt(bytes[offset + i * 4 + 1]) << 16) |
                (Byte.toUnsignedInt(bytes[offset + i * 4 + 2]) << 8) |
                Byte.toUnsignedInt(bytes[offset + i * 4 + 3]);
            int opcode = word >>> 26;
            if (word != 0 && (opcode == 4 || opcode == 14 ||
                    opcode == 15 || opcode == 16 || opcode == 17 ||
                    opcode == 18 || opcode == 19 || opcode == 21 ||
                    opcode == 24 || opcode == 31 || opcode == 32 ||
                    opcode == 33 || opcode == 34 || opcode == 35 ||
                    opcode == 36 || opcode == 37 || opcode == 40 ||
                    opcode == 41 || opcode == 58 || opcode == 62)) {
                ++score;
            }
        }
        return score;
    }

    private static boolean hasConsistentKernelMetadata(byte[] bytes,
            long imageBase, int exportRva, List<Section> sections) {
        Section pdata = null, edata = null, text = null;
        for (Section section : sections) {
            if (".pdata".equals(section.name())) pdata = section;
            if (".edata".equals(section.name())) edata = section;
            if (".text".equals(section.name())) text = section;
        }
        if (pdata == null || edata == null || text == null ||
                pdata.executable() || edata.executable() || !text.executable() ||
                pdata.virtualSize() < 16 * 8 ||
                (pdata.virtualSize() & 7) != 0 ||
                !range(bytes.length, pdata.virtualAddress(), pdata.virtualSize()) ||
                exportRva < edata.virtualAddress() ||
                !range((long) edata.virtualAddress() + edata.virtualSize(),
                        exportRva, 40)) {
            return false;
        }

        // A genuine retail kernel exposes hundreds of exports. Validate its
        // little-endian PE export table, independent of the executable bytes.
        int ordinalBase = u32(bytes, exportRva + 16);
        int functionCount = u32(bytes, exportRva + 20);
        int functionsRva = u32(bytes, exportRva + 28);
        if (ordinalBase != 1 || functionCount < 128 ||
                functionCount > 4096 ||
                !range(bytes.length, functionsRva, (long) functionCount * 4) ||
                functionsRva < edata.virtualAddress() ||
                (long) functionsRva + (long) functionCount * 4 >
                    (long) edata.virtualAddress() + edata.virtualSize()) {
            return false;
        }
        int validExports = 0;
        for (int i = 0; i < 16; ++i) {
            int target = u32(bytes, functionsRva + i * 4);
            if (target > 0 && target < bytes.length) ++validExports;
        }
        if (validExports < 12) return false;

        // Kernel .pdata is big-endian and holds absolute function addresses.
        // Require the first sixteen entries to point in ascending order into
        // the executable section. This checks a separate metadata source,
        // not just an arbitrary eight-word PPC opcode sample.
        int plausibleAtRva = 0;
        int evidenceAgainstRaw = 0;
        long lastAddress = 0;
        for (int i = 0; i < 16; ++i) {
            long va = ((long) Byte.toUnsignedInt(bytes[pdata.virtualAddress() + 8 * i]) << 24) |
                    ((long) Byte.toUnsignedInt(bytes[pdata.virtualAddress() + 8 * i + 1]) << 16) |
                    ((long) Byte.toUnsignedInt(bytes[pdata.virtualAddress() + 8 * i + 2]) << 8) |
                    Byte.toUnsignedInt(bytes[pdata.virtualAddress() + 8 * i + 3]);
            long rva = va - imageBase;
            if (va <= lastAddress || (va & 3) != 0 ||
                    rva < text.virtualAddress() ||
                    rva >= (long) text.virtualAddress() + text.virtualSize()) {
                return false;
            }
            lastAddress = va;
            // Compare the same .pdata-designated function at its virtual RVA
            // and at the address that ordinary PE raw mapping would use.
            int virtualOffset = (int) rva;
            int rawOffset = (int) (rva - text.virtualAddress() +
                    (long) text.pointerToRawData());
            boolean virtualCode = ppcScore(bytes, virtualOffset) > 0;
            boolean diskCode = ppcScore(bytes, rawOffset) > 0;
            if (virtualCode) ++plausibleAtRva;
            if (virtualCode && !diskCode) ++evidenceAgainstRaw;
        }
        // Fail closed on ambiguous images, even if the PE base/size and the
        // start of .text resemble the reconstructed kernel.
        return plausibleAtRva >= 14 && evidenceAgainstRaw >= 4;
    }

    static Image detect(byte[] bytes) {
        if (bytes.length < 0x400 || bytes.length > 64 * 1024 * 1024 ||
                bytes[0] != 'M' || bytes[1] != 'Z') return null;
        long pe = Integer.toUnsignedLong(u32(bytes, 0x3c));
        if (!range(bytes.length, pe, 24) ||
                bytes[(int) pe] != 'P' || bytes[(int) pe + 1] != 'E' ||
                bytes[(int) pe + 2] != 0 || bytes[(int) pe + 3] != 0) return null;
        int machine = u16(bytes, (int) pe + 4);
        int count = u16(bytes, (int) pe + 6);
        int optionalLength = u16(bytes, (int) pe + 20);
        long optional = pe + 24;
        if (machine != 0x01f2 || count < 1 || count > 96 ||
                optionalLength < 0x68 || !range(bytes.length, optional, optionalLength) ||
                !range(bytes.length, optional + optionalLength, (long) count * 40)) {
            return null;
        }
        int opt = (int) optional;
        if (u16(bytes, opt) != 0x10b) return null;
        long imageBase = Integer.toUnsignedLong(u32(bytes, opt + 28));
        int sizeOfImage = u32(bytes, opt + 56);
        int sizeOfHeaders = u32(bytes, opt + 60);
        int entryPointRva = u32(bytes, opt + 16);
        // Xbox 360 retail kernels are loaded at 0x80040000. Restricting this
        // loader to that base avoids hijacking ordinary native PPC PE files.
        if (imageBase != 0x80040000L || sizeOfImage != bytes.length ||
                sizeOfHeaders <= 0 || sizeOfHeaders > bytes.length ||
                sizeOfHeaders > 0x10000 || entryPointRva < 0 ||
                entryPointRva >= sizeOfImage) return null;

        int exportRva = 0, exportSize = 0;
        if (optionalLength >= 104 && Integer.compareUnsigned(u32(bytes, opt + 92), 1) >= 0) {
            exportRva = u32(bytes, opt + 96);
            exportSize = u32(bytes, opt + 100);
        }
        ArrayList<Section> sections = new ArrayList<>();
        boolean memoryLayoutEvidence = false;
        int sec = opt + optionalLength;
        for (int i = 0; i < count; ++i, sec += 40) {
            int nameLength = 0;
            while (nameLength < 8 && bytes[sec + nameLength] != 0) ++nameLength;
            String name = new String(bytes, sec, nameLength, StandardCharsets.US_ASCII);
            int virtualSize = u32(bytes, sec + 8);
            int rva = u32(bytes, sec + 12);
            int rawSize = u32(bytes, sec + 16);
            int raw = u32(bytes, sec + 20);
            int flags = u32(bytes, sec + 36);
            if (rva < 0 || virtualSize < 0 || raw < 0 || rawSize < 0 ||
                    (virtualSize != 0 && !range(bytes.length, rva, virtualSize))) {
                return null;
            }
            if (virtualSize == 0) continue;
            Section s = new Section(name, rva, virtualSize, raw, rawSize, flags);
            sections.add(s);
            if (".text".equals(name) && s.executable() &&
                    raw != rva && raw != 0 && range(bytes.length, raw, 32) &&
                    range(bytes.length, rva, 32)) {
                // The reconstructed kernel's real code starts at the RVA.
                // Stale disk PE offsets point to empty or unrelated data.
                int virtualScore = ppcScore(bytes, rva);
                int rawScore = ppcScore(bytes, raw);
                memoryLayoutEvidence = virtualScore >= 3 && virtualScore > rawScore;
            }
        }
        return memoryLayoutEvidence &&
                hasConsistentKernelMetadata(bytes, imageBase, exportRva, sections)
                ? new Image(imageBase, sizeOfImage, sizeOfHeaders, entryPointRva,
                        exportRva, exportSize, List.copyOf(sections))
                : null;
    }
}
