package xexloaderwv;

/**
 * Structural, address-independent Xenon/PowerPC CRT non-local jump patterns.
 *
 * Keep this class independent of Ghidra so the complete byte matcher can be
 * regression tested by a stock JDK. Identifiers are not tied to a particular
 * dashboard or XAM firmware revision.
 */
public final class XenonNonlocalJumpPatterns {
    @FunctionalInterface
    public interface Words {
        int word(int relativeByteOffset) throws Exception;
    }

    private XenonNonlocalJumpPatterns() {
    }

    private static boolean isBranchAndLink(int word) {
        // PPC relative direct branch with LK=1, AA=0; ignore displacement.
        return (word & 0xFC000003) == 0x48000001;
    }

    private static int fprLoad(int reg, int base, int displacement) {
        return 0xC8000000 | (reg << 21) | (base << 16) | displacement;
    }

    private static int gprLoad(int reg, int base, int displacement) {
        return 0xE8000000 | (reg << 21) | (base << 16) | displacement;
    }

    private static int lwz(int reg, int base, int displacement) {
        return 0x80000000 | (reg << 21) | (base << 16) | displacement;
    }

    private static int mr(int dst, int src) {
        // or dst,src,src
        return 0x7C000378 | (src << 21) | (dst << 16) | (src << 11);
    }

    /**
     * Return true only when the entry restores an entire Xenon setjmp
     * register image and performs the defined longjmp transfer. Different
     * stack-frame sizes and call displacements are allowed, but the
     * instruction semantics and save layout must all match.
     */
    public static boolean isLongjmp(Words words) {
        try {
            if (words.word(0) != 0x7C0802A6) return false; // mflr r0

            // The value argument (r4) is changed from 0 to 1.
            boolean zeroCheck = false, forceOne = false, contextFlag = false;
            for (int off = 4; off <= 0x6C; off += 4) {
                int word = words.word(off);
                if (word == 0x2C040000) zeroCheck = true; // cmpwi r4,0
                if (word == 0x38C00001) forceOne = true; // li r6,1
                if (word == lwz(0, 3, 0x138)) contextFlag = true;
            }
            if (!zeroCheck || !forceOne || !contextFlag) return false;

            // Scan for f14..f31 and r13..r31 restoration. The base register
            // may differ between compiler builds but must be consistent.
            for (int start = 0x24; start <= 0xB0; start += 4) {
                for (int base = 3; base <= 31; base++) {
                    if (words.word(start) != fprLoad(14, base, 0)) continue;
                    int cursor = start;
                    boolean match = true;
                    for (int reg = 14; reg <= 31; reg++, cursor += 4) {
                        if (words.word(cursor) != fprLoad(reg, base, (reg - 14) * 8)) {
                            match = false;
                            break;
                        }
                    }
                    if (!match) continue;
                    for (int reg = 13; reg <= 31; reg++, cursor += 4) {
                        if (words.word(cursor) != gprLoad(reg, base, 0x98 + (reg - 13) * 8)) {
                            match = false;
                            break;
                        }
                    }
                    if (!match) continue;

                    // Rebuild LR, SP and CR from the same jump buffer before
                    // returning to the saved continuation (not our caller).
                    if (words.word(cursor) != lwz(5, base, 0x134) ||
                            words.word(cursor + 4) != lwz(4, base, 0x130) ||
                            words.word(cursor + 8) != 0x7CA803A6 || // mtlr r5
                            words.word(cursor + 12) != gprLoad(1, base, 0x90) ||
                            words.word(cursor + 16) != 0x7C8FF120 || // mtcrf 0xff,r4
                            words.word(cursor + 20) != mr(3, 6) ||
                            words.word(cursor + 24) != 0x4E800020) { // blr
                        continue;
                    }

                    // Alternate SEH-backed unwind path in this CRT family.
                    // We do not require a particular RtlUnwind target address.
                    int unwind = cursor + 28;
                    if (words.word(unwind) != lwz(3, base, 4) ||
                            words.word(unwind + 4) != lwz(4, base, 0) ||
                            !isBranchAndLink(words.word(unwind + 8)) ||
                            words.word(unwind + 12) != lwz(3, base, 0) ||
                            words.word(unwind + 16) != lwz(4, base, 4) ||
                            !isBranchAndLink(words.word(unwind + 20))) {
                        continue;
                    }
                    return true;
                }
            }
        } catch (Exception unreadable) {
            // A candidate must have ALL required bytes mapped.
        }
        return false;
    }

    /**
     * Recognize the common optional-callback wrapper ending in
     * longjmp(jumpBuffer, 1). The analyzer separately verifies the final
     * direct call's target, so this is never used to classify the callee.
     */
    public static boolean isCallbackWrapper(Words words, int terminalCallOffset) {
        if (terminalCallOffset < 0x20 || terminalCallOffset > 0x400 ||
                (terminalCallOffset & 3) != 0) return false;
        try {
            if (words.word(terminalCallOffset - 8) != 0x38800001 || // li r4,1
                    words.word(terminalCallOffset - 4) != 0x7FE3FB78 ||
                    !isBranchAndLink(words.word(terminalCallOffset)) ||
                    words.word(terminalCallOffset + 4) != 0) return false;

            boolean loadCallback = false, callCallback = false, setCtr = false;
            for (int off = 0; off < terminalCallOffset - 8; off += 4) {
                int w = words.word(off);
                if (w == 0x817F0140) loadCallback = true; // lwz r11,0x140(r31)
                if (w == 0x7D6903A6) setCtr = true;       // mtctr r11
                if (w == 0x4E800421) callCallback = true; // bctrl
            }
            return loadCallback && setCtr && callCallback;
        } catch (Exception unreadable) {
            return false;
        }
    }
}
