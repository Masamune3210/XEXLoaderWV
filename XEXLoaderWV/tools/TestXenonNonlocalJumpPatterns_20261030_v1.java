import xexloaderwv.XenonNonlocalJumpPatterns;

/**
 * Standalone JDK regression for the firmware-independent Xenon CRT matcher.
 *
 * From XEXLoaderWV/:
 * javac -d build/longjmp-test src/main/java/xexloaderwv/XenonNonlocalJumpPatterns.java tools/TestXenonNonlocalJumpPatterns_20261030_v1.java
 * java -cp build/longjmp-test TestXenonNonlocalJumpPatterns_20261030_v1
 */
public final class TestXenonNonlocalJumpPatterns_20261030_v1 {
    private static int passed;

    private static final class Code {
        private final int[] words = new int[160];
        void at(int offset, int word) { words[offset / 4] = word; }
        int get(int offset) {
            if (offset < 0 || (offset & 3) != 0 ||
                    offset / 4 >= words.length) throw new IllegalArgumentException();
            return words[offset / 4];
        }
        XenonNonlocalJumpPatterns.Words reader() { return this::get; }
    }

    private static int loadFpr(int register, int base, int disp) {
        return 0xC8000000 | (register << 21) | (base << 16) | disp;
    }
    private static int loadGpr(int register, int base, int disp) {
        return 0xE8000000 | (register << 21) | (base << 16) | disp;
    }
    private static int lwz(int register, int base, int disp) {
        return 0x80000000 | (register << 21) | (base << 16) | disp;
    }
    private static int mr(int dest, int src) {
        return 0x7C000378 | (src << 21) | (dest << 16) | (src << 11);
    }

    private static Code longjmp(int firstSave, int baseRegister) {
        Code c = new Code();
        c.at(0, 0x7C0802A6); // entry mflr
        c.at(0x10, 0x2C040000); // cmpwi r4,0
        c.at(0x14, 0x80030138); // lwz r0,0x138(r3)
        c.at(0x28, 0x38C00001); // li r6,1
        int at = firstSave;
        for (int r = 14; r <= 31; r++, at += 4) {
            c.at(at, loadFpr(r, baseRegister, (r - 14) * 8));
        }
        for (int r = 13; r <= 31; r++, at += 4) {
            c.at(at, loadGpr(r, baseRegister, 0x98 + (r - 13) * 8));
        }
        c.at(at, lwz(5, baseRegister, 0x134));
        c.at(at + 4, lwz(4, baseRegister, 0x130));
        c.at(at + 8, 0x7CA803A6); // mtlr r5
        c.at(at + 12, loadGpr(1, baseRegister, 0x90));
        c.at(at + 16, 0x7C8FF120); // mtcrf 0xff,r4
        c.at(at + 20, mr(3, 6));
        c.at(at + 24, 0x4E800020); // blr to saved LR
        int unwind = at + 28;
        c.at(unwind, lwz(3, baseRegister, 4));
        c.at(unwind + 4, lwz(4, baseRegister, 0));
        c.at(unwind + 8, 0x4BC6156D); // direct call helper; target varies
        c.at(unwind + 12, lwz(3, baseRegister, 0));
        c.at(unwind + 16, lwz(4, baseRegister, 4));
        c.at(unwind + 20, 0x48001EFD); // direct call RtlUnwind
        return c;
    }

    private static Code callbackWrapper() {
        Code c = new Code();
        c.at(0x14, 0x817F0140); // lwz r11,0x140(r31)
        c.at(0x20, 0x7D6903A6); // mtctr r11
        c.at(0x24, 0x4E800421); // bctrl
        c.at(0x28, 0x38800001); // li r4,1
        c.at(0x2C, 0x7FE3FB78); // mr r3,r31
        c.at(0x30, 0x48024EF1); // direct call the confirmed longjmp
        c.at(0x34, 0); // padding
        return c;
    }

    private static void check(boolean value, String description) {
        if (!value) throw new AssertionError(description);
        passed++;
    }

    public static void main(String[] args) {
        Code dash = longjmp(0x3C, 7);
        check(XenonNonlocalJumpPatterns.isLongjmp(dash.reader()),
            "1888 dashboard restored-register sequence must match");
        Code xamStyle = longjmp(0x40, 8);
        check(XenonNonlocalJumpPatterns.isLongjmp(xamStyle.reader()),
            "different save offset/base register must match");
        Code changed = longjmp(0x3C, 7);
        changed.at(0x10, 0); // normalizing requested return value is mandatory
        check(!XenonNonlocalJumpPatterns.isLongjmp(changed.reader()),
            "no zero-to-one conversion");
        changed = longjmp(0x3C, 7);
        changed.at(0x3C + 17 * 4, 0); // last saved FPR
        check(!XenonNonlocalJumpPatterns.isLongjmp(changed.reader()),
            "incomplete FPR restoration");
        changed = longjmp(0x3C, 7);
        changed.at(0x3C + 18 * 4 + 7 * 4, 0); // one GPR
        check(!XenonNonlocalJumpPatterns.isLongjmp(changed.reader()),
            "incomplete GPR restoration");
        changed = longjmp(0x3C, 7);
        changed.at(0x3C + 18 * 4 + 19 * 4 + 12, 0); // missing SP restoration
        check(!XenonNonlocalJumpPatterns.isLongjmp(changed.reader()),
            "missing saved stack pointer");
        changed = longjmp(0x3C, 7);
        changed.at(0x3C + 18 * 4 + 19 * 4 + 28 + 20, 0);
        check(!XenonNonlocalJumpPatterns.isLongjmp(changed.reader()),
            "missing unwind transfer");

        Code wrapper = callbackWrapper();
        check(XenonNonlocalJumpPatterns.isCallbackWrapper(wrapper.reader(), 0x30),
            "1888 callback wrapper pattern");
        wrapper.at(0x24, 0);
        check(!XenonNonlocalJumpPatterns.isCallbackWrapper(wrapper.reader(), 0x30),
            "callback must use bctrl");
        wrapper = callbackWrapper();
        wrapper.at(0x34, 0x60000000);
        check(!XenonNonlocalJumpPatterns.isCallbackWrapper(wrapper.reader(), 0x30),
            "must not treat executable fallthrough as padding");
        wrapper = callbackWrapper();
        wrapper.at(0x30, 0x48024EF0);
        check(!XenonNonlocalJumpPatterns.isCallbackWrapper(wrapper.reader(), 0x30),
            "terminal call must set PPC LK");
        check(!XenonNonlocalJumpPatterns.isLongjmp(callbackWrapper().reader()),
            "callback wrapper itself is not longjmp");
        System.out.println("Xenon nonlocal jump regression: " +
            passed + " checks passed.");
    }
}
