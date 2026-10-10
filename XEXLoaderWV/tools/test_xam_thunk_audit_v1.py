#!/usr/bin/env python3
"""Offline contract checks for the read-only XAM/native import-thunk audit.

These tests verify its discriminating byte patterns and source safeguards.
They cannot substitute for executing the Java script inside Ghidra.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / "ghidra_scripts" / "AuditXamImportThunkLinksV1.java"


def classify_native_stub(image: bytes) -> str:
    if len(image) != 16:
        return "other"
    a, b, c, d = (int.from_bytes(image[p:p + 4], "big")
                  for p in (0, 4, 8, 12))
    if (a & 0xffff0000) == 0x01000000 and (
            b & 0xffff0000) == 0x02000000 and (
            a & 0xffff) == (b & 0xffff) and (
            c, d) == (0x7d6903a6, 0x4e800420):
        return "raw"
    if (a, b, c, d) == (
            0x3d600000, 0x616b0000, 0x7d6903a6, 0x4e800420):
        return "veneer"
    return "other"


def words(*values: int) -> bytes:
    return b"".join(value.to_bytes(4, "big") for value in values)


class XamThunkAuditTests(unittest.TestCase):
    def test_native_stub_byte_oracle(self):
        for ordinal in (0, 1, 126, 0x8000, 0xffff):
            original = words(0x01000000 | ordinal, 0x02000000 | ordinal,
                             0x7d6903a6, 0x4e800420)
            self.assertEqual(classify_native_stub(original), "raw")
            mismatch = words(0x01000000 | ordinal,
                             0x02000000 | ((ordinal + 1) & 0xffff),
                             0x7d6903a6, 0x4e800420)
            self.assertEqual(classify_native_stub(mismatch), "other")
        self.assertEqual(classify_native_stub(words(
            0x3d600000, 0x616b0000, 0x7d6903a6, 0x4e800420)), "veneer")
        self.assertEqual(classify_native_stub(words(
            0x0100007e, 0x0200007e, 0x7d6903a6, 0x4e800421)), "other")
        self.assertEqual(classify_native_stub(b""), "other")

    def test_java_audit_is_read_only_and_classifies_linkage(self):
        source = JAVA.read_text(encoding="utf-8")
        for required in (
            "class AuditXamImportThunkLinksV1",
            "isRawImport(word0, word1, word2, word3)",
            "functions.getFunctionAt(site.address)",
            "function.isThunk()",
            "function.getThunkedFunction(true)",
            "target.isExternal()",
            "library.getAssociatedProgramPath()",
            '"Bad Instruction".equalsIgnoreCase(bookmark.getCategory())',
            "isVeneer(a, b, c, d)",
            "monitor.checkCancelled()",
            "UNRESOLVED / INCORRECT STATES",
        ):
            self.assertIn(required, source)
        for forbidden in (
            ".setBytes(", ".removeBookmark(", ".createThunkFunction(",
            ".setFlowOverride(", ".setComment(", ".createFunction(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
