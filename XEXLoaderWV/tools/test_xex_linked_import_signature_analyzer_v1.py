"""Guard the reusable linked-XEX signature analyzer policy against accidental weakening.

Static source checks are not equivalent to a Ghidra runtime / SLEIGH build.
"""
from pathlib import Path
import re
import unittest

SRC = (Path(__file__).resolve().parents[1] / "src" / "main" / "java" /
       "xexloaderwv" / "XexLinkedImportSignatureAnalyzer.java").read_text()

class TestLinkedImportPolicy(unittest.TestCase):
    def test_xex_only(self):
        self.assertIn('"XEX Loader by Warranty Voider".equals(program.getExecutableFormat())', SRC)
    def test_project_link_only(self):
        self.assertIn("getExternalLibraryPath(library)", SRC)
        self.assertIn("getReadOnlyDomainObject(this, -1, monitor)", SRC)
    def test_abi_compatibility(self):
        self.assertIn("getLanguageID().equals(provider.getLanguageID())", SRC)
        self.assertIn("getCompilerSpecID()", SRC)
        self.assertIn("getDefaultPointerSize()", SRC)
    def test_no_partial_fpr_copy(self):
        self.assertIn("f.getSignatureSource() != SourceType.USER_DEFINED", SRC)
        self.assertIn('name.startsWith("undefined")', SRC)
        self.assertIn("f.hasCustomVariableStorage()", SRC)
    def test_preserve_existing_external(self):
        self.assertIn("f.getParameterCount() == 0", SRC)
        self.assertIn("f.getSignatureSource() != SourceType.USER_DEFINED", SRC)
        self.assertIn("FunctionRenameOption.NO_CHANGE", SRC)
    def test_ambiguous_names_not_resolved(self):
        self.assertIn("match.getEntryPoint().equals(candidate.getEntryPoint())", SRC)
        self.assertIn("return null; // namespace collision: never guess", SRC)
    def test_no_ordinal_hardcoding_or_machine_writes(self):
        self.assertNotIn("80080", SRC)
        self.assertNotIn(".setBytes(", SRC)
        self.assertNotIn(".setName(", SRC)
        self.assertNotIn("ordinal", SRC.lower().split("public class")[1].split("}",1)[0])
    def test_rerunnable(self):
        self.assertIn("setSupportsOneTimeAnalysis()", SRC)
        self.assertIn("untouchedExternal(imported)", SRC)

if __name__ == "__main__":
    unittest.main()
