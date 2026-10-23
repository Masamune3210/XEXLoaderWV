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

    def test_datatype_deps_preflight(self):
        self.assertIn("Set<DataType> required = new LinkedHashSet<>();", SRC)
        self.assertIn("complete(source, importing.getDataTypeManager(), required)", SRC)
        self.assertIn("getDefinedComponents()", SRC)
        self.assertIn("((TypeDef) type).getBaseDataType()", SRC)
        self.assertIn("local.isEquivalent(type)", SRC)
        self.assertIn("missing.add(type)", SRC)

    def test_conflict_protection_and_exact_type_install(self):
        self.assertIn("DataTypeConflictHandler.KEEP_HANDLER", SRC)
        self.assertIn("if (!existing.isEquivalent(source))", SRC)
        self.assertIn("if (copy == null || !copy.isEquivalent(source))", SRC)
        self.assertIn("target.addDataType(", SRC)

    def test_atomic_signature_with_datatypes(self):
        self.assertIn("int transaction = importing.startTransaction(", SRC)
        self.assertIn("importing.endTransaction(transaction, committed)", SRC)
        self.assertIn("installDependencies(required,", SRC)
        self.assertIn("ApplyFunctionSignatureCmd command", SRC)
        self.assertIn("committed = true;", SRC)

    def test_do_not_overwrite_edited_signatures_or_infer_registers(self):
        self.assertIn("!untouchedExternal(imported)", SRC)
        self.assertIn("f.getSignatureSource() != SourceType.USER_DEFINED", SRC)
        self.assertIn("f.hasCustomVariableStorage()", SRC)
        self.assertIn("FunctionRenameOption.NO_CHANGE", SRC)

if __name__ == "__main__":
    unittest.main()
