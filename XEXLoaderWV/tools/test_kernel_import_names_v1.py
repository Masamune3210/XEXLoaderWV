"""Exercise real Java ordinal lookup against independently documented kernel names."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class KernelImportNames(unittest.TestCase):
    def test_real_java_lookup_and_other_module_controls(self):
        root = Path(__file__).resolve().parents[1]
        java_bin = Path(os.environ['JAVA_HOME']) / 'bin' if os.environ.get('JAVA_HOME') else None
        javac = str(java_bin / 'javac') if java_bin else shutil.which('javac')
        java = str(java_bin / 'java') if java_bin else shutil.which('java')
        self.assertTrue(javac and java, 'JDK is required; this test must not silently skip')
        fixture = '''
import xexloaderwv.ImportRenamer;
public class KernelImportNameFixture {
 public static void main(String[] args) {
  int failures=0,checks=0;
  String[][] cases={
   {"xboxkrnl.exe","295","RtlFreeAnsiString"},
   {"xboxkrnl.exe","296","RtlFreeUnicodeString"},
   {"xboxkrnl.exe","867","XeKeysGetTruncatedSecondaryConsoleId"},
   {"xboxkrnl.exe","889","VdSetStudioRGBMode"},
   {"XBOXKRNL.EXE","296","RtlFreeUnicodeString"},
   {"XBOXKRNL.EXE","867","XeKeysGetTruncatedSecondaryConsoleId"},
   {"XBOXKRNL.EXE","889","VdSetStudioRGBMode"},
   {"xboxkrnl","296","RtlFreeUnicodeString"},
   {"xboxkrnl","867","XeKeysGetTruncatedSecondaryConsoleId"},
   {"xboxkrnl","889","VdSetStudioRGBMode"},
   {"xam.xex","867","XuiTextElementSetText"},
   {"xam.xex","889","XUIElementPropVal_Construct"},
   {"xboxkrnl.exe","65535","xboxkrnl.exe_ord_65535"},
   {"unknown.xex","296","unknown.xex_ord_296"}
  };
  for(String[] c:cases){checks++;String actual=ImportRenamer.Rename(c[0],Integer.parseInt(c[1]));if(!actual.equals(c[2])){failures++;System.err.println(c[0]+" ordinal"+c[1]+" expected="+c[2]+" actual="+actual);}}
  if(failures!=0)throw new AssertionError(failures+"/"+checks+" real ordinal lookup checks failed");
  System.out.println("KERNEL IMPORT NAME REGRESSION: "+checks+" PASS");
 }
}
'''
        with tempfile.TemporaryDirectory(prefix='xex-kernel-names-') as tmp:
            path = Path(tmp)
            (path / 'KernelImportNameFixture.java').write_text(fixture)
            subprocess.run([javac, '-d', tmp, str(root / 'src/main/java/xexloaderwv/ImportRenamer.java'), str(path / 'KernelImportNameFixture.java')], check=True)
            result = subprocess.run([java, '-cp', tmp, 'KernelImportNameFixture'], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('14 PASS', result.stdout)
            print(result.stdout.strip())


if __name__ == '__main__':
    unittest.main()
