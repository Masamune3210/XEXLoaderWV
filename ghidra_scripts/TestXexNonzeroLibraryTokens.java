// Regression: real loader/guard must recognize same-library token pairs beyond index0.
// Test-only Unsafe allocation avoids XEX decryption/constructor I/O; actual production
// methods, Program, external manager, native bytes and disassembler are exercised.
import java.nio.file.*;
import java.util.*;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.program.model.address.*;
import ghidra.program.disassemble.Disassembler;
import xexloaderwv.*;
public class TestXexNonzeroLibraryTokens extends GhidraScript {
 int cases=0;List<String> failures=new ArrayList<>();
 void check(boolean b,String label){cases++;if(!b&&failures.size()<30)failures.add(label);}
 byte[] pair(int lib,int ordinal){return ByteBuffer.allocate(16).putInt(0x01000000|(lib<<16)|ordinal).putInt(0x02000000|(lib<<16)|ordinal).putInt(0x7d6903a6).putInt(0x4e800420).array();}
 public void run()throws Exception{
  Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
  var uf=sun.misc.Unsafe.class.getDeclaredField("theUnsafe");uf.setAccessible(true);var unsafe=(sun.misc.Unsafe)uf.get(null);XEXHeader h=(XEXHeader)unsafe.allocateInstance(XEXHeader.class);
  var loader=XEXHeader.class.getDeclaredMethod("IsCanonicalImportThunk",BinaryReader.class,ImportFunction.class);loader.setAccessible(true);var guard=XenonImportAwareDisassembler.class.getDeclaredMethod("isCanonicalTokenPair",byte[].class);guard.setAccessible(true);
  var base=toAddr("10010000");if(currentProgram.getMemory().contains(base))throw new IllegalStateException("Scratch collision");
  try{
   var block=currentProgram.getMemory().createInitializedBlock("private_import_library_test",base,0x200,(byte)0,monitor,false);block.setExecute(true);h.imageBaseAddress=(int)base.getOffset();h.blocks=new ArrayList<>(List.of(block));h.useImportAnalysisVeneers=false;ImportFunction imp=new ImportFunction();imp.address=(int)base.getOffset();imp.thunk=(int)base.add(16).getOffset();
   for(int lib=0;lib<256;lib++)for(int ordinal:new int[]{0,15,65535}){
    byte[] good=pair(lib,ordinal);List<byte[]> inputs=new ArrayList<>();List<Boolean> wants=new ArrayList<>();inputs.add(good);wants.add(true);
    byte[] mismatch=good.clone();mismatch[5]^=1;inputs.add(mismatch);wants.add(false);byte[] ord=good.clone();ord[7]^=1;inputs.add(ord);wants.add(false);byte[] type=good.clone();type[0]=2;inputs.add(type);wants.add(false);byte[] tail=good.clone();tail[15]^=1;inputs.add(tail);wants.add(false);
    for(int k=0;k<inputs.size();k++){byte[] raw=inputs.get(k);boolean want=wants.get(k);check((boolean)guard.invoke(null,(Object)raw)==want,"guard lib="+lib+" ordinal="+ordinal+" fixture="+k);h.peImage=new byte[64];System.arraycopy(raw,0,h.peImage,16,16);imp.ordinal=ordinal;check((boolean)loader.invoke(h,new BinaryReader(new ByteArrayProvider(h.peImage),false),imp)==want,"loader lib="+lib+" ordinal="+ordinal+" fixture="+k);}
   }
   h.peImage=new byte[64];ByteBuffer.wrap(h.peImage).putInt(0x0000000f).putInt(0x0001000f);System.arraycopy(pair(0,15),0,h.peImage,16,16);System.arraycopy(pair(1,15),0,h.peImage,32,16);currentProgram.getMemory().setBytes(base,h.peImage);h.importLibs=new ArrayList<>();
   for(int lib=0;lib<2;lib++){ImportLibrary l=new ImportLibrary();l.name=lib==0?"xam.xex":"xboxkrnl.exe";l.records.add((int)base.add(lib*4).getOffset());l.records.add((int)base.add(16+16*lib).getOffset());h.importLibs.add(l);}
   h.ProcessImportLibraries(currentProgram,monitor);
   for(int lib=0;lib<2;lib++){var entry=base.add(16+16*lib);var f=getFunctionAt(entry);check(f!=null&&f.isThunk()&&f.getThunkedFunction(false).isExternal(),"real loader creates native external thunk lib="+lib);check(getInstructionContaining(entry)==null&&getDataContaining(entry)==null,"real loader keeps tokens undefined lib="+lib);check(getInstructionAt(entry.add(8))!=null&&getInstructionAt(entry.add(12))!=null,"real loader decodes PPC tail lib="+lib);check(Disassembler.getDisassembler(currentProgram,monitor,null).disassemble(entry,null,null,true).isEmpty(),"real disassembler rejects registered token lib="+lib);check(currentProgram.getBookmarkManager().getBookmark(entry,"Error","Bad Instruction")==null,"real token seed has no invalid-opcode diagnostic lib="+lib);}
  }finally{end(false);start();}
  check(!currentProgram.getMemory().contains(base),"all test fixtures rolled back");Files.writeString(out.resolve("result.txt"),"cases="+cases+"\nfailures="+failures+"\nTEST_PRIVATE_MUTATIONS_ROLLED_BACK=true\n");if(!failures.isEmpty())throw new IllegalStateException("Nonzero-library token regression: "+failures);println("XEX MULTI-LIBRARY TOKEN REGRESSION: "+cases+" PASS; all private mutations rolled back");
 }
}
