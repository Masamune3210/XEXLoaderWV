// Numerical regression for classic LVSL, RA=0 semantics, and existing right/VMX128 masks.
import java.nio.file.*;
import java.util.*;
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.pcode.PcodeOp;
@SuppressWarnings("removal")
public class TestXenonLvslMasks extends GhidraScript {
 record Fixture(String name,int word,int dest,int ra,int rb,boolean right){}
 int xform(int d,int a,int b,int xo){return (31<<26)|(d<<21)|(a<<16)|(b<<11)|(xo<<1);}
 int vx128(int d,int a,int b){return (4<<26)|((d&31)<<21)|(a<<16)|(b<<11)|((d&32)!=0?4:0)|((d&64)!=0?8:0)|3;}
 void require(boolean b,String m){if(!b)throw new IllegalStateException(m);}
 public void run()throws Exception{
  Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);var base=toAddr("91010000");require(!currentProgram.getMemory().contains(base),"Private fixture collision");List<String> errors=new ArrayList<>();int cases=0,failed=0,passed=0;Map<String,Integer> byFamily=new TreeMap<>();Random random=new Random(0x1a17559);
  Fixture[] fixtures={new Fixture("lvsl_native_dash_v7_a0_b4",0x7ce0200c,7,0,4,false),new Fixture("lvsl_native_dash_v0_a0_b5",0x7c00280c,0,0,5,false),new Fixture("lvsl_v31_a4_b5",xform(31,4,5,6),31,4,5,false),new Fixture("lvsl_v13_a4_b4",xform(13,4,4,6),13,4,4,false),new Fixture("lvsl_v7_a0_b0",xform(7,0,0,6),7,0,0,false),new Fixture("lvsr_v7_a0_b4",xform(7,0,4,38),7,0,4,true),new Fixture("lvsl128_v7_a0_b4",vx128(7,0,4),7,0,4,false),new Fixture("lvsl128_v103_a4_b5",vx128(103,4,5),103,4,5,false)};
  try{
   var block=currentProgram.getMemory().createInitializedBlock("private_lvsl_numerical_test",base,0x200,(byte)0,monitor,false);block.setExecute(true);
   for(int n=0;n<fixtures.length;n++){var f=fixtures[n];var site=base.add(8*n);byte[] code=java.nio.ByteBuffer.allocate(8).putInt(f.word).putInt(0x4e800020).array();currentProgram.getMemory().setBytes(site,code);for(int delta:new int[]{0,4}){var a=site.add(delta);require(new DisassembleCommand(a,new AddressSet(a,a.add(3)),false).applyTo(currentProgram,monitor),"Fixture decoder "+f.name);}}
   for(int n=0;n<fixtures.length;n++){var f=fixtures[n];var site=base.add(8*n);for(int nibble=0;nibble<16;nibble++)for(int trial=0;trial<16;trial++){
    EmulatorHelper e=new EmulatorHelper(currentProgram);try{long[] input=new long[32];for(int r=0;r<32;r++)input[r]=random.nextLong();input[0]=(input[0]&~15L)|13L;input[4]=random.nextLong();input[5]=random.nextLong();long effectiveA=f.ra==0?0:input[f.ra];if(f.ra!=f.rb)input[f.rb]=(input[f.rb]&~15L)|((nibble-effectiveA)&15L);else input[f.rb]=(input[f.rb]&~15L)|nibble;for(int r=0;r<32;r++)e.writeRegister("r"+r,input[r]);String vector=f.dest<32?"vs"+(32+f.dest):"xv"+f.dest;e.writeRegister(vector,new BigInteger(128,random));e.writeRegister(e.getPCRegister(),site.getOffset());byte[] want=new byte[16];int off=(int)(((f.ra==0?0:input[f.ra])+input[f.rb])&15L);for(int i=0;i<16;i++)want[i]=(byte)(i+(f.right?16-off:off));boolean ok=e.step(monitor);String error=ok?"":e.getLastError();if(ok)ok=e.readRegister(vector).equals(new BigInteger(1,want));if(ok)for(int r=0;r<32;r++)if(e.readRegister("r"+r).longValue()!=input[r]){ok=false;error="GPR carrier changed r"+r;break;}cases++;if(ok){passed++;byFamily.merge(f.name,1,Integer::sum);}else{failed++;if(errors.size()<8)errors.add(f.name+" off="+off+" error="+error);}}finally{e.dispose();}
   }}
   // Also inspect the instruction already present in the supplied analyzed Program.
   var stored=getInstructionAt(toAddr("92866aac"));if(stored!=null){boolean opaque=false,wrongR0=false;for(var op:stored.getPcode()){if(op.getOpcode()==PcodeOp.CALLOTHER)opaque=true;for(var input:op.getInputs())if(input.isRegister()&&input.getSize()==8&&input.getAddress().equals(currentProgram.getRegister("r0").getAddress()))wrongR0=true;}cases++;if(!opaque&&!wrongR0){passed++;byFamily.put("stored_DASH_lvsl_concrete_zero_base",1);}else{failed++;errors.add("stored_DASH_lvsl opaque="+opaque+" wrong_r0_read="+wrongR0);}}
  }finally{end(false);start();}
  require(!currentProgram.getMemory().contains(base),"Private numerical fixtures survived rollback");Files.writeString(out.resolve("result.txt"),"cases="+cases+"\npassed="+passed+"\nfailed="+failed+"\nby_family="+byFamily+"\nexamples="+errors+"\nPRIVATE_PROGRAM_MUTATIONS_ROLLED_BACK=true\nAll16 alignments, independent byte-array mask oracle, GPR high carriers/overflow and RA/RB overlap including RA0/RB0. Existing stored DASH opcode must have concrete p-code and must not read r0 as its zero base. No userop mocks, native firmware patch or hardware execution.\n");if(failed!=0)throw new IllegalStateException("LVSL MASK REGRESSION: "+failed+"/"+cases+" failed; "+errors);println("XENON LVSL MASKS: "+passed+" numerical/stored-instruction checks PASS; fixtures rolled back");
 }
}
