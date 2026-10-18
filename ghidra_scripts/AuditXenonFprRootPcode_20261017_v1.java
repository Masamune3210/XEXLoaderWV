// READ_ONLY: inspect the native machine-state FPR saver and its call-site
// p-code to establish the origin of false f1..f13 parameter inference.
// No signatures or memory bytes are modified.
//@category Xbox360.Analysis
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class AuditXenonFprRootPcode_20261017_v1 extends GhidraScript {
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String SAVER_FINGERPRINT =
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final long[] TARGETS = {
        0x80075a38L, // native FPR machine-state saver, 33 FP instructions
        0x800759f8L, // direct wrapper
        0x800778a8L, // caller
        0x80077b38L, // caller
        0x800755d0L, // DPC/dispatch
        0x80075504L, // IRQL/APC dispatch
        0x80078118L, // APC delivery
        0x8007018cL, // spinlock release
        0x80071a68L, // process type query
        0x8008bd90L, // process type wrapper
        0x80089eb0L  // NtClose
    };
    private PrintWriter out;
    private void log(String value) {
        println(value);
        out.println(value);
    }
    private Address at(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
    private Function function(long value) {
        return currentProgram.getFunctionManager().getFunctionAt(at(value));
    }
    private String sha256(byte[] bytes) throws Exception {
        StringBuilder sb = new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
            sb.append(String.format("%02x",b&255));
        return sb.toString();
    }
    private String reg(Varnode var) {
        if(var == null)return "<none>";
        if(!var.isRegister())return var.toString();
        Register r = currentProgram.getRegister(var.getAddress(),var.getSize());
        return (r == null ? "<unmapped>" : r.getName())+"["+var+"]";
    }
    private String pcode(PcodeOp p) {
        StringBuilder sb = new StringBuilder();
        sb.append(p.getMnemonic()).append(" output=").append(reg(p.getOutput()));
        for(int i=0;i<p.getNumInputs();i++)
            sb.append(" input").append(i).append("=").append(reg(p.getInput(i)));
        return sb.toString();
    }
    private void prototype(Function f) {
        if(f==null)return;
        StringBuilder sb=new StringBuilder("PROTOTYPE "+f.getEntryPoint()+" "+
            f.getPrototypeString(true,true)+" source="+f.getSignatureSource()+
            " custom="+f.hasCustomVariableStorage());
        for(Parameter p:f.getParameters())
            sb.append(" | ").append(p.getName()).append(":")
                .append(p.getDataType().getName()).append("@")
                .append(p.getVariableStorage());
        log(sb.toString());
    }
    private void inspect(long address, boolean detailed) throws Exception {
        Function f=function(address);
        if(f==null) {
            log("MISSING_FUNCTION "+Long.toHexString(address));
            return;
        }
        prototype(f);
        int count=0,fp=0,calls=0;
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction ins=it.next();
            count++;
            String mnemonic=ins.getMnemonicString().toLowerCase(Locale.ROOT);
            boolean isFp=mnemonic.startsWith("f")||
                mnemonic.startsWith("stfd")||mnemonic.startsWith("stfs")||
                mnemonic.startsWith("lfd")||mnemonic.startsWith("lfs")||
                mnemonic.startsWith("ps_");
            if(isFp)fp++;
            if(ins.getFlowType().isCall())calls++;
            if(!detailed && !isFp && !ins.getFlowType().isCall())continue;
            log("INSN "+ins.getAddress()+" "+ins.toString());
            if(ins.getFlowType().isCall()) {
                Address[] flows=ins.getFlows();
                if(flows.length==0)log("INDIRECT_CALL "+ins.getAddress());
                else for(Address dest:flows)log("CALL_TARGET "+ins.getAddress()+" -> "+dest);
            }
            for(PcodeOp p:ins.getPcode())
                log("  PCODE "+pcode(p));
        }
        log("FUNCTION_SUMMARY "+f.getEntryPoint()+" nativeInstructions="+count+
            " nativeFpInstructions="+fp+" calls="+calls+
            " detail="+detailed);
    }
    @Override protected void run() throws Exception {
        if(!"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString()) ||
            !SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            println("READ_ONLY_REFUSED: unexpected language or kernel SHA");
            return;
        }
        byte[] original=new byte[0x8c];
        if(currentProgram.getMemory().getBytes(at(0x80075a38L),original)!=original.length ||
            !SAVER_FINGERPRINT.equals(sha256(original))) {
            println("READ_ONLY_REFUSED: native saver bytes do not match verified fingerprint");
            return;
        }
        File dl=new File(System.getProperty("user.home"),"Downloads");
        File root=dl.isDirectory()?dl:new File(System.getProperty("java.io.tmpdir"));
        File report=File.createTempFile("XenonFprRootPcode_20261017_v1_",".txt",root);
        try(PrintWriter file=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(report),StandardCharsets.UTF_8))) {
            out=file;
            log("ROOT_CAUSE_PCODE_READ_ONLY program="+currentProgram.getName()+
                " domain="+currentProgram.getDomainFile().getName()+
                " language="+currentProgram.getLanguageID());
            log("EXPECTED_VERIFIED_SIGNATURES_FROM_SANDBOX count=13");
            log("SAVER_FINGERPRINT_OK "+SAVER_FINGERPRINT);
            log("INPUT_ABI_CONTEXT f1..f13 are input slots under Xenon __stdcall");
            log("ABI_CONTEXT xenon_64_32.cspec byte-identical to upstream ppc_64_32.cspec");
            log("SAVER_EXAMINATION raw pcode is instruction semantics, not decompiler metadata");
            for(long addr:TARGETS) {
                monitor.checkCancelled();
                inspect(addr,addr==0x80075a38L || addr==0x800759f8L);
            }
            log("DONE_READ_ONLY no bytes or metadata modified; report="+report.getAbsolutePath());
        } finally {out=null;}
        println("REPORT "+report.getAbsolutePath());
    }
}
