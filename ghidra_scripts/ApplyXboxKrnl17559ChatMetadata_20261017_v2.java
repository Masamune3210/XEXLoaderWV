// Retail xboxkrnl 17559: consolidate all established metadata from the
// XAM-readiness, CR0, protection-mask and FPR-context discussions.
// Idempotent, SHA-guarded. Does not normalize or strip inferred FPR arguments.
//@category Xbox360.Kernel
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class ApplyXboxKrnl17559ChatMetadata_20261017_v2 extends GhidraScript {
    // Set false to run every audit without applying anything.
    private static final boolean APPLY = true;
    private static final String KERNEL_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String CR0_CATEGORY = "XenonCR0SF0_20261017";
    private static final String FPR_COMMENT_TAG = "[XenonFPRStateSave17559]";
    private static final String FPR_WRAPPER_TAG = "[XenonFPRSaveWrapper17559]";
    private static final long[][] CR0_SITES = {
        {0x80080cb4L, 0x556b05e9L, 0x4182000cL, 0x200L},
        {0x80083af0L, 0x556b0499L, 0x4182006cL, 0x4000L},
        {0x800925e4L, 0x556b075fL, 0x41820010L, 0x8L},
        {0x800a81e8L, 0x556b0733L, 0x4082003cL, 0x10L},
        {0x8010bf8cL, 0x554a0203L, 0x41820018L, 0x1000000L}
    };
    private static class VoidTarget {
        final long entry; final int length, parameters, xamCalls;
        final String name, nativeSha;
        VoidTarget(long e, int n, int p, int x, String name, String sha) {
            this.entry=e;this.length=n;this.parameters=p;this.xamCalls=x;
            this.name=name;this.nativeSha=sha;
        }
    }
    // Independently rehashed from the user's original native ASM export.
    private static final VoidTarget[] VOID_TARGETS = {
        new VoidTarget(0x800718e0L, 0x14, 0, 460, "KeEnterCriticalRegion",
            "b804cbd2243abdb5c607944ce5de1595e6b9267943aef85e67b893460a439e39"),
        new VoidTarget(0x800718f8L, 0x38, 0, 496, "KeLeaveCriticalRegion",
            "b87c0e3f2713fc1a71ec6c77394d08a42d8a807cdbc996f53fc5e30645a1afae"),
        new VoidTarget(0x8008b928L, 0x88, 1, 126, "ObDereferenceObject",
            "31379f86f1061492a6be17a9bca7b70f3093e47a5b02bc012dfad87c253a8e34"),
        new VoidTarget(0x800750f4L, 0x34, 1, 116, "KfLowerIrql",
            "c1c3c1223ae0cdf60695c9999e6e12877f48b20dba543bc9ee702b6641214a25"),
        new VoidTarget(0x8007020cL, 0x10, 1, 112, "KeReleaseSpinLockFromRaisedIrql",
            "8528b6bfa38c3cc6a7c4320b6291ef768e36ec4d8757de3f4a858dfcb79f03e5")
    };
    // These declarations were already established in the user's live CR0
    // checkpoint. They are audit-only: DO NOT synthesize their unresolved types.
    private static class Preserved {
        final long addr; final String name, ret, signatureSource; final int params;
        Preserved(long a,String n,String r,int p,String s) {
            addr=a;name=n;ret=r;params=p;signatureSource=s;
        }
    }
    private static final Preserved[] PRESERVED = {
        new Preserved(0x8007f978L,"QueryPageMappingWordObserved","ulonglong",1,"USER_DEFINED"),
        new Preserved(0x80080ac0L,"MiGetPteAddress","ulonglong",1,"USER_DEFINED"),
        new Preserved(0x80080af8L,"MiGetMappedPteAddress","uint *",1,"USER_DEFINED"),
        new Preserved(0x80080c60L,"DecodeMappingProtectionWordObserved","ushort",1,"ANALYSIS"),
        new Preserved(0x800854d8L,"MiReadPhysicalMappingTable","byte",2,"USER_DEFINED"),
        new Preserved(0x80096bb0L,"EmaExecuteSingle","undefined8",13,"ANALYSIS"),
        new Preserved(0x80096cb0L,"EmaExecute","undefined8",13,"ANALYSIS"),
        new Preserved(0x800b9578L,"QueryPageMappingWordTailObserved","ulonglong",1,"USER_DEFINED"),
        new Preserved(0x800bfa50L,"VdpSmcReadF0RegisterWordObserved","uint",14,"USER_DEFINED"),
        new Preserved(0x8010f278L,"RtlpFormatBinary64FixedObserved","undefined8",3,"ANALYSIS"),
        new Preserved(0x80120be0L,"BnReleaseOperationContextObserved","ulonglong",15,"USER_DEFINED"),
        new Preserved(0x80121268L,"BnDivide128By64Observed","undefined8",5,"USER_DEFINED"),
        new Preserved(0x80121768L,"BnDivideLimbs64Observed","bool",7,"USER_DEFINED"),
        new Preserved(0x80122c98L,"BnAddModularVectorObserved","ulonglong",5,"USER_DEFINED"),
        new Preserved(0x80123080L,"BnRandomModularVectorObserved","ulonglong",16,"USER_DEFINED")
    };
    private int applied=0, already=0, withheld=0, audited=0;
    private Address at(long address) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
    }
    private String sha(byte[] bytes) throws Exception {
        StringBuilder hex=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
            hex.append(String.format(Locale.ROOT,"%02x",b&255));
        return hex.toString();
    }
    private boolean nativeProof(long entry, int len, String expected) throws Exception {
        Address a=at(entry);
        Function f=currentProgram.getFunctionManager().getFunctionAt(a);
        if(f==null || f.isThunk() || !f.getBody().contains(a.add(len-4)))return false;
        for(int off=0;off<len;off+=4) {
            Instruction ins=currentProgram.getListing().getInstructionAt(a.add(off));
            if(ins==null || ins.getLength()!=4)return false;
        }
        byte[] bytes=new byte[len];
        return currentProgram.getMemory().getBytes(a,bytes)==len &&
            expected.equals(sha(bytes));
    }
    private long word(Address a) throws Exception {
        return currentProgram.getMemory().getInt(a)&0xffffffffL;
    }
    private String cr0Width(Instruction instruction) {
        int four=0,eight=0,other=0;
        for(PcodeOp p:instruction.getPcode(false)) {
            if(p.getOpcode()!=PcodeOp.INT_EQUAL &&
                p.getOpcode()!=PcodeOp.INT_SLESS &&
                p.getOpcode()!=PcodeOp.INT_SLESSEQUAL)continue;
            if(p.getNumInputs()!=2)continue;
            Varnode a=p.getInput(0),b=p.getInput(1);
            boolean az=a.isConstant() && a.getOffset()==0;
            boolean bz=b.isConstant() && b.getOffset()==0;
            if(!az && !bz)continue;
            int size=az?b.getSize():a.getSize();
            if(size==4)four++;
            else if(size==8)eight++;
            else other++;
        }
        if(four>0 && eight==0 && other==0)return "LOW32_COMPARISONS";
        if(eight>0 && four==0 && other==0)return "FULL64_COMPARISONS";
        return "INCONCLUSIVE("+four+","+eight+","+other+")";
    }
    private void cr0() throws Exception {
        for(long[] site:CR0_SITES) {
            monitor.checkCancelled();
            Address a=at(site[0]);
            Instruction instr=currentProgram.getListing().getInstructionAt(a);
            Instruction next=currentProgram.getListing().getInstructionAt(a.add(4));
            if(instr==null || next==null ||
                !instr.getMnemonicString().startsWith("rlwinm") ||
                word(a)!=site[1] || word(a.add(4))!=site[2]) {
                println("WITHHELD_CR0 "+a+" native instruction/branch mismatch");
                withheld++;continue;
            }
            String mode=cr0Width(instr);
            println("CR0 "+a+" "+mode+" branch="+next.getMnemonicString());
            if(!"LOW32_COMPARISONS".equals(mode)) {
                println("WITHHELD_CR0 "+a+" loaded Xenon p-code differs from verified LOW32");
                withheld++;continue;
            }
            // The first site already had private native-witness verification.
            // The other four receive model-only REVIEW bookmarks, not runtime claims.
            if(site[0]==0x80080cb4L) {
                audited++;continue;
            }
            if(currentProgram.getBookmarkManager().getBookmark(a,
                    BookmarkType.NOTE,CR0_CATEGORY)!=null) {
                already++;println("ALREADY_CR0_BOOKMARK "+a);continue;
            }
            if(!APPLY) {println("WOULD_ADD_CR0_BOOKMARK "+a);continue;}
            String message="Native bytes verified, wrapping rlwinm. followed by CR0 branch. "+
                "Fixed-SF0 model witness input low32=0x"+
                Long.toHexString(site[3])+
                ". P-code comparison=LOW32_COMPARISONS. Model witness, NOT proof "+
                "of runtime reachability or MSR[SF]. Preserve native GPR64.";
            currentProgram.getBookmarkManager().setBookmark(a,BookmarkType.NOTE,
                CR0_CATEGORY,message);
            applied++;println("APPLIED_CR0_BOOKMARK "+a);
        }
    }
    private void protectionMask() throws Exception {
        final long address=0x80080cb0L;
        String proof="aa65bd4ee6b78e0ce6ccdad8e8dd90235f998103e9189d07166f5ac7f6827381";
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(address));
        if(!nativeProof(address,0x74,proof) || f==null ||
            f.getParameterCount()!=2 || f.getReturnType().getLength()!=8) {
            println("WITHHELD_PROTECTION_MASK 80080cb0 proof/parameters/return changed");
            withheld++;return;
        }
        Parameter[] p=f.getParameters();
        if(p[0].getLength()!=4 || p[1].getLength()!=4 ||
            !(p[1].getDataType() instanceof Pointer)) {
            println("WITHHELD_PROTECTION_MASK 80080cb0 argument datatypes changed");
            withheld++;return;
        }
        println("MASK_PROOF_OK "+f.getPrototypeString(true,true));
        if("MiMakePhysicalProtectionMask".equals(f.getName())) {
            already++;println("ALREADY_MASK_NAME");
        }
        else if("FUN_80080cb0".equals(f.getName())) {
            if(APPLY) {
                f.setName("MiMakePhysicalProtectionMask",SourceType.ANALYSIS);
                applied++;println("APPLIED_MASK_NAME");
            }
            else println("WOULD_RENAME_MASK");
        }
        else {
            withheld++;println("WITHHELD_MASK_NAME existing="+f.getName());
        }
        String[] names={"protectionFlags","outPhysicalMask"};
        for(int i=0;i<2;i++) {
            if(names[i].equals(p[i].getName())) {
                already++;println("ALREADY_MASK_PARAM "+i);continue;
            }
            if(p[i].getName().startsWith("param_") &&
                p[i].getSource()!=SourceType.USER_DEFINED) {
                if(APPLY) {
                    p[i].setName(names[i],SourceType.ANALYSIS);
                    applied++;println("APPLIED_MASK_PARAM "+i+" "+names[i]);
                }
                else println("WOULD_NAME_MASK_PARAM "+i);
            }
            else {
                withheld++;println("WITHHELD_MASK_PARAM "+i+
                    " existing="+p[i].getName());
            }
        }
    }
    private boolean areaMatches(Structure s) {
        if(s.getLength()!=0x108 || s.getNumComponents()!=2)return false;
        DataTypeComponent a=s.getComponentAt(0), b=s.getComponentAt(8);
        if(a==null || b==null || a.getLength()!=8 || b.getLength()!=0x100)
            return false;
        if(!"fpscrRaw".equals(a.getFieldName()) ||
            !"fprBits".equals(b.getFieldName()))return false;
        if(!a.getDataType().isEquivalent(UnsignedLongLongDataType.dataType))
            return false;
        if(!(b.getDataType() instanceof Array))return false;
        Array arr=(Array)b.getDataType();
        return arr.getNumElements()==32 && arr.getElementLength()==8 &&
            arr.getDataType().isEquivalent(UnsignedLongLongDataType.dataType);
    }
    private void saveArea() {
        CategoryPath category=new CategoryPath("/Xbox360/Xenon");
        String name="XenonFloatingPointSaveAreaView";
        DataTypeManager mgr=currentProgram.getDataTypeManager();
        DataType existing=mgr.getDataType(category,name);
        if(existing!=null) {
            if(existing instanceof Structure && areaMatches((Structure)existing)) {
                already++;println("ALREADY_FPR_SAVE_AREA "+existing.getPathName());
            }
            else {
                withheld++;println("WITHHELD_FPR_SAVE_AREA conflicting definition "+
                    existing.getPathName());
            }
            return;
        }
        if(!APPLY) {println("WOULD_ADD_FPR_SAVE_AREA 0x108");return;}
        StructureDataType area=new StructureDataType(category,name,0);
        area.add(UnsignedLongLongDataType.dataType,8,"fpscrRaw",
            "FPSCR encoded by mffs f0 and stored at context+0x980");
        area.add(new ArrayDataType(UnsignedLongLongDataType.dataType,32,8),
            0x100,"fprBits",
            "Raw FPR0..FPR31 bits stored at context+0x988..0xA80");
        if(!areaMatches(area)) {
            withheld++;println("WITHHELD_FPR_SAVE_AREA candidate size/layout failed");
            return;
        }
        DataType result=mgr.addDataType(area,DataTypeConflictHandler.KEEP_HANDLER);
        if(!(result instanceof Structure) || !areaMatches((Structure)result)) {
            withheld++;println("WITHHELD_FPR_SAVE_AREA failed datatype resolution");
            return;
        }
        applied++;println("APPLIED_FPR_SAVE_AREA "+result.getPathName()+
            " length=0x108 members=0x00:uint64,0x08:uint64[32]");
    }
    private void appendRepeatable(Function f, String tag, String text)
            throws Exception {
        String old=f.getRepeatableComment();
        if(old!=null && old.contains(tag)) {
            already++;println("ALREADY_COMMENT "+f.getEntryPoint());return;
        }
        if(!APPLY) {println("WOULD_ADD_COMMENT "+f.getEntryPoint());return;}
        f.setRepeatableComment((old==null || old.isEmpty()?"":old+"\n")+
            tag+" "+text);
        applied++;println("APPLIED_COMMENT "+f.getEntryPoint());
    }
    private void fprSaver() throws Exception {
        final long address=0x80075a38L;
        String fingerprint="99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
        if(!nativeProof(address,0x8c,fingerprint)) {
            withheld++;println("WITHHELD_FPR_SAVER native SHA/function boundary mismatch");
            return;
        }
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(address));
        boolean intact=f.getParameterCount()==14 &&
            f.hasCustomVariableStorage() &&
            f.getParameter(13).getVariableStorage().toString().equals("r3:4") &&
            f.getParameter(13).getDataType().getName().equals("int");
        for(int i=0;i<13 && intact;i++) {
            Parameter p=f.getParameter(i);
            intact=("f"+(i+1)+":8").equals(p.getVariableStorage().toString()) &&
                "undefined8".equals(p.getDataType().getName());
        }
        println("FPR_SAVER_VERIFIED "+f.getPrototypeString(true,true)+
            " existingFpr13StoragePreserved="+intact);
        if(!intact) {
            withheld++;println("WITHHELD_FPR_SAVER metadata shape differs; do not reset");
            return;
        }
        // A separate rollback-only Ghidra experiment proved that these
        // are implicit machine-state values, but we intentionally DO NOT
        // remove or reinterpret the stored custom parameter declarations.
        saveArea();
        if("SaveFloatingPointRegisterState".equals(f.getName())) {
            already++;println("ALREADY_FPR_SAVER_NAME");
        }
        else if("FUN_80075a38".equals(f.getName())) {
            if(APPLY) {
                f.setName("SaveFloatingPointRegisterState",SourceType.ANALYSIS);
                applied++;println("APPLIED_FPR_SAVER_NAME "+f.getEntryPoint());
            }
            else println("WOULD_RENAME_FPR_SAVER");
        }
        else {
            withheld++;println("WITHHELD_FPR_SAVER_NAME existing="+f.getName());
        }
        appendRepeatable(f,FPR_COMMENT_TAG,
            "Native 17559: saves FP0..FP31 to context+r3 offsets 0x988..0xA80; "+
            "mffs f0 saves FPSCR to +0x980. Matching view: "+
            "XenonFloatingPointSaveAreaView (relative to context+0x980). "+
            "f1..f13 are machine-state inputs, NOT established ABI arguments. "+
            "Do not change preserved signature/storage until a generic "+
            "analysis-level correction is validated.");
        final long wrapper=0x800759f8L;
        String wrapperSha="c35f0e0312681934d6776c932bf37db7c1eab97d85bdaad53f8e5540f2d21fec";
        if(nativeProof(wrapper,0x18,wrapperSha)) {
            Function w=currentProgram.getFunctionManager().getFunctionAt(at(wrapper));
            appendRepeatable(w,FPR_WRAPPER_TAG,
                "Calls native 0x80075A38 FP state saver. Saved f1..f13 "+
                "inputs currently propagate from its inferred signature. "+
                "Wrapper ABI requires separate analysis; preserve existing "+
                "custom parameter metadata.");
        }
        else {
            withheld++;println("WITHHELD_FPR_WRAPPER_COMMENT native bytes mismatch");
        }
    }
    private String[] snapshotParams(Function f) {
        Parameter[] p=f.getParameters();
        String[] out=new String[p.length];
        for(int i=0;i<p.length;i++) {
            out[i]=p[i].getDataType().getPathName()+"|"+
                p[i].getName()+"|"+p[i].getVariableStorage().toString()+"|"+
                p[i].getSource();
        }
        return out;
    }
    private void voidReturns() throws Exception {
        for(VoidTarget t:VOID_TARGETS) {
            monitor.checkCancelled();
            Function f=currentProgram.getFunctionManager().getFunctionAt(at(t.entry));
            if(f==null || !nativeProof(t.entry,t.length,t.nativeSha) ||
                !t.name.equals(f.getName()) ||
                f.getParameterCount()!=t.parameters) {
                withheld++;println("WITHHELD_VOID "+at(t.entry)+
                    " function/name/body/native SHA/parameter mismatch");
                continue;
            }
            String old=f.getReturnType().getName();
            if("void".equals(old)) {
                already++;println("ALREADY_VOID "+at(t.entry)+" "+t.name);
                continue;
            }
            if(!old.startsWith("undefined") || f.hasCustomVariableStorage() ||
                f.getSignatureSource()==SourceType.USER_DEFINED) {
                withheld++;println("WITHHELD_VOID "+at(t.entry)+" "+t.name+
                    " existingReturn="+old+" customStorage="+
                    f.hasCustomVariableStorage()+" signatureSource="+
                    f.getSignatureSource()+" (preserve existing contract)");
                continue;
            }
            if(!APPLY) {
                println("WOULD_APPLY_VOID "+at(t.entry)+" "+t.name);continue;
            }
            String[] before=snapshotParams(f);
            f.setReturnType(VoidDataType.dataType,SourceType.ANALYSIS);
            if(!"void".equals(f.getReturnType().getName()) ||
                !Arrays.equals(before,snapshotParams(f))) {
                throw new IllegalStateException(
                    "Ghidra unexpectedly changed argument storage at "+f.getEntryPoint()+
                    "; DO NOT SAVE; inspect transaction/Undo and restore backup");
            }
            applied++;println("APPLIED_VOID "+at(t.entry)+" "+t.name+
                " xamBranchReferences="+t.xamCalls);
        }
    }
    private void preserved() {
        int good=0;
        for(Preserved p:PRESERVED) {
            Function f=currentProgram.getFunctionManager().getFunctionAt(at(p.addr));
            if(f==null) {
                withheld++;println("PRESERVED_MISSING "+at(p.addr)+" "+p.name);
                continue;
            }
            boolean correct=p.name.equals(f.getName()) &&
                p.ret.equals(f.getReturnType().getDisplayName()) &&
                p.params==f.getParameterCount() &&
                p.signatureSource.equals(f.getSignatureSource().toString());
            if(correct)good++;
            else withheld++;
            println((correct?"PRESERVED_OK ":"PRESERVED_DIFFERENT ")+at(p.addr)+
                " name="+f.getName()+
                " return="+f.getReturnType().getDisplayName()+
                " params="+f.getParameterCount()+
                " signatureSource="+f.getSignatureSource());
        }
        println("PRESERVED_BASELINE "+good+"/"+PRESERVED.length+
            " correct; signatures are audited only, NEVER reset");
    }
    @Override protected void run() throws Exception {
        println("XBOXKRNL_17559_CHAT_METADATA_V2 apply="+APPLY);
        if(!"xboxkrnl.exe".equalsIgnoreCase(currentProgram.getName()) ||
            !LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString()) ||
            !KERNEL_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            println("REFUSE_WRONG_PROGRAM_NAME_LANGUAGE_OR_SHA");return;
        }
        // Guard all edits against the exact retail executable rather than
        // treating same-named functions in other builds as identical.
        cr0();
        protectionMask();
        fprSaver();
        voidReturns();
        preserved();
        println("FINAL_SUMMARY applied="+applied+" already="+already+
            " withheld="+withheld+" audited="+audited);
        println("NON_ACTIONS: 13 machine-state FPR parameters preserved; no ABI/cspec "+
            "modification; no inferred missing signatures or ordinal names; "+
            "no direct XAM external signature changes.");
        println("RERUN_EXPECTED: applied=0 when verified changes already present.");
    }
}
