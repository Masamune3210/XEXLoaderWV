// Disposable FPR_SANDBOX only. Apply/verify eight experimentally verified
// FPR signatures, then test Parameter ID on the clean object-close leaf and
// its caller; audit USER_DEFINED process type/bugcheck paths without mutation.
// Never run on production. Preserve unrelated user-defined metadata.
//@category Xbox360.Analysis
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ProbeXenonFprObjectCloseSandbox_20261017_v6 extends GhidraScript {
    private static final String EXE_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String SAVER_SHA =
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final long SAVER=0x80075a38L;
    private static final long WRAPPER=0x800759f8L;
    private static final long FIRST_CALLER=0x800778a8L;
    private static final long SECOND_CALLER=0x80077b38L;
    private static final long DPC=0x800755d0L;
    private static final long IRQL=0x80075504L;
    private static final long APC=0x80078118L;
    private static final long RELEASE=0x8007018cL;
    private static final long NTCLOSE=0x80089eb0L;
    private static final long OBJECT_PROBE=0x8008bd90L;
    private static final long CLOSE_HELPER=0x80089df0L;
    private static final long CLOSE_LEAF=0x80089d40L;
    private static final long PROCESS_TYPE=0x80071a68L;
    private static final long BUGCHECK=0x800716e8L;
    private PrintWriter output;

    private Address at(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }
    private Function f(long v) {
        return currentProgram.getFunctionManager().getFunctionAt(at(v));
    }
    private void log(String msg) {
        println(msg);
        if (output != null) output.println(msg);
    }
    private int fpr(Function fun) {
        if (fun == null) return -1;
        int count=0;
        for(Parameter p: fun.getParameters())
            if ("undefined8".equals(p.getDataType().getName()))
                for(int j=1;j<=13;j++)
                    if (p.getVariableStorage().toString().equals("f"+j+":8")) {
                        count++;
                        break;
                    }
        return count;
    }
    private boolean fprPrefix(Function fun, int slots) {
        if(fun==null || fun.getParameterCount()<slots) return false;
        for(int i=0;i<slots;i++) {
            Parameter p=fun.getParameter(i);
            if(!"undefined8".equals(p.getDataType().getName())
                || !("f"+(i+1)+":8").equals(p.getVariableStorage().toString()))
                return false;
        }
        return true;
    }
    private boolean param(Parameter p, String name, String type, String storage) {
        return p!=null && p.getName().equals(name) &&
            p.getDataType().getName().equals(type) &&
            p.getVariableStorage().toString().equals(storage);
    }
    private int nativeFp(Function fun) throws Exception {
        int n=0;
        InstructionIterator it=currentProgram.getListing().getInstructions(fun.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            String x=it.next().getMnemonicString().toLowerCase(Locale.ROOT);
            if (x.startsWith("f") || x.startsWith("lfd") || x.startsWith("lfs") ||
                x.startsWith("stfd") || x.startsWith("stfs") || x.startsWith("ps_"))
                n++;
        }
        return n;
    }
    private String describe(Function fun) {
        if(fun==null) return "MISSING";
        StringBuilder s=new StringBuilder(fun.getPrototypeString(true,true));
        s.append(" source=").append(fun.getSignatureSource())
            .append(" custom=").append(fun.hasCustomVariableStorage())
            .append(" phantomFprs=").append(fpr(fun))
            .append(" returnStorage=").append(fun.getReturn().getVariableStorage());
        for(Parameter p:fun.getParameters())
            s.append(" | ").append(p.getName()).append(":")
                .append(p.getDataType().getName()).append("@")
                .append(p.getVariableStorage());
        return s.toString();
    }
    private String fingerprint(byte[] bytes) throws Exception {
        StringBuilder s=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
            s.append(String.format("%02x",b&255));
        return s.toString();
    }
    private void require(boolean ok, String why) {
        if(!ok) throw new IllegalStateException("ABORT_UNEXPECTED_METADATA "+why);
    }
    private boolean calls(Function caller, long dest) throws Exception {
        InstructionIterator it=currentProgram.getListing().getInstructions(caller.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction op=it.next();
            if(!op.getFlowType().isCall()) continue;
            for(Address a:op.getFlows())
                if(a.equals(at(dest))) return true;
        }
        return false;
    }
    private void signature(long address, String tag) {
        log(tag+" "+Long.toHexString(address)+" "+describe(f(address)));
    }
    private boolean applyParamId(long address) throws Exception {
        Function fun=f(address);
        require(fun!=null && !fun.isThunk(), "missing function "+Long.toHexString(address));
        if(fun.getSignatureSource()!=SourceType.ANALYSIS) {
            log("PARAMID_SKIPPED_USER_DEFINED "+fun.getEntryPoint());
            return false;
        }
        int before=fpr(fun);
        DecompilerParameterIdCmd cmd=new DecompilerParameterIdCmd(
            "Sandbox Xenon FPR caller recovery "+fun.getEntryPoint(),
            new AddressSet(fun.getEntryPoint(),fun.getEntryPoint()),
            SourceType.ANALYSIS,true,false,60);
        boolean success=cmd.applyTo(currentProgram,monitor);
        log("PARAMID "+Long.toHexString(address)+" success="+success+
            " status="+cmd.getStatusMsg()+" fprBefore="+before+
            " fprAfter="+fpr(f(address)));
        require(success, "Parameter ID failed at "+fun.getEntryPoint());
        return fpr(f(address))!=before;
    }
    private void applyVerifiedMetadata() throws Exception {
        Function root=f(SAVER);
        require(root!=null && !root.isThunk(),"saver missing");
        byte[] bytes=new byte[0x8c];
        require(currentProgram.getMemory().getBytes(at(SAVER),bytes)==bytes.length
            && SAVER_SHA.equals(fingerprint(bytes)),"saver native bytes differ");
        signature(SAVER,"VERIFIED_METADATA_BEFORE");
        if(fpr(root)==13) {
            require(root.getParameterCount()==14 && fprPrefix(root,13)
                && "int".equals(root.getParameter(13).getDataType().getName())
                && "r3:4".equals(root.getParameter(13).getVariableStorage().toString())
                && root.getSignatureSource()==SourceType.ANALYSIS,
                "unexpected saver baseline");
            String returnType=root.getReturnType().getName();
            String returnStorage=root.getReturn().getVariableStorage().toString();
            for(int i=12;i>=0;i--)root.removeParameter(i);
            root.setSignatureSource(SourceType.USER_DEFINED);
            require(root.getReturnType().getName().equals(returnType)
                && root.getReturn().getVariableStorage().toString().equals(returnStorage),
                "saver return changed");
            log("VERIFIED_METADATA_APPLIED saver removed 13 phantom FPR arguments");
        } else {
            require(fpr(root)==0 && root.getParameterCount()==1
                && "int".equals(root.getParameter(0).getDataType().getName())
                && "r3:4".equals(root.getParameter(0).getVariableStorage().toString())
                && root.getSignatureSource()==SourceType.USER_DEFINED,
                "unexpected cleaned saver");
            log("VERIFIED_METADATA_ALREADY_PRESENT saver");
        }
        signature(SAVER,"VERIFIED_METADATA_AFTER");

        long[] chain={WRAPPER,FIRST_CALLER,SECOND_CALLER,DPC};
        String[] expectedReturns={"undefined","undefined","undefined","uint"};
        int[] expectedParams={1,1,1,0};
        for(int i=0;i<chain.length;i++) {
            Function fun=f(chain[i]);
            require(fun!=null && !fun.isThunk(), "missing verified function");
            signature(chain[i],"VERIFIED_METADATA_BEFORE");
            if(fpr(fun)==13) {
                require(fun.getSignatureSource()==SourceType.ANALYSIS
                    && fprPrefix(fun,13),
                    "unexpected signature source for verified caller "+fun.getEntryPoint());
                applyParamId(chain[i]);
            }
            fun=f(chain[i]);
            require(fpr(fun)==0 && fun.getParameterCount()==expectedParams[i]
                && expectedReturns[i].equals(fun.getReturnType().getName()),
                "verified function disagrees with sandbox recovery at "+fun.getEntryPoint());
            if(expectedParams[i]==1)
                require("int".equals(fun.getParameter(0).getDataType().getName())
                    && "r3:4".equals(fun.getParameter(0).getVariableStorage().toString()),
                    "retained argument differs at "+fun.getEntryPoint());
            log("VERIFIED_METADATA_APPLIED_OR_CONFIRMED "+fun.getEntryPoint());
            signature(chain[i],"VERIFIED_METADATA_AFTER");
        }

        Function irql=f(IRQL);
        require(irql!=null, "missing IRQL dispatch function");
        // Accept either original contaminated signature or the v4-corrected
        // signature. Never destroy the previously verified GP parameter names.
        int offset=fpr(irql)==13?13:0;
        require((offset==13 && irql.getParameterCount()==15 && fprPrefix(irql,13))
            || (offset==0 && fpr(irql)==0 && irql.getParameterCount()==2),
            "IRQL signature differs from either known baseline");
        require(param(irql.getParameter(offset),"requestedIrql","ulonglong","r3:8")
            && param(irql.getParameter(offset+1),"pendingLevelsWord","ulonglong","r4:8"),
            "protected IRQL two GP parameters differ");
        log("VERIFIED_METADATA_PRESERVED irql requestedIrql@r3:8 and pendingLevelsWord@r4:8");
    }
    private Map<Address,String> protectedSignatures() throws Exception {
        Map<Address,String> s=new HashMap<>();
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Function fun=it.next();
            if(fun.getSignatureSource()==SourceType.USER_DEFINED)
                s.put(fun.getEntryPoint(),describe(fun));
        }
        return s;
    }
    private void printCallees(long address) throws Exception {
        Function fun=f(address);
        if(fun==null)return;
        log("CALLEES_BEGIN "+fun.getName()+"@"+fun.getEntryPoint()+
            " nativeFp="+nativeFp(fun));
        InstructionIterator it=currentProgram.getListing().getInstructions(fun.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction op=it.next();
            if(!op.getFlowType().isCall())continue;
            Address[] targets=op.getFlows();
            if(targets.length==0) log("INDIRECT_CALL "+op.getAddress()+" "+op);
            for(Address target:targets) {
                Function dest=currentProgram.getFunctionManager().getFunctionAt(target);
                log("CALLEE callSite="+op.getAddress()+" dest="+target+
                    " name="+(dest==null?"UNRESOLVED":dest.getName())+
                    " phantomFprs="+fpr(dest));
            }
        }
    }
    private void decompile(PrintWriter p,DecompInterface di,long address) throws Exception {
        Function fun=f(address);
        if(fun==null)return;
        di.flushCache();
        DecompileResults results=di.decompileFunction(fun,90,monitor);
        p.println("DECOMP_BEGIN "+fun.getEntryPoint()+" "+fun.getName());
        if(results.decompileCompleted() && results.getDecompiledFunction()!=null)
            p.println(results.getDecompiledFunction().getC());
        else p.println("DECOMP_FAILED "+results.getErrorMessage());
        p.println("DECOMP_END "+fun.getEntryPoint());
    }
    private void applyCycleProbe() throws Exception {
        Function release=f(RELEASE);
        require(release!=null && release.getSignatureSource()==SourceType.USER_DEFINED
            && !release.isThunk(), "missing spinlock metadata");
        signature(RELEASE,"VERIFIED_CYCLE_METADATA_BEFORE_SPINLOCK");
        if(fpr(release)==13) {
            require(release.getParameterCount()==15 && fprPrefix(release,13)
                && param(release.getParameter(13),"spinLock","uint *32","r3:4")
                && param(release.getParameter(14),"previousIrql","ulonglong","r4:8")
                && nativeFp(release)==0 && calls(release,IRQL),
                "spinlock native/signature evidence insufficient");
            String returnType=release.getReturnType().getName();
            String returnStorage=release.getReturn().getVariableStorage().toString();
            for(int i=12;i>=0;i--) release.removeParameter(i);
            require(release.getReturnType().getName().equals(returnType)
                && release.getReturn().getVariableStorage().toString().equals(returnStorage),
                "spinlock return changed");
            log("VERIFIED_CYCLE_METADATA_APPLIED spinlock 13 FPR artifacts removed");
        }
        release=f(RELEASE);
        require(fpr(release)==0 && release.getParameterCount()==2
            && param(release.getParameter(0),"spinLock","uint *32","r3:4")
            && param(release.getParameter(1),"previousIrql","ulonglong","r4:8")
            && "undefined".equals(release.getReturnType().getName()),
            "spinlock two-parameter post-v4 signature differs");
        signature(RELEASE,"VERIFIED_CYCLE_METADATA_AFTER_SPINLOCK");
        // The v4 result establishes these two Parameter ID outcomes.
        // Repair if needed, otherwise leave already recovered metadata intact.
        for(long address:new long[]{APC,IRQL}) {
            Function fun=f(address);
            require(fun!=null && fun.getSignatureSource()==SourceType.ANALYSIS,
                "unexpected APC/IRQL signature source");
            signature(address,"VERIFIED_CYCLE_METADATA_BEFORE");
            if(fpr(fun)==13) applyParamId(address);
            fun=f(address);
            if(address==APC)
                require(fpr(fun)==0 && fun.getParameterCount()==0
                    && "undefined".equals(fun.getReturnType().getName()),
                    "APC signature not recovered as v4");
            else
                require(fpr(fun)==0 && fun.getParameterCount()==2
                    && param(fun.getParameter(0),"requestedIrql","ulonglong","r3:8")
                    && param(fun.getParameter(1),"pendingLevelsWord","ulonglong","r4:8")
                    && "undefined".equals(fun.getReturnType().getName()),
                    "IRQL signature not recovered as v4");
            signature(address,"VERIFIED_CYCLE_METADATA_AFTER");
        }
    }

    private void auditSuspectTree(long root, int maxDepth) throws Exception {
        // Report-only search: inspect the remaining callee paths without
        // removing ambiguous FPR parameters from any other function.
        Queue<long[]> q=new ArrayDeque<>();
        Set<Long> visited=new LinkedHashSet<>();
        q.add(new long[]{root,0});
        while(!q.isEmpty() && visited.size()<96) {
            monitor.checkCancelled();
            long[] next=q.remove();
            long address=next[0];
            int depth=(int)next[1];
            if(!visited.add(address)) continue;
            Function fun=f(address);
            if(fun==null) {
                log("SUSPECT_NO_FUNCTION address="+Long.toHexString(address));
                continue;
            }
            log("SUSPECT_NODE depth="+depth+" address="+Long.toHexString(address)+
                " nativeFp="+nativeFp(fun)+" "+describe(fun));
            if(depth>=maxDepth)continue;
            InstructionIterator it=currentProgram.getListing()
                .getInstructions(fun.getBody(),true);
            while(it.hasNext()) {
                monitor.checkCancelled();
                Instruction ins=it.next();
                if(!ins.getFlowType().isCall())continue;
                Address[] dests=ins.getFlows();
                if(dests.length==0) log("SUSPECT_INDIRECT_CALL from="+fun.getEntryPoint()+
                    " site="+ins.getAddress()+" opcode="+ins);
                for(Address dest:dests) {
                    Function callee=currentProgram.getFunctionManager().getFunctionAt(dest);
                    int ghosts=fpr(callee);
                    log("SUSPECT_EDGE depth="+depth+" caller="+fun.getEntryPoint()+
                        " site="+ins.getAddress()+" target="+dest+
                        " callee="+(callee==null?"UNRESOLVED":callee.getName())+
                        " phantomFprs="+ghosts);
                    if(callee!=null && ghosts>0)
                        q.add(new long[]{callee.getEntryPoint().getOffset(),depth+1});
                }
            }
        }
        log("SUSPECT_TREE_SUMMARY root="+Long.toHexString(root)+
            " visited="+visited.size()+" limit=96");
    }

    private void probeCleanObjectCloseBranch() throws Exception {
        // v5 showed this caller is the first leaf with no contaminated
        // direct callees. We test regular Parameter ID first, without
        // manually editing its signature.
        Function leaf=f(CLOSE_LEAF), helper=f(CLOSE_HELPER), close=f(NTCLOSE);
        require(leaf!=null && helper!=null && close!=null,
            "object close branch functions are missing");
        require(calls(helper,CLOSE_LEAF) && calls(close,CLOSE_HELPER)
            && calls(close,OBJECT_PROBE), "object close path differs");
        for(long a:new long[]{CLOSE_LEAF,CLOSE_HELPER,NTCLOSE})
            signature(a,"OBJECT_CLOSE_BEFORE");
        require("undefined".equals(leaf.getReturnType().getName())
            && "undefined".equals(helper.getReturnType().getName())
            && "undefined8".equals(close.getReturnType().getName()),
            "object close return-type baseline changed");
        require(nativeFp(leaf)==0 && nativeFp(helper)==0
            && nativeFp(close)==0,"native FP instruction unexpectedly present");
        require(leaf.getSignatureSource()==SourceType.ANALYSIS
            && fpr(leaf)==13 && leaf.getParameterCount()==15
            && fprPrefix(leaf,13)
            && param(leaf.getParameter(13),"param_14","longlong","r3:8")
            && param(leaf.getParameter(14),"param_15","ulonglong","r4:8"),
            "leaf parameters differ from v5");
        require(helper.getSignatureSource()==SourceType.ANALYSIS
            && fpr(helper)==13 && helper.getParameterCount()==15
            && fprPrefix(helper,13)
            && param(helper.getParameter(13),"param_14","longlong","r3:8")
            && param(helper.getParameter(14),"param_15","ulonglong","r4:8"),
            "helper parameters differ from v5");
        // No indirect calls or still-contaminated callees at the leaf.
        int outgoing=0;
        InstructionIterator it=currentProgram.getListing()
            .getInstructions(leaf.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction op=it.next();
            if(!op.getFlowType().isCall()) continue;
            Address[] destinations=op.getFlows();
            require(destinations.length>0,"leaf has unresolved indirect call");
            for(Address a:destinations) {
                outgoing++;
                Function callee=currentProgram.getFunctionManager().getFunctionAt(a);
                require(callee!=null && fpr(callee)==0,
                    "leaf has unexpected contaminated direct callee "+a);
            }
        }
        log("CLEAN_LEAF_GUARD passed directCalls="+outgoing);
        applyParamId(CLOSE_LEAF);
        leaf=f(CLOSE_LEAF);
        signature(CLOSE_LEAF,"OBJECT_CLOSE_LEAF_AFTER");
        if (fpr(leaf)!=0 || leaf.getParameterCount()!=2) {
            log("STOP_OBJECT_CLOSE_CHAIN leaf Parameter ID did not recover two GP args");
            return;
        }
        require("undefined".equals(leaf.getReturnType().getName())
            && "longlong".equals(leaf.getParameter(0).getDataType().getName())
            && "r3:8".equals(leaf.getParameter(0).getVariableStorage().toString())
            && "ulonglong".equals(leaf.getParameter(1).getDataType().getName())
            && "r4:8".equals(leaf.getParameter(1).getVariableStorage().toString()),
            "leaf GP parameters/return changed unexpectedly");
        applyParamId(CLOSE_HELPER);
        helper=f(CLOSE_HELPER);
        signature(CLOSE_HELPER,"OBJECT_CLOSE_HELPER_AFTER");
        if(fpr(helper)!=0 || helper.getParameterCount()!=2) {
            log("STOP_OBJECT_CLOSE_CHAIN helper still contains phantom FPRs;"
                +" check bctrl call and p-code before further mutations");
            return;
        }
        require("undefined".equals(helper.getReturnType().getName())
            && "longlong".equals(helper.getParameter(0).getDataType().getName())
            && "r3:8".equals(helper.getParameter(0).getVariableStorage().toString())
            && "ulonglong".equals(helper.getParameter(1).getDataType().getName())
            && "r4:8".equals(helper.getParameter(1).getVariableStorage().toString()),
            "helper GP parameters/return changed unexpectedly");
        // NtClose still calls KeGetCurrentProcessType through OBJECT_PROBE.
        // Measure re-inference; do not require a cleaned signature yet.
        applyParamId(NTCLOSE);
        signature(NTCLOSE,"OBJECT_CLOSE_NTCLOSE_AFTER");
    }

    private void auditRemainingProcessBranch() throws Exception {
        Function proc=f(PROCESS_TYPE), bug=f(BUGCHECK), entry=f(OBJECT_PROBE);
        require(proc!=null && bug!=null && entry!=null
            && calls(entry,PROCESS_TYPE) && calls(proc,BUGCHECK),
            "v5 process/bugcheck path differs");
        for(long addr:new long[]{OBJECT_PROBE,PROCESS_TYPE,BUGCHECK}) {
            Function fun=f(addr);
            signature(addr,"PROCESS_BRANCH_BASELINE");
            log("PROCESS_BRANCH_FP_COUNT "+Long.toHexString(addr)+
                " count="+nativeFp(fun));
            printCallees(addr);
        }
        // No changes to USER_DEFINED KeGetCurrentProcessType.
        // KeBugCheckEx has real integer parameters and several complicated
        // callees. Unconditional removal of all f1..f13 is not justified.
        log("PROCESS_BRANCH_READ_ONLY KeGetCurrentProcessType preserves USER_DEFINED"
            +" byte return and its current signature; bugcheck signature"
            +" preserved pending independent inference");
    }
    @Override protected void run() throws Exception {
        if(currentProgram.getDomainFile()==null ||
            !currentProgram.getDomainFile().getName()
                .toUpperCase(Locale.ROOT).contains("FPR_SANDBOX")) {
            println("REFUSE_PRODUCTION: disposable FPR_SANDBOX copy only");
            return;
        }
        if(!EXE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())
            || !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE_IMAGE: unexpected kernel executable/language");
            return;
        }
        File dl=new File(System.getProperty("user.home"),"Downloads");
        File dir=dl.isDirectory()?dl:new File(System.getProperty("java.io.tmpdir"));
        File report=File.createTempFile("XenonFprObjectCloseSandbox_20261017_v6_",".txt",dir);
        try(PrintWriter writer=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(report),StandardCharsets.UTF_8))) {
            output=writer;
            log("SANDBOX_METADATA_AND_APC_CYCLE program="+currentProgram.getName());
            Map<Address,String> protectedBefore=protectedSignatures();
            applyVerifiedMetadata();
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                signature(target,"SCC_BEFORE");
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                printCallees(target);
            // First confirm that the APC/IRQL/spinlock structure is real.
            require(f(APC)!=null && calls(f(IRQL),APC)
                && calls(f(APC),RELEASE) && calls(f(RELEASE),IRQL),
                "expected IRQL -> APC -> spinlock -> IRQL cycle missing");
            applyCycleProbe();
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE,OBJECT_PROBE,CLOSE_HELPER})
                printCallees(target);
            probeCleanObjectCloseBranch();
            auditRemainingProcessBranch();
            DecompInterface di=new DecompInterface();
            try{
                require(di.openProgram(currentProgram),"decompiler open failed");
                for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE,OBJECT_PROBE,CLOSE_HELPER,CLOSE_LEAF,PROCESS_TYPE,BUGCHECK})
                    decompile(writer,di,target);
            } finally { di.dispose(); }
            int protectedChanged=0;
            for(Map.Entry<Address,String> entry:protectedBefore.entrySet()) {
                Address address=entry.getKey();
                if(address.equals(at(RELEASE))) continue; // explicit sandbox probe
                Function fun=currentProgram.getFunctionManager().getFunctionAt(address);
                if(fun==null || !entry.getValue().equals(describe(fun))) {
                    // SAVER is only USER_DEFINED before the probe if v2 was run.
                    protectedChanged++;
                    log("PROTECTED_SIGNATURE_CHANGED "+address);
                }
            }
            log("PROTECTED_SIGNATURES_UNCHANGED otherThanTest="+
                (protectedBefore.size()-(protectedBefore.containsKey(at(RELEASE))?1:0))+
                " unexpectedChanges="+protectedChanged);
            require(protectedChanged==0,"unrelated pre-existing USER_DEFINED signature changed");
            log("DONE SANDBOX_ONLY eight verified signatures applied/checked; "+
                "object close branch Parameter ID tested; process branch audit-only; report="+
                report.getAbsolutePath());
        } finally { output=null; }
        println("REPORT "+report.getAbsolutePath());
    }
}
