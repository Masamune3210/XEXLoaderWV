// Find implicit floating-point machine-state usage feeding spurious ABI args.
// Read-only, architecture-generic to Xenon executable image: no address whitelist,
// no function names or explicit ABI corrections. Uses current saved Program metadata.
//@category Xbox360.Analysis
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class AuditXenonFprContextPropagation_20261017_v2 extends GhidraScript {
    private static final Pattern FP_PARAM = Pattern.compile("f(?:[1-9]|1[0-3]):8");
    private static final Pattern FP_REG = Pattern.compile("f(?:[0-9]|[12][0-9]|3[01])");
    private static class Node {
        final Function function;
        final Address address;
        final Set<String> storedFp = new HashSet<>();
        int fpFormal, instructions, directNativeFp;
        boolean root;
        Node(Function f) {function=f;address=f.getEntryPoint();}
        String name() {return function.getName();}
        String signatureSource() {return function.getSignatureSource().toString();}
    }
    private static boolean nativeFpInstruction(String mnemonic) {
        if (mnemonic == null) return false;
        String s=mnemonic.toLowerCase(java.util.Locale.ROOT);
        return s.startsWith("f") || s.startsWith("lfd") || s.startsWith("lfs") ||
            s.startsWith("stfd") || s.startsWith("stfs") || s.startsWith("ps_");
    }
    private static String cell(String s) {
        return s.replace('\t',' ').replace('\n',' ').replace('\r',' ');
    }
    private Map<Address,List<Address>> reverseCalls(Map<Address,Node> nodes)
            throws ghidra.util.exception.CancelledException {
        Map<Address,List<Address>> result = new HashMap<>();
        ReferenceManager manager=currentProgram.getReferenceManager();
        for (Node dest:nodes.values()) {
            monitor.checkCancelled();
            ReferenceIterator refs=manager.getReferencesTo(dest.address);
            while (refs.hasNext()) {
                Reference r=refs.next();
                if (!r.getReferenceType().isFlow()) continue;
                Function owner=currentProgram.getFunctionManager().getFunctionContaining(
                    r.getFromAddress());
                if (owner==null || owner.getEntryPoint().equals(dest.address)) continue;
                if (nodes.containsKey(owner.getEntryPoint()))
                    result.computeIfAbsent(dest.address,k->new ArrayList<>())
                        .add(owner.getEntryPoint());
            }
        }
        return result;
    }
    @Override public void run() throws Exception {
        if (!currentProgram.getLanguageID().getIdAsString()
                .equals("PowerPC:BE:64:XENON-32addr")) {
            throw new IllegalStateException("Expected the Xenon PowerPC language");
        }
        Map<Address,Node> nodes=new LinkedHashMap<>();
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f=it.next();
            if (f.isExternal() || f.isThunk() || f.getBody().isEmpty()) continue;
            Node n=new Node(f);
            for (Parameter p:f.getParameters()) {
                String storage=p.getVariableStorage().toString();
                if (FP_PARAM.matcher(storage).matches() &&
                    p.getDataType().getName().startsWith("undefined")) n.fpFormal++;
            }
            InstructionIterator instr=currentProgram.getListing().getInstructions(f.getBody(),true);
            while (instr.hasNext()) {
                Instruction op=instr.next();
                n.instructions++;
                String mnemonic=op.getMnemonicString();
                if (nativeFpInstruction(mnemonic)) n.directNativeFp++;
                if ("stfd".equalsIgnoreCase(mnemonic)) {
                    String operand=op.getDefaultOperandRepresentation(0);
                    if (FP_REG.matcher(operand.trim()).matches())
                        n.storedFp.add(operand.trim());
                }
            }
            // Capturing nearly all FPRs is a strong machine-state-save
            // signature, not proof that the input FPRs are ABI arguments.
            n.root=n.storedFp.size()>=28;
            nodes.put(n.address,n);
        }
        Map<Address,List<Address>> reverse=reverseCalls(nodes);
        Map<Address,Integer> distance=new HashMap<>();
        Map<Address,Address> next=new HashMap<>();
        ArrayDeque<Address> q=new ArrayDeque<>();
        for (Node n:nodes.values()) if(n.root) {
            distance.put(n.address,0);
            q.add(n.address);
        }
        while(!q.isEmpty()) {
            monitor.checkCancelled();
            Address callee=q.removeFirst();
            for(Address caller:reverse.getOrDefault(callee,Collections.emptyList())) {
                if(distance.containsKey(caller))continue;
                distance.put(caller,distance.get(callee)+1);
                next.put(caller,callee);
                q.addLast(caller);
            }
        }
        int[][] matrix=new int[2][2];
        int directZero=0, all13=0;
        for(Node n:nodes.values()){
            boolean reaches=distance.containsKey(n.address);
            boolean has13=n.fpFormal==13;
            matrix[reaches?1:0][has13?1:0]++;
            if(has13){all13++;if(n.directNativeFp==0)directZero++;}
        }
        println("XENON_FPR_CONTEXT_AUDIT READ_ONLY program="+currentProgram.getName()+
            " executableSHA256="+currentProgram.getExecutableSHA256());
        println("FUNCTIONS="+nodes.size()+" roots="+
            nodes.values().stream().filter(n->n.root).count()+
            " FPR13="+all13+" FPR13_WITH_NO_NATIVE_FP="+directZero);
        println("MATRIX reachable_13="+matrix[1][1]+" reachable_not13="+matrix[1][0]+
            " unreachable_13="+matrix[0][1]+
            " unreachable_not13="+matrix[0][0]);
        for(Node n:nodes.values())if(n.root)
            println("FPR_CONTEXT_ROOT "+n.address+" "+n.name()+
                " fpStored="+n.storedFp.size()+" nativeInstructions="+n.instructions+
                " formalFprSlots="+n.fpFormal);
        Node sample=nodes.get(currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(0x80089eb0L));
        if(sample!=null && distance.containsKey(sample.address)) {
            StringBuilder route=new StringBuilder("EXAMPLE_PATH ");
            Address cursor=sample.address;
            Set<Address> seen=new HashSet<>();
            while(cursor!=null && seen.add(cursor)) {
                Node n=nodes.get(cursor);
                if(n==null)break;
                if(route.length()>13)route.append(" -> ");
                route.append(n.name()).append("@").append(cursor);
                cursor=next.get(cursor);
            }
            println(route.toString());
        }
        File downloads=new File(System.getProperty("user.home"),"Downloads");
        File dir=downloads.isDirectory()?downloads:
            new File(System.getProperty("java.io.tmpdir"));
        File out=File.createTempFile("XenonFprContextAudit_",".tsv",dir);
        try(PrintWriter p=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(out),StandardCharsets.UTF_8))) {
            p.println("address\tname\tformal_undefined_fpr_slots\tfp_native_instructions"+
                "\tunique_stored_fp_registers\tcontext_save_candidate"+
                "\tcan_reach_context_saver\tminimum_calls_to_saver\tsignature_source");
            for(Node n:nodes.values()) {
                p.println(n.address+"\t"+cell(n.name())+"\t"+n.fpFormal+"\t"+
                    n.directNativeFp+"\t"+n.storedFp.size()+"\t"+n.root+"\t"+
                    distance.containsKey(n.address)+"\t"+
                    distance.getOrDefault(n.address,-1)+"\t"+
                    n.signatureSource());
            }
        }
        println("REPORT "+out.getAbsolutePath());
        println("DONE no changes to Program bytes, signatures, types or bookmarks");
    }
}
