// Read-only diagnostic for XEX: Sync linked import signatures.
// @category Xbox360.XEX
// Run on the newly imported 1888 dash.xex Program. Does not change metadata
// or bytes and does not require rebuilding the XEXLoaderWV extension.
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

public class AuditXex1888LinkedSignatureSync_20261030_v1 extends GhidraScript {
    private final Map<String, Integer> counts = new TreeMap<>();
    private static final String OUTPUT_FOLDER = "G:\\Users\\Johnny\\Downloads\\3";

    private void count(String name) {
        counts.merge(name, 1, Integer::sum);
    }

    private static boolean compatible(Program a, Program b) {
        return a.getLanguageID().equals(b.getLanguageID())
            && a.getCompilerSpec().getCompilerSpecID().equals(
                b.getCompilerSpec().getCompilerSpecID())
            && a.getDefaultPointerSize() == b.getDefaultPointerSize();
    }

    private static boolean untouched(Function f) {
        return f != null && f.getParameterCount() == 0
            && !f.hasCustomVariableStorage()
            && f.getReturnType().getName().startsWith("undefined")
            && f.getSignatureSource() != SourceType.USER_DEFINED;
    }

    // Duplicate the actual extension analyzer's matching rules. An address
    // mismatch must not silently fall back to a function with the same name.
    private static Function matchingFunction(Program provider, ExternalLocation location) {
        String name = location.getLabel();
        Address address = location.getAddress();
        if (address != null) {
            if (!address.isMemoryAddress()) return null;
            Function source = provider.getFunctionManager().getFunctionAt(address);
            return source != null && name.equals(source.getName()) ? source : null;
        }
        Function match = null;
        SymbolIterator symbols = provider.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (!sym.getAddress().isMemoryAddress()) continue;
            Function candidate = provider.getFunctionManager().getFunctionAt(sym.getAddress());
            if (candidate == null || !name.equals(candidate.getName())) continue;
            if (match != null &&
                    !match.getEntryPoint().equals(candidate.getEntryPoint())) return null;
            match = candidate;
        }
        return match;
    }

    // Same type-confidence rules as XexLinkedImportSignatureAnalyzer. Report
    // the first blocker, including nested datatype conflicts, but do not
    // install anything.
    private static String typeBlocker(DataType type, DataTypeManager target,
            Set<DataType> seen, Set<DataType> missing) {
        if (type == null) return "null datatype";
        if (!seen.add(type)) return null;
        String name = type.getName();
        if (name.startsWith("undefined") || "pointer".equals(name)
                || "default".equals(name)) return "opaque " + type.getPathName();
        if (type instanceof Pointer) {
            DataType base = ((Pointer) type).getDataType();
            return typeBlocker(base, target, seen, missing);
        }
        if (type instanceof ghidra.program.model.data.Array) {
            return typeBlocker(((ghidra.program.model.data.Array) type)
                .getDataType(), target, seen, missing);
        }
        if (type instanceof TypeDef) {
            String problem = typeBlocker(((TypeDef) type).getBaseDataType(),
                target, seen, missing);
            if (problem != null) return problem;
        }
        if (type instanceof Composite) {
            for (DataTypeComponent component : ((Composite) type).getDefinedComponents()) {
                DataType member = component.getDataType();
                if (member == null || member.getName().startsWith("undefined")
                        || "default".equals(member.getName())) continue;
                String problem = typeBlocker(member, target, seen, missing);
                if (problem != null) return problem;
            }
        }
        if (type instanceof TypeDef || type instanceof Composite
                || type instanceof ghidra.program.model.data.Enum) {
            DataType local = target.getDataType(type.getCategoryPath(), type.getName());
            if (local != null && !local.isEquivalent(type)) {
                return "conflicting type " + type.getPathName();
            }
            if (local == null) missing.add(type);
        }
        return null;
    }

    private static String sourceBlocker(Function source, DataTypeManager target,
            Set<DataType> missing) {
        if (source.getSignatureSource() != SourceType.USER_DEFINED)
            return "SOURCE_NOT_USER_DEFINED";
        if (source.hasCustomVariableStorage()) return "SOURCE_CUSTOM_STORAGE";
        FunctionSignature signature = source.getSignature(true);
        String reason = typeBlocker(signature.getReturnType(),
            target, new HashSet<>(), missing);
        if (reason != null) return "SOURCE_RETURN_TYPE: " + reason;
        ParameterDefinition[] args = signature.getArguments();
        for (int i = 0; i < args.length; i++) {
            reason = typeBlocker(args[i].getDataType(),
                target, new HashSet<>(), missing);
            if (reason != null) return "SOURCE_PARAM_" + i + ": " + reason;
        }
        return missing.isEmpty() ? "ELIGIBLE" :
            "ELIGIBLE_WITH_MISSING_TYPES_" + missing.size();
    }

    private static String safe(String value) {
        return value == null ? "(none)" :
            value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private static String funcDetails(Function f) {
        if (f == null) return "(no function)";
        StringBuilder b = new StringBuilder();
        b.append("name=").append(safe(f.getName()))
            .append(" entry=").append(f.getEntryPoint())
            .append(" sigSource=").append(f.getSignatureSource())
            .append(" customStorage=").append(f.hasCustomVariableStorage())
            .append(" return=").append(safe(f.getReturnType().getPathName()))
            .append(" params=").append(f.getParameterCount())
            .append(" conv=").append(safe(f.getCallingConventionName()))
            .append(" noReturn=").append(f.hasNoReturn());
        Parameter[] args = f.getParameters();
        for (int i = 0; i < args.length; i++) {
            Parameter p = args[i];
            b.append(" | p").append(i).append("=")
                .append(safe(p.getName())).append(":")
                .append(safe(p.getDataType().getPathName()))
                .append("@").append(safe(p.getVariableStorage().toString()));
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null || currentProgram.getDomainFile() == null) {
            printerr("Open a saved XEX Program before running this script.");
            return;
        }
        DomainFile consumerFile = currentProgram.getDomainFile();
        if (consumerFile.getParent() == null) {
            printerr("Program has no project folder.");
            return;
        }
        ProjectData projectData = consumerFile.getParent().getProjectData();
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS").format(new Date());
        File dir = new File(OUTPUT_FOLDER);
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Could not create output directory " + dir);
        }
        File output = new File(dir, "Xex1888LinkedSignatureSyncAudit_v1_" +
            timestamp + ".txt");
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            out.println("READ-ONLY XEX LINKED SIGNATURE SYNC AUDIT");
            out.println("consumer=" + consumerFile.getPathname());
            out.println("programName=" + currentProgram.getName());
            out.println("format=" + currentProgram.getExecutableFormat());
            out.println("language=" + currentProgram.getLanguageID());
            out.println("compilerSpec=" + currentProgram.getCompilerSpec().getCompilerSpecID());
            out.println();
            int linked = 0, examined = 0, nonFunctions = 0;
            ExternalManager ext = currentProgram.getExternalManager();
            for (String lib : ext.getExternalLibraryNames()) {
                monitor.checkCancelled();
                String path = ext.getExternalLibraryPath(lib);
                if (path == null || path.isBlank()) continue;
                DomainFile providerFile = projectData.getFile(path);
                if (providerFile == null || providerFile.equals(consumerFile)) {
                    out.println("LIBRARY MISSING: " + lib + " path=" + path);
                    count("LIBRARY_PATH_NOT_RESOLVED");
                    continue;
                }
                Program provider = null;
                try {
                    Object object = providerFile.getReadOnlyDomainObject(this, -1, monitor);
                    if (!(object instanceof Program)) {
                        if (object instanceof ghidra.framework.model.DomainObject) {
                            ((ghidra.framework.model.DomainObject) object).release(this);
                        }
                        out.println("LIBRARY NOT PROGRAM: " + path);
                        continue;
                    }
                    provider = (Program) object;
                    out.println("LIBRARY " + lib + " -> " + path);
                    if (!compatible(currentProgram, provider)) {
                        out.println("  INCOMPATIBLE language/compiler spec/pointer width");
                        count("LIBRARY_ABI_INCOMPATIBLE");
                        continue;
                    }
                    linked++;
                    ExternalLocationIterator locations = ext.getExternalLocations(lib);
                    while (locations.hasNext()) {
                        monitor.checkCancelled();
                        ExternalLocation location = locations.next();
                        if (!location.isFunction()) {
                            nonFunctions++;
                            continue;
                        }
                        examined++;
                        Function consumer = location.getFunction();
                        Function source = matchingFunction(provider, location);
                        String reason;
                        if (consumer == null) {
                            reason = "CONSUMER_FUNCTION_NULL";
                        } else if (!untouched(consumer)) {
                            if (consumer.getSignatureSource() == SourceType.USER_DEFINED) {
                                reason = "CONSUMER_USER_DEFINED";
                            } else {
                                reason = "CONSUMER_ALREADY_TYPED_OR_CUSTOM";
                            }
                        } else if (source == null) {
                            reason = "SOURCE_UNMATCHED";
                        } else {
                            Set<DataType> missing = new LinkedHashSet<>();
                            reason = sourceBlocker(source,
                                currentProgram.getDataTypeManager(), missing);
                        }
                        count(reason);
                        if (source != null && consumer != null &&
                                source.hasNoReturn() && !consumer.hasNoReturn()) {
                            count("NORETURN_PROPAGATION_CANDIDATE");
                        }
                        out.println(reason + "\t" + lib + "::" +
                            safe(location.getLabel()) + "\tlinkedAddress=" +
                            location.getAddress());
                        out.println("  consumer: " + funcDetails(consumer));
                        out.println("  provider: " + funcDetails(source));
                        if (source == null && location.getAddress() != null) {
                            Function at = provider.getFunctionManager()
                                .getFunctionAt(location.getAddress());
                            out.println("  functionAtLinkedAddress: " + funcDetails(at));
                        }
                    }
                } catch (CancelledException cancelled) {
                    throw cancelled;
                } catch (Exception problem) {
                    count("LIBRARY_READ_ERROR");
                    out.println("LIBRARY ERROR " + lib + ": " + problem);
                } finally {
                    if (provider != null) provider.release(this);
                }
            }
            out.println();
            out.println("SUMMARY linkedLibraries=" + linked +
                " examinedFunctionLocations=" + examined +
                " nonFunctionLocations=" + nonFunctions);
            for (Map.Entry<String, Integer> item : counts.entrySet()) {
                out.println("  " + item.getKey() + "=" + item.getValue());
            }
            out.println("No metadata or native bytes changed.");
        }
        println("XEX linked import signature audit: " + output.getAbsolutePath());
    }
}
