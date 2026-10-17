package xexloaderwv;

import java.util.HashSet;
import java.util.Set;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Cross-program XEX signature sync after Ghidra has associated imported modules.
 *
 * Ghidra external-program linking provides navigation, not automatic function
 * signature import. This analyzer only copies complete USER_DEFINED signatures
 * from a uniquely identified linked function into an untouched default external.
 * It does not use firmware versions, hardcoded ordinal maps, or guessed ABIs.
 *
 * To revisit XEX programs linked AFTER initial analysis, run this analyzer as a
 * one-shot analysis pass; normal import cannot see those future associations.
 */
public class XexLinkedImportSignatureAnalyzer extends AbstractAnalyzer {
    public XexLinkedImportSignatureAnalyzer() {
        super("XEX: Sync verified linked import signatures",
            "Propagate complete user-defined signatures from uniquely resolved linked " +
            "XEX dependencies; do not overwrite edited imports or import opaque registers.",
            AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "XEX Loader by Warranty Voider".equals(program.getExecutableFormat()) &&
            program.getDomainFile() != null &&
            program.getDomainFile().getParent() != null;
    }

    private static boolean compatible(Program importing, Program provider) {
        return importing.getLanguageID().equals(provider.getLanguageID()) &&
            importing.getCompilerSpec().getCompilerSpecID()
                .equals(provider.getCompilerSpec().getCompilerSpecID()) &&
            importing.getDefaultPointerSize() == provider.getDefaultPointerSize();
    }

    // A conservative portability check. Complex types must ALREADY exist in
    // the importing program with an equivalent definition, so linking cannot
    // silently install conflicting structures or typedefs.
    private static boolean portable(DataType type, DataTypeManager target, Set<DataType> seen) {
        if (type == null || !seen.add(type)) return type != null;
        String name = type.getName();
        if (name.startsWith("undefined") || "pointer".equals(name) ||
            "default".equals(name)) return false;
        if (type instanceof Pointer) {
            DataType base = ((Pointer) type).getDataType();
            return base != null && portable(base, target, seen);
        }
        if (type instanceof Array) {
            return portable(((Array) type).getDataType(), target, seen);
        }
        if (type instanceof TypeDef || type instanceof Composite ||
            type instanceof ghidra.program.model.data.Enum) {
            DataType local = target.getDataType(type.getCategoryPath(), type.getName());
            return local != null && local.isEquivalent(type);
        }
        return true;
    }

    private static boolean complete(Function f, DataTypeManager target) {
        if (f.getSignatureSource() != SourceType.USER_DEFINED ||
            f.hasCustomVariableStorage()) return false;
        FunctionSignature signature = f.getSignature(true);
        if (!portable(signature.getReturnType(), target, new HashSet<>())) return false;
        for (ParameterDefinition arg : signature.getArguments()) {
            if (!portable(arg.getDataType(), target, new HashSet<>())) return false;
        }
        return true;
    }

    private static boolean untouchedExternal(Function f) {
        return f != null && f.getParameterCount() == 0 &&
            !f.hasCustomVariableStorage() &&
            f.getReturnType().getName().startsWith("undefined") &&
            f.getSignatureSource() != SourceType.USER_DEFINED;
    }

    private static Function matchingFunction(Program provider, ExternalLocation importLocation) {
        String name = importLocation.getLabel();
        Address linkedAddress = importLocation.getAddress();
        if (linkedAddress != null) {
            if (!linkedAddress.isMemoryAddress()) return null;
            Function byAddress = provider.getFunctionManager().getFunctionAt(linkedAddress);
            return byAddress != null && name.equals(byAddress.getName()) ? byAddress : null;
        }
        Function match = null;
        SymbolIterator symbols = provider.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.getAddress().isMemoryAddress()) continue;
            Function candidate = provider.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (candidate == null || !name.equals(candidate.getName())) continue;
            if (match != null && !match.getEntryPoint().equals(candidate.getEntryPoint()))
                return null; // namespace collision: never guess
            match = candidate;
        }
        return match;
    }

    @Override
    public boolean added(Program importing, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        ProjectData projectData = importing.getDomainFile().getParent().getProjectData();
        ExternalManager externalManager = importing.getExternalManager();
        int applied = 0, skipped = 0, missing = 0, libraries = 0;
        for (String library : externalManager.getExternalLibraryNames()) {
            monitor.checkCancelled();
            String path = externalManager.getExternalLibraryPath(library);
            if (path == null || path.isBlank()) continue;
            DomainFile providerFile = projectData.getFile(path);
            if (providerFile == null ||
                providerFile.equals(importing.getDomainFile())) continue;
            Program provider = null;
            try {
                Object opened = providerFile.getReadOnlyDomainObject(this, -1, monitor);
                if (!(opened instanceof Program)) {
                    if (opened != null) ((ghidra.framework.model.DomainObject) opened).release(this);
                    continue;
                }
                provider = (Program) opened;
                if (!compatible(importing, provider)) {
                    log.appendMsg("XEX signature sync: incompatible linked library " + library);
                    continue;
                }
                libraries++;
                ExternalLocationIterator locations =
                    externalManager.getExternalLocations(library);
                while (locations.hasNext()) {
                    monitor.checkCancelled();
                    ExternalLocation location = locations.next();
                    if (!location.isFunction()) continue;
                    Function imported = location.getFunction();
                    if (!untouchedExternal(imported)) {
                        skipped++;
                        continue;
                    }
                    Function source = matchingFunction(provider, location);
                    if (source == null) {
                        missing++;
                        continue;
                    }
                    if (!complete(source, importing.getDataTypeManager())) {
                        skipped++;
                        continue;
                    }
                    // This command preserves the imported symbol name and
                    // its existing calling convention; foreign types are
                    // resolved against the importing program's manager.
                    ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(
                        imported.getEntryPoint(), source.getSignature(true),
                        SourceType.IMPORTED, true, false,
                        DataTypeConflictHandler.KEEP_HANDLER,
                        FunctionRenameOption.NO_CHANGE);
                    if (command.applyTo(importing, monitor)) {
                        applied++;
                    }
                    else {
                        skipped++;
                        log.appendMsg("XEX signature sync refused " + library +
                            "::" + location.getLabel() + " " + command.getStatusMsg());
                    }
                }
            }
            catch (CancelledException cancelled) {
                throw cancelled;
            }
            catch (Exception failure) {
                log.appendMsg("XEX signature sync skipped " + library +
                    ": " + failure.getMessage());
            }
            finally {
                if (provider != null) provider.release(this);
            }
        }
        log.appendMsg("XEX linked-signature sync: linkedLibraries=" + libraries +
            " applied=" + applied + " skipped=" + skipped +
            " unmatched=" + missing +
            " (complete USER_DEFINED signatures only; no native bytes changed)");
        return true;
    }
}
