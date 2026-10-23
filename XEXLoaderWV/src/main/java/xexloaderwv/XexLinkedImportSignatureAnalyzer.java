package xexloaderwv;

import java.util.HashSet;
import java.util.LinkedHashSet;
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
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Parameter;
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
 * Missing dependencies are copied from the linked provider only if no conflicting
 * type exists, and each signature + datatype installation is transactional.
 * Also synchronizes a missing calling convention on an already typed external
 * when its source's return/parameter types, varargs, and parameter storage
 * exactly match; the linked provider may have an IMPORTED prototype.
 * It does not use firmware versions, hardcoded ordinal maps, or guessed ABIs.
 *
 * To revisit XEX programs linked AFTER initial analysis, run this analyzer as a
 * one-shot analysis pass; normal import cannot see those future associations.
 */
public class XexLinkedImportSignatureAnalyzer extends AbstractAnalyzer {
    public XexLinkedImportSignatureAnalyzer() {
        super("XEX: Sync linked import signatures",
            "Propagate complete user-defined signatures from uniquely resolved linked " +
            "XEX dependencies and reconcile known calling conventions on matching " +
            "import prototypes; do not overwrite edited signatures or infer registers.",
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

    // Validate every type before changing the importing Program. Collect
    // missing dependency definitions in dependency-first order. Never accept
    // unresolved signature types, incompatible existing types, or a hidden
    // nested conflict inside a provider composite.
    private static boolean portable(DataType type, DataTypeManager target,
            Set<DataType> seen, Set<DataType> missing) {
        if (type == null) return false;
        if (!seen.add(type)) return true;
        String name = type.getName();
        if (name.startsWith("undefined") || "pointer".equals(name) ||
            "default".equals(name)) return false;
        if (type instanceof Pointer) {
            DataType base = ((Pointer) type).getDataType();
            return base != null && portable(base, target, seen, missing);
        }
        if (type instanceof Array) {
            return portable(((Array) type).getDataType(), target, seen, missing);
        }
        if (type instanceof TypeDef) {
            if (!portable(((TypeDef) type).getBaseDataType(), target, seen, missing))
                return false;
        }
        if (type instanceof Composite) {
            for (DataTypeComponent component : ((Composite) type).getDefinedComponents()) {
                DataType member = component.getDataType();
                // Existing provider structure padding/unknown fields are
                // preserved exactly; their presence does not imply that an
                // unknown FUNCTION parameter can be propagated.
                if (member == null || member.getName().startsWith("undefined") ||
                    "default".equals(member.getName())) continue;
                if (!portable(member, target, seen, missing)) return false;
            }
        }
        if (type instanceof TypeDef || type instanceof Composite ||
            type instanceof ghidra.program.model.data.Enum) {
            DataType local = target.getDataType(type.getCategoryPath(), type.getName());
            if (local != null) return local.isEquivalent(type);
            missing.add(type);
        }
        return true;
    }

    private static boolean complete(Function f, DataTypeManager target,
            Set<DataType> missing) {
        if (f.getSignatureSource() != SourceType.USER_DEFINED ||
            f.hasCustomVariableStorage()) return false;
        FunctionSignature signature = f.getSignature(true);
        if (!portable(signature.getReturnType(), target,
                new HashSet<>(), missing)) return false;
        for (ParameterDefinition arg : signature.getArguments()) {
            if (!portable(arg.getDataType(), target,
                    new HashSet<>(), missing)) return false;
        }
        return true;
    }

    private static int installDependencies(Set<DataType> missing,
            DataTypeManager target) throws Exception {
        int installed = 0;
        for (DataType source : missing) {
            // Preflight was before any mutations. Recheck here in case
            // Ghidra installed a dependency recursively during an earlier add.
            DataType existing = target.getDataType(
                source.getCategoryPath(), source.getName());
            if (existing != null) {
                if (!existing.isEquivalent(source))
                    throw new IllegalStateException(
                        "Conflicting imported datatype " + source.getPathName());
                continue;
            }
            DataType copy = target.addDataType(
                source, DataTypeConflictHandler.KEEP_HANDLER);
            if (copy == null || !copy.isEquivalent(source))
                throw new IllegalStateException(
                    "Failed to import equivalent datatype " + source.getPathName());
            installed++;
        }
        return installed;
    }

    private static boolean untouchedExternal(Function f) {
        return f != null && f.getParameterCount() == 0 &&
            !f.hasCustomVariableStorage() &&
            f.getReturnType().getName().startsWith("undefined") &&
            f.getSignatureSource() != SourceType.USER_DEFINED;
    }

    // Imported CRT declarations can already have a fully matching prototype
    // yet retain Ghidra's unknown calling convention. Both Programs use the
    // SAME ABI (checked by compatible()), so this metadata belongs to the
    // imported external too. Never replace an existing known convention or
    // any USER_DEFINED consumer declaration.
    private static boolean needsCallingConvention(Function imported) {
        return imported != null &&
            imported.getParameterCount() > 0 &&
            !imported.hasCustomVariableStorage() &&
            imported.getSignatureSource() != SourceType.USER_DEFINED &&
            "unknown".equals(imported.getCallingConventionName());
    }

    private static boolean equivalentApartFromConvention(
            Function imported, Function source) {
        if (source == null || source.hasCustomVariableStorage() ||
            (source.getSignatureSource() != SourceType.USER_DEFINED &&
             source.getSignatureSource() != SourceType.IMPORTED))
            return false;
        String convention = source.getCallingConventionName();
        if (convention == null || convention.isBlank() ||
            "unknown".equals(convention)) return false;
        if (imported.getParameterCount() != source.getParameterCount() ||
            imported.hasVarArgs() != source.hasVarArgs() ||
            !imported.getReturnType().isEquivalent(source.getReturnType()))
            return false;
        if (imported.getReturnType().getName().startsWith("undefined"))
            return false;
        for (int i = 0; i < imported.getParameterCount(); i++) {
            Parameter a = imported.getParameter(i);
            Parameter b = source.getParameter(i);
            if (!a.getDataType().isEquivalent(b.getDataType()) ||
                a.getDataType().getName().startsWith("undefined") ||
                !a.getVariableStorage().equals(b.getVariableStorage()))
                return false;
        }
        return true;
    }

    private static boolean sameContract(Function imported, Function source,
            String expectedConvention) {
        if (!expectedConvention.equals(imported.getCallingConventionName()) ||
            imported.getParameterCount() != source.getParameterCount() ||
            imported.hasVarArgs() != source.hasVarArgs() ||
            !imported.getReturnType().isEquivalent(source.getReturnType()))
            return false;
        for (int i = 0; i < imported.getParameterCount(); i++) {
            if (!imported.getParameter(i).getDataType().isEquivalent(
                    source.getParameter(i).getDataType()) ||
                !imported.getParameter(i).getVariableStorage().equals(
                    source.getParameter(i).getVariableStorage()))
                return false;
        }
        return true;
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
        int typesInstalled = 0, failed = 0, conventionsFixed = 0;
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
                        if (needsCallingConvention(imported)) {
                            Function conventionSource = matchingFunction(provider, location);
                            if (equivalentApartFromConvention(imported, conventionSource) &&
                                importing.getCompilerSpec().getCallingConvention(
                                    conventionSource.getCallingConventionName()) != null) {
                                int transaction = importing.startTransaction(
                                    "XEX linked calling convention: " + library +
                                    "::" + location.getLabel());
                                boolean committed = false;
                                try {
                                    String convention = conventionSource.getCallingConventionName();
                                    imported.setCallingConvention(convention);
                                    if (!sameContract(imported, conventionSource, convention))
                                        throw new IllegalStateException(
                                            "Calling convention changed existing parameter ABI");
                                    committed = true;
                                    conventionsFixed++;
                                }
                                catch (Exception failure) {
                                    failed++;
                                    log.appendMsg("XEX convention sync refused " + library +
                                        "::" + location.getLabel() + ": " + failure.getMessage());
                                }
                                finally {
                                    importing.endTransaction(transaction, committed);
                                }
                                if (committed) continue;
                            }
                        }
                        skipped++;
                        continue;
                    }
                    Function source = matchingFunction(provider, location);
                    if (source == null) {
                        missing++;
                        continue;
                    }
                    Set<DataType> required = new LinkedHashSet<>();
                    if (!complete(source, importing.getDataTypeManager(), required)) {
                        skipped++;
                        continue;
                    }
                    // The XEX image is untouched. Type dependencies and the
                    // external signature form a single atomic metadata update:
                    // a failed signature application must not leave orphaned
                    // types behind in the importing Program.
                    int transaction = importing.startTransaction(
                        "XEX linked signature: " + library + "::" + location.getLabel());
                    boolean committed = false;
                    try {
                        int addedTypes = installDependencies(required,
                            importing.getDataTypeManager());
                        // No ordinal/name rewriting. Foreign signature types
                        // resolve against the consumer's now-complete type set.
                        ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(
                            imported.getEntryPoint(), source.getSignature(true),
                            SourceType.IMPORTED, true, false,
                            DataTypeConflictHandler.KEEP_HANDLER,
                            FunctionRenameOption.NO_CHANGE);
                        if (command.applyTo(importing, monitor)) {
                            committed = true;
                            applied++;
                            typesInstalled += addedTypes;
                        }
                        else {
                            skipped++;
                            failed++;
                            log.appendMsg("XEX signature sync refused " + library +
                                "::" + location.getLabel() + " " + command.getStatusMsg());
                        }
                    }
                    catch (CancelledException cancelled) {
                        throw cancelled;
                    }
                    catch (Exception failure) {
                        skipped++;
                        failed++;
                        log.appendMsg("XEX signature sync refused " + library +
                            "::" + location.getLabel() + ": " + failure.getMessage());
                    }
                    finally {
                        importing.endTransaction(transaction, committed);
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
            " unmatched=" + missing + " typesInstalled=" + typesInstalled +
            " conventionsFixed=" + conventionsFixed + " failed=" + failed +
            " (complete USER_DEFINED signatures and equivalent ABI conventions;"
            + " no native bytes changed)");
        return true;
    }
}
