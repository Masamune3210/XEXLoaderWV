package xexloaderwv;

import java.util.HashSet;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
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
import ghidra.program.model.data.FunctionDefinition;
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
 * signature import. This analyzer copies complete USER_DEFINED signatures
 * from a uniquely identified linked function into an untouched default external.
 * It independently propagates a linked provider's positive No Return flag, even
 * when its signature is incomplete or the importing function is already typed.
 * All named provider structs/unions, enums, typedefs and function definitions
 * are copied independently of signature eligibility. Existing destination types
 * are never overwritten; incompatible names are reported and left alone.
 * Missing signature-specific dependencies retain their transactional installation.
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
            "Copy linked provider-defined datatypes, propagate complete user-defined " +
            "signatures and positive No Return flags, and reconcile known calling " +
            "conventions without overwriting existing metadata or guessing registers.",
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

    /**
     * Copy all named definitions from the linked provider, not only types
     * referenced by functions eligible for signature propagation. In
     * particular, native XAM and the dashboard often still have opaque
     * function parameters even when their structure definitions are useful.
     *
     * Basic/pointer/array types are reconstructed as dependencies by Ghidra;
     * the named declarations worth preserving independently are composites,
     * typedefs, enums and function-definition datatypes.
     *
     * A single failing or incompatible declaration must not abort the other
     * copies or alter existing destination types. Each attempted addition is
     * isolated in a Program transaction so automatically introduced nested
     * dependencies are rolled back if equivalence cannot be established.
     */
    private static boolean namedProviderType(DataType type) {
        return type instanceof Composite || type instanceof TypeDef ||
            type instanceof ghidra.program.model.data.Enum ||
            type instanceof FunctionDefinition;
    }

    /**
     * Preorder the provider's named datatype graph by dependencies. Cycles
     * (including pointer-to-own-struct and mutually recursive definitions)
     * are visited only once; Ghidra's addDataType resolver handles the
     * deferred portions of such cycles while committing each declaration.
     */
    private static void addDependencyFirst(DataType type, Set<DataType> visited,
            List<DataType> ordered) {
        if (type == null || !visited.add(type)) return;
        if (type instanceof Pointer) {
            addDependencyFirst(((Pointer) type).getDataType(), visited, ordered);
        }
        if (type instanceof Array) {
            addDependencyFirst(((Array) type).getDataType(), visited, ordered);
        }
        if (type instanceof TypeDef) {
            addDependencyFirst(((TypeDef) type).getBaseDataType(), visited, ordered);
        }
        if (type instanceof Composite) {
            for (DataTypeComponent member : ((Composite) type).getDefinedComponents()) {
                addDependencyFirst(member.getDataType(), visited, ordered);
            }
        }
        if (type instanceof FunctionDefinition) {
            FunctionDefinition def = (FunctionDefinition) type;
            addDependencyFirst(def.getReturnType(), visited, ordered);
            for (ParameterDefinition argument : def.getArguments()) {
                addDependencyFirst(argument.getDataType(), visited, ordered);
            }
        }
        if (namedProviderType(type)) {
            ordered.add(type);
        }
    }

    private static final class TypeCopyResults {
        int copied;
        int equivalent;
        int conflicts;
        int failed;
    }

    private static TypeCopyResults copyProviderDatatypes(Program consumer,
            Program provider, String library, MessageLog log,
            TaskMonitor monitor) throws CancelledException {
        DataTypeManager destination = consumer.getDataTypeManager();
        List<DataType> candidates = new ArrayList<>();
        provider.getDataTypeManager().getAllDataTypes(candidates);
        candidates.sort(Comparator.comparing(DataType::getPathName));
        // Dependencies precede users, including across category paths. The
        // built-in resolver still handles cyclic/recursive type graphs.
        List<DataType> dependencyFirst = new ArrayList<>();
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (DataType candidate : candidates) {
            addDependencyFirst(candidate, visited, dependencyFirst);
        }
        TypeCopyResults results = new TypeCopyResults();
        int reportedProblems = 0;

        for (DataType source : dependencyFirst) {
            monitor.checkCancelled();
            DataType existing = destination.getDataType(
                source.getCategoryPath(), source.getName());
            if (existing != null) {
                if (existing.isEquivalent(source)) {
                    results.equivalent++;
                } else {
                    results.conflicts++;
                    if (reportedProblems++ < 20) {
                        log.appendMsg("XEX datatype sync: conflicting existing " +
                            source.getPathName() + " from " + library +
                            "; keeping destination declaration");
                    }
                }
                continue;
            }

            int transaction = consumer.startTransaction(
                "XEX linked datatype: " + library + "::" + source.getPathName());
            boolean committed = false;
            try {
                DataType copy = destination.addDataType(source,
                    DataTypeConflictHandler.KEEP_HANDLER);
                if (copy == null ||
                        !copy.getPathName().equals(source.getPathName()) ||
                        !copy.isEquivalent(source)) {
                    throw new IllegalStateException(
                        "cloned definition or dependencies differ from provider");
                }
                committed = true;
                results.copied++;
            } catch (Exception failure) {
                results.failed++;
                if (reportedProblems++ < 20) {
                    log.appendMsg("XEX datatype sync: refused " +
                        source.getPathName() + " from " + library +
                        ": " + failure.getMessage());
                }
            } finally {
                consumer.endTransaction(transaction, committed);
            }
        }
        log.appendMsg("XEX datatype sync: " + library + " copied=" +
            results.copied + " equivalent=" + results.equivalent +
            " conflicting=" + results.conflicts + " failed=" + results.failed +
            " (all named provider definitions, including unused ones; " +
            "existing types preserved)");
        if (reportedProblems > 20) {
            log.appendMsg("XEX datatype sync: " + library + " has " +
                (reportedProblems - 20) + " additional conflicts/failures " +
                "not shown individually");
        }
        return results;
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
        int typesCloned = 0, typesEquivalent = 0, typesConflicted = 0;
        int typeCloneFailed = 0;
        int noReturnApplied = 0, noReturnFailed = 0;
        // Strict barrier across *all* linked providers:
        // phase 1 clones every available datatype; phase 2 touches function
        // signatures, calling conventions and No Return flags. Do not run
        // the consumer work for library A before provider B's types exist.
        for (int phase = 1; phase <= 2; phase++) {
            log.appendMsg(phase == 1
                ? "XEX signature sync: phase 1/2 cloning all linked provider datatypes"
                : "XEX signature sync: phase 2/2 propagating function metadata");
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
                    if (phase == 1) {
                        libraries++;
                        // Even opaque or custom-storage function prototypes cannot
                        // prevent their provider's independently defined types
                        // from being available to other linked libraries.
                        TypeCopyResults copied = copyProviderDatatypes(
                            importing, provider, library, log, monitor);
                        typesCloned += copied.copied;
                        typesInstalled += copied.copied;
                        typesEquivalent += copied.equivalent;
                        typesConflicted += copied.conflicts;
                        typeCloneFailed += copied.failed;
                        continue;
                    }

                    // No function-dependent action executes until the phase-1
                    // loop has completed across every linked provider.
                    ExternalLocationIterator locations =
                        externalManager.getExternalLocations(library);
                    while (locations.hasNext()) {
                        monitor.checkCancelled();
                        ExternalLocation location = locations.next();
                        if (!location.isFunction()) continue;
                        Function imported = location.getFunction();
                        if (imported == null) {
                            skipped++;
                            continue;
                        }
                        Function source = matchingFunction(provider, location);

                        // External-program linking establishes navigation to the
                        // provider but does not synchronize semantic function flags.
                        // No Return is independent of signature completeness and
                        // must reach the importer even when the provider has
                        // unresolved parameters or the consumer is already typed.
                        // Only propagate a positive flag from an exact, unique
                        // linked provider. Never infer No Return from a function
                        // name or clear a flag already present in the consumer.
                        if (source != null && source.hasNoReturn() &&
                                !imported.hasNoReturn()) {
                            int transaction = importing.startTransaction(
                                "XEX linked No Return: " + library +
                                "::" + location.getLabel());
                            boolean committed = false;
                            try {
                                imported.setNoReturn(true);
                                if (!imported.hasNoReturn()) {
                                    throw new IllegalStateException(
                                        "Imported external did not retain No Return");
                                }
                                committed = true;
                                noReturnApplied++;
                            }
                            catch (Exception failure) {
                                noReturnFailed++;
                                log.appendMsg("XEX No Return sync refused " + library +
                                    "::" + location.getLabel() + ": " + failure.getMessage());
                            }
                            finally {
                                importing.endTransaction(transaction, committed);
                            }
                        }

                        if (!untouchedExternal(imported)) {
                            if (needsCallingConvention(imported)) {
                                Function conventionSource = source;
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
            log.appendMsg("XEX signature sync: phase " + phase + "/2 complete");
        }
        log.appendMsg("XEX linked-signature sync: linkedLibraries=" + libraries +
            " applied=" + applied + " skipped=" + skipped +
            " unmatched=" + missing + " typesInstalled=" + typesInstalled +
            " typesCloned=" + typesCloned +
            " typesEquivalent=" + typesEquivalent +
            " typesConflicted=" + typesConflicted +
            " typeCloneFailed=" + typeCloneFailed +
            " conventionsFixed=" + conventionsFixed +
            " noReturnApplied=" + noReturnApplied +
            " noReturnFailed=" + noReturnFailed +
            " failed=" + failed +
            " (all-provider datatype prepass; complete USER_DEFINED" +
            " signatures, equivalent ABI conventions and linked-provider" +
            " No Return flags; no native bytes changed)");
        return true;
    }
}
