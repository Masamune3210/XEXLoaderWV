package xexloaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Imports Xenia CF/CG-reconstructed kernel PEs in their actual in-memory
 * layout. They are NOT ordinary disk PEs: section PointerToRawData fields
 * predate the applied update and must not be used to select file bytes.
 *
 * A strict header and PowerPC section-content signature prevents this
 * loader from claiming ordinary PE files or arbitrary MZ executables.
 */
public class XboxKernelMemoryPeLoader extends AbstractLibrarySupportLoader {
    public static final String PROCESS_PDATA_OPTION = "Process .pdata";

    @Override
    public String getName() {
        return "Xbox 360 Reconstructed Kernel (RVA Memory Image)";
    }

    @Override
    public int getTierPriority() {
        // Offer the memory-image interpretation before the generic PE
        // importer, but ONLY for binaries positively recognized by detect.
        return -100;
    }

    private static byte[] read(ByteProvider provider) throws IOException {
        if (provider.length() < 0x400 || provider.length() > 64L * 1024 * 1024) {
            return null;
        }
        byte[] bytes = provider.getInputStream(0).readAllBytes();
        return bytes.length == provider.length() ? bytes : null;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
            throws IOException {
        byte[] bytes = read(provider);
        if (bytes == null || XboxKernelMemoryPe.detect(bytes) == null) {
            return List.of();
        }
        List<LoadSpec> specs = new ArrayList<>();
        boolean xenonAvailable = false;
        try {
            DefaultLanguageService.getLanguageService().getLanguageDescription(
                new LanguageID("PowerPC:BE:64:XENON-32addr"));
            xenonAvailable = true;
        } catch (Exception unavailable) {
            // Compatible fallback where the Xenon language is not installed.
        }
        if (xenonAvailable) {
            specs.add(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("PowerPC:BE:64:XENON-32addr", "default"), true));
        }
        specs.add(new LoadSpec(this, 0,
            new LanguageCompilerSpecPair("PowerPC:BE:64:A2ALT-32addr", "default"),
            !xenonAvailable));
        return specs;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean loadIntoProgram,
            boolean mirrorFsLayout) {
        List<Option> options = new ArrayList<>(super.getDefaultOptions(
                provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout));
        options.add(new Option(PROCESS_PDATA_OPTION, true));
        return options;
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        byte[] bytes = read(settings.provider());
        XboxKernelMemoryPe.Image image = bytes == null
                ? null : XboxKernelMemoryPe.detect(bytes);
        if (image == null) {
            throw new IOException("Not an RVA-indexed, reconstructed Xbox 360 kernel PE");
        }
        TaskMonitor monitor = settings.monitor();
        MessageLog log = settings.log();
        long base = image.imageBase();
        try {
            program.setImageBase(program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(base), true);

            // Preserve the actual PE headers as read-only data at the image
            // base. All later blocks are copied from their VIRTUAL RVAs.
            int headerSize = image.sizeOfHeaders();
            int firstSection = image.sections().stream()
                    .mapToInt(XboxKernelMemoryPe.Section::virtualAddress)
                    .min().orElse(headerSize);
            if (headerSize > firstSection) {
                throw new IOException("Kernel PE headers overlap the first section");
            }
            block(program, "PE_HEADERS", base, bytes, 0, headerSize,
                    true, false, false, log, monitor);
            byte[] pdata = null;
            for (XboxKernelMemoryPe.Section section : image.sections()) {
                monitor.checkCancelled();
                int rva = section.virtualAddress();
                int size = section.virtualSize();
                long address = image.address(rva);
                block(program, section.name(), address, bytes, rva, size,
                        section.readable(), section.writable(),
                        section.executable(), log, monitor);
                if (".pdata".equals(section.name())) {
                    pdata = java.util.Arrays.copyOfRange(bytes, rva, rva + size);
                }
            }
            log.appendMsg("Xbox kernel RVA PE: mapped " + image.sections().size() +
                    " virtual sections from RVA offsets (ignoring stale PointerToRawData)");
            importExports(program, image, bytes, log, monitor);
            if (pdata != null && XEXLoaderWVLoader.getBooleanOption(
                    settings.options(), PROCESS_PDATA_OPTION, true)) {
                importPData(program, pdata, monitor, log);
            }
            Address entry = address(program, image.address(image.entryPointRva()));
            if (entry != null && program.getMemory().getBlock(entry) != null) {
                program.getSymbolTable().addExternalEntryPoint(entry);
                program.getSymbolTable().createLabel(entry, "entry", SourceType.ANALYSIS);
            }
        } catch (CancelledException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to map reconstructed Xbox kernel PE", e);
        }
    }

    private static Address address(Program program, long value) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private static void block(Program program, String name, long address,
            byte[] image, int offset, int size,
            boolean read, boolean write, boolean execute,
            MessageLog log, TaskMonitor monitor) throws Exception {
        if (!XboxKernelMemoryPe.range(image.length, offset, size)) {
            throw new IOException("Invalid RVA extent for " + name);
        }
        MemoryBlock mapped = MemoryBlockUtils.createInitializedBlock(
                program, false, name, address(program, address),
                new ByteArrayInputStream(image, offset, size), size,
                name + " (RVA memory image, file offset = virtual RVA)",
                null, read, write, execute, log, monitor);
        if (mapped == null) {
            throw new IOException("Failed to map kernel PE section " + name +
                    " at 0x" + Long.toHexString(address));
        }
    }

    private static boolean mapped(Program program, XboxKernelMemoryPe.Image image,
            int rva, int length) {
        if (!XboxKernelMemoryPe.range(image.sizeOfImage(),
                Integer.toUnsignedLong(rva), length)) return false;
        Address start = address(program, image.address(rva));
        Address end = address(program, image.address(rva + length - 1));
        MemoryBlock first = program.getMemory().getBlock(start);
        return first != null && first == program.getMemory().getBlock(end);
    }

    private static void importExports(Program program, XboxKernelMemoryPe.Image image,
            byte[] bytes, MessageLog log, TaskMonitor monitor) throws Exception {
        int exportRva = image.exportDirectoryRva();
        if (!mapped(program, image, exportRva, 40)) {
            log.appendMsg("Xbox kernel exports: PE export directory is absent or unmapped");
            return;
        }
        int ordinalBase = XboxKernelMemoryPe.u32(bytes, exportRva + 16);
        int count = XboxKernelMemoryPe.u32(bytes, exportRva + 20);
        int functionsRva = XboxKernelMemoryPe.u32(bytes, exportRva + 28);
        if (ordinalBase < 0 || count < 0 || count > 0x10000 ||
                (long) ordinalBase + count > 0x10000 ||
                count == 0 || !mapped(program, image, functionsRva, count * 4)) {
            throw new IOException("Invalid kernel PE export directory");
        }
        int functions = 0, globals = 0;
        for (int i = 0; i < count; ++i) {
            monitor.checkCancelled();
            int targetRva = XboxKernelMemoryPe.u32(bytes, functionsRva + i * 4);
            if (targetRva == 0 || !mapped(program, image, targetRva, 1)) continue;
            Address target = address(program, image.address(targetRva));
            int ordinal = ordinalBase + i;
            // Match the names that this extension gives XAM's imported
            // xboxkrnl ordinals, so native library linking can resolve them.
            String symbol = ImportRenamer.Rename("xboxkrnl", ordinal);
            if (symbol.startsWith("xboxkrnl_ord_")) {
                // Unknown exports must still match unknown import names.
                symbol = "xboxkrnl_ord_" + ordinal;
            }
            MemoryBlock memory = program.getMemory().getBlock(target);
            if (memory.isExecute() && (targetRva & 3) == 0) {
                ensureFunction(program, target, monitor);
                Function function = program.getFunctionManager().getFunctionAt(target);
                if (function != null && function.getSymbol().getSource() == SourceType.DEFAULT) {
                    function.setName(symbol, SourceType.ANALYSIS);
                } else {
                    program.getSymbolTable().createLabel(target, symbol, SourceType.ANALYSIS);
                }
                ++functions;
            } else {
                program.getSymbolTable().createLabel(target, symbol, SourceType.ANALYSIS);
                ++globals;
            }
            program.getSymbolTable().addExternalEntryPoint(target);
        }
        log.appendMsg("Xbox kernel PE exports: function ordinals=" +
                functions + ", data ordinals=" + globals);
    }

    private static void importPData(Program program, byte[] pdata,
            TaskMonitor monitor, MessageLog log) throws Exception {
        if ((pdata.length & 7) != 0) {
            throw new IOException("Malformed kernel .pdata length");
        }
        int created = 0;
        for (int pos = 0; pos < pdata.length; pos += 8) {
            if ((pos & 0xfff) == 0) monitor.checkCancelled();
            long va = ((long) Byte.toUnsignedInt(pdata[pos]) << 24) |
                    ((long) Byte.toUnsignedInt(pdata[pos + 1]) << 16) |
                    ((long) Byte.toUnsignedInt(pdata[pos + 2]) << 8) |
                    Byte.toUnsignedInt(pdata[pos + 3]);
            Address target = address(program, va);
            MemoryBlock block = program.getMemory().getBlock(target);
            if (block == null || !block.isExecute() ||
                    program.getFunctionManager().getFunctionAt(target) != null) continue;
            if (ensureFunction(program, target, monitor)) {
                Function function = program.getFunctionManager().getFunctionAt(target);
                if (function != null && function.getSymbol().getSource() == SourceType.DEFAULT) {
                    function.setName(String.format("Function_%08X", va), SourceType.ANALYSIS);
                }
                ++created;
            }
        }
        log.appendMsg("Xbox kernel .pdata: created " + created + " functions");
    }

    private static boolean ensureFunction(Program program, Address target,
            TaskMonitor monitor) throws Exception {
        if (program.getFunctionManager().getFunctionAt(target) != null) return true;
        if (program.getListing().getInstructionAt(target) == null) {
            DisassembleCommand command = new DisassembleCommand(target, null, true);
            command.enableCodeAnalysis(false);
            if (!command.applyTo(program, monitor)) return false;
        }
        if (program.getListing().getInstructionAt(target) == null) return false;
        return new CreateFunctionCmd(target, false).applyTo(program, monitor);
    }
}
