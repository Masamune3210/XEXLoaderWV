package xexloaderwv;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Re-runnable XDBF/SPA analysis for already imported XEX programs.
 *
 * First detects XDBF headers in existing mapped bytes. If the original
 * XEX is still at Program.executablePath, decode it and use its authenticated
 * resource descriptors to fill PE-section gaps (no overwrite of mapped data)
 * and apply header/entry/free table types and record labels. Otherwise
 * annotate only verified, presently mapped table bytes, without inventing
 * the unmapped payload.
 */
public final class XexXdbfAnalyzer extends AbstractAnalyzer {
    private static final int WINDOW = 0x10000;
    private static final int MAX_CANDIDATES = 128;
    private static final long MAX_SOURCE_BYTES = 256L * 1024L * 1024L;

    public XexXdbfAnalyzer() {
        super("XEX: Type XDBF / SPA databases",
            "Recognize embedded title XDBF/SPA databases in existing XEX " +
            "programs and apply their header, entry-table and free-table " +
            "datatypes. Restore resource gaps when the original XEX is available.",
            AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis(); // Appears under Analysis > One Shot.
        setPriority(AnalysisPriority.DATA_ANALYSIS.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "XEX Loader by Warranty Voider".equals(program.getExecutableFormat()) &&
            program.getLanguage().isBigEndian();
    }

    private static boolean headerAt(Memory memory, Address at) {
        try {
            byte[] h = new byte[24];
            if (memory.getBytes(at, h) != h.length ||
                    h[0] != 'X' || h[1] != 'D' ||
                    h[2] != 'B' || h[3] != 'F') return false;
            long version = XexXdbfResource.be32(h, 4);
            long entries = XexXdbfResource.be32(h, 8);
            long active = XexXdbfResource.be32(h, 12);
            long free = XexXdbfResource.be32(h, 16);
            long freeActive = XexXdbfResource.be32(h, 20);
            long tableEnd = 24 + entries * 18 + free * 8;
            return version == 0x10000 &&
                entries <= 0x10000 && free <= 0x10000 &&
                active <= entries && freeActive <= free &&
                tableEnd < 0x2000000;
        }
        catch (Exception invalid) {
            return false;
        }
    }

    private static List<Address> discover(Program program, TaskMonitor monitor)
            throws CancelledException {
        List<Address> starts = new ArrayList<>();
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !block.isRead()) continue;
            long length = block.getSize();
            for (long offset = 0; offset < length; offset += WINDOW) {
                monitor.checkCancelled();
                int count = (int) Math.min(length - offset, WINDOW);
                byte[] chunk = new byte[count];
                Address chunkStart;
                try {
                    chunkStart = block.getStart().add(offset);
                    if (memory.getBytes(chunkStart, chunk) != count) continue;
                }
                catch (Exception unavailable) {
                    continue;
                }
                for (int i = 0; i < count; i++) {
                    if (chunk[i] != 'X') continue;
                    // headerAt reads the whole header from Program memory:
                    // it also handles signatures crossing a scan-window edge.
                    Address candidate = chunkStart.add(i);
                    if (headerAt(memory, candidate)) {
                        starts.add(candidate);
                        if (starts.size() == MAX_CANDIDATES) return starts;
                    }
                }
            }
        }
        return starts;
    }

    private static boolean matchesProgram(Program program, XEXHeader header,
            List<Address> found) {
        if (Integer.toUnsignedLong(header.imageBaseAddress) !=
                program.getImageBase().getOffset() ||
                header.peImage == null) return false;
        boolean candidateMatched = false;
        Memory memory = program.getMemory();
        for (XEXOptionalHeader opt : header.optHeaders) {
            if (opt.id != 0x000002ff || opt.data == null) continue;
            for (XexXdbfResource.Resource resource : XexXdbfResource.parse(
                    header.peImage, header.imageBaseAddress, opt.data)) {
                try {
                    Address start = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(resource.address);
                    if (!found.contains(start)) continue;

                    // An XDBF header alone may match between different
                    // revisions of the same title. Compare *every* byte
                    // already mapped inside the resource before reconstructing
                    // any missing resource gaps from the source file.
                    long end = resource.address + resource.length;
                    long verified = 0;
                    for (MemoryBlock block : memory.getBlocks()) {
                        if (!block.isInitialized() || !block.isRead()) continue;
                        long from = Math.max(resource.address,
                            block.getStart().getOffset());
                        long to = Math.min(end,
                            block.getEnd().getOffset() + 1);
                        for (long cursor = from; cursor < to;) {
                            int count = (int) Math.min(0x10000L, to - cursor);
                            byte[] mapped = new byte[count];
                            Address at = start.getAddressSpace().getAddress(cursor);
                            if (memory.getBytes(at, mapped) != count)
                                return false;
                            int offset = resource.rva +
                                (int) (cursor - resource.address);
                            for (int i = 0; i < count; i++) {
                                if (mapped[i] != header.peImage[offset + i])
                                    return false;
                            }
                            verified += count;
                            cursor += count;
                        }
                    }
                    if (verified < 24) return false;
                    candidateMatched = true;
                }
                catch (Exception invalid) {
                    return false;
                }
            }
        }
        return candidateMatched;
    }

    /**
     * Original on-disk file is optional. Do not use it unless both image base
     * and mapped XDBF header bytes match the currently imported program.
     */
    private static boolean recoverFromSource(Program program, List<Address> found,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        String executable = program.getExecutablePath();
        if (executable == null || executable.isBlank()) return false;
        Path path;
        try {
            path = Path.of(executable);
            if (!Files.isRegularFile(path)) return false;
            long length = Files.size(path);
            if (length < 24 || length > MAX_SOURCE_BYTES) return false;
        }
        catch (Exception invalidPath) {
            return false;
        }
        try {
            byte[] raw = Files.readAllBytes(path);
            if (raw[0] != 'X' || raw[1] != 'E' || raw[2] != 'X' || raw[3] != '2')
                return false;
            boolean[] devkit = {false, true, false, true};
            boolean[] legacy = {false, false, true, true};
            for (int i = 0; i < devkit.length; i++) {
                monitor.checkCancelled();
                try {
                    XEXHeader header = new XEXHeader(raw, Collections.emptyList(),
                        devkit[i], legacy[i]);
                    if (!matchesProgram(program, header, found)) continue;
                    XexXdbfGhidra.apply(header, program, log, monitor);
                    log.appendMsg("XEX XDBF analyzer: restored verified resource " +
                        "metadata from matching source XEX " + path);
                    return true;
                }
                catch (CancelledException cancellation) {
                    throw cancellation;
                }
                catch (Exception incorrectKeyOrInvalidImage) {
                    // Try the remaining retail/devkit and XEX1/XEX2 keys.
                }
            }
        }
        catch (CancelledException cancellation) {
            throw cancellation;
        }
        catch (Exception sourceUnavailable) {
            log.appendMsg("XEX XDBF: source XEX not usable: " +
                sourceUnavailable.getMessage());
        }
        return false;
    }

    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        List<Address> candidates = discover(program, monitor);
        if (candidates.isEmpty()) return true;

        boolean recovered = recoverFromSource(program, candidates, monitor, log);
        int scanned = 0;
        for (Address at : candidates) {
            monitor.checkCancelled();
            try {
                // Also useful when source XEX has moved. Types are restricted
                // to memory that is initialized and already mapped.
                XexXdbfGhidra.typeMappedLayout(program, at, log);
                scanned++;
            }
            catch (CancelledException cancellation) {
                throw cancellation;
            }
            catch (Exception error) {
                log.appendMsg("XEX XDBF " + at +
                    ": mapped-only annotation skipped: " + error.getMessage());
            }
        }
        log.appendMsg("XEX XDBF analyzer: recognized=" + candidates.size() +
            " mappedLayoutsChecked=" + scanned + " sourceRecovered=" +
            recovered + (recovered ? "" :
            " (unmapped bytes cannot be recovered without a matching source XEX)"));
        return true;
    }
}
