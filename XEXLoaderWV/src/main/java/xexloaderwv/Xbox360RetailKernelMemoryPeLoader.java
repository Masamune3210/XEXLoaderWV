package xexloaderwv;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.FileHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.SectionFlags;
import ghidra.app.util.bin.format.pe.SectionHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Import the exact, SHA256-verified Xbox 360 retail 17559 kernel as a PE
 * extracted from a *memory image*, not from an on-disk PE file.
 *
 * This uses Ghidra's normal PeLoader data-directory / symbol handling while
 * mapping section contents at their VirtualAddress (= offset into the captured
 * kernel memory image). The raw-file offsets in the embedded COFF section
 * headers describe a different on-disk layout and MUST NOT be used against
 * the memory-image bytes. No input image bytes or headers are rewritten.
 */
public class Xbox360RetailKernelMemoryPeLoader extends PeLoader {

    public static final String LOADER_NAME = "Xbox 360 Kernel 17559 Memory Image PE";
    private static final String VERIFIED_SHA256 =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final long IMAGE_SIZE = 0x1B0000L;
    private static final int MACHINE_POWERPC_FP = 0x01F2;

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    private static String sha256(ByteProvider provider) throws IOException {
        final MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }
        long length = provider.length();
        for (long offset = 0; offset < length;) {
            int count = (int)Math.min(0x10000L, length - offset);
            md.update(provider.readBytes(offset, count));
            offset += count;
        }
        byte[] digest = md.digest();
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) hex.append(String.format("%02x", b & 0xff));
        return hex.toString();
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        // Deliberately refuse all other PEs, including normalized-file-layout
        // copies of this image. They belong to Ghidra's built-in PE loader.
        if (provider.length() != IMAGE_SIZE ||
                !VERIFIED_SHA256.equals(sha256(provider))) {
            return List.of();
        }
        PortableExecutable pe = new PortableExecutable(provider, SectionLayout.MEMORY, false, false);
        NTHeader nt = pe.getNTHeader();
        if (nt == null || nt.getOptionalHeader() == null ||
                nt.getFileHeader().getMachine() != MACHINE_POWERPC_FP ||
                nt.getOptionalHeader().getImageBase() != 0x80040000L) {
            return List.of();
        }
        return super.findSupportedLoadSpecs(provider);
    }

    @Override
    protected SectionLayout getSectionLayout() {
        return SectionLayout.MEMORY;
    }

    @Override
    protected Map<SectionHeader, Address> processMemoryBlocks(PortableExecutable pe,
            Program program, FileBytes fileBytes, TaskMonitor monitor, MessageLog log)
            throws AddressOverflowException {

        // When interpreting a captured PE memory image, a section's virtual
        // address is also its physical source offset in the provider. Using
        // SectionHeader.getPointerToRawData() instead would shift .text by
        // 0x4c00 and destroy valid PowerPC instructions/function entrypoints.
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        OptionalHeader optional = pe.getNTHeader().getOptionalHeader();
        FileHeader fileHeader = pe.getNTHeader().getFileHeader();
        SectionHeader[] sections = fileHeader.getSectionHeaders();
        Map<SectionHeader, Address> result = new HashMap<>();

        long imageBase = optional.getImageBase();
        int headersSize = (int)Math.min(optional.getSizeOfHeaders(), fileBytes.getSize());
        if (headersSize <= 0 || imageBase != 0x80040000L) {
            throw new IllegalStateException("Unexpected retail kernel memory-image header");
        }

        MemoryBlockUtils.createInitializedBlock(program, false, HEADERS,
            space.getAddress(imageBase), fileBytes, 0, headersSize,
            "", "", true, false, false, log);

        for (int i = 0; i < sections.length; i++) {
            if (monitor.isCancelled()) break;
            SectionHeader section = sections[i];
            long rva = Integer.toUnsignedLong(section.getVirtualAddress());
            long virtualSize = Integer.toUnsignedLong(section.getVirtualSize());
            if (virtualSize == 0) continue;
            if (rva < headersSize || rva + virtualSize > IMAGE_SIZE) {
                throw new IllegalStateException("Kernel section extends outside original image: " +
                    section.getName());
            }

            int flags = section.getCharacteristics();
            boolean readable = (flags & SectionFlags.IMAGE_SCN_MEM_READ.getMask()) != 0;
            boolean writable = (flags & SectionFlags.IMAGE_SCN_MEM_WRITE.getMask()) != 0;
            boolean executable = (flags & SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask()) != 0;
            Address address = space.getAddress(imageBase + rva);
            String name = section.getReadableName();
            if (name.isBlank()) name = "SECTION." + i;

            // Unlike FILE-layout PE loading, the entire virtual section is
            // physically present in the full memory snapshot (including the
            // zeroed .data tail). Keep its initialized contents exactly.
            MemoryBlockUtils.createInitializedBlock(program, false, name,
                address, fileBytes, rva, virtualSize, "", "",
                readable, writable, executable, log);
            result.put(section, address);
        }
        log.appendMsg("Xbox 360 kernel 17559: sections loaded from their actual memory-image RVAs");
        return result;
    }
}
