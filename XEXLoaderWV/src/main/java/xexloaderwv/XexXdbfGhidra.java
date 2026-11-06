package xexloaderwv;

import java.io.ByteArrayInputStream;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

/**
 * Map and type verified title XDBF/SPA resources during a normal XEX import.
 * The XEX RESOURCE_INFO record supplies the *container* extent; active
 * XDBF table entries identify live data within it. Padding is not typed.
 */
final class XexXdbfGhidra {
    private static final CategoryPath TYPES = new CategoryPath("/Xbox360/XDBF");
    private static final String MARKER = "[XEX XDBF]";

    private XexXdbfGhidra() {
    }

    static void apply(XEXHeader header, Program program, MessageLog log,
            TaskMonitor monitor) throws Exception {
        if (header.peImage == null || !program.getLanguage().isBigEndian())
            return;
        for (XEXOptionalHeader optional : header.optHeaders) {
            if (optional.id != 0x000002ff || optional.data == null) continue;
            List<XexXdbfResource.Resource> resources = XexXdbfResource.parse(
                    header.peImage, header.imageBaseAddress, optional.data);
            for (XexXdbfResource.Resource resource : resources) {
                monitor.checkCancelled();
                try {
                    // A title SPA may cross gaps between PE sections. Only
                    // map bytes actually present in the decoded XEX image;
                    // leave existing PE blocks and their permissions alone.
                    mapMissingResourceBytes(header, program, resource, log, monitor);
                    typeResource(program, resource, log, monitor);
                }
                catch (CancelledException cancelled) {
                    throw cancelled;
                }
                catch (Exception e) {
                    log.appendMsg("XEX XDBF resource " + resource.name +
                            " at 0x" + Long.toHexString(resource.address) +
                            " not fully annotated: " + e.getMessage());
                }
            }
        }
    }

    private static Address address(Program program, long value) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private static void mapMissingResourceBytes(XEXHeader header, Program program,
            XexXdbfResource.Resource resource, MessageLog log,
            TaskMonitor monitor) throws Exception {
        Memory memory = program.getMemory();
        long end = resource.address + resource.length;
        long cursor = resource.address;
        int added = 0;
        while (cursor < end) {
            monitor.checkCancelled();
            Address at = address(program, cursor);
            MemoryBlock block = memory.getBlock(at);
            if (block != null) {
                if (!block.isInitialized() || !block.isRead())
                    throw new IllegalStateException("resource crosses an inaccessible block " +
                            block.getName());
                cursor = Math.min(end, block.getEnd().getOffset() + 1);
                continue;
            }
            long next = end;
            for (MemoryBlock existing : memory.getBlocks()) {
                long start = existing.getStart().getOffset();
                if (start > cursor && start < next) next = start;
            }
            int bytes = (int) (next - cursor);
            if (bytes <= 0) throw new IllegalStateException("invalid resource gap length");
            int offset = resource.rva + (int) (cursor - resource.address);
            String name = String.format("XDBF_%s_gap%02d",
                    safeName(resource.name), added++);
            header.MakeBlock(program, name, "XEX title XDBF resource " +
                    resource.name + " (decoded bytes between PE sections)",
                    cursor, new ByteArrayInputStream(header.peImage, offset, bytes),
                    bytes, "100", null, log, monitor);
            cursor = next;
        }
        log.appendMsg("XEX XDBF " + resource.name + ": mapped " + added +
                " PE-section gap blocks (preserved existing mapped sections)");
    }

    private static String safeName(String name) {
        return name.replaceAll("[^A-Za-z0-9_]", "_");
    }

    private static DataType put(Program program, StructureDataType type) {
        return program.getDataTypeManager().addDataType(
                type, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static DataType[] defineDatatypes(Program program) {
        StructureDataType header = new StructureDataType(TYPES, "XdbfHeader", 0);
        header.add(new ArrayDataType(ByteDataType.dataType, 4, 1), 4,
                "magic", "ASCII XDBF, Xbox big-endian");
        header.add(DWordDataType.dataType, 4, "version", "Typically 0x00010000");
        header.add(DWordDataType.dataType, 4, "entryTableCapacity", "Number of 18-byte entries");
        header.add(DWordDataType.dataType, 4, "entryCount", "Active entries");
        header.add(DWordDataType.dataType, 4, "freeSpaceTableCapacity", "Number of 8-byte entries");
        header.add(DWordDataType.dataType, 4, "freeSpaceCount", "Active free-space entries");

        StructureDataType entry = new StructureDataType(TYPES, "XdbfEntry", 0);
        entry.add(UnsignedShortDataType.dataType, 2, "namespace",
                "SPA: 1 metadata, 2 images, 3 string tables");
        entry.add(QWordDataType.dataType, 8, "id", "64-bit record ID");
        entry.add(DWordDataType.dataType, 4, "offsetSpecifier",
                "Relative to payload start, after both capacity-sized tables");
        entry.add(DWordDataType.dataType, 4, "length", "Record payload byte length");

        StructureDataType free = new StructureDataType(TYPES, "XdbfFreeSpaceEntry", 0);
        free.add(DWordDataType.dataType, 4, "offsetSpecifier",
                "Relative to data area");
        free.add(DWordDataType.dataType, 4, "length",
                "Free span length; final entry can be a size sentinel");

        DataType[] result = {put(program, header), put(program, entry), put(program, free)};
        if (result[0].getLength() != XexXdbfResource.HEADER_SIZE ||
                result[1].getLength() != XexXdbfResource.ENTRY_SIZE ||
                result[2].getLength() != XexXdbfResource.FREE_ENTRY_SIZE)
            throw new IllegalStateException("existing XDBF datatypes have incompatible widths");
        return result;
    }

    private static boolean clear(Listing listing, Address start, long length) {
        if (length <= 0) return true;
        Address end = start.add(length - 1);
        if (listing.getInstructionContaining(start) != null ||
                listing.getDefinedDataContaining(start) != null)
            return false;
        Instruction instruction = listing.getInstructionAfter(start);
        if (instruction != null && instruction.getMinAddress().compareTo(end) <= 0)
            return false;
        Data data = listing.getDefinedDataAfter(start);
        return data == null || data.getMinAddress().compareTo(end) > 0;
    }

    private static boolean typeIfEmpty(Listing listing, Address at,
            DataType type, MessageLog log, String label) throws Exception {
        Data old = listing.getDefinedDataAt(at);
        if (old != null && old.getLength() == type.getLength() &&
                old.getDataType().isEquivalent(type)) return true;
        if (!clear(listing, at, type.getLength())) {
            log.appendMsg("XEX XDBF: preserving preexisting data/code at " +
                    at + " for " + label);
            return false;
        }
        listing.createData(at, type);
        return true;
    }

    private static void label(Program program, Address at, String name)
            throws Exception {
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(at);
        if (symbol == null || symbol.getSource() == SourceType.DEFAULT)
            program.getSymbolTable().createLabel(at, name, SourceType.ANALYSIS);
    }

    /**
     * Fallback for already imported programs when the original XEX is no
     * longer accessible. Restrict annotations to initialized and readable
     * mapped bytes: never synthesize data or assume a missing resource size.
     */
    private static boolean rangeMapped(Memory memory, Address start, long size) {
        if (size <= 0) return false;
        long cursor = start.getOffset();
        long end = cursor + size;
        if (end <= cursor) return false;
        while (cursor < end) {
            try {
                MemoryBlock block = memory.getBlock(start.getAddressSpace().getAddress(cursor));
                if (block == null || !block.isInitialized() || !block.isRead())
                    return false;
                cursor = Math.min(end, block.getEnd().getOffset() + 1);
            }
            catch (Exception invalid) {
                return false;
            }
        }
        return true;
    }

    static void typeMappedLayout(Program program, Address base,
            MessageLog log) throws Exception {
        Memory memory = program.getMemory();
        if (!rangeMapped(memory, base, XexXdbfResource.HEADER_SIZE))
            return;
        byte[] header = new byte[XexXdbfResource.HEADER_SIZE];
        if (memory.getBytes(base, header) != header.length ||
                header[0] != 'X' || header[1] != 'D' ||
                header[2] != 'B' || header[3] != 'F' ||
                XexXdbfResource.be32(header, 4) != 0x10000) return;

        long capacity = XexXdbfResource.be32(header, 8);
        long used = XexXdbfResource.be32(header, 12);
        long freeCapacity = XexXdbfResource.be32(header, 16);
        long freeUsed = XexXdbfResource.be32(header, 20);
        if (capacity > 0x10000 || freeCapacity > 0x10000 ||
                used > capacity || freeUsed > freeCapacity) return;
        long entriesLength = capacity * XexXdbfResource.ENTRY_SIZE;
        long freeLength = freeCapacity * XexXdbfResource.FREE_ENTRY_SIZE;
        long tablesEnd = XexXdbfResource.HEADER_SIZE + entriesLength + freeLength;
        if (tablesEnd > 0x2000000) return;

        DataType[] types = defineDatatypes(program);
        Listing listing = program.getListing();
        String addressSuffix = String.format("%08X", base.getOffset());
        if (typeIfEmpty(listing, base, types[0], log, "XDBF header"))
            label(program, base, "Xdbf_" + addressSuffix);
        Address entriesAt = base.add(XexXdbfResource.HEADER_SIZE);
        if (capacity > 0) {
            if (rangeMapped(memory, entriesAt, entriesLength)) {
                typeIfEmpty(listing, entriesAt,
                    new ArrayDataType(types[1], (int) capacity,
                        types[1].getLength()),
                    log, "XDBF entry table");
            }
            else log.appendMsg("XEX XDBF " + base +
                ": entry table crosses uninitialized/unmapped bytes; " +
                "source XEX required for complete datatype");
        }

        Address freeAt = base.add(XexXdbfResource.HEADER_SIZE + entriesLength);
        if (freeCapacity > 0) {
            if (rangeMapped(memory, freeAt, freeLength)) {
                typeIfEmpty(listing, freeAt,
                    new ArrayDataType(types[2], (int) freeCapacity,
                        types[2].getLength()),
                    log, "XDBF free-space table");
            }
            else log.appendMsg("XEX XDBF " + base +
                ": free table crosses uninitialized/unmapped bytes; " +
                "source XEX required for complete datatype");
        }
        if (rangeMapped(memory, base.add(tablesEnd), 1)) {
            label(program, base.add(tablesEnd), "XdbfPayload_" + addressSuffix);
        }
        if (listing.getComment(CommentType.PLATE, base) == null) {
            listing.setComment(base, CommentType.PLATE, MARKER +
                " Recovered from mapped data. Entry capacity=" + capacity +
                ", active=" + used + ", free capacity=" + freeCapacity +
                ", active=" + freeUsed + ". Only currently mapped " +
                "XDBF tables were typed; no image padding was inferred.");
        }
    }

    private static void typeResource(Program program,
            XexXdbfResource.Resource resource, MessageLog log,
            TaskMonitor monitor) throws Exception {
        Listing listing = program.getListing();
        DataType[] types = defineDatatypes(program);
        Address base = address(program, resource.address);
        String suffix = safeName(resource.name) + "_" +
                String.format("%08X", resource.address);
        if (!typeIfEmpty(listing, base, types[0], log, "header")) return;
        label(program, base, "Xdbf_" + suffix);
        if (resource.entryCapacity > 0) {
            DataType entries = new ArrayDataType(types[1], resource.entryCapacity,
                    types[1].getLength());
            typeIfEmpty(listing, base.add(XexXdbfResource.HEADER_SIZE),
                    entries, log, "entry table");
        }
        if (resource.freeCapacity > 0) {
            DataType frees = new ArrayDataType(types[2], resource.freeCapacity,
                    types[2].getLength());
            typeIfEmpty(listing, base.add(resource.freeOffset),
                    frees, log, "free space table");
        }
        Address dataStart = base.add(resource.dataOffset);
        label(program, dataStart, "XdbfPayload_" + suffix);
        // The resource's declared size may include padding or data not
        // referenced by the active entry table. Do NOT type the whole tail.
        // Annotate each active record, leaving bodies available for SPA
        // structure/string/PNG analyzers and manual work.
        int labeled = 0;
        for (XexXdbfResource.Record record : resource.records) {
            monitor.checkCancelled();
            if (record.length == 0) continue;
            Address at = dataStart.add(record.offset);
            String name = String.format("Xdbf_%s_NS%04X_ID%016X",
                    safeName(resource.name), record.namespace, record.id);
            try {
                label(program, at, name);
                if (listing.getComment(CommentType.PLATE, at) == null) {
                    listing.setComment(at, CommentType.PLATE, MARKER +
                            " resource=" + resource.name +
                            " namespace=" + record.namespace +
                            " id=0x" + String.format("%016X", record.id) +
                            " size=0x" + Long.toHexString(record.length) +
                            " (SPA payload; offset relative to data area)");
                }
                labeled++;
            }
            catch (Exception e) {
                log.appendMsg("XEX XDBF payload " + at + ": label skipped: " +
                        e.getMessage());
            }
        }
        if (listing.getComment(CommentType.PLATE, base) == null) {
            listing.setComment(base, CommentType.PLATE, MARKER +
                    " " + resource.name + " XEX resource size=0x" +
                    Integer.toHexString(resource.length) +
                    " entries=" + resource.entryCount + "/" +
                    resource.entryCapacity + " free=" + resource.freeCount +
                    "/" + resource.freeCapacity + " dataArea=+0x" +
                    Integer.toHexString(resource.dataOffset) +
                    " highestReferencedDataEnd=+0x" +
                    Long.toHexString(resource.highestReferencedPayloadEnd) +
                    ". The resource's declared end is NOT the last live record.");
        }
        log.appendMsg("XEX XDBF: " + resource.name + " at " + base +
                " size=0x" + Integer.toHexString(resource.length) +
                " typed header/entry/free arrays, labeled=" + labeled +
                " active records, highestReferencedPayloadEnd=0x" +
                Long.toHexString(resource.highestReferencedPayloadEnd) +
                " (resource padding left untyped)");
    }
}
