package xexloaderwv;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recognize embedded XMA1 WAV files and null-interleaved UTF-16 strings.
 * Never rewrites bytes, disassembles payloads or replaces preexisting data.
 * Defined arrays may receive a resource label/comment, but are never retyped.
 */
public final class XexEmbeddedResourceAnalyzer extends AbstractAnalyzer {
    private static final int WINDOW = 0x10000;
    private static final long MAX_RIFF = 64L * 1024 * 1024;
    private static final int MIN_TEXT = 7;
    private static final int MAX_TEXT = 4096;
    private static final String MARKER = "[XEX embedded WAVE]";


    private static final class Chunk {
        int offset, size;
        String id;
        Chunk(int offset, int size, String id) {
            this.offset = offset;
            this.size = size;
            this.id = id;
        }
    }

    private static final class XmaWave {
        long length, dataOffset, dataLength;
        int streams, sampleRate, channels, formatTag;
        boolean seek;
        final List<Chunk> chunks = new ArrayList<>();
    }

    private static final class TextMatch {
        int bytes;
        boolean little, terminated;
    }

    public XexEmbeddedResourceAnalyzer() {
        super("XEX: Detect embedded XMA1 and UTF-16 resources",
            "Recognize complete embedded XMA1 RIFF/WAVE assets and " +
            "null-interleaved UTF-16 strings without overwriting existing data.",
            AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
        // Standard data/code recovery must settle before we add annotations.
        // A later one-shot run must never replace manually established data.
        setPriority(AnalysisPriority.DATA_ANALYSIS.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        return "XEX Loader by Warranty Voider".equals(program.getExecutableFormat());
    }

    private static int u16(byte[] bytes, int p) {
        return (bytes[p] & 0xff) | ((bytes[p + 1] & 0xff) << 8);
    }

    private static long u32(byte[] bytes, int p) {
        return ((long) bytes[p] & 0xff) |
            (((long) bytes[p + 1] & 0xff) << 8) |
            (((long) bytes[p + 2] & 0xff) << 16) |
            (((long) bytes[p + 3] & 0xff) << 24);
    }

    private static boolean magic(byte[] bytes, int p, String value) {
        if (p < 0 || p + 4 > bytes.length) return false;
        for (int i = 0; i < 4; i++) {
            if (bytes[p + i] != (byte) value.charAt(i)) return false;
        }
        return true;
    }

    private static byte[] read(Memory memory, Address address, int count)
            throws Exception {
        byte[] bytes = new byte[count];
        return memory.getBytes(address, bytes) == count ? bytes : null;
    }


    // Validate the entire RIFF container before marking anything. Recognize
    // all legitimate WAVE format tags, while decoding XMA1 specifically.
    // Some embedded WAVs are not XMA1 or have different ancillary chunks.
    private static XmaWave parseWave(Memory memory, Address address, long room)
            throws Exception {
        if (room < 44) return null;
        byte[] riff = read(memory, address, 12);
        if (riff == null || !magic(riff, 0, "RIFF") ||
                !magic(riff, 8, "WAVE")) return null;
        long length = u32(riff, 4) + 8;
        if (length < 44 || length > MAX_RIFF || length > room ||
                length > Integer.MAX_VALUE) return null;
        XmaWave found = new XmaWave();
        found.length = length;
        boolean hasFmt = false, hasData = false;
        long at = 12;
        int count = 0;
        while (at < length && count++ < 256) {
            if (length - at < 8) return null;
            byte[] chunk = read(memory, address.add(at), 8);
            if (chunk == null) return null;
            long chunkSize = u32(chunk, 4);
            long padded = chunkSize + (chunkSize & 1);
            long end = at + 8 + padded;
            if (end <= at || end > length) return null;
            String id = new String(chunk, 0, 4, java.nio.charset.StandardCharsets.US_ASCII);
            found.chunks.add(new Chunk((int) at, (int) chunkSize, id));

            if (magic(chunk, 0, "fmt ")) {
                if (hasFmt || chunkSize < 16 || chunkSize > 4096) return null;
                byte[] fmt = read(memory, address.add(at + 8), (int) chunkSize);
                if (fmt == null) return null;
                int tag = u16(fmt, 0);
                int channels = u16(fmt, 2);
                long sampleRate = u32(fmt, 4);
                // Ordinary WAVEFORMATEX and Xbox XMAWAVEFORMAT have
                // different offsets, so decode XMA1 separately.
                if (tag == 0x0165) {
                    if (chunkSize < 0x20) return null;
                    int streams = u16(fmt, 8);
                    if (streams < 1 || streams > 8 ||
                            chunkSize != 0x0c + streams * 0x14) return null;
                    channels = 0;
                    sampleRate = 0;
                    for (int n = 0; n < streams; n++) {
                        int off = 0x0c + n * 0x14;
                        long rate = u32(fmt, off + 4);
                        int channelCount = fmt[off + 0x11] & 255;
                        if (rate < 8000 || rate > 192000 ||
                                channelCount < 1 || channelCount > 6 ||
                                (sampleRate != 0 && rate != sampleRate)) return null;
                        channels += channelCount;
                        sampleRate = rate;
                    }
                    found.streams = streams;
                }
                else {
                    // Generic RIFF/WAVE recognition requires recognizable
                    // WAVEFORMAT fields; don't invent a codec interpretation.
                    // Compressed WAVs can legitimately omit an average
                    // byte-rate estimate. Do not reject them for zero here.
                    if (tag == 0 || channels < 1 || channels > 16 ||
                            sampleRate < 4000 || sampleRate > 384000) return null;
                    found.streams = 0;
                }
                found.formatTag = tag;
                found.channels = channels;
                found.sampleRate = (int) sampleRate;
                hasFmt = true;
            }
            else if (magic(chunk, 0, "data")) {
                if (hasData || chunkSize == 0) return null;
                found.dataOffset = at + 8;
                found.dataLength = chunkSize;
                hasData = true;
            }
            else if (magic(chunk, 0, "seek")) {
                found.seek = true;
            }
            at = end;
        }
        return hasFmt && hasData && at == length ? found : null;
    }

    // Do not clear undefined-element arrays either: they can be user-created.
    private static boolean empty(Listing listing, Address start, int length) {
        Address end = start.add(length - 1L);
        if (listing.getInstructionContaining(start) != null ||
                listing.getDefinedDataContaining(start) != null) return false;
        Instruction instruction = listing.getInstructionAfter(start);
        if (instruction != null &&
                instruction.getMinAddress().compareTo(end) <= 0) return false;
        Data data = listing.getDefinedDataAfter(start);
        return data == null || data.getMinAddress().compareTo(end) > 0;
    }


    /**
     * Each detected file gets an actual named, size-correct Ghidra structure.
     * Numeric RIFF fields remain bytes to avoid misinterpreting LE numbers
     * under the big-endian Xenon language.
     */
    private static DataType makeWaveType(Program program, Address address,
            XmaWave wave) {
        String typeName = String.format("XexEmbeddedWave_%08X", address.getOffset());
        StructureDataType structure = new StructureDataType(
            new CategoryPath("/XEX/EmbeddedWaves"), typeName, (int) wave.length);
        structure.replaceAtOffset(0, new ArrayDataType(ByteDataType.dataType, 12, 1),
            12, "riffWaveHeader", "RIFF size is little-endian");
        int index = 0;
        for (Chunk chunk : wave.chunks) {
            String kind = chunk.id.equals("fmt ") ? "format" :
                chunk.id.equals("data") ? "audio" :
                chunk.id.equals("seek") ? "seek" : "unknown";
            String name = String.format("chunk%02d_%s", index++, kind);
            structure.replaceAtOffset(chunk.offset,
                new ArrayDataType(ByteDataType.dataType, 8, 1),
                8, name + "_header", "FourCC and little-endian data size");
            if (chunk.size > 0) {
                structure.replaceAtOffset(chunk.offset + 8,
                    new ArrayDataType(ByteDataType.dataType, chunk.size, 1),
                    chunk.size, name + "_payload",
                    kind.equals("audio") ? "Encoded WAVE audio" :
                    "Little-endian WAVE chunk data");
            }
            // Odd-sized RIFF chunks have a trailing padding byte; leaving
            // the byte undefined in the structure preserves its offset.
        }
        return program.getDataTypeManager().addDataType(
            structure, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private static int markWave(Program program, Address start, XmaWave wave,
            MessageLog log) {
        Listing listing = program.getListing();
        // Do not even create types/labels inside user-owned arrays or other
        // definitions; read-only recognition remains visible in the totals.
        if (!empty(listing, start, (int) wave.length)) return 0;
        int tx = program.startTransaction("XEX embedded WAVE " + start);
        boolean commit = false;
        try {
            DataType type = makeWaveType(program, start, wave);
            listing.createData(start, type);
            String label = String.format("EmbeddedWave_%08X", start.getOffset());
            Symbol existing = program.getSymbolTable().getPrimarySymbol(start);
            if (existing == null || existing.getSource() == SourceType.DEFAULT) {
                program.getSymbolTable().createLabel(start, label, SourceType.ANALYSIS);
            }
            String comment = MARKER + " RIFF length=0x" +
                Long.toHexString(wave.length) + " formatTag=0x" +
                Integer.toHexString(wave.formatTag) +
                " streams=" + wave.streams + " channels=" + wave.channels +
                " rate=" + wave.sampleRate + " audio=+0x" +
                Long.toHexString(wave.dataOffset) + "/0x" +
                Long.toHexString(wave.dataLength) + " seek=" + wave.seek +
                ". Header integers are little-endian.";
            if (listing.getComment(CommentType.PLATE, start) == null)
                listing.setComment(start, CommentType.PLATE, comment);
            commit = true;
            return 1;
        }
        catch (Exception e) {
            log.appendMsg("XEX WAVE at " + start +
                ": type definition refused: " + e.getMessage());
            return 0;
        }
        finally {
            program.endTransaction(tx, commit);
        }
    }


    private static boolean printable(int b) {
        return b >= 0x20 && b <= 0x7e;
    }

    private static boolean formatCode(int b) {
        // Includes observed XAM 1888 in-band dialogue controls: 0x0b,
        // 0x82, 0x04, CR and LF. Only a small fraction may be controls.
        return b >= 1 && (b < 0x20 || (b >= 0x7f && b <= 0x9f));
    }

    private static boolean prefix(byte[] bytes, int at, boolean little) {
        if (at + 12 > bytes.length) return false;
        int visible = 0;
        for (int n = 0; n < 6; n++) {
            int p = at + n * 2;
            int c = bytes[p + (little ? 0 : 1)] & 255;
            if (bytes[p + (little ? 1 : 0)] != 0 ||
                    (!printable(c) && !formatCode(c))) return false;
            if (printable(c)) visible++;
        }
        return visible >= 5;
    }

    private static TextMatch parseText(Memory memory, Address start,
            long room, boolean little) throws Exception {
        int length = (int) Math.min(room, (MAX_TEXT + 1L) * 2);
        if (length < MIN_TEXT * 2) return null;
        byte[] bytes = read(memory, start, length);
        if (bytes == null) return null;
        boolean[] seen = new boolean[128];
        int unique = 0, letters = 0, visible = 0, controls = 0, chars = 0;
        boolean terminated = false;
        for (int p = 0; p + 1 < length; p += 2) {
            int c = bytes[p + (little ? 0 : 1)] & 255;
            int hi = bytes[p + (little ? 1 : 0)] & 255;
            if (c == 0 && hi == 0) {
                terminated = true;
                break;
            }
            if (hi != 0 || (!printable(c) && !formatCode(c))) break;
            chars++;
            if (printable(c)) {
                visible++;
                if (Character.isLetter((char) c)) letters++;
                if (!seen[c]) { seen[c] = true; unique++; }
            }
            else controls++;
        }
        // Require a strong text-like run before defining an unterminated
        // (fixed-size) UTF-16 string. Control bytes are retained in place.
        if (chars < MIN_TEXT || letters < 4 || unique < 3 ||
                visible * 4 < chars * 3 || controls * 6 > chars)
            return null;
        if (!terminated && chars < 14) return null;
        TextMatch result = new TextMatch();
        result.bytes = chars * 2 + (terminated ? 2 : 0);
        result.terminated = terminated;
        result.little = little;
        return result;
    }

    private static boolean markText(Program program, Address start,
            TextMatch match, MessageLog log) {
        Listing listing = program.getListing();
        if (!empty(listing, start, match.bytes)) return false;
        int tx = program.startTransaction("XEX embedded UTF-16 " + start);
        boolean commit = false;
        try {
            Data data = listing.createData(start,
                match.terminated ? TerminatedUnicodeDataType.dataType :
                    UnicodeDataType.dataType, match.bytes);
            EndianSettingsDefinition.DEF.setBigEndian(data, !match.little);
            commit = true;
            return true;
        }
        catch (Exception e) {
            log.appendMsg("XEX UTF-16 at " + start + ": " + e.getMessage());
            return false;
        }
        finally {
            program.endTransaction(tx, commit);
        }
    }


    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        Memory memory = program.getMemory();
        int waves = 0, typedWaves = 0, preservedWaves = 0, utf16 = 0;
        int rejectedWaveCandidates = 0;
        int waveHeadersSeen = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !block.isRead()) continue;
            long size = block.getSize();
            // Resource bodies may span contiguous Ghidra memory blocks.
            // Parse through initialized mapped memory, not through a
            // single block's artificial section boundary.
            long waveEndExclusive = -1;
            long offset = 0;
            while (offset < size) {
                monitor.checkCancelled();
                int count = (int) Math.min(WINDOW + 16L, size - offset);
                byte[] buffer;
                try {
                    buffer = read(memory, block.getStart().add(offset), count);
                }
                catch (Exception e) {
                    offset += WINDOW;
                    continue;
                }
                if (buffer == null) {
                    offset += WINDOW;
                    continue;
                }
                int scan = (int) Math.min(WINDOW, size - offset);
                // Never skip a future RIFF candidate based on an earlier
                // candidate's length. Record protected ranges separately
                // so the UTF-16 pass still avoids compressed payloads.
                for (int i = 0; i < scan; i++) {
                    long position = offset + i;
                    Address candidate = block.getStart().add(position);
                    if (magic(buffer, i, "RIFF")) {
                        try {
                            // Check the full program's mapped address range.
                            // Memory.getBytes will still reject holes or
                            // unmapped/uninitialized trailing bytes.
                            long remainingMapped = memory.getMaxAddress().getOffset() -
                                candidate.getOffset() + 1;
                            XmaWave wave = parseWave(memory, candidate, remainingMapped);
                            if (wave != null) {
                                waves++;
                                waveEndExclusive = Math.max(waveEndExclusive,
                                    position + wave.length);
                                int typed = markWave(program, candidate, wave, log);
                                typedWaves += typed;
                                preservedWaves += (typed == 0 ? 1 : 0);
                                log.appendMsg("XEX WAVE recognized at " + candidate +
                                    " format=0x" + Integer.toHexString(wave.formatTag) +
                                    " size=0x" + Long.toHexString(wave.length) +
                                    (typed == 1 ? " typed" :
                                        " existing/overlapping data preserved"));
                                // Continue scanning for additional RIFF
                                // headers without consuming future candidates.
                            }
                            else if (i + 12 <= buffer.length &&
                                    magic(buffer, i + 8, "WAVE")) {
                                waveHeadersSeen++;
                                rejectedWaveCandidates++;
                                if (rejectedWaveCandidates <= 20) {
                                    log.appendMsg("XEX WAVE candidate not validated at " +
                                        candidate + " (incomplete or unsupported RIFF/chunks)");
                                }
                            }
                        }
                        catch (Exception ignored) {
                            // Invalid/truncated RIFF: leave unrelated data alone.
                        }
                    }
                    if (!block.isExecute() && position >= waveEndExclusive) {
                        try {
                            TextMatch match = null;
                            if (prefix(buffer, i, true))
                                match = parseText(memory, candidate, size - position, true);
                            if (match == null && prefix(buffer, i, false))
                                match = parseText(memory, candidate, size - position, false);
                            if (match != null && markText(program, candidate, match, log)) {
                                utf16++;
                                if (utf16 <= 20) {
                                    log.appendMsg("XEX UTF-16 recognized at " + candidate +
                                        " length=0x" + Integer.toHexString(match.bytes) +
                                        (match.little ? " LE" : " BE") +
                                        (match.terminated ? " terminated" : " fixed-length"));
                                }
                                i += match.bytes - 1;
                            }
                        }
                        catch (Exception ignored) {
                            // A partial candidate never modifies existing data.
                        }
                    }
                }
                offset += scan;
            }
        }
        log.appendMsg("XEX embedded resources: wavesFound=" + waves +
            " wavesTyped=" + typedWaves +
            " wavesPreservedOrBlocked=" + preservedWaves +
            " waveCandidatesRejected=" + rejectedWaveCandidates +
            " rejectedHeadersSeen=" + waveHeadersSeen +
            " utf16Typed=" + utf16 +
            " (never clear existing data or code)");
        return true;
    }

}
