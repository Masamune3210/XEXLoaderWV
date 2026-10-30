package xexloaderwv;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
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
    private static final int MAX_TEXT = 512;
    private static final String MARKER = "[XEX embedded XMA1]";

    private static final class XmaWave {
        long length, dataOffset, dataLength;
        int streams, sampleRate, channels;
        boolean seek;
    }

    private static final class TextMatch {
        int bytes;
        boolean little;
    }

    public XexEmbeddedResourceAnalyzer() {
        super("XEX: Detect embedded XMA1 and UTF-16 resources",
            "Recognize complete embedded XMA1 RIFF/WAVE assets and " +
            "null-interleaved UTF-16 strings without overwriting existing data.",
            AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
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

    // Parse little-endian RIFF chunks without relying on the program endian.
    // Require the real XMA1 format tag, 0x14-byte stream entries and complete
    // 2048-byte XMA packets, not merely an incidental "RIFF" string.
    private static XmaWave parseWave(Memory memory, Address address, long room)
            throws Exception {
        if (room < 0x3c) return null;
        byte[] riff = read(memory, address, 12);
        if (riff == null || !magic(riff, 0, "RIFF") ||
                !magic(riff, 8, "WAVE")) return null;
        long length = u32(riff, 4) + 8;
        if (length < 0x3c || length > MAX_RIFF || length > room ||
                (length & 1) != 0) return null;
        XmaWave found = new XmaWave();
        found.length = length;
        boolean hasFmt = false, hasData = false;
        long at = 12;
        int chunkCount = 0;
        while (at < length && chunkCount++ < 128) {
            if (length - at < 8) return null;
            byte[] chunk = read(memory, address.add(at), 8);
            if (chunk == null) return null;
            long size = u32(chunk, 4);
            long next = at + 8 + size + (size & 1);
            if (next <= at || next > length) return null;
            if (magic(chunk, 0, "fmt ")) {
                if (hasFmt || size < 0x20 || size > 0x200) return null;
                byte[] fmt = read(memory, address.add(at + 8), (int) size);
                if (fmt == null || u16(fmt, 0) != 0x0165) return null;
                int streams = u16(fmt, 8);
                if (streams < 1 || streams > 8 ||
                        size != 0x0c + streams * 0x14) return null;
                int rate = 0, channels = 0;
                for (int n = 0; n < streams; n++) {
                    int stream = 0x0c + n * 0x14;
                    long streamRate = u32(fmt, stream + 4);
                    int streamChannels = fmt[stream + 0x11] & 0xff;
                    if (streamRate < 8000 || streamRate > 192000 ||
                            streamChannels < 1 || streamChannels > 6 ||
                            (rate != 0 && rate != (int) streamRate)) return null;
                    rate = (int) streamRate;
                    channels += streamChannels;
                }
                found.streams = streams;
                found.sampleRate = rate;
                found.channels = channels;
                hasFmt = true;
            }
            else if (magic(chunk, 0, "data")) {
                if (hasData || size == 0 || (size % 2048) != 0) return null;
                found.dataOffset = at + 8;
                found.dataLength = size;
                hasData = true;
            }
            else if (magic(chunk, 0, "seek")) {
                if (size < 8 || (size & 3) != 0) return null;
                found.seek = true;
            }
            at = next;
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

    private static int markWave(Program program, Address start, XmaWave wave,
            MessageLog log) {
        Listing listing = program.getListing();
        try {
            Symbol existing = program.getSymbolTable().getPrimarySymbol(start);
            if (existing == null || existing.getSource() == SourceType.DEFAULT ||
                    (existing.getSource() == SourceType.ANALYSIS &&
                     existing.getName().matches("DAT_[0-9A-Fa-f]+"))) {
                program.getSymbolTable().createLabel(start,
                    String.format("EmbeddedXma1Wave_%08X", start.getOffset()),
                    SourceType.ANALYSIS);
            }
            String comment = MARKER + " complete RIFF/WAVE: length=0x" +
                Long.toHexString(wave.length) + " tag=0x0165 streams=" +
                wave.streams + " channels=" + wave.channels +
                " rate=" + wave.sampleRate + " data=+0x" +
                Long.toHexString(wave.dataOffset) + " length=0x" +
                Long.toHexString(wave.dataLength) + " seek=" + wave.seek +
                ". RIFF fields are little-endian.";
            String old = listing.getComment(CommentType.PLATE, start);
            if (old == null || old.isEmpty())
                listing.setComment(start, CommentType.PLATE, comment);
            else if (!old.contains(MARKER))
                listing.setComment(start, CommentType.PLATE, old + "\n" + comment);
            if (empty(listing, start, (int) wave.length)) {
                listing.createData(start,
                    new ArrayDataType(ByteDataType.dataType,
                        (int) wave.length, 1));
                return 1;
            }
        }
        catch (Exception e) {
            log.appendMsg("XEX XMA1 at " + start + ": " + e.getMessage());
        }
        return 0;
    }

    private static boolean printable(int b) {
        return b >= 0x20 && b <= 0x7e;
    }

    private static boolean prefix(byte[] bytes, int at, boolean little) {
        if (at + 8 > bytes.length) return false;
        for (int n = 0; n < 4; n++) {
            int p = at + n * 2;
            if (!printable(bytes[p + (little ? 0 : 1)] & 0xff) ||
                    bytes[p + (little ? 1 : 0)] != 0) return false;
        }
        return true;
    }

    // Conservative ASCII-range, NUL-terminated UTF-16LE/BE detection. This
    // deliberately leaves short, non-ASCII and unterminated strings untouched.
    private static TextMatch parseText(Memory memory, Address start,
            long room, boolean little) throws Exception {
        int length = (int) Math.min(room, (MAX_TEXT + 1L) * 2);
        if (length < (MIN_TEXT + 1) * 2) return null;
        byte[] bytes = read(memory, start, length);
        if (bytes == null) return null;
        boolean[] seen = new boolean[128];
        int unique = 0, letters = 0;
        for (int p = 0; p + 1 < length; p += 2) {
            int c = bytes[p + (little ? 0 : 1)] & 0xff;
            int hi = bytes[p + (little ? 1 : 0)] & 0xff;
            if (c == 0 && hi == 0) {
                if (p / 2 < MIN_TEXT || letters < 4 || unique < 3) return null;
                TextMatch found = new TextMatch();
                found.bytes = p + 2;
                found.little = little;
                return found;
            }
            if (hi != 0 || !printable(c)) return null;
            if (Character.isLetter((char) c)) letters++;
            if (!seen[c]) { seen[c] = true; unique++; }
        }
        return null;
    }

    private static boolean markText(Program program, Address start,
            TextMatch text, MessageLog log) {
        Listing listing = program.getListing();
        if (!empty(listing, start, text.bytes)) return false;
        try {
            Data data = listing.createData(start,
                TerminatedUnicodeDataType.dataType, text.bytes);
            // The XEX instruction set is BE, but resource text can be LE.
            EndianSettingsDefinition.DEF.setBigEndian(data, !text.little);
            return true;
        }
        catch (Exception e) {
            log.appendMsg("XEX UTF-16 at " + start + ": " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException {
        Memory memory = program.getMemory();
        int waves = 0, waveArrays = 0, utf16 = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !block.isRead()) continue;
            long size = block.getSize();
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
                long advance = scan;
                for (int i = 0; i < scan; i++) {
                    long position = offset + i;
                    Address candidate = block.getStart().add(position);
                    if (magic(buffer, i, "RIFF")) {
                        try {
                            XmaWave wave = parseWave(memory, candidate, size - position);
                            if (wave != null) {
                                waves++;
                                waveArrays += markWave(program, candidate, wave, log);
                                // Skip the entire compressed audio resource, even if a
                                // user-defined array prevents retyping its contents.
                                advance = i + wave.length;
                                break;
                            }
                        }
                        catch (Exception ignored) {
                            // Incomplete or incidental RIFF marker: not an asset.
                        }
                    }
                    if (!block.isExecute()) {
                        try {
                            TextMatch text = null;
                            if (prefix(buffer, i, true))
                                text = parseText(memory, candidate, size - position, true);
                            if (text == null && prefix(buffer, i, false))
                                text = parseText(memory, candidate, size - position, false);
                            if (text != null && markText(program, candidate, text, log)) {
                                utf16++;
                                i += text.bytes - 1;
                            }
                        }
                        catch (Exception ignored) {
                            // A partial candidate never modifies the program.
                        }
                    }
                }
                offset += advance;
            }
        }
        log.appendMsg("XEX embedded resource detection: xma1Found=" + waves +
            " xma1Defined=" + waveArrays + " utf16Defined=" + utf16 +
            " (existing data and code preserved)");
        return true;
    }
}
