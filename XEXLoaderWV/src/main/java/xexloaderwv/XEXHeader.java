package xexloaderwv;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import xexloaderwv.PDBFile.SymbolRecord;

public class XEXHeader {
	public int magic;
	public int flags;
	public int offsetPE;
	public int reserved;
	public int offsetSecuInfo;
	public int nOptHeader;
	public ArrayList<XEXOptionalHeader> optHeaders = new ArrayList<XEXOptionalHeader>();
	public BaseFileFormat baseFileFormat;
	public XEXLoaderInfo loaderInfo;
	public byte[] sessionKey;
	public ArrayList<XEXSection> sections = new ArrayList<XEXSection>();
	public byte[] peImage;
	public int imageBaseAddress;
	public int entryPointAddress;
	public boolean useImportAnalysisVeneers;
	public ArrayList<String> stringTable;
	public ArrayList<ImportLibrary> importLibs;
	public ArrayList<MemoryBlock> blocks = new ArrayList<MemoryBlock>();
	public XEXPatchDescriptor patchDescriptor;
	
	public XEXHeader(byte[] data, List<Option> list, boolean isDevKit) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		magic = b.readInt(0);
		flags = b.readInt(4);
		String[] flagNames = {"Title Module","Exports To Title","System Debugger","DLL Module","Module Patch","Patch Full","Patch Delta","User Mode"};
		ArrayList<String> flagList = new ArrayList<String>();
		for(int i = 0; i < 8; i++)
			if((flags & (1 << i)) != 0)
				flagList.add(flagNames[i]);
		for(String flag : flagList)
			Msg.info(this, "XEX Loader: Flag : " + flag);
		offsetPE = b.readInt(8);
		reserved = b.readInt(12);
		offsetSecuInfo = b.readInt(16);
		nOptHeader = b.readInt(20);
		Msg.info(this, "XEX Loader: Loading optional headers");
		int pos = 24;
		for(int i = 0; i < nOptHeader; i++)
		{
			optHeaders.add(new XEXOptionalHeader(data, pos));
			pos += 8;
		}
		for(int i = 0; i < nOptHeader; i++)
		{
			XEXOptionalHeader oh = optHeaders.get(i);
			int test = oh.id & 0xFF;
			if(test == 0xFF)
			{
				int len = b.readInt(oh.value);
				oh.data = b.readByteArray(oh.value, len);
			}
			else if (test < 2)
				oh.data = b.readByteArray(24 + i * 8 + 4, 4);
			else
			{
				int len = test * 4;
				oh.data = b.readByteArray(oh.value, len);	
			}
		}
		ProcessOptionalHeaders();
		Msg.info(this, "XEX Loader: Loading loader info");
		loaderInfo = new XEXLoaderInfo(data, offsetSecuInfo);
		loaderInfo.isDevKit = isDevKit;
		// Preserve raw imported bytes unless the analysis-time veneer option is enabled.
		useImportAnalysisVeneers = list.size() > 4 && Boolean.TRUE.equals(list.get(4).getValue());
		DecryptFileKey();
		Msg.info(this, "XEX Loader: Loading section info");
		int sectionCount = b.readInt(offsetSecuInfo + 0x180);
		for(int i=0; i < sectionCount; i++)
			sections.add(new XEXSection(data, offsetSecuInfo + (i * 24) + 0x184));
		if(baseFileFormat.compression != 3)
			ReadPEImage(data);
	}
	
	public void DecryptFileKey() throws Exception
	{
		byte[] key;
		if(loaderInfo.isDevKit)
			key = new byte[16];
		else
			key  = Helper.hexStringToByteArray("20B185A59D28FDC340583FBB0896BF91");
		String s = "";
		for(byte b : loaderInfo.fileKey)
			s += String.format("%02X ", b);
		Msg.info(this, "XEX Loader: File key    = " + s);	
		sessionKey = Helper.AESDecrypt(key, loaderInfo.fileKey);
		s = "";
		for(byte b : sessionKey)
			s += String.format("%02X ", b);
		Msg.info(this, "XEX Loader: Session key = " + s);		
	}
	
	public void ProcessOptionalHeaders() throws Exception
	{
		Msg.info(this, "XEX Loader: Processing section info");
		for(XEXOptionalHeader sec : optHeaders)
		{
			String s = "";
			BinaryReader b = null;
			if(sec.data != null)
				b = new BinaryReader(new ByteArrayProvider(sec.data), false);
			switch(sec.id >> 8)
			{
				case 0x2:
					for(int i = 4; i < 12; i++)
						s += (char)b.readByte(i);
					Msg.info(this, "XEX Loader: Ressource Info = " + s);
					break;
				case 0x3:
					baseFileFormat = new BaseFileFormat(sec.data);				
					break;
				case 0x5:
					patchDescriptor = new XEXPatchDescriptor(sec.data, 0);
					break;
				case 0x80:
					for(int i = 4; i < sec.data.length; i++)
					{
						int test = b.readByte(i);
						if(test == 0)
							break;
						s += (char)test;
					}
					Msg.info(this, "XEX Loader: Bounding Path = " + s);
					break;
				case 0x101:					
					entryPointAddress = b.readInt(0);
					Msg.info(this, "XEX Loader: Entry point address = 0x" + String.format("%08X", entryPointAddress));
					break;
				case 0x102:
					imageBaseAddress = b.readInt(0);
					Msg.info(this, "XEX Loader: Imagebase address = 0x" + String.format("%08X", imageBaseAddress));
					break;
				case 0x103:
					ReadImportLibraries(sec.data);
					break;
				
			}
		}
	}
	
	public void ProcessAdditionalPDB(PDBFile pdb, Program program, TaskMonitor monitor, boolean loadTypes, boolean loadSymbols) throws Exception
	{

		if(loadTypes)
			pdb.tpi.ImportTypeRecords(program, monitor);
		if(loadSymbols)
		{
			DOSHeader dos = new DOSHeader(peImage);
			NTHeader nt = new NTHeader(peImage, dos.e_lfanew);
			int address = imageBaseAddress;
			for(NTHeader.SectionHeader sec : nt.secHeaders)
				if(sec.Name.equals(".text"))
				{
					address += sec.VirtualAddress;
					break;
				}
			int count = 0;
			monitor.setProgress(0);
			monitor.setMaximum(pdb.symbols.size());
			monitor.setMessage("Applying symbol records");
			for(int i = 0; i < pdb.symbols.size(); i++)
			{
				if(monitor.isCancelled())
					return;
				monitor.setProgress(i);
				SymbolRecord sym = pdb.symbols.get(i);
				if(sym.pubsymflags == 2 && sym.rectyp == 0x110e)
				{
					Address addr = MakeAddress((address + sym.off) & 0xFFFFFFFFL);
					if(addr != null)
					{
						int len = sym.name.length();
						String s = sym.name.substring(0, len < 2000 ? len : 2000);
						SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, s, SourceType.ANALYSIS);
						count++;
					}
				}
			}
			monitor.setProgress(0);
			Msg.info(this, "XEX Loader: Loaded " + count + " pdb function symbols");	
		}
	}
	
	/**
	 * Model XEX import records before .pdata disassembly can interpret the
	 * import-token words as PowerPC instructions. If opted in, patch the mapped
	 * Ghidra image with placeholder PPC relocation instructions, retaining the
	 * original token values as a plate comment and in the source XEX.
	 */
	public void ProcessImportLibraries(Program program, TaskMonitor monitor) throws Exception
	{
		if (importLibs == null || importLibs.isEmpty())
			return;
		BinaryReader image = new BinaryReader(new ByteArrayProvider(peImage), false);
		ghidra.program.model.symbol.ExternalManager externals = program.getExternalManager();
		ghidra.program.model.listing.FunctionManager functions = program.getFunctionManager();
		int references = 0;
		int thunks = 0;
		int dataOnly = 0;
		int unsupported = 0;
		for (ImportLibrary lib : importLibs)
		{
			monitor.checkCancelled();
			lib.functions.clear();
			ImportFunction last = null;
			for (int record : lib.records)
			{
				long off = Integer.toUnsignedLong(record) - Integer.toUnsignedLong(imageBaseAddress);
				if (off < 0 || off + 4 > peImage.length) {
					Msg.warn(this, "XEX Loader: Import record outside image: 0x" + Integer.toHexString(record));
					unsupported++;
					continue;
				}
				int token = image.readInt(off);
				int ordinal = token & 0xFFFF;
				int type = token >>> 24;
				if (type == 0) {
					last = new ImportFunction();
					last.address = record;
					last.ordinal = ordinal;
					last.thunk = 0;
					lib.functions.add(last);
				}
				else if (type == 1 && last != null && last.thunk == 0 &&
						last.ordinal == ordinal) {
					last.thunk = record;
				}
				else {
					Msg.warn(this, "XEX Loader: Unexpected import record type/ordinal at 0x" +
						Integer.toHexString(record));
					unsupported++;
				}
			}
			String library = lib.name.strip();
			for (ImportFunction imp : lib.functions)
			{
				monitor.checkCancelled();
				Address slot = MakeAddress(Integer.toUnsignedLong(imp.address));
				if (slot == null) {
					unsupported++;
					continue;
				}
				String name = ImportRenamer.Rename(library, imp.ordinal);
				SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, slot,
					null, "__imp__" + name, SourceType.IMPORTED);
				boolean canonicalThunk = imp.thunk != 0 && IsCanonicalImportThunk(image, imp);
				ghidra.program.model.symbol.ExternalLocation external =
					externals.getUniqueExternalLocation(library, name);
				if (external == null) {
					external = canonicalThunk
						? externals.addExtFunction(library, name, null, SourceType.IMPORTED)
						: externals.addExtLocation(library, name, null, SourceType.IMPORTED);
				}
				if (canonicalThunk && !external.isFunction())
					external.createFunction();
				program.getReferenceManager().addExternalReference(slot,
					ghidra.program.model.symbol.Reference.MNEMONIC, external,
					SourceType.IMPORTED, ghidra.program.model.symbol.RefType.DATA);
				references++;
				if (imp.thunk == 0) {
					dataOnly++;
					continue;
				}
				Address entry = MakeAddress(Integer.toUnsignedLong(imp.thunk));
				if (!canonicalThunk || entry == null) {
					Msg.warn(this, "XEX Loader: Noncanonical import thunk at 0x" +
						Integer.toHexString(imp.thunk) + "; leaving bytes and code undefined");
					unsupported++;
					continue;
				}
				if (functions.getFunctionContaining(entry) != null ||
						program.getListing().getInstructionContaining(entry) != null ||
						program.getListing().getInstructionContaining(entry.add(4)) != null) {
					Msg.warn(this, "XEX Loader: Existing code/function overlaps thunk " + entry);
					unsupported++;
					continue;
				}
				ghidra.program.model.listing.Function externalFunction = external.getFunction();
				if (externalFunction == null) {
					unsupported++;
					continue;
				}
				// Imported Xbox 360 thunks are *linker inputs*. At runtime the
				// kernel replaces the two descriptor words with PPC instructions
				// loading the target address into r11 (Xenia models this too).
				// A function whose first byte is typed data causes Ghidra's
				// disassembler to generate persistent "conflicting data" errors.
				// For analysis we use a zero-valued relocation placeholder; the
				// genuine external function relationship supplies the destination.
				// The source XEX and peImage remain unmodified.
				ghidra.program.model.address.AddressSet body =
					new ghidra.program.model.address.AddressSet(entry, entry.add(15));
				ghidra.program.model.listing.Function thunk =
					functions.createThunkFunction(name, program.getGlobalNamespace(),
						entry, body, externalFunction, SourceType.IMPORTED);
				if (thunk == null) {
					unsupported++;
					continue;
				}
				if (useImportAnalysisVeneers) {
					// lis r11, 0 ; ori r11, r11, 0
					// mtctr r11 ; bctr remain the ORIGINAL image instructions.
					byte[] veneer = new byte[] {
						(byte) 0x3D, (byte) 0x60, 0, 0,
						(byte) 0x61, (byte) 0x6B, 0, 0
					};
					program.getMemory().setBytes(entry, veneer);
					int original0 = image.readInt(Integer.toUnsignedLong(imp.thunk) -
						Integer.toUnsignedLong(imageBaseAddress));
					int original1 = image.readInt(Integer.toUnsignedLong(imp.thunk) -
						Integer.toUnsignedLong(imageBaseAddress) + 4);
					program.getListing().setComment(entry,
						ghidra.program.model.listing.CommentType.PLATE,
						String.format(
							"XEX import thunk: %s ordinal 0x%04X\\n" +
							"Original XEX token words: %08X %08X\\n" +
							"Source XEX bytes unchanged; Ghidra maps an analysis-only " +
							"zero-address PPC relocation veneer (lis/ori r11) " +
							"so the native external thunk can be disassembled. " +
							"Runtime linker substitutes the actual destination.",
							library, imp.ordinal, original0, original1));
				}
				thunks++;
			}
		}
		Msg.info(this, "XEX Loader: Linked " + references + " external import slots, " +
			thunks + " native thunk functions, " + dataOnly +
			" unclassified data-only imports, " + unsupported + " unsupported entries");
	}

	private boolean IsCanonicalImportThunk(BinaryReader image, ImportFunction imp) throws Exception
	{
		long off = Integer.toUnsignedLong(imp.thunk) - Integer.toUnsignedLong(imageBaseAddress);
		if (off < 0 || off + 16 > peImage.length)
			return false;
		int token1 = image.readInt(off);
		int token2 = image.readInt(off + 4);
		return (token1 >>> 16) == 0x0100 && (token1 & 0xFFFF) == imp.ordinal &&
			(token2 >>> 16) == 0x0200 && (token2 & 0xFFFF) == imp.ordinal &&
			image.readInt(off + 8) == 0x7D6903A6 &&
			image.readInt(off + 12) == 0x4E800420 &&
			MakeAddress(Integer.toUnsignedLong(imp.thunk) + 15) != null;
	}

	public void ReadStringTable(byte[] data, int start, int len) throws Exception
	{
		stringTable = new ArrayList<String>();
		int pos = start;
		String s = "";
		while(pos < start + len)
		{
			if(data[pos] != 0)
				s += (char)data[pos];
			else
			{
				while(data[pos + 1] == 0 && pos < start + len - 1)
					pos++;
				stringTable.add(s);
				s = "";
			}
			pos++;
		}
	}
	
	public void ReadImportLibraries(byte[] data) throws Exception
	{
		importLibs = new ArrayList<ImportLibrary>();
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		int pos = 4;
		int stringSize = b.readInt(pos);
		int libCount = b.readInt(pos + 4);
		pos += 8;
		ReadStringTable(data, pos, stringSize);
		pos += stringSize;
		for(int i = 0; i < libCount; i++)
		{
			ImportLibrary lib = new ImportLibrary();
			pos += 0x24;
			short nameIdx = b.readShort(pos);
			short count = b.readShort(pos + 2);
			pos += 4;
			lib.name = stringTable.get(nameIdx);
			for(int j = 0; j < count; j++)
				lib.records.add(b.readInt(pos + j * 4));
			importLibs.add(lib);
			pos += count * 4;
		}
	}
	
	public void ReadPEImage(byte[] data) throws Exception
	{
		Msg.info(this, "XEX Loader: Loading PE Image");
		int len = data.length - offsetPE;
		byte[] compressed;
		compressed = new byte[len];
		for(int i = 0; i < len; i ++)
			compressed[i] = data[offsetPE + i];
		Msg.info(this, "XEX Loader: Encryption type = " + baseFileFormat.encryption);
		Msg.info(this, "XEX Loader: Compression type = " + baseFileFormat.compression);		
		switch(baseFileFormat.encryption)
		{
			case 0:
				break;
			case 1:
				String s = "";
				for(byte b : sessionKey)
					s += String.format("%02X ", b);
				Msg.info(this, "XEX Loader: Decrypting using key    = " + s);	
				compressed = Helper.AESDecrypt(sessionKey, compressed);
				break;
			default:
				throw new Exception("Encryption type " + baseFileFormat.encryption + " not supported");
		}
		peImage = new byte[loaderInfo.imageSize];
		int posIn = 0, posOut = 0;
		switch(baseFileFormat.compression)
		{
			case 1:
				for(BaseFileFormat.BasicCompression bc : baseFileFormat.basic)
				{
					for(int i = 0; i < bc.dataSize && posIn + i < compressed.length; i++)
						peImage[i + posOut] = compressed[posIn + i];
					posOut += bc.dataSize + bc.zeroSize;
					posIn += bc.dataSize;
				}
				break;
			case 0:
			case 3:
				peImage = compressed;
				break;
			case 2:
				BaseFileFormat.NormalCompression nc = baseFileFormat.normal;
				byte[] buff = new byte[nc.blockSize];
				for(int i = 0; i < nc.blockSize; i++)
					buff[i] = compressed[posIn + i];
				posIn += nc.blockSize;
				ByteArrayOutputStream bop = new ByteArrayOutputStream();
				BinaryReader br = new BinaryReader(new ByteArrayProvider(buff), false);
				int nextSize;
				do
				{
					nextSize = br.readInt(0);
					for(int i = 24; i < buff.length;)
					{
						len = br.readUnsignedShort(i);
						if(len == 0)
							break;
						for(int j = 0; j < len; j++)
							bop.write(buff[i + j + 2]);
						i += 2 + len;
					}
					if(nextSize != 0)
					{
						buff = new byte[nextSize];
						for(int i = 0; i < nextSize; i++)
							buff[i] = compressed[posIn + i];
						posIn += nextSize;
						br = new BinaryReader(new ByteArrayProvider(buff), false);
					}
				}
				while(nextSize != 0);
				byte[] input = bop.toByteArray();
				// The XEX specifies the LZX dictionary size. Do not use the
				// decompressor's legacy 32 KiB default for a larger window.
				int windowSize = nc.windowSize;
				if (windowSize < (1 << 15) || windowSize > (1 << 21)
						|| (windowSize & (windowSize - 1)) != 0) {
					throw new Exception("Invalid XEX LZX window size: 0x"
							+ Integer.toHexString(windowSize));
				}
				int windowBits = Integer.numberOfTrailingZeros(windowSize);
				byte[] output = new LzxDecompression().DecompressLZX(
						input, null, loaderInfo.imageSize, windowBits);
				if (output.length != peImage.length) {
					throw new Exception("XEX decompressed image size mismatch: "
							+ output.length + " != " + peImage.length);
				}
				System.arraycopy(output, 0, peImage, 0, output.length);
				break;
			default:
				throw new Exception("Compression type " + baseFileFormat.compression + " not supported");
		}
	}
	
	public void ProcessPData(byte[] data, Program program, TaskMonitor monitor) throws Exception	
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		int created = 0;
		for(int i = 0; i < data.length; i += 8)
		{
			int address = b.readInt(i);
			Address addr = MakeAddress(address & 0xFFFFFFFFL);
			if(addr != null)
			{
				SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, "Function_" + String.format("%08X", address), SourceType.ANALYSIS);
				if(EnsureFunction(addr, program, monitor))
					created++;
			}
		}
		Msg.info(this, "XEX Loader: Loaded " + (data.length / 8) + " additional function symbols and defined " + created + " functions");
	}
	
	public void ProcessPEImage(Program program, TaskMonitor monitor, MessageLog log, boolean ProcessPData) throws Exception
	{
		Msg.info(this, "XEX Loader: Processing PE Image");
		DOSHeader dos = new DOSHeader(peImage);
		NTHeader nt = new NTHeader(peImage, dos.e_lfanew);
		byte[] pdata = null;
		for(NTHeader.SectionHeader sec : nt.secHeaders)
		{
			int address = sec.VirtualAddress;
			address += imageBaseAddress;
			int size = sec.PhysicalAddressOrVirtualSize;
			Msg.info(this, "XEX Loader: Loading section " + sec.Name + " at 0x" + String.format("%08X", address) + " size = 0x" + String.format("%08X", size));			
			byte[] data = new byte[size];
			if( sec.VirtualAddress + size <= peImage.length)
				for(int i = 0; i < size; i++)
					data[i] = peImage[sec.VirtualAddress + i];
			InputStream ds = new ByteArrayInputStream(data);		
			String perm = ""; 
			perm += ((sec.Characteristics & 0x40000000) != 0) ? "1" : "0";
			perm += ((sec.Characteristics & 0x80000000) != 0) ? "1" : "0";
			perm += ((sec.Characteristics & 0x20000000) != 0) ? "1" : "0";
			MakeBlock(program, sec.Name, sec.Name, address & 0xFFFFFFFFL, ds, data.length, perm, null, log, monitor);
			ds.close();	
			if(sec.Name.equals(".pdata"))
				pdata = data;
		}
		// Imports must be typed/linked before .pdata-driven code discovery.
		ProcessImportLibraries(program, monitor);
		if(pdata != null && ProcessPData)
			ProcessPData(pdata, program, monitor);
		Address addr = MakeAddress(entryPointAddress & 0xFFFFFFFFL);
		if(addr != null)
		{
			program.getSymbolTable().addExternalEntryPoint(addr);
		    program.getSymbolTable().createLabel(addr, "entry", SourceType.ANALYSIS);
		}
	}
	
	public void MakeBlock(Program program, String name, String desc, long address, InputStream s, int size, String perm, Structure struc, MessageLog log, TaskMonitor monitor)
	{
		try
		{
			byte[] bf = perm.getBytes();
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, name, addr, s, size, desc, null, bf[0] == '1', bf[1] == '1', bf[2] == '1', log, monitor);
			blocks.add(block);
			if(struc != null)
				DataUtilities.createData(program, block.getStart(), struc, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (Exception e) {
			Msg.error(this, ExceptionUtils.getStackTrace(e));
		}
	}
	
	public Address MakeAddress(long address)
	{
	    for(MemoryBlock block : blocks)
	    {
	        if(address >= block.getStart().getAddressableWordOffset() &&
	           address <= block.getEnd().getAddressableWordOffset())
	        {
	            Address addr = block.getStart();
	            return addr.add(address - addr.getAddressableWordOffset());            
	        }
	    }
	    return null;
	}

	private boolean EnsureFunction(Address addr, Program program, TaskMonitor monitor)
	{
		try
		{
			if(program.getFunctionManager().getFunctionAt(addr) != null)
				return false;

			if(program.getListing().getInstructionAt(addr) == null)
			{
				DisassembleCommand disassembleCmd = new DisassembleCommand(addr, null, true);
				disassembleCmd.enableCodeAnalysis(false);
				disassembleCmd.applyTo(program, monitor);
			}

			if(program.getListing().getInstructionAt(addr) == null)
				return false;

			CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(addr, false);
			if(!createFunctionCmd.applyTo(program, monitor))
				return false;
			return program.getFunctionManager().getFunctionAt(addr) != null;
		}
		catch (Exception ex)
		{
			return false;
		}
	}
}
