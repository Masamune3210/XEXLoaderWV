package xexloaderwv;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.SwingConstants;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import pdb.symbolserver.ui.LoadPdbDialog;
import pdb.symbolserver.ui.LoadPdbDialog.LoadPdbResults;

public class XEXLoaderWVLoader extends AbstractLibrarySupportLoader {

	public static final String PROCESS_PDATA_OPTION = "Process .pdata";
	public static final String LOAD_PDB_OPTION = "Load PDB File";
	public static final String EXPERIMENTAL_PDB_OPTION = "use experimental PDB loader";
	public static final String XEXP_PATH_OPTION = "Path to xexp";
	public static final String THUNK_VENEERS_OPTION =
		"EXPERIMENTAL: rewrite XEX import thunk bytes in mapped analysis image";

	public static boolean getBooleanOption(List<Option> options, String name, boolean defaultValue) {
		for (Option option : options) {
			if (name.equals(option.getName())) {
				return Boolean.TRUE.equals(option.getValue());
			}
		}
		return defaultValue;
	}

	private static String getStringOption(List<Option> options, String name, String defaultValue) {
		for (Option option : options) {
			if (name.equals(option.getName())) {
				return (String) option.getValue();
			}
		}
		return defaultValue;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Msg.info(this, "XEX Loader: Checking Signature");
		BinaryReader br = new BinaryReader(provider, false);
		if (br.readInt(0) != 0x58455832)
			return loadSpecs;

		// All Xbox 360 XEX binaries can contain Xenon VMX128 instructions,
		// not just the retail kernel. Prefer the expanded language if installed,
		// while retaining stock A2ALT as a selectable fallback.
		boolean xenonAvailable = false;
		try {
			// Check only metadata here; importing options must not compile SLEIGH.
			DefaultLanguageService.getLanguageService().getLanguageDescription(
					new LanguageID("PowerPC:BE:64:XENON-32addr"));
			xenonAvailable = true;
		}
		catch (Exception unavailable) {
			// Existing installations without the Xenon language remain supported.
		}
		if (xenonAvailable)
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair("PowerPC:BE:64:XENON-32addr", "default"), true));
		loadSpecs.add(new LoadSpec(this, 0,
			new LanguageCompilerSpecPair("PowerPC:BE:64:A2ALT-32addr", "default"), !xenonAvailable));
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "XEX Loader by Warranty Voider";
	}


	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		load(settings.provider(), settings.loadSpec(), settings.options(), program, settings.monitor(), settings.log());
	}

	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		try {
			byte[] original = provider.getInputStream(0).readAllBytes();
			String patchPath = getStringOption(options, XEXP_PATH_OPTION, "");
			XEXHeader header = null;
			ArrayList<Exception> decodeFailures = new ArrayList<>();
			boolean[] devkitKeys = {false, true, false, true};
			boolean[] legacyKeys = {false, false, true, true};
			for (int attempt = 0; attempt < devkitKeys.length; attempt++) {
				String keyName = (legacyKeys[attempt] ? "XEX1" : "XEX2") +
					(devkitKeys[attempt] ? " devkit" : " retail");
				try {
					Msg.info(this, "XEX Loader: Trying " + keyName + " key");
					header = prepareXEX(original, options, patchPath,
						devkitKeys[attempt], legacyKeys[attempt]);
					break;
				} catch (Exception decodeFailure) {
					monitor.checkCancelled();
					decodeFailures.add(decodeFailure);
					Msg.warn(this, "XEX Loader: " + keyName + " decode failed", decodeFailure);
				}
			}
			if (header == null) {
				IOException failure = new IOException(
					"XEX decode failed for XEX2 and XEX1 retail/devkit master keys");
				for (Exception decodeFailure : decodeFailures)
					failure.addSuppressed(decodeFailure);
				throw failure;
			}

			// All master-key attempts are entirely in memory. From here on, errors
			// must fail the import; retrying with the other key would corrupt the
			// partially mapped Program and hide the real import failure.
			program.setImageBase(program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(Integer.toUnsignedLong(header.imageBaseAddress)), true);
			boolean processPData = getBooleanOption(options, PROCESS_PDATA_OPTION, true);
			header.ProcessPEImage(program, monitor, log, processPData);
			if (header.blocks.isEmpty()) {
				throw new IOException("XEX image imported without any memory blocks");
			}
			if (getBooleanOption(options, LOAD_PDB_OPTION, false)) {
				LoadPDB(program, monitor,
					getBooleanOption(options, EXPERIMENTAL_PDB_OPTION, false), header);
			}
		} catch (CancelledException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		} catch (Exception e) {
			throw new IOException("XEX image import failed after decoding", e);
		}
	}

	private XEXHeader prepareXEX(byte[] original, List<Option> options,
			String patchPath, boolean isDevKit, boolean useXex1MasterKey) throws Exception {
		// XEXP may mutate its input; each decryption attempt must start from
		// independent original bytes, and neither may touch the Ghidra Program.
		byte[] image = original.clone();
		if (!patchPath.isEmpty()) {
			image = ApplyPatch(image, patchPath, options, isDevKit, useXex1MasterKey);
		}
		XEXHeader header = new XEXHeader(image, options, isDevKit, useXex1MasterKey);
		if (header.peImage == null || header.peImage.length < 0x100) {
			throw new IOException("XEX is not a usable base image (possibly an unapplied XEXP patch)");
		}
		// A wrong retail/devkit key can produce a nonempty image buffer full of
		// garbage. Check the decompressed PE signature before selecting a key,
		// so the alternative key is tried BEFORE any memory blocks are created.
		byte[] pe = header.peImage;
		if (pe[0] != 'M' || pe[1] != 'Z') {
			throw new IOException("Decoded XEX image lacks an MZ header");
		}
		long ntOffset = ((long) (pe[0x3C] & 0xFF)) |
			((long) (pe[0x3D] & 0xFF) << 8) |
			((long) (pe[0x3E] & 0xFF) << 16) |
			((long) (pe[0x3F] & 0xFF) << 24);
		if (ntOffset < 0x40 || ntOffset > pe.length - 0x18L ||
			pe[(int) ntOffset] != 'P' || pe[(int) ntOffset + 1] != 'E' ||
			pe[(int) ntOffset + 2] != 0 || pe[(int) ntOffset + 3] != 0) {
			throw new IOException("Decoded XEX image has an invalid PE signature");
		}
		int machine = (pe[(int) ntOffset + 4] & 0xFF) |
			((pe[(int) ntOffset + 5] & 0xFF) << 8);
		if (machine != 0x01F2) {
			throw new IOException("Decoded XEX PE is not an Xbox 360 PowerPC image: machine=0x" +
				Integer.toHexString(machine));
		}
		int sectionCount = (pe[(int) ntOffset + 6] & 0xFF) |
			((pe[(int) ntOffset + 7] & 0xFF) << 8);
		int optionalSize = (pe[(int) ntOffset + 20] & 0xFF) |
			((pe[(int) ntOffset + 21] & 0xFF) << 8);
		if (sectionCount <= 0 || sectionCount > 96 ||
			optionalSize < 0x60 ||
			ntOffset + 24L + optionalSize + (long) sectionCount * 40 > pe.length) {
			throw new IOException("Decoded XEX PE section directory is invalid");
		}
		return header;
	}

	public void LoadPDB(Program program, TaskMonitor monitor, boolean useExperimental, XEXHeader h) throws Exception {
		LoadPdbResults loadPdbResults = LoadPdbDialog.choosePdbForProgram(program);
		if (loadPdbResults == null || loadPdbResults.pdbFile == null)
			return;
		File pdbFile = loadPdbResults.pdbFile;
		if (!useExperimental) {
			DataTypeManagerService dataTypeManagerService = AutoAnalysisManager.getAnalysisManager(program)
					.getDataTypeManagerService();
			LoadPdbTask loadPdbTask = new LoadPdbTask(program, pdbFile, loadPdbResults.useMsDiaParser,
					loadPdbResults.control, dataTypeManagerService);
			TaskBuilder.withTask(loadPdbTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);
			new TaskLauncher(loadPdbTask, null, 0);
		} else
			h.ProcessAdditionalPDB(new PDBFile(pdbFile.getPath(), monitor, program), program, monitor, true, true);
	}

	public byte[] ChangeBaseFileFormat(byte[] image) throws Exception {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(image), false);
		int offsetBFF = -1;
		int nOptHeader = b.readInt(20);
		int pos = 24;
		for (int i = 0; i < nOptHeader; i++) {
			int id = b.readInt(pos);
			if (id >> 8 == 3)
				offsetBFF = b.readInt(pos + 4);
			pos += 8;
		}
		image[offsetBFF + 5] = 0;
		image[offsetBFF + 7] = 0;
		return image;
	}

	public byte[] ApplyPatch(byte[] buffROM, String patchPath, List<Option> options, boolean isDevKit)
			throws Exception {
		return ApplyPatch(buffROM, patchPath, options, isDevKit, false);
	}

	public byte[] ApplyPatch(byte[] buffROM, String patchPath, List<Option> options,
			boolean isDevKit, boolean useXex1MasterKey) throws Exception {
		Msg.info(this, "XEX Loader: Applying patch");
		byte[] buffPatch = Files.readAllBytes(Path.of(patchPath));
		Msg.info(this, "XEX Loader: ### Loading Original XEX");
		XEXHeader orgHeader = new XEXHeader(buffROM, options, isDevKit, useXex1MasterKey);
		Msg.info(this, "XEX Loader: ### Loading Patch XEX");
		XEXHeader patchHeader = new XEXHeader(buffPatch, options, isDevKit, useXex1MasterKey);
		if (patchHeader.baseFileFormat.compression == 3) {
			XEXPatchDescriptor desc = patchHeader.patchDescriptor;
			byte[] sourceData = new byte[desc.delta_patch.uncompressed_len];
			for (int i = 0; i < desc.delta_patch.uncompressed_len; i++)
				sourceData[i] = buffROM[i + desc.delta_patch.old_addr];
			byte[] patchResult = new LzxDecompression().DecompressLZX(desc.delta_patch.patch_data, sourceData,
					desc.delta_patch.uncompressed_len);
			for (int i = 0; i < desc.delta_patch.uncompressed_len; i++)
				buffROM[i + desc.delta_patch.new_addr] = patchResult[i];
			int oldSize = orgHeader.peImage.length + orgHeader.offsetPE;
			int totalSize = orgHeader.offsetPE + patchHeader.loaderInfo.imageSize;
			if (oldSize > totalSize)
				totalSize = oldSize;
			byte[] temp = new byte[totalSize];
			int headerSize = orgHeader.offsetPE;
			for (int i = 0; i < headerSize; i++)
				temp[i] = buffROM[i];
			for (int i = 0; i < orgHeader.peImage.length; i++)
				temp[i + headerSize] = orgHeader.peImage[i];
			buffROM = temp;
			Msg.info(this, "XEX Loader: ### Loading XEX with patched header");
			XEXHeader newHeader = new XEXHeader(buffROM, options, isDevKit, useXex1MasterKey);
			byte[] newSessionKey = newHeader.sessionKey;
			patchHeader.sessionKey = Helper.AESDecrypt(newSessionKey, patchHeader.loaderInfo.fileKey);
			patchHeader.ReadPEImage(buffPatch);
			BinaryReader b = new BinaryReader(new ByteArrayProvider(patchHeader.peImage), false);
			int nextBlockSize = patchHeader.baseFileFormat.normal.blockSize;
			int pos = 0;
			while (nextBlockSize != 0) {
				int currentBlockSize = nextBlockSize;
				nextBlockSize = b.readInt(pos);
				int start = pos;
				pos += 24;
				while (pos < start + currentBlockSize) {
					XEXDeltaPatch delta_patch = new XEXDeltaPatch(patchHeader.peImage, pos);
					if (delta_patch.old_addr == 0 && delta_patch.new_addr == 0 && delta_patch.compressed_len == 0
							&& delta_patch.uncompressed_len == 0)
						break;
					switch (delta_patch.compressed_len) {
					case 0:
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[headerSize + delta_patch.new_addr + i] = 0;
						pos += 12;
						break;
					case 1:
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[headerSize + delta_patch.new_addr + i] = buffROM[headerSize + delta_patch.old_addr
									+ i];
						pos += 12;
						break;
					default:
						byte[] patchData = new byte[delta_patch.compressed_len];
						for (int i = 0; i < delta_patch.compressed_len; i++)
							patchData[i] = patchHeader.peImage[pos + i + 12];
						byte[] baseData = new byte[delta_patch.uncompressed_len];
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							baseData[i] = buffROM[i + delta_patch.old_addr + headerSize];
						patchResult = new LzxDecompression().DecompressLZX(patchData, baseData,
								delta_patch.uncompressed_len);
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[i + delta_patch.new_addr + headerSize] = patchResult[i];
						pos += 12 + delta_patch.compressed_len;
						break;
					}
				}
				pos = start + currentBlockSize;
			}
		}
		return ChangeBaseFileFormat(buffROM);
	}



	/**
	 * Link existing imported libraries only from the folder into which Ghidra
	 * will save the newly imported Program. Using Loaded.getProjectFolderPath()
	 * handles both normal imports and mirrored filesystem layouts, without
	 * searching the project root, sibling version directories, or the separate
	 * library destination option.
	 *
	 * If the destination is not yet an existing project folder, fail closed:
	 * guessing a different folder could silently bind the wrong firmware.
	 */
	@Override
	protected List<DomainFolder> getLibrarySearchFolders(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) {
		if (settings.project() == null || !isLinkExistingLibraries(settings) ||
				loadedPrograms.isEmpty()) {
			return List.of();
		}
		String destinationPath = loadedPrograms.getFirst().getProjectFolderPath();
		DomainFolder destination = destinationPath == null ? null :
			settings.project().getProjectData().getFolder(destinationPath);
		if (destination == null) {
			settings.log().appendMsg("XEX library linking: destination project folder [" +
				destinationPath + "] unavailable; leaving existing libraries unresolved");
			return List.of();
		}
		settings.log().appendMsg("XEX library linking: searching only destination folder [" +
			destination.getPathname() + "]");
		return List.of(destination);
	}

	/**
	 * Never search beyond the provided destination folder, including when an
	 * import names a library with a relative or device-qualified path. Only
	 * actual Ghidra Program files can satisfy a dependency.
	 *
	 * Exact names take precedence over the loader's name comparator. When
	 * multiple non-exact matches exist in one folder, leave the dependency
	 * unresolved instead of selecting the first Program arbitrarily.
	 */
	@Override
	protected DomainFile findLibraryInProject(String library, DomainFolder folder,
			List<LibrarySearchPath> searchPaths, ImporterSettings settings)
			throws CancelledException {
		if (folder == null || library == null) {
			return null;
		}
		int lastSlash = Math.max(library.lastIndexOf('/'), library.lastIndexOf('\\'));
		String filename = library.substring(lastSlash + 1);
		if (filename.isEmpty()) {
			return null;
		}
		DomainFile compatible = null;
		for (DomainFile candidate : folder.getFiles()) {
			settings.monitor().checkCancelled();
			Class<?> objectClass = candidate.getDomainObjectClass();
			if (objectClass == null || !Program.class.isAssignableFrom(objectClass)) {
				continue;
			}
			if (candidate.getName().equalsIgnoreCase(filename)) {
				return candidate;
			}
			if (getLibraryNameComparator().compare(candidate.getName(), filename) != 0) {
				continue;
			}
			if (compatible != null) {
				settings.log().appendMsg("XEX library linking: ambiguous [" + filename +
					"] within [" + folder.getPathname() + "]; not linking automatically");
				return null;
			}
			compatible = candidate;
		}
		return compatible;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,	DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		// Preserve Ghidra's standard options for linking already imported libraries.
		List<Option> list = new ArrayList<>(super.getDefaultOptions(
			provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout));
		list.add(new Option(PROCESS_PDATA_OPTION, true));
		list.add(new Option(LOAD_PDB_OPTION, false));
		list.add(new Option(EXPERIMENTAL_PDB_OPTION, false));
		list.add(new Option(XEXP_PATH_OPTION, ""));
		list.add(new Option(THUNK_VENEERS_OPTION, false));
		return list;
	}
}
