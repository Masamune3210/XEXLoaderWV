package xexloaderwv;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
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
			XEXHeader header;
			try {
				Msg.info(this, "XEX Loader: Trying to load as retail...");
				header = prepareXEX(original, options, patchPath, false);
			} catch (Exception retailFailure) {
				monitor.checkCancelled();
				Msg.warn(this, "XEX Loader: Retail decode failed; attempting devkit decode", retailFailure);
				try {
					header = prepareXEX(original, options, patchPath, true);
				} catch (Exception devkitFailure) {
					IOException failure = new IOException(
						"XEX decode failed for both retail and devkit keys", devkitFailure);
					failure.addSuppressed(retailFailure);
					throw failure;
				}
			}

			// Both decryption attempts are entirely in memory. From here on, errors
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
			String patchPath, boolean isDevKit) throws Exception {
		// XEXP may mutate its input; each decryption attempt must start from
		// independent original bytes, and neither may touch the Ghidra Program.
		byte[] image = original.clone();
		if (!patchPath.isEmpty()) {
			image = ApplyPatch(image, patchPath, options, isDevKit);
		}
		XEXHeader header = new XEXHeader(image, options, isDevKit);
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
		Msg.info(this, "XEX Loader: Applying patch");
		byte[] buffPatch = Files.readAllBytes(Path.of(patchPath));
		Msg.info(this, "XEX Loader: ### Loading Original XEX");
		XEXHeader orgHeader = new XEXHeader(buffROM, options, isDevKit);
		Msg.info(this, "XEX Loader: ### Loading Patch XEX");
		XEXHeader patchHeader = new XEXHeader(buffPatch, options, isDevKit);
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
			XEXHeader newHeader = new XEXHeader(buffROM, options, isDevKit);
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
	 * Ghidra prints the folder returned by getLinkSearchFolder(), not the
	 * DomainFile returned by findLibraryInProject(). When every imported library
	 * has one unique provider in the same project folder, supply that actual
	 * folder so the stock "Found ... in ..." message is truthful.
	 *
	 * For imports spread across folders, use project root as the search scope;
	 * the recursive lookup below logs each exact provider path.
	 */
	@Override
	protected DomainFolder getLinkSearchFolder(Program program, ImporterSettings settings) {
		DomainFolder standard = super.getLinkSearchFolder(program, settings);
		if (!isLinkExistingLibraries(settings) || settings.project() == null ||
			settings.mirrorFsLayout() ||
			!getStringOption(settings.options(), LINK_SEARCH_FOLDER_OPTION_NAME, "").isBlank()) {
			return standard;
		}
		DomainFolder root = settings.project().getProjectData().getRootFolder();
		if (root == null) {
			return standard;
		}
		DomainFolder commonParent = null;
		boolean hasLibraries = false;
		for (String library : program.getExternalManager().getExternalLibraryNames()) {
			if (ghidra.program.model.listing.Library.UNKNOWN.equals(library) ||
				getLibraryNameComparator().compare(library, program.getName()) == 0) {
				continue;
			}
			hasLibraries = true;
			try {
				DomainFile provider = findUniqueProjectLibrary(library, settings, false);
				if (provider == null) {
					// Preserve normal same-folder priority if another project
					// folder contains a provider with an identical name.
					if (standard != null &&
						super.findLibraryInProject(library, standard, List.of(), settings) != null) {
						return standard;
					}
					return root;
				}
				DomainFolder parent = provider.getParent();
				if (commonParent != null && !commonParent.getPathname().equals(parent.getPathname())) {
					return root;
				}
				commonParent = parent;
			}
			catch (CancelledException cancelled) {
				// This hook cannot throw; the base loader checks cancellation.
				return standard;
			}
		}
		return hasLibraries && commonParent != null ? commonParent : standard;
	}

	/**
	 * Find a unique matching Program anywhere in the project. Only actual
	 * Program files are eligible and ambiguous names remain unresolved.
	 */
	private DomainFile findUniqueProjectLibrary(String library, ImporterSettings settings,
			boolean report) throws CancelledException {
		DomainFolder root = settings.project().getProjectData().getRootFolder();
		if (root == null) {
			return null;
		}
		ArrayDeque<DomainFolder> pending = new ArrayDeque<>();
		Set<String> visited = new HashSet<>();
		pending.push(root);
		DomainFile match = null;
		while (!pending.isEmpty()) {
			settings.monitor().checkCancelled();
			DomainFolder current = pending.pop();
			if (!visited.add(current.getPathname())) {
				continue;
			}
			for (DomainFile candidate : current.getFiles()) {
				settings.monitor().checkCancelled();
				Class<?> type = candidate.getDomainObjectClass();
				if (type == null || !Program.class.isAssignableFrom(type) ||
					getLibraryNameComparator().compare(candidate.getName(), library) != 0) {
					continue;
				}
				if (match != null) {
					if (report) {
						settings.log().appendMsg("XEX project-wide library lookup: ambiguous [" +
							library + "] between [" + match.getPathname() + "] and [" +
							candidate.getPathname() + "]; not linking automatically");
					}
					return null;
				}
				match = candidate;
			}
			for (DomainFolder child : current.getFolders()) {
				pending.push(child);
			}
		}
		if (match != null && report) {
			settings.log().appendMsg("XEX project-wide library lookup: [" + library +
				"] -> [" + match.getPathname() + "]");
		}
		return match;
	}

	/**
	 * Ghidra's base lookup is intentionally shallow. A null folder means
	 * "do not search" and must not accidentally trigger our recursive lookup.
	 */
	@Override
	protected DomainFile findLibraryInProject(String library, DomainFolder folder,
			List<LibrarySearchPath> searchPaths, ImporterSettings settings)
			throws CancelledException {
		if (folder == null) {
			return null;
		}
		DomainFile direct = super.findLibraryInProject(library, folder, searchPaths, settings);
		if (direct != null || !isLinkExistingLibraries(settings) ||
			settings.project() == null ||
			!getStringOption(settings.options(), LINK_SEARCH_FOLDER_OPTION_NAME, "").isBlank()) {
			return direct;
		}
		return findUniqueProjectLibrary(library, settings, true);
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
