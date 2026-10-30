# XEX import linking: firmware-scoped providers (2026-10-30)

## Reason for change

Ghidra projects may contain native Xbox 360 software from multiple system-update families. Matching import providers by name across the whole project can silently link e.g. 1888 `dash.xex` against an unrelated version's `xam.xex`.

A previous `XEXLoaderWVLoader` override recursively scanned all project folders for providers and synthesized a search folder based on the global matches. That behavior has been removed on `testing`.

## Behavior now implemented

On each newly imported XEX, existing-library matching uses only its **destination project folder**, obtained from Ghidra's `Loaded<Program>.getProjectFolderPath()` and `ProjectData.getFolder()`. Searches check only immediate Program files; never descendants, siblings or generic project root. Exact filenames have priority over comparator aliases. Multiple comparator-only matches are ambiguous and left unresolved, without guessing the first.

**Sole cross-folder exception:** when the missing import is named exactly `xboxkrnl.exe` (case-insensitive), and the destination folder is below the named ancestor `System Firmware`, use the **direct** `xboxkrnl.exe` Program at that ancestor, if present. This does not consult the parent if it is named anything else and does not recurse further after reaching `System Firmware`. A local kernel always takes precedence. A local ambiguous kernel alias remains unresolved rather than falling back.

Example:

```text
/System Firmware/xboxkrnl.exe       <- optional shared kernel
/System Firmware/1888/xam.xex
/System Firmware/1888/dash.xex
/System Firmware/17559/xam.xex
/System Firmware/17559/dash.xex
```

For imports into `/System Firmware/1888`, `xam.xex` links only to `/System Firmware/1888/xam.xex`, and `xboxkrnl.exe` may link to `/System Firmware/xboxkrnl.exe` if no local version exists. Libraries absent in the destination remain unresolved, except for that kernel case. Version suffixes on filenames and duplicate kernels in each folder are **not necessary**.

This deliberately anchors the fallback to the known `System Firmware` project directory. A different root name requires a conscious adjustment rather than silent global search.

## Work and verification status

Source: `XEXLoaderWV/src/main/java/xexloaderwv/XEXLoaderWVLoader.java` on `testing`.

- `0e2d05595db7fc792dbbca58fa8d9f45e8453b53`: destination-only local matching (removed recursive project-global search).
- `3745bf84021eb30ab644a615ee7eb545c4eac267`: narrow exception for the shared kernel at the firmware root.

Static source checks confirm the fallback guards, local-first ordering, Program datatype checks, and lack of recursive project lookup. Ghidra's **12.1.3** `AbstractLibrarySupportLoader` source confirms the APIs and that `getLibrarySearchFolders` and `findLibraryInProject` are the supported hooks. **A full extension build and an actual Ghidra import test have not been run** in this session.

## Manual smoke test after rebuilding extension

1. With `/System Firmware/xboxkrnl.exe` and `/System Firmware/1888/xam.xex` already present, import `dash.xex` into `/System Firmware/1888`.
2. Confirm the import log says `XEX library linking: searching only destination folder [/System Firmware/1888]`. Verify the external `xam.xex` path points to `/System Firmware/1888/xam.xex`, and `xboxkrnl.exe` points to `/System Firmware/xboxkrnl.exe`.
3. Import a different `dash.xex` into a sibling firmware-version folder with its own `xam.xex`; confirm the new dashboard resolves its own local XAM, not the one from 1888.
4. If a version folder has no local XAM, confirm the external stays unresolved; do not create a cross-family link.

**No existing Program's external references are retroactively altered.** Re-link or reimport an affected consumer as necessary after upgrading the extension. Do not discard user annotations merely to reimport.


## 1888 dash XEX import parser crash and repair (2026-10-30)

User's import of build 1888 `dash.xex` failed **before the external provider lookup ran**. All four key attempts ended at `XEXHeader.ReadImportLibraries:506` with `IndexOutOfBoundsException: Index 52685 out of bounds for length 2`, where `52685 = 0xCDCD` (characteristic filler value). This error is unrelated to the destination-folder library-link change.

Original `ReadImportLibraries` skipped the entry header by a hardcoded `0x24` and advanced to the next entry by `0x28 + importCount*4`, discarding the record's actual `size` field. `ReadStringTable` also accumulated strings byte-by-byte without each name's 4-byte alignment. On a padded table, this can misread a name index from the filler bytes.

Implemented on `testing`:

- `XEXLoaderWV/src/main/java/xexloaderwv/XEXImportTableParser.java`: pure Java, no Ghidra runtime dependencies. Parses descriptor size, name table length and library count, reads NUL-terminated **4-byte-aligned** library names, accepts 0x00/0xCD alignment padding, decodes `name_index & 0xff` (high byte reserved), walks the library list by each entry's declared **size**, bounds-checks names and record counts, and emits precise offsets for malformed tables.
- `XEXHeader.ReadImportLibraries`: forwards to the parser, preserving `stringTable` and `importLibs` for all existing users.
- `XEXLoaderWV/tools/TestXEXImportTables_20261030_v1.java`: standalone regression with two libraries, padded names, 0xCD high name-index byte, an extra 4-byte gap after first record list, and invalid-index/record-size/count cases.
- `XEXLoaderWVLoader.java`: top-level load failure now includes the first specific error; full per-key suppressed diagnostics remain.

**Verification:** An independently reproduced Java parser source was compiled with the available `javac` and passed aligned-name, padded-entry, high-byte 0xCD name-index, invalid-index, invalid-size and invalid-import-count checks. The exact file in the remote repository and full extension have **not** been compiled against Ghidra 12.1.3 in this environment. No execution against the actual 1888 XEX has been performed. Treat success on the user's file as pending.

Regressions and remaining work:
1. Rebuild `XEXLoaderWV/testing` with Ghidra 12.1.3 and import the same 1888 `dash.xex`. If it fails, use the specific `XEX import table: ...` message (including byte offsets) and the new log to determine whether that XEX family has additional header variation.
2. After successful import, verify `xam.xex` resolves only inside the target 1888 folder and `xboxkrnl.exe` may resolve to `/System Firmware/xboxkrnl.exe`.
3. Preserve existing imported programs and annotations. This loader fix does not retroactively rewrite earlier external links, and should not be used as grounds to reimport completed analysis databases.


## Targeted 1888 dashboard nonlocal-jump correction (2026-10-30)

A Ghidra "Bad Instruction" bookmark at `0x9242D534` (00 00 00 00) was observed after `Function_9242D500` calls `Function_92452420` at `0x9242D530`. This is **intentional post-call padding**, not evidence of corrupt XEX import, the Xenon SLEIGH decoder or source bytes.

`0x92452420` is identified with high confidence as C runtime **`longjmp`**: it checks the integer value parameter `r4` and substitutes 1 when zero, restores nonvolatile FPR14-FPR31 and GPR13-GPR31 plus saved stack pointer/CR/LR before a context-transfer `blr`, and alternatively calls `xboxkrnl.exe::RtlUnwind`. Both branches transfer control to the saved continuation, not the immediate caller. XenonRecomp's published documentation independently identifies calls to `RtlUnwind` as a longjmp characteristic, and Microsoft/NT PowerPC longjmp references show the zero-to-one and RtlUnwind behavior. The caller's zero word at `0x9242D534` is not an executable PowerPC instruction.

**Useful Ghidra metadata (1888 `dash.xex`, not `xboxkrnl.exe`):**

- `0x92452420` -> `longjmp` (C runtime, generalized symbol); mark **No Return**.
- Ghidra function-editor prototype: `void longjmp(undefined4 * jumpBuffer, int returnValue)` (preserves the unresolved buffer pointer type; the second argument is demonstrably 32-bit; no semicolon in function editor).
- `0x9242D500` -> `LongjmpAfterOptionalCallback` (generalized): conditionally calls a function pointer loaded from `jumpBuffer+0x140` and always finishes in `longjmp(jumpBuffer, 1)`; mark **No Return**, including for its approximately 20 callers.
- `0x9242D530`: calls `longjmp(jumpBuffer, 1)`. `0x9242D534–0x9242D537` contains 4 zero bytes of padding, not instructions.
- Do not blindly impose a jump-buffer struct: multiple save/unwind modes are visible and the complete buffer layout isn't established. No changes to the linked `RtlUnwind` external or to code bytes are justified.

**Script:** `ghidra_scripts/RefineXenonLongjmp1888_20261030_v1.java` validates eight exact PPC words, renames the callee and optional-callback wrapper unless distinct USER_DEFINED names exist, marks both No Return, refines only unresolved longjmp signature parts (void return, integer returnValue, argument names) when there are exactly two parameters with standard variable storage, and adds non-overwriting comments. It refuses to run on different binaries. A Ghidra analysis refresh of the caller may be needed to remove an old Bad Instruction bookmark.

**Verification:** Disassembly evidence and Ghidra 12.1.3 Java API signatures inspected; script committed on `testing`. The script has **not yet been executed in the user's Ghidra database**; the after-call control-flow correction is pending user test. This is a targeted metadata correction independent of the successfully validated XEX import/link signature analyzer.
