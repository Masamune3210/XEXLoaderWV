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
