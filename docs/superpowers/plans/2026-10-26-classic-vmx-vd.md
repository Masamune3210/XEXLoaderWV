# Classic VMX Vd Semantics Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans in this session. The user explicitly forbids agents; do not delegate.

**Goal:** Restore the vector/CR6 dataflow required for Vd retraining.

**Architecture:** Replace onlyfour inherited opaque constructors in the generated Xenon-only AltiVec include, retaining their declarations/IDs. Define their concrete semantics in one small included SLEIGH file. Verify isolated instruction fixtures and the existing kernel without changing its bytes or language ID.

**Tech Stack:** Ghidra12.1.3, SLEIGH, Java21, Gradle9.3.1, Python unittest.

**Spec:** `docs/classic-vmx-vd-semantics-20261026.md`.

## Global Constraints

- Native execution in this session; no agents or worktrees.
- Four constructors only: vand,vsrw,vcmpequw,vcmpequw.; stock Ghidra untouched.
- Keep instruction masks, userop IDs, language ID and all existing kernel bytes/metadata.
- Normal checkpoint commits/pushes to existing branches; no history rewrite.

## Review Focus

- Alltrue, none and mixed lane matches update onlyrecord-form CR6.
- Destination/source aliases use original operands.
- Word shifts use unsigned lanes and lowfive shift bits, including0/31/32/63/FFFFFFFF inputs.
- Generated include fails closed if upstream constructor layout changes.
- Private fixture memory/instructions roll back; old kernel native proofs remain valid.

### Task1: Regression evidence

**Files:** Create `ghidra_scripts/TestXenonClassicVmxNative.java`.

**Interfaces:** CurrentProgram's existing Xenon language; outputdirectory/result.txt with cases,failures and rollback status.

- [x] Write2048 instruction cases spanning fourfamilies, register aliases, random/edge lanes, allCR fields and GPR/vector preservation. Baseline fallback computes opaque output only; never CR6.
- [x] Run against current installed language. Expected: regression fails for stale CR6 and opaque semantics, with fixture rollback proved.

### Task2: Native Xenon-only semantics

**Files:** Create `XEXLoaderWV/data/languages/xenon_classic_vector_v1.sinc`; modify `XEXLoaderWV/build.gradle` and `data/languages/xenon_64_be.slaspec`.

**Interfaces:** Existing vrD/vrA/vrB fields, standard128-bit registers and cr6. Keep declarations/IDs in the inherited include.

- [x] Remove exactlyfour guarded upstream constructors during generation; include concrete constructors with unchanged decode fields.
- [x] Implement AND, perword unsigned shifts and equality; dotform alone writes CR6=(all<<3)|(none<<1).
- [x] Run allPython unittest discovery and `gradle --offline buildExtension`. Expected: alltests and actual SLEIGH compilation pass; existing warnings recorded.

### Task3: Integration and continuation

**Files:** Verification results under `/workspace/kernel-import-audit/vd14/output`; extension README and manifest/provenance in the eventual Vd checkpoint.

**Interfaces:** Private Ghidra copy containing newly built extension; existing archived kernel and unchanged language ID.

- [x] Run the regression in a private install. Expected:2048cases pass, zero opaque fallbacks, exact flags/aliases/preservation and full fixture rollback.
- [x] Run state3/4 native probe without vector callbacks. Expected: native lane selection reaches state5 with the independently predicted normalized nibbles.
- [ ] Review diff myself, install onlythe verified cloud extension, rerun the existing Vd suites and continue state3/4/5 tests and92byte observed-record annotations.
- [ ] Commit/push extension fix and kernel evidence as coherent verified checkpoints; verify remote heads.
