# Ghidra scripts

Read-only scripts run through `tools\run-headless.ps1` with `-ReadOnly`.
Query output and logs belong in an ignored scratch directory.

## Script index

This index covers every Java script in this directory.

- `DumpDataValues.java` prints defined data values at selected guest VAs.
- `ExportFunctionFingerprints.java` exports deterministic function fingerprints as JSON Lines.
- `DumpFunctionNeighborhood.java` dumps exact function boundaries around selected addresses.
- `DumpFunctionNeighborhoodBatch.java` dumps bounded neighborhoods for multiple targets.
- `DumpFunctions.java` batches decompilation with caller and callee lists.
- `DumpInstructions.java` prints bounded instruction windows from selected guest VAs.
- `DumpMemoryWords.java` prints bounded big-endian word windows around selected guest VAs.
- `DumpReferences.java` lists code and data references to selected guest VAs.
- `DumpStringBoundary.java` dumps exact string references and a bounded native closure.
- `DumpStringsInRange.java` prints defined strings inside one bounded guest address range.
- `FindCallConstantArgs.java` finds direct calls whose nearest selected argument write is a requested immediate constant.
- `FindFieldAccesses.java` classifies reads and writes inside selected functions and an optional caller closure.
- `FindFieldRefs.java` finds PowerPC register-plus-displacement operands for selected offsets.
- `FindPointerValues.java` finds exact aligned 32-bit pointer values in initialized guest memory.
- `FindStrings.java` finds capped, case-insensitive substrings in defined guest strings.
- `FixXenonThunks.java` repairs undecodable Xenon VMX128 thunk slots.
- `RebuildTruncatedFunctions.java` rebuilds functions whose last instruction is a call.
- `RecoverSplitConstRefs.java` reruns the PowerPC constant-reference analyzer.
- `SeedGeneratedFunctions.java` seeds code and functions from a ReXGlue generated map.

The repair scripts are mutating and are not query post-scripts. Run them only
as the ordered chain through `tools\bootstrap-ghidra.ps1`. A generated function
map and optional code-seed sites restore code coverage after structural repair:

1. `FixXenonThunks.java`
2. `RebuildTruncatedFunctions.java`
3. `SeedGeneratedFunctions.java` (optional)
4. `RecoverSplitConstRefs.java`

The constant-reference acceptance target and sites default to the current
version 1.3 program. Pass both overrides together for a different image.

The bootstrap requires an explicit disposable project and refuses the project
configured by `REREVVED_GHIDRA_PROJECTS` and `REREVVED_GHIDRA_PROJECT`.
