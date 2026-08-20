# Headless Ghidra workflow

All Ghidra access uses the repository drivers. Read-only queries use
`tools\run-headless.ps1` and must pass `-ReadOnly`. The repair chain uses
`tools\bootstrap-ghidra.ps1` and always targets a disposable project.

Set the local environment once per shell:

```powershell
$env:REREVVED_GHIDRA_HOME = '<ghidra-root>'
$env:REREVVED_GHIDRA_PROJECTS = '<canonical-project-directory>'
$env:REREVVED_GHIDRA_PROJECT = '<canonical-project-name>'
$env:REREVVED_GHIDRA_PROGRAM = 'rerevved_image.bin'
$env:REREVVED_GHIDRA_JAVA_HOME = '<jdk-root>'
```

The canonical project is query-only. To repair a fresh image, first make an
explicit disposable project copy and supply dedicated output and log paths:

```powershell
$disposable = '<disposable-project-directory>'
$bootstrapOut = '<ignored-bootstrap-scratch>\repair-result.json'
$bootstrapLog = '<ignored-bootstrap-scratch>\repair.headless.log'
tools\bootstrap-ghidra.ps1 `
  -DisposableProjectDir $disposable `
  -DisposableProjectName '<disposable-project-name>' `
  -Out $bootstrapOut `
  -LogPath $bootstrapLog
```

For a ReXGlue image, also supply its generated function map and any exact code
sites that must be decoded even when a Xenon-only instruction interrupts normal
PowerPC flow:

```powershell
tools\bootstrap-ghidra.ps1 `
  -DisposableProjectDir $disposable `
  -DisposableProjectName '<disposable-project-name>' `
  -FunctionMap '<generated-init.cpp>' `
  -CodeSeedSites '0x8269CAE0,0x8269CAE4' `
  -ConstRefAcceptTarget '0x821B15C0' `
  -ConstRefAcceptSites '0x82DAB144,0x82DAB14C,0x82DAB154' `
  -Out $bootstrapOut `
  -LogPath $bootstrapLog
```

The generated-image chain runs `FixXenonThunks.java`,
`RebuildTruncatedFunctions.java`, `SeedGeneratedFunctions.java`, then
`RecoverSplitConstRefs.java`. Use `-Plan` with the same explicit paths to
validate the guard and print the order without starting Ghidra or writing files.

The machine-local program is the separately imported supported image pinned by
`manifests/image.json`. Flat images and all Ghidra projects stay outside this
repository.

Batch-decompile a narrow function set with callers and callees:

```powershell
$queryScratch = '<ignored-query-scratch>'
$null = New-Item -ItemType Directory -Force -Path $queryScratch
tools\run-headless.ps1 -Script DumpFunctions.java -ReadOnly `
  -Out (Join-Path $queryScratch 'rerevved-functions.txt') `
  -ScriptEnv @{ REREVVED_TARGET_VAS = '0x821F2CA0,0x821F6B30' }
```

Find uses of a structure offset inside a bounded function set:

```powershell
tools\run-headless.ps1 -Script FindFieldRefs.java -ReadOnly `
  -Out (Join-Path $queryScratch 'rerevved-field-refs.txt') `
  -ScriptEnv @{
    REREVVED_FIELD_OFFSETS = '0x28'
    REREVVED_FUNCTION_VAS = '0x821F2CA0,0x821F6B30,0x821F4948,0x822688C0'
  }
```

Classify accesses while expanding through direct callers:

```powershell
tools\run-headless.ps1 -Script FindFieldAccesses.java -ReadOnly `
  -Out (Join-Path $queryScratch 'rerevved-field-accesses.txt') `
  -ScriptEnv @{
    REREVVED_FIELD_OFFSETS = '0x28'
    REREVVED_SEED_VAS = '0x821F2CA0,0x822688C0'
    REREVVED_CALLER_DEPTH = '2'
  }
```

Trace an indirect entry point back to a dispatch table or address materializer:

```powershell
tools\run-headless.ps1 -Script DumpReferences.java -ReadOnly `
  -Out (Join-Path $queryScratch 'rerevved-references.txt') `
  -ScriptEnv @{ REREVVED_TARGET_VAS = '0x821FBC38' }
```

## Function fingerprint comparison

Export each independently identified Ghidra program to JSON Lines. Change the
configured project and program between source and target runs:

```powershell
tools\run-headless.ps1 -Script ExportFunctionFingerprints.java -ReadOnly `
  -Out (Join-Path $queryScratch 'source-functions.jsonl')

tools\run-headless.ps1 -Script ExportFunctionFingerprints.java -ReadOnly `
  -Out (Join-Path $queryScratch 'target-functions.jsonl')
```

ReXGlue generated output can supply an independent instruction-text corpus:

```powershell
python tools\export-generated-fingerprints.py `
  --generated-dir '<generated-directory>' `
  --prefix '<generated-prefix>' `
  --out (Join-Path $queryScratch 'generated-functions.jsonl')
```

Match only exports from the same fingerprint algorithm:

```powershell
python tools\match-version-functions.py `
  --source (Join-Path $queryScratch 'source-functions.jsonl') `
  --target (Join-Path $queryScratch 'target-functions.jsonl') `
  --out (Join-Path $queryScratch 'function-matches.json')
```

The matcher rejects different exporter algorithms, caps heuristic pools at 256,
rejects tied candidates, and demotes many-source-to-one-target collisions. An
exact or strong result is an identity candidate, not sufficient evidence for a
semantic claim. Re-query the target program, compare the bounded generated body
when available, and promote only the supported fact. Fingerprint streams,
reports, and headless logs remain ignored scratch and are deleted after the
supported facts enter a topic manifest.

When a promoted packet depends on another current packet, list that topic under
`dependencies`. The [topic manifest contract](topic-manifests.md) defines the
resolving topic and current-evidence rules. Each dependent packet still carries
the current-image locators required to support its claim.

Promote only compact findings into `manifests/`. Keep query output and
headless logs in a dedicated ignored scratch directory outside the shared
operating-system temp directory. For a behavioral claim, compare a narrow
generated C++ window and confirm it with a default-off runtime probe.
