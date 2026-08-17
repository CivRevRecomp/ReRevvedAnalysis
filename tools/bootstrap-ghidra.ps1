<#
.SYNOPSIS
    Runs the ordered ReRevved Ghidra repair chain on a disposable project.

.DESCRIPTION
    This is the only supported entry point for mutating analysis state. Query
    scripts continue to use run-headless.ps1 with -ReadOnly.

    The disposable project and both output paths are deliberately explicit.
    -Plan validates the guard and prints the exact ordered plan without
    starting Ghidra or writing files.
#>
[CmdletBinding()]
param(
    [Alias('ProjectDir')][string]$DisposableProjectDir,
    [Alias('ProjectName')][string]$DisposableProjectName,
    [Alias('OutputPath')][string]$Out,
    [Parameter(Mandatory = $false)][string]$LogPath,
    [string]$GhidraHome = $env:REREVVED_GHIDRA_HOME,
    [string]$Program = $env:REREVVED_GHIDRA_PROGRAM,
    [string]$CanonicalProjectDir = $env:REREVVED_GHIDRA_PROJECTS,
    [string]$CanonicalProjectName = $env:REREVVED_GHIDRA_PROJECT,
    [string]$JavaHome = $env:REREVVED_GHIDRA_JAVA_HOME,
    [string]$FunctionMap,
    [string]$CodeSeedSites,
    [string]$ConstRefAcceptTarget,
    [string]$ConstRefAcceptSites,
    [string]$ThunkRangeStart,
    [string]$ThunkRangeEnd,
    [string]$MaxMem = '8G',
    [switch]$Plan
)

$ErrorActionPreference = 'Stop'

$repairScripts = @(
    'FixXenonThunks.java',
    'RebuildTruncatedFunctions.java',
    'RecoverSplitConstRefs.java'
)
if (-not [string]::IsNullOrWhiteSpace($CodeSeedSites) -and
    [string]::IsNullOrWhiteSpace($FunctionMap)) {
    throw 'Code seed sites require a generated function map.'
}
if ([string]::IsNullOrWhiteSpace($ConstRefAcceptTarget) -xor
    [string]::IsNullOrWhiteSpace($ConstRefAcceptSites)) {
    throw 'Constant-reference acceptance requires both target and sites.'
}
# FixXenonThunks takes its slot range as script arguments and defaults to one
# block. An image with save/restore thunks in more than one block needs the
# range stated, so it is passed through rather than changing that default.
if ([string]::IsNullOrWhiteSpace($ThunkRangeStart) -xor
    [string]::IsNullOrWhiteSpace($ThunkRangeEnd)) {
    throw 'Thunk range requires both start and end.'
}
if (-not [string]::IsNullOrWhiteSpace($FunctionMap)) {
    $repairScripts = @(
        'FixXenonThunks.java',
        'RebuildTruncatedFunctions.java',
        'SeedGeneratedFunctions.java',
        'RecoverSplitConstRefs.java'
    )
}

function Require-Explicit {
    param([string]$Value, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name is required; do not use the configured canonical project."
    }
    return $Value
}

function Full-Path {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Assert-OutsideSharedTemp {
    param([string]$Path, [string]$What, [switch]$AllowSharedTemp)
    $fullPath = Full-Path $Path
    $tempRoot = (Full-Path ([System.IO.Path]::GetTempPath())) + '\'
    if (-not $AllowSharedTemp -and
        $fullPath.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$What must not use the shared operating-system temp directory: $fullPath"
    }
    return $fullPath
}

if ([string]::IsNullOrWhiteSpace($Program)) { $Program = 'rerevved_image.bin' }
$DisposableProjectDir = Full-Path (Require-Explicit $DisposableProjectDir 'Disposable project directory')
$DisposableProjectName = Require-Explicit $DisposableProjectName 'Disposable project name'
$Out = Assert-OutsideSharedTemp (Require-Explicit $Out 'Output path') 'Output path' -AllowSharedTemp:$Plan
$LogPath = Assert-OutsideSharedTemp (Require-Explicit $LogPath 'Log path') 'Log path' -AllowSharedTemp:$Plan
if ($Out.Equals($LogPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Output path and log path must be different files.'
}

if ((-not [string]::IsNullOrWhiteSpace($CanonicalProjectDir)) -xor
    (-not [string]::IsNullOrWhiteSpace($CanonicalProjectName))) {
    throw 'Canonical project configuration must provide both directory and name.'
}
if (-not [string]::IsNullOrWhiteSpace($CanonicalProjectDir)) {
    $canonicalDir = Full-Path $CanonicalProjectDir
    if ($DisposableProjectDir.Equals($canonicalDir, [System.StringComparison]::OrdinalIgnoreCase) -and
        $DisposableProjectName.Equals($CanonicalProjectName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing the configured canonical project '$CanonicalProjectName' at '$canonicalDir'."
    }
}

$scriptRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'ghidra'
$functionMapPath = if ([string]::IsNullOrWhiteSpace($FunctionMap)) {
    $null
} else {
    Full-Path $FunctionMap
}
$planRecord = [ordered]@{
    Mode = if ($Plan) { 'Plan' } else { 'Execute' }
    ProjectDirectory = $DisposableProjectDir
    ProjectName = $DisposableProjectName
    Program = $Program
    Scripts = $repairScripts
    ScriptPath = $scriptRoot
    Output = $Out
    Log = $LogPath
    MaxMem = $MaxMem
    NoAnalysis = $true
}
if ($functionMapPath) { $planRecord['FunctionMap'] = $functionMapPath }
if (-not [string]::IsNullOrWhiteSpace($CodeSeedSites)) {
    $planRecord['CodeSeedSites'] = $CodeSeedSites
}
if (-not [string]::IsNullOrWhiteSpace($ConstRefAcceptTarget)) {
    $planRecord['ConstRefAcceptTarget'] = $ConstRefAcceptTarget
    $planRecord['ConstRefAcceptSites'] = $ConstRefAcceptSites
}
if (-not [string]::IsNullOrWhiteSpace($ThunkRangeStart)) {
    $planRecord['ThunkRangeStart'] = $ThunkRangeStart
    $planRecord['ThunkRangeEnd'] = $ThunkRangeEnd
}

if ($Plan) {
    $planRecord | ConvertTo-Json -Depth 4
    return
}

if (-not (Test-Path -LiteralPath $GhidraHome -PathType Container)) {
    throw "Ghidra install root not found: $GhidraHome"
}
$headless = Join-Path $GhidraHome 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless -PathType Leaf)) {
    throw "analyzeHeadless.bat not found under $GhidraHome"
}
if (-not (Test-Path -LiteralPath $DisposableProjectDir -PathType Container)) {
    throw "Disposable project directory not found: $DisposableProjectDir"
}
if ($JavaHome -and -not (Test-Path -LiteralPath $JavaHome -PathType Container)) {
    throw "JDK not found: $JavaHome"
}
foreach ($script in $repairScripts) {
    if (-not (Test-Path -LiteralPath (Join-Path $scriptRoot $script) -PathType Leaf)) {
        throw "Repair script not found: $script"
    }
}
if ($functionMapPath -and -not (Test-Path -LiteralPath $functionMapPath -PathType Leaf)) {
    throw "Function map not found: $functionMapPath"
}
$lockFile = Join-Path $DisposableProjectDir "$DisposableProjectName.lock"
if (Test-Path -LiteralPath $lockFile) {
    throw "Disposable project appears locked: $lockFile"
}

$outParent = Split-Path -Parent $Out
$logParent = Split-Path -Parent $LogPath
if ($outParent) { $null = New-Item -ItemType Directory -Force -Path $outParent }
if ($logParent) { $null = New-Item -ItemType Directory -Force -Path $logParent }
Set-Content -LiteralPath $LogPath -Value '' -Encoding UTF8

$oldMutationGuard = [System.Environment]::GetEnvironmentVariable(
    'REREVVED_GHIDRA_MUTATION', 'Process')
$oldJavaHome = [System.Environment]::GetEnvironmentVariable('JAVA_HOME', 'Process')
$oldPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Process')
$oldMaxMem = [System.Environment]::GetEnvironmentVariable('GHIDRA_HEADLESS_MAXMEM', 'Process')
$oldFunctionMap = [System.Environment]::GetEnvironmentVariable(
    'REREVVED_FUNCTION_MAP', 'Process')
$oldCodeSeedSites = [System.Environment]::GetEnvironmentVariable(
    'REREVVED_CODE_SEED_SITES', 'Process')
$oldConstRefTarget = [System.Environment]::GetEnvironmentVariable(
    'REREVVED_CONSTREF_ACCEPT_TARGET', 'Process')
$oldConstRefSites = [System.Environment]::GetEnvironmentVariable(
    'REREVVED_CONSTREF_ACCEPT_SITES', 'Process')
$steps = @()
try {
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_GHIDRA_MUTATION', 'ALLOW_DISPOSABLE_PROJECT', 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'GHIDRA_HEADLESS_MAXMEM', $MaxMem, 'Process')
    if ($functionMapPath) {
        [System.Environment]::SetEnvironmentVariable(
            'REREVVED_FUNCTION_MAP', $functionMapPath, 'Process')
    }
    if (-not [string]::IsNullOrWhiteSpace($CodeSeedSites)) {
        [System.Environment]::SetEnvironmentVariable(
            'REREVVED_CODE_SEED_SITES', $CodeSeedSites, 'Process')
    }
    if (-not [string]::IsNullOrWhiteSpace($ConstRefAcceptTarget)) {
        [System.Environment]::SetEnvironmentVariable(
            'REREVVED_CONSTREF_ACCEPT_TARGET', $ConstRefAcceptTarget, 'Process')
        [System.Environment]::SetEnvironmentVariable(
            'REREVVED_CONSTREF_ACCEPT_SITES', $ConstRefAcceptSites, 'Process')
    }
    if ($JavaHome) {
        [System.Environment]::SetEnvironmentVariable('JAVA_HOME', $JavaHome, 'Process')
        [System.Environment]::SetEnvironmentVariable(
            'PATH', (Join-Path $JavaHome 'bin') + ';' + $oldPath, 'Process')
    }

    foreach ($script in $repairScripts) {
        Add-Content -LiteralPath $LogPath -Value "=== $script ===" -Encoding UTF8
        $headlessArgs = @(
            $DisposableProjectDir, $DisposableProjectName,
            '-process', $Program,
            '-noanalysis',
            '-scriptPath', $scriptRoot,
            '-postScript', $script
        )
        if ($script -eq 'FixXenonThunks.java' -and
            -not [string]::IsNullOrWhiteSpace($ThunkRangeStart)) {
            $headlessArgs += @($ThunkRangeStart, $ThunkRangeEnd)
        }
        $stepOutput = @(& $headless @headlessArgs 2>&1)
        $exitCode = $LASTEXITCODE
        $stepOutput | ForEach-Object { ([string]$_).Replace([string][char]0, '') } |
            Add-Content -LiteralPath $LogPath -Encoding UTF8
        $steps += [ordered]@{ Script = $script; ExitCode = $exitCode }
        if ($exitCode -ne 0) {
            throw "Ghidra repair failed in $script with exit code $exitCode. See $LogPath"
        }
        $scriptFailure = $stepOutput -match `
            'SCRIPT ERROR|Abort due to Headless analyzer error'
        if ($scriptFailure) {
            throw "Ghidra reported a script failure in $script. See $LogPath"
        }
    }
    $planRecord['Steps'] = $steps
    $planRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Out -Encoding UTF8
}
finally {
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_GHIDRA_MUTATION', $oldMutationGuard, 'Process')
    [System.Environment]::SetEnvironmentVariable('JAVA_HOME', $oldJavaHome, 'Process')
    [System.Environment]::SetEnvironmentVariable('PATH', $oldPath, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'GHIDRA_HEADLESS_MAXMEM', $oldMaxMem, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_FUNCTION_MAP', $oldFunctionMap, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_CODE_SEED_SITES', $oldCodeSeedSites, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_CONSTREF_ACCEPT_TARGET', $oldConstRefTarget, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'REREVVED_CONSTREF_ACCEPT_SITES', $oldConstRefSites, 'Process')
}
