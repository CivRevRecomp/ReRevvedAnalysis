<#
.SYNOPSIS
    Runs a Ghidra headless post-script against the analyzed guest image.

.DESCRIPTION
    Required environment, or matching parameters:
      REREVVED_GHIDRA_HOME
      REREVVED_GHIDRA_PROJECTS
      REREVVED_GHIDRA_PROJECT
    Optional:
      REREVVED_GHIDRA_PROGRAM       default rerevved_image.bin
      REREVVED_GHIDRA_JAVA_HOME     JDK root

    Query scripts must pass -ReadOnly. Run in the foreground. Query output and
    process logs must use a dedicated scratch directory outside the shared
    operating-system temp directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Script,
    [string[]]$ScriptPath,
    [hashtable]$ScriptEnv = @{},
    [string[]]$ScriptArgs,
    [string]$Out,
    [switch]$ReadOnly,
    [switch]$Analyze,
    [string]$GhidraHome = $env:REREVVED_GHIDRA_HOME,
    [string]$ProjectDir = $env:REREVVED_GHIDRA_PROJECTS,
    [string]$ProjectName = $env:REREVVED_GHIDRA_PROJECT,
    [string]$Program = $env:REREVVED_GHIDRA_PROGRAM,
    [string]$JavaHome = $env:REREVVED_GHIDRA_JAVA_HOME,
    [string]$MaxMem = '8G',
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

function Require-Value {
    param([string]$Value, [string]$EnvName, [string]$What)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$What not set. Set `$env:$EnvName or pass the matching parameter."
    }
    return $Value
}

function Assert-OutsideSharedTemp {
    param([string]$Path, [string]$What)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $tempRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()
    ).TrimEnd('\') + '\'
    if ($fullPath.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$What must not use the shared operating-system temp directory: $fullPath"
    }
    return $fullPath
}

$GhidraHome = Require-Value $GhidraHome 'REREVVED_GHIDRA_HOME' 'Ghidra install root'
$ProjectDir = Require-Value $ProjectDir 'REREVVED_GHIDRA_PROJECTS' 'Ghidra project directory'
$ProjectName = Require-Value $ProjectName 'REREVVED_GHIDRA_PROJECT' 'Ghidra project name'
if ([string]::IsNullOrWhiteSpace($Program)) { $Program = 'rerevved_image.bin' }

$headless = Join-Path $GhidraHome 'support\analyzeHeadless.bat'
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $GhidraHome" }
if (-not (Test-Path $ProjectDir)) { throw "Project directory not found: $ProjectDir" }
if ($JavaHome -and -not (Test-Path $JavaHome)) { throw "JDK not found: $JavaHome" }

if (-not $ScriptPath) { $ScriptPath = @(Join-Path (Split-Path -Parent $PSScriptRoot) 'ghidra') }
$resolved = $null
foreach ($dir in $ScriptPath) {
    $candidate = Join-Path $dir $Script
    if (Test-Path $candidate) { $resolved = $candidate; break }
}
if (-not $resolved) { throw "Post-script '$Script' not found in: $($ScriptPath -join '; ')" }

$lockFile = Join-Path $ProjectDir "$ProjectName.lock"
if ((Test-Path $lockFile) -and
    ((Get-Process javaw, java -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)) {
    Write-Warning "$ProjectName appears locked by a running Ghidra instance."
}

if ($Out) {
    $Out = Assert-OutsideSharedTemp $Out 'Query output'
    $ScriptEnv['REREVVED_DUMP_PATH'] = $Out
}
if (-not $LogPath) {
    if (-not $Out) {
        throw 'Set -Out or -LogPath to a dedicated query scratch path.'
    }
    $LogPath = [System.IO.Path]::ChangeExtension($Out, '.headless.log')
}
$LogPath = Assert-OutsideSharedTemp $LogPath 'Headless log'

$saved = @{}
$applied = @{
    'GHIDRA_HEADLESS_MAXMEM' = $MaxMem
    'GHIDRA_JAVA_OPTIONS' = '-Dlog4j.skipJansi=true'
}
if ($JavaHome) {
    $applied['JAVA_HOME'] = $JavaHome
    $applied['PATH'] = (Join-Path $JavaHome 'bin') + ';' + $env:PATH
}
foreach ($key in $ScriptEnv.Keys) { $applied[$key] = [string]$ScriptEnv[$key] }

$headlessArgs = @($ProjectDir, $ProjectName, '-process', $Program)
if (-not $Analyze) { $headlessArgs += '-noanalysis' }
if ($ReadOnly) { $headlessArgs += '-readOnly' }
$headlessArgs += @('-scriptPath', ($ScriptPath -join ';'), '-postScript', $Script)
if ($ScriptArgs) { $headlessArgs += $ScriptArgs }

try {
    foreach ($key in $applied.Keys) {
        $saved[$key] = [System.Environment]::GetEnvironmentVariable($key)
        Set-Item -Path "env:$key" -Value $applied[$key]
    }
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    & $headless @headlessArgs *> $LogPath
    $headlessExit = $LASTEXITCODE
    $timer.Stop()
}
finally {
    foreach ($key in $saved.Keys) {
        if ($null -eq $saved[$key]) {
            Remove-Item -Path "env:$key" -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path "env:$key" -Value $saved[$key]
        }
    }
}

$log = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
if ($null -eq $log) { $log = '' }
$status = 'OK'
if ($log -match 'LockException: Unable to lock project') {
    $status = 'LOCKED'
} elseif ($log -match 'SCRIPT ERROR|Abort due to Headless analyzer error') {
    $status = 'SCRIPT_ERROR'
} elseif ($headlessExit -ne 0) {
    $status = 'HEADLESS_ERROR'
}

[pscustomobject]@{
    Script = $Script
    Status = $status
    Seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
    ReadOnly = [bool]$ReadOnly
    Output = $Out
    Log = $LogPath
} | Format-List

if ($status -ne 'OK') {
    Select-String -Path $LogPath -Pattern 'ERROR|Exception' |
        Select-Object -First 8 | ForEach-Object { $_.Line.Trim() }
    exit 1
}
