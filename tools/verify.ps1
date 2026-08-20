[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = New-Object 'System.Collections.Generic.List[string]'

function Add-Failure([string]$Message) {
    [void]$failures.Add($Message)
}

function Relative-Path([string]$Path) {
    return $Path.Substring($repo.Length + 1).Replace('\', '/')
}

try {
    $tracked = @(git -C $repo ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) {
        throw 'git ls-files returned no tracked files'
    }
} catch {
    Add-Failure "tracked file listing failed: $($_.Exception.Message)"
    $tracked = @()
}

# Include all present tracked and nonignored untracked files so pre-stage checks
# cover the same candidate content that CI will inspect after commit.
$trackedPaths = @($tracked | ForEach-Object { Join-Path $repo $_ } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
foreach ($input in @(
    (Join-Path $repo 'schemas/common.schema.json'),
    (Join-Path $repo 'tools/catalog_validator.py'),
    (Join-Path $repo 'tools/verify.ps1'),
    (Join-Path $repo 'tests/test_catalog_validator.py'),
    (Join-Path $repo '.github/workflows/checks.yml')
)) {
    if ((Test-Path -LiteralPath $input -PathType Leaf) -and
        $trackedPaths -notcontains $input) {
        $trackedPaths += $input
    }
}

# Parse every tracked JSON file, including schemas and catalog data.
$jsonFiles = @($trackedPaths | Where-Object { $_ -match '(?i)\.json$' })
foreach ($file in $jsonFiles) {
    try {
        $null = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Add-Failure "JSON parse failed: $(Relative-Path $file): $($_.Exception.Message)"
    }
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Add-Failure 'python executable is required for schema, AST, and unit-test checks'
} else {
    $validatorArgs = @(
        (Join-Path $repo 'tools/catalog_validator.py'),
        '--repo',
        $repo
    )
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $validatorOutput = @(& $python.Source @validatorArgs 2>&1)
        $validatorExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($validatorExitCode -ne 0) {
        Add-Failure "catalog validation failed: $($validatorOutput -join ' ')"
    }

    $referenceArgs = @(
        (Join-Path $repo 'tools/reference_data.py')
    )
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $referenceOutput = @(& $python.Source @referenceArgs 2>&1)
        $referenceExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($referenceExitCode -ne 0) {
        Add-Failure "reference data validation failed: $($referenceOutput -join ' ')"
    }

    $pythonFiles = @($trackedPaths | Where-Object { $_ -match '(?i)\.py$' })
    if ($pythonFiles.Count -eq 0) {
        Add-Failure 'no tracked Python files found'
    } else {
        $astCode = @'
import ast, pathlib, sys
for name in sys.argv[1:]:
    if name == chr(45) * 2:
        continue
    ast.parse(pathlib.Path(name).read_bytes().decode(), filename=name)
'@
        $savedErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $astOutput = @(& $python.Source -c $astCode -- $pythonFiles 2>&1)
            $astExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorAction
        }
        if ($astExitCode -ne 0) {
            Add-Failure "Python AST parse failed: $($astOutput -join ' ')"
        }
    }

    $testArgs = @(
        '-B', '-m', 'unittest', 'discover',
        '-s', (Join-Path $repo 'tests'),
        '-p', 'test_*.py'
    )
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $testOutput = @(& $python.Source @testArgs 2>&1)
        $testExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($testExitCode -ne 0) {
        Add-Failure "Python tests failed: $($testOutput -join ' ')"
    }
}

# Parse every tracked PowerShell file with the native language parser.
$psFiles = @($trackedPaths | Where-Object { $_ -match '(?i)\.ps1$' })
$parser = [System.Management.Automation.Language.Parser]
foreach ($file in $psFiles) {
    try {
        $tokens = $null
        $errors = $null
        $null = $parser::ParseFile($file, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw $errors[0].Message }
    } catch {
        Add-Failure "PowerShell AST parse failed: $(Relative-Path $file): $($_.Exception.Message)"
    }
}

# Validate local Markdown links against the tracked checkout.
$markdownFiles = @($trackedPaths | Where-Object { $_ -match '(?i)\.md$' })
foreach ($file in $markdownFiles) {
    $markdown = Get-Content -LiteralPath $file -Raw -Encoding UTF8
    foreach ($match in [regex]::Matches($markdown, '\]\(([^)]*)\)')) {
        $target = $match.Groups[1].Value.Trim()
        if (-not $target -or $target -match '^(?i)(https?|mailto):' -or
            $target.StartsWith('#')) {
            continue
        }
        $target = ($target -split '\s+', 2)[0].Trim('<', '>')
        $target = ($target -split '#', 2)[0]
        if (-not $target) { continue }
        try { $target = [Uri]::UnescapeDataString($target) } catch { }
        $candidate = Join-Path (Split-Path -Parent $file) $target
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Add-Failure "Markdown link missing: $(Relative-Path $file) -> $target"
        }
    }
}

# Tracked source is ASCII so byte-oriented tools remain deterministic.
foreach ($file in $trackedPaths) {
    try {
        foreach ($byte in [IO.File]::ReadAllBytes($file)) {
            if ($byte -gt 127) {
                throw "non-ASCII byte 0x$('{0:X2}' -f $byte)"
            }
        }
    } catch {
        Add-Failure "ASCII check failed: $(Relative-Path $file): $($_.Exception.Message)"
    }
}

# Every Java query script must appear exactly once in the Ghidra index.
try {
    $ghidraDir = Join-Path $repo 'ghidra'
    $javaFiles = @($trackedPaths | Where-Object {
        $_ -match '(?i)[\\/]ghidra[\\/][^\\/]+\.java$'
    } | ForEach-Object { Split-Path -Leaf $_ } | Sort-Object -Unique)
    $indexText = Get-Content -LiteralPath (Join-Path $ghidraDir 'README.md') -Raw
    $listedScripts = @([regex]::Matches($indexText,
        '(?m)^- `([^`]+\.java)`') | ForEach-Object { $_.Groups[1].Value } |
        Sort-Object)
    $missingIndex = @($javaFiles | Where-Object { $listedScripts -notcontains $_ })
    $missingScript = @($listedScripts | Where-Object { $javaFiles -notcontains $_ })
    if ($missingIndex.Count -gt 0) {
        Add-Failure "Ghidra index missing: $($missingIndex -join ', ')"
    }
    if ($missingScript.Count -gt 0) {
        Add-Failure "Ghidra index lists missing script: $($missingScript -join ', ')"
    }
    if ($listedScripts.Count -ne ($listedScripts | Sort-Object -Unique).Count) {
        Add-Failure 'Ghidra index contains duplicate script entries'
    }
} catch {
    Add-Failure "Ghidra index check failed: $($_.Exception.Message)"
}

# Repository hygiene is evaluated from tracked paths, so private assets never
# become a prerequisite for this lightweight gate.
$forbidden = @($tracked | Where-Object {
    $_ -match '(^|/)(private|generated|artifacts|logs|out|scratch|temp|tmp)/' -or
    $_ -match '(?i)\.(bin|iso|xex|xexp|exe|dll|pdb|idb|i64|gpr|gzf)$'
})
if ($forbidden.Count -gt 0) {
    Add-Failure "Forbidden tracked path: $($forbidden -join ', ')"
}

# Check both worktree and index whitespace errors without changing git state.
foreach ($cached in @($false, $true)) {
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($cached) {
            $diffOutput = @(& git -C $repo diff --cached --check 2>&1)
        } else {
            $diffOutput = @(& git -C $repo diff --check 2>&1)
        }
        $diffExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($diffExitCode -ne 0) {
        $label = if ($cached) { 'cached git diff' } else { 'git diff' }
        Add-Failure "$label check failed: $($diffOutput -join ' ')"
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Error $failure }
    exit 1
}

$summary = "verify: passed JSON={0} PythonAST={1} PythonTests=1 ReferenceData=1 " +
    "PowerShellAST={2} MarkdownLinks={3} ASCII=1 GhidraIndex=1 " +
    "repository-hygiene=1 git-diff=1 cached-diff=1"
Write-Output ($summary -f
    $jsonFiles.Count, $pythonFiles.Count, $psFiles.Count, $markdownFiles.Count)
