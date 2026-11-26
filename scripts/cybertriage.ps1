[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('configure', 'build', 'import-data', 'start', 'stop', 'status', 'logs')]
    [string]$Action,
    [switch]$Graph
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$environmentPath = Join-Path $projectRoot '.env.docker.local'
$composePath = Join-Path $projectRoot 'compose.yaml'

function Write-SecretOnce([string]$Path, [string]$Prompt, [bool]$Generate = $false) {
    if (Test-Path -LiteralPath $Path) {
        Write-Host "Keeping existing secret file: $([IO.Path]::GetFileName($Path))"
        return
    }
    $clearValue = $null
    $pointer = [IntPtr]::Zero
    try {
        if ($Generate) {
            $bytes = New-Object byte[] 32
            $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
            $clearValue = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        } else {
            $secureValue = Read-Host $Prompt -AsSecureString
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
            $clearValue = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        }
        if ([string]::IsNullOrEmpty($clearValue) -or $clearValue.Length -gt 4096 -or $clearValue -match '[\x00-\x1f]') {
            throw 'A nonempty single-line credential is required.'
        }
        if ($Path.EndsWith('ingestion.token') -and ($clearValue.Length -lt 32 -or $clearValue.Length -gt 512 -or $clearValue -match '[^\x21-\x7e]')) {
            throw 'The ingestion token must contain 32-512 non-whitespace ASCII characters.'
        }
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($clearValue)
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    } finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $clearValue = $null
    }
}

if ($Action -eq 'configure') {
    if (-not (Test-Path -LiteralPath $environmentPath)) {
        Copy-Item -LiteralPath (Join-Path $projectRoot '.env.docker.example') -Destination $environmentPath
        $modelsDirectory = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ollama/models').Replace('\', '/')
        $environmentText = [IO.File]::ReadAllText($environmentPath).Replace('C:/Users/YOUR_USERNAME/.ollama/models', $modelsDirectory)
        [IO.File]::WriteAllText($environmentPath, $environmentText, (New-Object Text.UTF8Encoding($false)))
    }
    $secretsDirectory = Join-Path $projectRoot 'config/secrets'
    $certsDirectory = Join-Path $projectRoot 'config/certs'
    New-Item -ItemType Directory -Force -Path $secretsDirectory, $certsDirectory | Out-Null
    Write-SecretOnce (Join-Path $secretsDirectory 'ingestion.token') 'Existing ingestion token configured in Wazuh'
    Write-SecretOnce (Join-Path $secretsDirectory 'indexer.password') 'Read-only Indexer password'
    Write-SecretOnce (Join-Path $secretsDirectory 'neo4j.password') '' $true
    Write-Host 'Local configuration created; existing files were retained.'
    Write-Host 'Edit .env.docker.local and copy the public Indexer CA to config/certs/indexer-ca.pem.'
    Write-Host 'Keep the configured analysts.local.yaml with its existing credential hashes.'
    exit 0
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker Desktop is required.' }
if (-not (Test-Path -LiteralPath $environmentPath)) { throw 'Run this script with configure first.' }
$composeArguments = @('compose', '--env-file', $environmentPath, '-f', $composePath)
if ($Graph -or $Action -in @('stop', 'status', 'logs')) { $composeArguments += @('--profile', 'graph') }

Push-Location $projectRoot
try {
    switch ($Action) {
        'build' { & docker @composeArguments build }
        'import-data' {
            & docker @composeArguments run --rm --no-deps bootstrap
            if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed. No import was attempted.' }
            & docker @composeArguments --profile maintenance run --rm --no-deps import-data
        }
        'start' {
            & docker @composeArguments up --build -d --wait --wait-timeout 300
            if ($LASTEXITCODE -eq 0) { Write-Host 'Local services are running. Use status for current health; the web port is configured in .env.docker.local (default http://127.0.0.1:5173).' }
        }
        'stop' { & docker @composeArguments down --timeout 210 }
        'status' { & docker @composeArguments ps --all }
        'logs' { & docker @composeArguments logs --tail 100 --follow }
    }
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed (exit $LASTEXITCODE). Inspect service logs; configuration and volumes were retained." }
} finally {
    Pop-Location
}
