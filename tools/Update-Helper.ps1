#Requires -Version 5.1
param(
    [string]$Manifest = "update_manifest.json.remote",
    [string]$RawBase = "https://raw.githubusercontent.com/hodakaram1/masrt/main/"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

if (-not (Test-Path $Manifest)) {
    Write-Host "[ERROR] Manifest not found: $Manifest" -ForegroundColor Red
    exit 1
}

$manifestJson = Get-Content $Manifest -Raw | ConvertFrom-Json
$remoteVersion = $manifestJson.version
Write-Host "[INFO] Remote manifest version: $remoteVersion" -ForegroundColor Cyan
Write-Host "[INFO] Raw base: $RawBase" -ForegroundColor Gray

$updatedCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($fileEntry in $manifestJson.files) {
    $relPath = $fileEntry.path
    $expectedHash = $fileEntry.sha256
    $fullPath = Join-Path $Root $relPath
    $url = "$RawBase$relPath"

    # If manifest has placeholder hash, skip hash check and always download if version differs (fallback)
    $isPlaceholder = ($expectedHash -eq "placeholder" -or $expectedHash.Length -lt 10)

    $needsUpdate = $true

    if (Test-Path $fullPath) {
        if (-not $isPlaceholder) {
            try {
                $localHash = (Get-FileHash $fullPath -Algorithm SHA256).Hash.ToLower()
                if ($localHash -eq $expectedHash.ToLower()) {
                    $needsUpdate = $false
                }
            } catch {
                $needsUpdate = $true
            }
        } else {
            # Placeholder: we can't know, but if file exists we skip unless it's version.txt/manifest
            if ($relPath -eq "version.txt" -or $relPath -eq "update_manifest.json") {
                $needsUpdate = $true
            } else {
                # For placeholder mode, we still download to be safe? Let's check size diff via remote? Simplify: download
                $needsUpdate = $true
            }
        }
    }

    if (-not $needsUpdate) {
        Write-Host "  [SKIP] $relPath (up to date)" -ForegroundColor DarkGray
        $skippedCount++
        continue
    }

    Write-Host "  [DOWNLOAD] $relPath ..." -ForegroundColor Yellow -NoNewline

    try {
        $dir = Split-Path $fullPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        # Download with Invoke-WebRequest
        Invoke-WebRequest -Uri $url -OutFile $fullPath -UseBasicParsing -TimeoutSec 30

        # Verify hash if not placeholder
        if (-not $isPlaceholder) {
            $newHash = (Get-FileHash $fullPath -Algorithm SHA256).Hash.ToLower()
            if ($newHash -ne $expectedHash.ToLower()) {
                Write-Host " HASH MISMATCH!" -ForegroundColor Red
                Write-Host "    Expected: $expectedHash" -ForegroundColor Red
                Write-Host "    Got:      $newHash" -ForegroundColor Red
                $failedCount++
                continue
            }
        }

        Write-Host " OK" -ForegroundColor Green
        $updatedCount++
    } catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
        $failedCount++
    }
}

Write-Host ""
Write-Host "Summary: Updated=$updatedCount Skipped=$skippedCount Failed=$failedCount" -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-Host "[WARN] Some files failed to update" -ForegroundColor Yellow
    exit 1
}

exit 0
