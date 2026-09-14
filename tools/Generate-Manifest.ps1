#Requires -Version 5.1
<#
.SYNOPSIS
    Generates update_manifest.json with SHA256 hashes for incremental updates
.DESCRIPTION
    Reads version.txt and creates manifest with file hashes.
    Only files listed in $FilesToTrack will be included.
    Run this after each update before committing.
.EXAMPLE
    .\tools\Generate-Manifest.ps1
    .\tools\Generate-Manifest.ps1 -Version "1.0.9"
#>
param(
    [string]$Version = "",
    [string]$Repo = "hodakaram1/masrt",
    [string]$Branch = "main"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

if (-not $Version) {
    if (Test-Path "$Root\version.txt") {
        $Version = (Get-Content "$Root\version.txt" -Raw).Trim()
    } else {
        $Version = "1.0.0"
    }
}

Write-Host "Generating manifest for version $Version ..." -ForegroundColor Cyan

$RawBase = "https://raw.githubusercontent.com/$Repo/$Branch/"

# Files to track for incremental update - only source/project files that change often
$FilesToTrack = @(
    "version.txt",
    "Imno/Version.h",
    "Imno/Imno.h",
    "Imno/Imno.cpp",
    "Imno/MemoryView.h",
    "Imno/MemoryView.cpp",
    "Imno/Imno.vcxproj",
    "Imno/Imno.vcxproj.filters",
    "Imno/Resource.h",
    "DBKKernel/DBKKernel.vcxproj",
    "build.bat",
    "update.bat",
    "update_manifest.json",
    "README.md"
)

$ManifestFiles = @()

foreach ($relPath in $FilesToTrack) {
    $fullPath = Join-Path $Root $relPath
    if (Test-Path $fullPath) {
        $hash = (Get-FileHash $fullPath -Algorithm SHA256).Hash.ToLower()
        $size = (Get-Item $fullPath).Length
        $type = "source"
        if ($relPath -like "*.vcxproj*") { $type = "project" }
        elseif ($relPath -like "*.bat") { $type = "script" }
        elseif ($relPath -eq "version.txt") { $type = "version" }
        elseif ($relPath -like "*.md") { $type = "doc" }

        $ManifestFiles += [PSCustomObject]@{
            path = $relPath.Replace('\','/')
            sha256 = $hash
            size = $size
            type = $type
        }
        Write-Host "  [OK] $relPath -> $hash" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] $relPath not found" -ForegroundColor Yellow
    }
}

$Manifest = [PSCustomObject]@{
    version = $Version
    branch = $Branch
    repo = $Repo
    raw_base = $RawBase
    generated = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    description = "Imno - DBK64 Kernel Clone - Incremental update manifest. Only changed files will be downloaded by update.bat"
    files = $ManifestFiles
    binaries = @(
        [PSCustomObject]@{ path = "x64/Release/Imno.exe"; type = "binary"; note = "Built via build.bat after source update" },
        [PSCustomObject]@{ path = "x64/Release/DBK64.sys"; type = "binary"; note = "Driver - requires signing" }
    )
}

$JsonPath = Join-Path $Root "update_manifest.json"
$Manifest | ConvertTo-Json -Depth 5 | Set-Content $JsonPath -Encoding UTF8

Write-Host "`nManifest generated at $JsonPath" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor White
Write-Host "Files tracked: $($ManifestFiles.Count)" -ForegroundColor White

# Also update Imno/Version.h automatically
$VersionHPath = Join-Path $Root "Imno/Version.h"
if (Test-Path $VersionHPath) {
    $parts = $Version.Split('.')
    $major = if ($parts.Count -gt 0) { $parts[0] } else { "1" }
    $minor = if ($parts.Count -gt 1) { $parts[1] } else { "0" }
    $patch = if ($parts.Count -gt 2) { $parts[2] } else { "0" }
    
    $versionHContent = @"
#pragma once

// Auto-generated version - update version.txt and run tools/Generate-Manifest.ps1
#define IMNO_VERSION_MAJOR $major
#define IMNO_VERSION_MINOR $minor
#define IMNO_VERSION_PATCH $patch

#define IMNO_VERSION_STRING "$Version"
#define IMNO_VERSION_WSTRING L"$Version"

#define IMNO_VERSION_FULL "Imno v$Version - DBK64 Kernel Clone (Memory Scanner Normal + Memory View CE Full)"
#define IMNO_VERSION_FULL_W L"Imno v$Version - DBK64 Kernel Clone (Memory Scanner Normal + Memory View CE Full)"

// For resource version info
#define IMNO_VERSION_FILEVERSION $major,$minor,$patch,0
#define IMNO_VERSION_PRODUCTVERSION $major,$minor,$patch,0
"@
    $versionHContent | Set-Content $VersionHPath -Encoding UTF8
    Write-Host "Updated $VersionHPath" -ForegroundColor Green
}

Write-Host "`nDone! Commit version.txt, Imno/Version.h and update_manifest.json" -ForegroundColor Cyan
