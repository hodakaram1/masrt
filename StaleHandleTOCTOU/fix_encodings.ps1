# ============================================================================
#  fix_encodings.ps1
#  يحوّل كل ملف في المشروع للترميز المطلوب تلقائياً:
#   - يحاول القراءة بترميز UTF-8 الصارم أولاً (أو UTF-16 عند وجود BOM)،
#     وإذا فشل يقرأ النص كـ Windows-1256 (العربية).
#   - يعيد كتابة:
#       resource.rc  -> UTF-16LE (مع BOM) لكي يقرأه rc.exe بدون خطأ RC2135
#       main.cpp     -> UTF-8 with BOM لكي يترجمه cl.exe /utf-8 بدون C4828
#       resource.h   -> ANSI (Windows-1252 / ASCII بدون BOM)
#       build.bat    -> ANSI (بدون BOM حتى لا يفشل CMD)
# ============================================================================

$ErrorActionPreference = "Stop"

function Read-SmartText {
    param([string]$Path)

    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }

    # محاولة UTF-8 الصارم (يرفض أي بايت غير صالح)
    $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        return $utf8Strict.GetString($bytes)
    }
    catch {
        # الرجوع التلقائي إلى ترميز Windows-1256 (العربية)
        $win1256 = [System.Text.Encoding]::GetEncoding(1256)
        return $win1256.GetString($bytes)
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

# 1) resource.rc -> UTF-16LE (Unicode with BOM)
if (Test-Path "resource.rc") {
    $txt = Read-SmartText "resource.rc"
    $utf16le = New-Object System.Text.UnicodeEncoding($false, $true)
    [System.IO.File]::WriteAllText((Join-Path $scriptDir "resource.rc"), $txt, $utf16le)
    Write-Host "[OK] resource.rc -> UTF-16LE (with BOM)" -ForegroundColor Green
}

# 2) main.cpp -> UTF-8 with BOM
if (Test-Path "main.cpp") {
    $txt = Read-SmartText "main.cpp"
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText((Join-Path $scriptDir "main.cpp"), $txt, $utf8Bom)
    Write-Host "[OK] main.cpp    -> UTF-8 with BOM" -ForegroundColor Green
}

# 3) resource.h -> ANSI (no BOM)
if (Test-Path "resource.h") {
    $txt = Read-SmartText "resource.h"
    $ansi = [System.Text.Encoding]::ASCII
    [System.IO.File]::WriteAllText((Join-Path $scriptDir "resource.h"), $txt, $ansi)
    Write-Host "[OK] resource.h  -> ANSI (no BOM)" -ForegroundColor Green
}

# 4) build.bat -> ANSI (no BOM)
if (Test-Path "build.bat") {
    $txt = Read-SmartText "build.bat"
    $ansi = [System.Text.Encoding]::ASCII
    [System.IO.File]::WriteAllText((Join-Path $scriptDir "build.bat"), $txt, $ansi)
    Write-Host "[OK] build.bat   -> ANSI (no BOM)" -ForegroundColor Green
}
