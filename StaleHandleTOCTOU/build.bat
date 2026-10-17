@echo off
setlocal
echo [1/3] Compiling Win32 Resources (resource.rc -> resource.res)...
rc.exe /nologo /fo resource.res resource.rc
if errorlevel 1 (
    echo [!] Resource compilation failed. Run powershell -ExecutionPolicy Bypass -File fix_encodings.ps1 first.
    exit /b 1
)

echo [2/3] Compiling C++17 Source (main.cpp -> StaleHandleBypass.exe)...
cl.exe /nologo /std:c++17 /utf-8 /W4 /O2 /EHsc /DUNICODE /D_UNICODE ^
    main.cpp resource.res ^
    /Fe:StaleHandleBypass.exe ^
    /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib advapi32.lib comctl32.lib
if errorlevel 1 (
    echo [!] C++ compilation failed.
    exit /b 1
)

echo [3/3] Build succeeded: StaleHandleBypass.exe
endlocal
