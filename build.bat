@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "CONFIG=Release"
if /I "%~1"=="Debug"   set "CONFIG=Debug"
if /I "%~1"=="Release" set "CONFIG=Release"
set "PLATFORM=x64"

echo ==========================================
echo   Building DBKKernel driver & Imno GUI
echo   Configuration: %CONFIG% %PLATFORM%
echo ==========================================

REM ---------------------------------------------------------------------
REM  Locate MSBuild.
REM
REM  Prefer vswhere.exe (ships with VS2017+ at a fixed path) so the build
REM  works for any edition (Community/Professional/Enterprise/BuildTools)
REM  and both VS2019 and VS2022. Fall back to the usual install paths if
REM  vswhere is unavailable.
REM ---------------------------------------------------------------------
set "MSBUILD_PATH="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -property installationPath`) do (
        if not defined MSBUILD_PATH if exist "%%i\MSBuild\Current\Bin\amd64\MSBuild.exe" set "MSBUILD_PATH=%%i\MSBuild\Current\Bin\amd64\MSBuild.exe"
        if not defined MSBUILD_PATH if exist "%%i\MSBuild\Current\Bin\MSBuild.exe"     set "MSBUILD_PATH=%%i\MSBuild\Current\Bin\MSBuild.exe"
    )
)

if not defined MSBUILD_PATH (
    for %%P in (
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    ) do if not defined MSBUILD_PATH if exist %%~P set "MSBUILD_PATH=%%~P"
)

if not defined MSBUILD_PATH (
    echo [ERROR] MSBuild.exe could not be found automatically.
    echo         Install Visual Studio 2019 or 2022 with the "Desktop development
    echo         with C++" workload, plus the Windows Driver Kit (WDK) for the
    echo         same Visual Studio version to build the kernel driver.
    goto error
)

REM The user-mode project must use the C++ toolset that matches the detected
REM Visual Studio (v142 = VS2019, v143 = VS2022). The driver always uses its
REM own WindowsKernelModeDriver10.0 toolset, so it is left untouched.
set "IMNO_TOOLSET=v142"
echo "%MSBUILD_PATH%" | findstr /i "2022" >nul && set "IMNO_TOOLSET=v143"

echo Using MSBuild: "%MSBUILD_PATH%"
echo Imno toolset:  %IMNO_TOOLSET%
echo.

REM ---------------------------------------------------------------------
REM  Build the driver first, then the GUI, logging errors to build_error.log.
REM  Each project outputs to its own x64\<Config>\ subfolder; the artifacts
REM  are copied to the top-level x64\<Config>\ folder below so DBK64.sys ends
REM  up next to Imno.exe.
REM ---------------------------------------------------------------------
echo [1/2] Building DBKKernel (kernel driver)...
"%MSBUILD_PATH%" "DBKKernel\DBKKernel.vcxproj" -nologo -p:Configuration=%CONFIG% -p:Platform=%PLATFORM% /v:minimal /fl /flp:LogFile=build_error.log;ErrorsOnly
if %ERRORLEVEL% NEQ 0 goto error

echo [2/2] Building Imno (GUI)...
"%MSBUILD_PATH%" "Imno\Imno.vcxproj" -nologo -p:Configuration=%CONFIG% -p:Platform=%PLATFORM% -p:PlatformToolset=%IMNO_TOOLSET% /v:minimal /fl /flp:LogFile=build_error.log;ErrorsOnly;Append
if %ERRORLEVEL% NEQ 0 goto error

echo.
echo ==========================================
echo   BUILD SUCCESSFUL! (%CONFIG% %PLATFORM%)
echo ==========================================
echo   NOTE: On x64 the driver must be signed before Windows will load it.
echo         Run sign_driver.bat %CONFIG% to test-sign DBK64.sys,
echo         then enable test mode (see README.md).

REM Gather both artifacts into x64\<Config>\ so DBK64.sys sits next to Imno.exe.
REM (Projects built directly drop their output into their own subfolder; a
REM  solution build drops it into the top-level folder. Accept both.)
if not exist "x64\%CONFIG%" mkdir "x64\%CONFIG%"

set "DRIVER_SYS="
if exist "DBKKernel\x64\%CONFIG%\DBK64.sys" set "DRIVER_SYS=DBKKernel\x64\%CONFIG%\DBK64.sys"
if not defined DRIVER_SYS if exist "x64\%CONFIG%\DBK64.sys" set "DRIVER_SYS=x64\%CONFIG%\DBK64.sys"

set "IMNO_EXE="
if exist "Imno\x64\%CONFIG%\Imno.exe" set "IMNO_EXE=Imno\x64\%CONFIG%\Imno.exe"
if not defined IMNO_EXE if exist "x64\%CONFIG%\Imno.exe" set "IMNO_EXE=x64\%CONFIG%\Imno.exe"

if defined DRIVER_SYS (
    copy /Y "%DRIVER_SYS%" "x64\%CONFIG%\DBK64.sys" >nul
    echo Copied DBK64.sys next to Imno.exe
) else (
    echo [INFO] DBK64.sys not found - make sure the DBKKernel project built successfully.
)
if defined IMNO_EXE (
    copy /Y "%IMNO_EXE%" "x64\%CONFIG%\Imno.exe" >nul
)

echo.
echo Output folder: x64\%CONFIG%\
pause
exit /b 0

:error
echo.
echo ==========================================
echo   BUILD FAILED! Check build_error.log for details.
echo ==========================================
if exist build_error.log (
    echo ------------------------------------------
    type build_error.log
    echo ------------------------------------------
)
pause
exit /b 1
