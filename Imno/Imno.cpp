#include "Imno.h"

#include <cstdarg>
#include <cstdio>

// Direct Link Libraries for D3D11 & DXGI
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "advapi32.lib")

// Smart Pointer Resolver struct (must be before globals)
struct ResolvedPointer {
    ULONG_PTR FinalAddress = 0;
    ULONG64   FinalValue = 0;
    std::string BaseModule;
    ULONG_PTR BaseOffset = 0;
    std::vector<LONG> Offsets;
    bool Success = false;
};

// Globals
HWND g_hWnd = NULL;
GLFWwindow* g_Window = NULL;
HANDLE g_hDriver = INVALID_HANDLE_VALUE;
bool   g_DriverConnected = false;

std::vector<ProcessInfo> g_ProcessList;
std::vector<ModuleInfo>  g_LoadedModules;
ULONG g_SelectedPid = 0;
ULONGLONG g_ProcessConnectTick = 0;
char  g_ProcessConnectTimeStr[32] = "";
char  g_ProcessFilter[64] = "";
char  g_ModuleFilter[64] = "";

// Scan State
int   g_SelectedDataType = 4; // 4 = 4 Bytes
char  g_ScanValueInput[128] = "";
char  g_ScanRangeStart[64] = "0x10000";
char  g_ScanRangeEnd[64] = "0x7FFFFFFFFFFF";
bool  g_UseScanRange = false;
bool  g_AllowUnaligned = false;

std::vector<ULONG_PTR> g_ScanResults;
std::mutex             g_ScanResultsLock;   // guards g_ScanResults between UI and scan workers
std::atomic<bool>      g_IsScanning(false);
std::atomic<int>       g_ScanProgress(0);
std::atomic<bool>      g_ScanTruncated(false);
std::atomic<unsigned>  g_ScanVersion(0);    // bumped whenever results change
int                    g_ResultsDataType = 4; // data type of the results currently shown
bool                   g_SelectedIs64 = true; // bitness of the selected target process

// Cheat Table & Freeze
std::vector<CheatItem> g_CheatTable;
std::mutex g_CheatTableLock;
std::atomic<bool> g_FreezeRunning(true);
std::thread g_FreezeThread;

// Auto-Reconnect Conquer.exe (with automatic 0.5s / 500ms re-attach)
#define CONQUER_REATTACH_DELAY_MS 500ULL
bool                  g_AutoConnectConquer = true;
std::atomic<bool>     g_ConquerWatchRunning(true);
std::thread           g_ConquerWatchThread;
std::mutex            g_ConquerWatchLock;
ULONG                 g_ConquerTrackedPid = 0;
ULONGLONG             g_ConquerConnectTick = 0;
char                  g_ConquerConnectTimeStr[32] = "";
bool                  g_ConquerReattachPending = false;
ULONGLONG             g_ConquerReattachTargetTick = 0;
bool                  g_ConquerReattachedAfterDelay = false;
std::atomic<unsigned> g_ConquerEventSeq(0);
std::atomic<unsigned> g_ConquerReconnectCount(0);

// Pointer Resolver & Assembler Patching
char g_PointerBaseInput[128] = "";
char g_PointerOffsetInput[128] = "0";
ULONG_PTR g_ResolvedAddress = 0;
ULONG64   g_ResolvedValue = 0;
ResolvedPointer g_LastResolved = {};

char g_PatchAddressInput[128] = "";
char g_PatchPatternInput[128] = "0x90, 0x90";

// Kernel tab state
ULONG     g_KernelVersion = 0;
ULONG64   g_KernelCR0 = 0;
ULONG64   g_KernelCR3 = 0;
ULONG64   g_KernelCR4 = 0;
ULONG64   g_KernelMsrValue = 0;
DBK_SEG_TABLE g_KernelIdt = {};
DBK_SEG_TABLE g_KernelGdt = {};
char      g_MsrReadInput[64] = "0xC0000082";   // IA32_LSTAR
char      g_MsrWriteMsr[64] = "0xC0000082";
char      g_MsrWriteValue[64] = "0";
char      g_PhysReadAddr[64] = "0";
char      g_PhysReadSize[64] = "0x100";
char      g_PhysReadDump[8192] = "";
char      g_PhysWriteAddr[64] = "0";
char      g_PhysWriteHex[1024] = "0x90, 0x90";
char      g_AllocNonPagedSize[64] = "0x1000";
ULONG64   g_AllocNonPagedAddr = 0;
char      g_AllocProcessSize[64] = "0x1000";
ULONG64   g_AllocProcessAddr = 0;
ULONG64   g_OpenProcessHandle = 0;
ULONG64   g_PeProcess = 0;
char      g_KernelStatus[256] = "";

// =====================================================================
//  Privilege & Driver Control Helpers
// =====================================================================

// Show a driver status message once, and record it in the Kernel tab log.
static void DriverMessage(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;

    snprintf(g_KernelStatus, sizeof(g_KernelStatus), "%s", buf);
    MessageBoxA(g_hWnd, buf, "DBK64 Driver", MB_ICONWARNING | MB_OK);
}

static const char* DriverWin32ErrorText(DWORD err, char* out, size_t outLen)
{
    out[0] = 0;
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        out, (DWORD)outLen, NULL);
    return out;
}

// Returns true when the current token holds the SeDebugPrivilege, even if
// AdjustTokenPrivileges has not (yet) enabled it. Used to diagnose the
// driver's DispatchCreate access check.
static bool HasSeDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    std::vector<BYTE> buf(needed);
    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)buf.data();

    bool found = false;
    if (GetTokenInformation(hToken, TokenPrivileges, buf.data(), needed, &needed)) {
        LUID seDebug;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &seDebug)) {
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                if (tp->Privileges[i].Luid.LowPart == seDebug.LowPart &&
                    tp->Privileges[i].Luid.HighPart == seDebug.HighPart) {
                    found = true;
                    break;
                }
            }
        }
    }

    CloseHandle(hToken);
    return found;
}

bool EnableSeDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = {};
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // AdjustTokenPrivileges succeeds (with GetLastError()==ERROR_SUCCESS)
    // even when the token does not hold the privilege, so explicitly verify
    // the token actually contains SeDebugPrivilege beforehand.
    bool held = HasSeDebugPrivilege();
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    bool ok = held && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

// Report a failure. `stage` describes where we are, `err` is the last error.
static bool DriverFail(const char* stage, DWORD err)
{
    char etext[512];
    DriverWin32ErrorText(err, etext, sizeof(etext));
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "%s failed (error %lu):\n%s", stage, err, etext);
    DriverMessage("%s", msg);
    return false;
}

// Fill the driver service key A/B/C/D values; the driver reads them in
// DriverEntry (they define the device name, symbolic link and event names).
static bool DriverWriteRegistryValues()
{
    HKEY hKey = NULL;
    DWORD err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, DBK_SERVICE_REG_KEY, 0, KEY_SET_VALUE, &hKey);
    if (err != ERROR_SUCCESS) {
        char etext[512];
        DriverWin32ErrorText(err, etext, sizeof(etext));
        char msg[1024];
        snprintf(msg, sizeof(msg),
            "Could not open the DBK64 service key for writing:\n(error %lu: %s)",
            err, etext);
        DriverMessage("%s", msg);
        return false;
    }

    const WCHAR* vals[4] = { DBK_DEVICE_NAME, DBK_SYMLINK_NAME, DBK_PROCESS_EVENT, DBK_THREAD_EVENT };
    const WCHAR* names[4] = { L"A", L"B", L"C", L"D" };
    for (int i = 0; i < 4; i++) {
        err = RegSetValueExW(hKey, names[i], 0, REG_SZ,
            (const BYTE*)vals[i], (DWORD)((wcslen(vals[i]) + 1) * sizeof(WCHAR)));
        if (err != ERROR_SUCCESS) {
            char etext[512];
            DriverWin32ErrorText(err, etext, sizeof(etext));
            RegCloseKey(hKey);
            char msg[1024];
            snprintf(msg, sizeof(msg), "RegSetValueExW(\"%S\") failed (error %lu):\n%s",
                names[i], err, etext);
            DriverMessage("%s", msg);
            return false;
        }
    }
    RegCloseKey(hKey);
    return true;
}

// Query a service's current status; returns false on failure.
static bool DriverQueryServiceStatus(SC_HANDLE hService, SERVICE_STATUS_PROCESS* out)
{
    DWORD needed = 0;
    QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;
    std::vector<BYTE> buf(needed);
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, buf.data(), needed, &needed))
        return false;
    memcpy(out, buf.data(), sizeof(SERVICE_STATUS_PROCESS));
    return true;
}

static DWORD DriverQueryServiceState(SC_HANDLE hService)
{
    SERVICE_STATUS_PROCESS ssp = {};
    if (!DriverQueryServiceStatus(hService, &ssp))
        return 0;
    return ssp.dwCurrentState;
}

bool LoadAndStartDriver()
{
    WCHAR sysPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH))
        return DriverFail("GetModuleFileNameW", GetLastError());
    wchar_t* lastSlash = wcsrchr(sysPath, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    else return DriverFail("locating the exe folder", ERROR_PATH_NOT_FOUND);
    wcscat_s(sysPath, MAX_PATH, DBK_DRIVER_FILE);

    if (GetFileAttributesW(sysPath) == INVALID_FILE_ATTRIBUTES) {
        char msg[1024];
        snprintf(msg, sizeof(msg),
            "DBK64.sys not found next to Imno.exe.\nExpected: %S\n"
            "Rebuild with build.bat (Release x64) so the driver is copied beside the exe.",
            sysPath);
        DriverMessage("%s", msg);
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return DriverFail("OpenSCManagerW (run Imno as Administrator)", GetLastError());

    SC_HANDLE hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hService) {
        DWORD err = GetLastError();
        // If the previous run just deleted the service, the SCM may still be
        // finishing the deletion (ERROR_SERVICE_MARKED_FOR_DELETE). Wait for it
        // to complete and retry.
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            for (int i = 0; i < 100; i++) {
                Sleep(100);
                hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS);
                if (hService) break;
                err = GetLastError();
                if (err != ERROR_SERVICE_MARKED_FOR_DELETE && err != ERROR_SERVICE_DOES_NOT_EXIST)
                    break;
            }
        }
        if (!hService && err == ERROR_SERVICE_DOES_NOT_EXIST) {
            hService = CreateServiceW(
                hSCM, DBK_SERVICE_NAME, DBK_SERVICE_NAME,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, sysPath,
                NULL, NULL, NULL, NULL, NULL);
            if (!hService) {
                CloseServiceHandle(hSCM);
                return DriverFail("CreateServiceW (DBK64)", GetLastError());
            }
        } else if (!hService) {
            CloseServiceHandle(hSCM);
            return DriverFail("OpenServiceW (DBK64)", err);
        }
    }

    // Always point the service at our DBK64.sys next to Imno.exe.
    if (!ChangeServiceConfigW(hService, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, sysPath, NULL, NULL, NULL, NULL, NULL, DBK_SERVICE_NAME)) {
        DWORD err = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return DriverFail("ChangeServiceConfigW (DBK64 image path)", err);
    }

    if (!DriverWriteRegistryValues()) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    // Stop any running instance first so a restart re-runs DriverEntry and
    // re-reads the A/B/C/D values (fixes "close/restart driver still not bound").
    DWORD state = DriverQueryServiceState(hService);
    if (state == SERVICE_RUNNING || state == SERVICE_START_PENDING) {
        SERVICE_STATUS ss = {};
        ControlService(hService, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 100; i++) {
            if (DriverQueryServiceState(hService) == SERVICE_STOPPED)
                break;
            Sleep(100);
        }
    }

    // Start the driver.
    if (!StartServiceW(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return DriverFail("StartServiceW (DBK64)", err);
        }
    }

    // Wait until it reaches RUNNING (or fails).
    bool running = false;
    for (int i = 0; i < 100; i++) {
        DWORD st = DriverQueryServiceState(hService);
        if (st == SERVICE_RUNNING) { running = true; break; }
        if (st == SERVICE_STOPPED)  break; // start failed and the SCM reverted it
        Sleep(100);
    }

    if (!running) {
        // The SCM reverted the service to STOPPED: the driver failed to load.
        // The authoritative reason is the service's Win32 exit code, e.g.
        //  577  ERROR_INVALID_IMAGE_HASH   (unsigned/bad signature)
        //  1275 ERROR_DRIVER_BLOCKED       (blocked by code integrity)
        //  2    ERROR_FILE_NOT_FOUND       (path missing)
        //  193  ERROR_BAD_EXE_FORMAT       (not a valid driver)
        SERVICE_STATUS_PROCESS ssp = {};
        DriverQueryServiceStatus(hService, &ssp);
        DWORD win32 = ssp.dwWin32ExitCode;
        DWORD svc   = ssp.dwServiceSpecificExitCode;

        char etext[512];
        DriverWin32ErrorText(win32 ? win32 : ERROR_DRIVER_BLOCKED, etext, sizeof(etext));
        char svctext[64] = "";
        if (svc) snprintf(svctext, sizeof(svctext), "\n  Service-specific code = %lu", svc);
        char msg[1024];
        snprintf(msg, sizeof(msg),
            "DBK64 failed to load: the service stopped with\n"
            "  Win32 exit code = %lu (%s)%s\n\n"
            "This is almost always a DRIVER SIGNING / code-integrity problem:\n"
            "  - x64 kernel drivers MUST be signed:\n"
            "      * test mode:  test-sign DBK64.sys, then\n"
            "        bcdedit /set testsigning on  and reboot, or\n"
            "      * normal:     WHQL / attestation signature\n"
            "  - Secure Boot must be OFF (BIOS/UEFI)\n"
            "  - Memory Integrity / Core isolation (HVCI) must be OFF\n"
            "  - Re-check with:  sc query DBK64  and the System event log\n"
            "    (Event ID 7000 / 7026, Service Control Manager).",
            win32 ? win32 : ERROR_DRIVER_BLOCKED, etext, svctext);
        DriverMessage("%s", msg);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

void StopAndUnloadDriver()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return;

    SC_HANDLE hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
        // Wait for it to actually stop before deleting so the symbolic link
        // and device are released.
        for (int i = 0; i < 100; i++) {
            if (DriverQueryServiceState(hService) == SERVICE_STOPPED)
                break;
            Sleep(100);
        }
        DeleteService(hService);
        CloseServiceHandle(hService);
    }

    // Clean the A/B/C/D values from the service key
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, DBK_SERVICE_REG_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"A");
        RegDeleteValueW(hKey, L"B");
        RegDeleteValueW(hKey, L"C");
        RegDeleteValueW(hKey, L"D");
        RegCloseKey(hKey);
    }

    CloseServiceHandle(hSCM);
}

bool ConnectDriver()
{
    DisconnectDriver();

    g_hDriver = CreateFileW(DBK_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_hDriver == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char etext[512];
        DriverWin32ErrorText(err, etext, sizeof(etext));
        char msg[1024];
        snprintf(msg, sizeof(msg),
            "Could not open the DBK64 device (%S):\n(error %lu: %s)\n\n"
            "The driver service started, but opening \\\\.\\DBK64 failed.\n"
            "Possible causes:\n"
            "  - The driver did not actually load (see System event log).\n"
            "  - Imno is not running elevated / lacks SeDebugPrivilege (the driver\n"
            "    rejects opens from callers without SeDebugPrivilege).\n"
            "  - The driver's symbolic link (\\DosDevices\\DBK64) was not created.",
            DBK_DEVICE_PATH, err, etext);
        DriverMessage("%s", msg);
        return false;
    }

    g_DriverConnected = true;
    if (!DbkGetVersion(&g_KernelVersion)) {
        g_KernelVersion = 0;
        DriverMessage("Opened DBK64 but could not read its version.\n"
            "The driver may be an incompatible build. Expected version %u.", DBK_VERSION_EXPECTED);
    }

    return true;
}

void DisconnectDriver()
{
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
    g_DriverConnected = false;
}

// =====================================================================
//  Low-level DBK64 IOCTL helpers
// =====================================================================
bool DbkIoctl(ULONG code, const void* in, ULONG inSize, void* out, ULONG outSize, ULONG* returned)
{
    if (g_hDriver == INVALID_HANDLE_VALUE) return false;
    DWORD br = 0;
    BOOL ok = DeviceIoControl(g_hDriver, code, (LPVOID)in, inSize, out, outSize, &br, NULL);
    if (returned) *returned = br;
    return ok != FALSE;
}

bool DbkReadBytes(ULONG pid, ULONG_PTR addr, void* out, ULONG size)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0 || size == 0 || size > DBK_MAX_IO_SIZE || out == NULL)
        return false;

    DBK_READ_REQUEST req;
    req.ProcessId = pid;
    req.Address = addr;
    req.BytesToRead = (USHORT)size;

    ULONG returned = 0;
    return DbkIoctl(IOCTL_CE_READMEMORY, &req, sizeof(req), out, size, &returned) && returned == size;
}

bool DbkWriteBytes(ULONG pid, ULONG_PTR addr, const void* in, ULONG size)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0 || size == 0 || size > DBK_MAX_IO_SIZE || in == NULL)
        return false;

    ULONG total = DBK_WRITE_HEADER_SIZE + size;
    std::vector<BYTE> buf(total, 0);
    *(ULONG64*)(&buf[0])  = pid;
    *(ULONG64*)(&buf[8])  = addr;
    *(USHORT*)(&buf[16])  = (USHORT)size;
    memcpy(&buf[DBK_WRITE_HEADER_SIZE], in, size);

    return DbkIoctl(IOCTL_CE_WRITEMEMORY, buf.data(), total, NULL, 0, NULL);
}

// =====================================================================
//  Memory & Patch Operations
// =====================================================================
ULONG GetDataSize(int dataType) {
    switch (dataType) {
    case 3: return 1;   // 1 Byte
    case 2: return 2;   // 2 Bytes
    case 4: return 4;   // 4 Bytes
    case 1: return 4;   // Float
    case 0: return 8;   // 8 Bytes
    case 5: return 8;   // Double
    default: return 4;
    }
}

void WriteMemory(ULONG pid, ULONG_PTR addr, ULONG64 val64, int dataType)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) return;
    ULONG sz = GetDataSize(dataType);
    DbkWriteBytes(pid, addr, &val64, sz);
}

void ReadMemory(ULONG pid, ULONG_PTR addr, ULONG64* outVal, int dataType)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) { *outVal = 0; return; }
    ULONG sz = GetDataSize(dataType);
    ULONG64 v = 0;
    if (!DbkReadBytes(pid, addr, &v, sz)) v = 0;
    *outVal = v;
}

void PatchMemory(ULONG_PTR addr, const UCHAR* pattern, ULONG size)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || g_SelectedPid == 0 || size == 0 || size > 32) return;
    DbkWriteBytes(g_SelectedPid, addr, pattern, size);
}

ULONG64 ParseInputToValue(const char* str, int dataType) {
    if (dataType == 1) { // Float
        float f = (float)atof(str);
        ULONG tmp;
        memcpy(&tmp, &f, sizeof(float));
        return (ULONG64)tmp;
    }
    else if (dataType == 5) { // Double
        double d = atof(str);
        ULONG64 tmp;
        memcpy(&tmp, &d, sizeof(double));
        return tmp;
    }
    else {
        return _strtoui64(str, NULL, 0);
    }
}

void FormatValueToString(ULONG64 val64, int dataType, char* outBuf, size_t maxLen)
{
    if (dataType == 1) { // Float
        ULONG tmp = (ULONG)val64;
        float f;
        memcpy(&f, &tmp, sizeof(float));
        sprintf_s(outBuf, maxLen, "%.2f", f);
    }
    else if (dataType == 5) { // Double
        double d;
        memcpy(&d, &val64, sizeof(double));
        sprintf_s(outBuf, maxLen, "%.2lf", d);
    }
    else if (dataType == 0) { // 8 Bytes / Int64
        sprintf_s(outBuf, maxLen, "%lld", (long long)val64);
    }
    else if (dataType == 3) { // Byte
        sprintf_s(outBuf, maxLen, "%u", (unsigned char)val64);
    }
    else if (dataType == 2) { // 2 Bytes
        sprintf_s(outBuf, maxLen, "%u", (unsigned short)val64);
    }
    else { // 4 Bytes
        sprintf_s(outBuf, maxLen, "%lu", (unsigned long)val64);
    }
}

// Forward declaration
static std::vector<LONG> ParseOffsetList(const char* str);

const ModuleInfo* FindModuleByAddress(ULONG_PTR addr)
{
    for (const auto& mod : g_LoadedModules) {
        if (addr >= mod.BaseAddress && addr < (mod.BaseAddress + mod.Size))
            return &mod;
    }
    return nullptr;
}

bool IsTarget64Bit(ULONG pid)
{
    if (pid == 0) return true;

    // If this is the currently attached process and we already resolved its bitness,
    // return the cached bitness without opening any user-mode handle.
    if (pid == g_SelectedPid && g_ConquerTrackedPid == pid)
        return g_SelectedIs64;

    // 1) Stealth Kernel Check (zero handles opened): inspect PE header at 0x400000 (standard 32-bit EXE base)
    //    or loaded modules via kernel memory reads if the DBK64 driver is connected.
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        BYTE hdr[512] = { 0 };
        if (DbkReadBytes(pid, 0x400000, hdr, sizeof(hdr)) && hdr[0] == 'M' && hdr[1] == 'Z') {
            LONG lfanew = *(LONG*)(hdr + 0x3C);
            if (lfanew >= 0x40 && lfanew <= (LONG)(sizeof(hdr) - 32) &&
                *(DWORD*)(hdr + lfanew) == IMAGE_NT_SIGNATURE) {
                WORD magic = *(WORD*)(hdr + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
                if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
                if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return true;
            }
        }
        if (pid == g_SelectedPid) {
            for (const auto& m : g_LoadedModules) {
                if (DbkReadBytes(pid, m.BaseAddress, hdr, sizeof(hdr)) && hdr[0] == 'M' && hdr[1] == 'Z') {
                    LONG lfanew = *(LONG*)(hdr + 0x3C);
                    if (lfanew >= 0x40 && lfanew <= (LONG)(sizeof(hdr) - 32) &&
                        *(DWORD*)(hdr + lfanew) == IMAGE_NT_SIGNATURE) {
                        WORD magic = *(WORD*)(hdr + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
                        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
                        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return true;
                    }
                }
            }
        }
    }

    // Never open a user-mode handle or module snapshot on Conquer.exe
    if (pid == g_ConquerTrackedPid)
        return false;

    // 2) User-mode fallback when driver is not loaded
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        BOOL wow64 = FALSE;
        BOOL ok = IsWow64Process(h, &wow64);
        CloseHandle(h);
        if (ok) return !wow64; // not WOW64 => native 64-bit
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        BOOL has32 = Module32FirstW(snap, &me);
        CloseHandle(snap);
        if (has32) return false;
    }

    return true;
}

ULONG GetPointerSize(ULONG pid)
{
    return IsTarget64Bit(pid) ? 8 : 4;
}

// Normalizes "C:\path\foo.exe" / "foo.exe" / "FOO.EXE" -> "foo"
static std::string ModuleBaseName(const std::string& name)
{
    std::string base = name;
    size_t slash = base.find_last_of("\\/");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    size_t dot = base.rfind('.');
    if (dot != std::string::npos) base = base.substr(0, dot);
    return base;
}

ULONG_PTR ParseAddressInput(const char* str)
{
    if (!str || !*str) return 0;

    // Find the last '+'/'-' after the first character (module<op>offset syntax).
    const char* sep = nullptr;
    char op = 0;
    for (const char* p = str + 1; *p; ++p) {
        if (*p == '+' || *p == '-') { sep = p; op = *p; }
    }

    if (!sep)
        return (ULONG_PTR)_strtoui64(str, NULL, 0); // raw hex / decimal

    std::string modName(str, sep - str);
    while (!modName.empty() && (modName.back() == ' ' || modName.back() == '\t'))
        modName.pop_back();

    ULONG_PTR off = (ULONG_PTR)_strtoui64(sep + 1, NULL, 0);
    if (modName.empty())
        return (ULONG_PTR)_strtoui64(str, NULL, 0); // e.g. just "-0x10": treat as raw

    std::string want = ModuleBaseName(modName);
    for (const auto& m : g_LoadedModules) {
        if (_stricmp(want.c_str(), ModuleBaseName(m.ModuleName).c_str()) == 0) {
            ULONG_PTR base = m.BaseAddress;
            return op == '-' ? base - off : base + off;
        }
    }

    return 0; // module not found
}

ResolvedPointer ResolvePointerSmart(ULONG pid, const char* addressInput, const char* offsetsInput)
{
    ResolvedPointer result;
    if (pid == 0) return result;

    ULONG_PTR baseAddr = ParseAddressInput(addressInput);
    if (baseAddr == 0) return result;

    const ModuleInfo* mod = FindModuleByAddress(baseAddr);
    if (mod) {
        result.BaseModule = mod->ModuleName;
        result.BaseOffset = baseAddr - mod->BaseAddress;
    }
    else {
        result.BaseModule = "Unknown";
        result.BaseOffset = baseAddr;
    }

    result.Offsets = ParseOffsetList(offsetsInput);
    if (result.Offsets.empty()) return result;

    // 32-bit targets use 4-byte pointers, 64-bit targets use 8-byte pointers.
    ULONG ptrSize = GetPointerSize(pid);

    ULONG_PTR current = baseAddr;
    for (size_t i = 0; i < result.Offsets.size(); ++i) {
        ULONG64 val64 = 0;
        if (!DbkReadBytes(pid, current, &val64, ptrSize) || val64 == 0)
            return result;

        if (i == result.Offsets.size() - 1) {
            result.FinalAddress = (ULONG_PTR)val64 + result.Offsets[i];
            ULONG64 fv = 0;
            DbkReadBytes(pid, result.FinalAddress, &fv, ptrSize);
            result.FinalValue = fv;
            result.Success = true;
        }
        else {
            current = (ULONG_PTR)val64 + result.Offsets[i];
        }
    }
    return result;
}

// =====================================================================
//  Zydis Disassembler Integration
// =====================================================================
std::string GetAutoOffsetForAddress(ULONG_PTR targetAddr)
{
    for (const auto& mod : g_LoadedModules) {
        if (targetAddr >= mod.BaseAddress && targetAddr < (mod.BaseAddress + mod.Size)) {
            ULONG_PTR offset = targetAddr - mod.BaseAddress;
            std::stringstream ss;
            ss << mod.ModuleName << " + 0x" << std::hex << offset;
            return ss.str();
        }
    }
    std::stringstream ss;
    ss << "0x" << std::hex << targetAddr;
    return ss.str();
}

std::string GetZydisDisassembledBytes(ULONG_PTR targetAddr, ULONG instructionCount)
{
    if (instructionCount == 0) instructionCount = 1;

    UCHAR codeBuffer[64] = { 0 };
    SIZE_T readableLen = 0;
    if (DbkReadBytes(g_SelectedPid, targetAddr, codeBuffer, sizeof(codeBuffer))) {
        readableLen = sizeof(codeBuffer);
    }
    else {
        for (ULONG offset = 0; offset < sizeof(codeBuffer); offset += 8) {
            ULONG64 val = 0;
            if (!DbkReadBytes(g_SelectedPid, targetAddr + offset, &val, 8))
                break;
            memcpy(codeBuffer + offset, &val, 8);
            readableLen += 8;
        }
    }

    if (readableLen == 0)
        return "0x90, 0x90";

    // 64-bit targets decode as long-mode 64-bit; 32-bit (WOW64) targets as
    // long-mode compatibility 32-bit, otherwise instructions are mis-decoded.
    bool is64 = IsTarget64Bit(g_SelectedPid);
    ZydisMachineMode mode = is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    ZydisStackWidth stackWidth = is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, mode, stackWidth);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    std::string resultBytes;
    bool firstByte = true;

    SIZE_T offset = 0;
    for (ULONG decoded = 0; decoded < instructionCount && offset < readableLen; decoded++) {
        if (ZydisDecoderDecodeFull(&decoder, codeBuffer + offset, readableLen - offset, &instruction, operands) != ZYAN_STATUS_SUCCESS)
            break;

        for (ZyanUSize b = 0; b < instruction.length; b++) {
            char hexByte[8];
            sprintf_s(hexByte, sizeof(hexByte), "0x%02X", codeBuffer[offset + b]);
            if (!firstByte) resultBytes += ", ";
            resultBytes += hexByte;
            firstByte = false;
        }
        offset += instruction.length;
    }

    if (resultBytes.empty()) resultBytes = "0x90, 0x90";
    return resultBytes;
}

ULONG_PTR ResolvePointerPath(ULONG pid, ULONG_PTR baseAddress, const std::vector<LONG>& offsets)
{
    if (pid == 0 || baseAddress == 0) return 0;

    ULONG ptrSize = GetPointerSize(pid);
    ULONG_PTR currentAddress = baseAddress;
    for (size_t i = 0; i < offsets.size(); ++i) {
        ULONG64 val64 = 0;
        if (!DbkReadBytes(pid, currentAddress, &val64, ptrSize) || val64 == 0)
            return 0;

        if (i == offsets.size() - 1) {
            return (ULONG_PTR)val64 + offsets[i];
        }
        else {
            currentAddress = (ULONG_PTR)val64 + offsets[i];
        }
    }
    return currentAddress;
}

// =====================================================================
//  Input parsing helpers
// =====================================================================
static bool ParseHexBytes(const char* str, UCHAR* outBytes, ULONG maxBytes, ULONG* outCount)
{
    ULONG count = 0;
    const char* p = str;
    while (*p && count < maxBytes) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        char* end = NULL;
        unsigned long v = strtoul(p, &end, 16);
        if (end == p || v > 0xFF) return false;
        outBytes[count++] = (UCHAR)v;
        p = end;
    }
    *outCount = count;
    return count > 0;
}

static std::vector<LONG> ParseOffsetList(const char* str)
{
    std::vector<LONG> offsets;
    const char* p = str;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        char* end = NULL;
        long v = strtol(p, &end, 0);
        if (end == p) break;
        offsets.push_back(v);
        p = end;
    }
    return offsets;
}

// =====================================================================
//  DBK64 feature helpers (Kernel tab)
// =====================================================================
bool DbkGetVersion(ULONG* version)
{
    if (version) *version = 0;
    ULONG v = 0;
    if (DbkIoctl(IOCTL_CE_GETVERSION, NULL, 0, &v, sizeof(v))) {
        if (version) *version = v;
        return true;
    }
    return false;
}

bool DbkGetCR0(ULONG64* out)
{
    if (out) *out = 0;
    ULONG64 v = 0;
    if (DbkIoctl(IOCTL_CE_GETCR0, NULL, 0, &v, sizeof(v))) { if (out) *out = v; return true; }
    return false;
}

bool DbkGetCR3(ULONG pid, ULONG64* out)
{
    if (out) *out = 0;
    ULONG inputPid = pid;
    ULONG64 v = 0;
    if (DbkIoctl(IOCTL_CE_GETCR3, &inputPid, sizeof(inputPid), &v, sizeof(v))) { if (out) *out = v; return true; }
    return false;
}

bool DbkGetCR4(ULONG64* out)
{
    if (out) *out = 0;
    ULONG64 v = 0;
    if (DbkIoctl(IOCTL_CE_GETCR4, NULL, 0, &v, sizeof(v))) { if (out) *out = v; return true; }
    return false;
}

bool DbkReadMsr(ULONG msr, ULONG64* out)
{
    if (out) *out = 0;
    ULONG64 v = 0;
    if (DbkIoctl(IOCTL_CE_READMSR, &msr, sizeof(msr), &v, sizeof(v))) { if (out) *out = v; return true; }
    return false;
}

bool DbkWriteMsr(ULONG64 msr, ULONG64 value)
{
    DBK_MSR_WRITE req;
    req.Msr = msr;
    req.Value = value;
    return DbkIoctl(IOCTL_CE_WRITEMSR, &req, sizeof(req), NULL, 0, NULL);
}

bool DbkGetIdt(USHORT* limit, ULONG_PTR* base)
{
    if (limit) *limit = 0;
    if (base) *base = 0;
    DBK_SEG_TABLE t = {};
    if (DbkIoctl(IOCTL_CE_GETIDT, NULL, 0, &t, sizeof(t))) {
        if (limit) *limit = t.Limit;
        if (base) *base = t.Base;
        return true;
    }
    return false;
}

bool DbkGetGdt(USHORT* limit, ULONG_PTR* base)
{
    if (limit) *limit = 0;
    if (base) *base = 0;
    DBK_SEG_TABLE t = {};
    if (DbkIoctl(IOCTL_CE_GETGDT, NULL, 0, &t, sizeof(t))) {
        if (limit) *limit = t.Limit;
        if (base) *base = t.Base;
        return true;
    }
    return false;
}

bool DbkReadPhysical(ULONG64 addr, void* out, ULONG size)
{
    if (size == 0 || size > 0x2000 || out == NULL) return false;   // driver maps a 0x2000 view
    DBK_PHYS_RW req;
    req.Address = addr;
    req.Bytes = size;
    return DbkIoctl(IOCTL_CE_READPHYSICALMEMORY, &req, sizeof(req), out, size, NULL);
}

bool DbkWritePhysical(ULONG64 addr, const void* in, ULONG size)
{
    if (size == 0 || size > 0x2000 || in == NULL) return false;
    ULONG total = sizeof(DBK_PHYS_RW) + size;
    std::vector<BYTE> buf(total, 0);
    *(ULONG64*)(&buf[0]) = addr;
    *(ULONG64*)(&buf[8]) = size;
    memcpy(&buf[sizeof(DBK_PHYS_RW)], in, size);
    return DbkIoctl(IOCTL_CE_WRITEPHYSICALMEMORY, buf.data(), total, NULL, 0, NULL);
}

bool DbkAllocNonPaged(ULONG size, ULONG64* out)
{
    if (out) *out = 0;
    ULONG64 addr = 0;
    if (DbkIoctl(IOCTL_CE_ALLOCATEMEM_NONPAGED, &size, sizeof(size), &addr, sizeof(addr))) {
        if (out) *out = addr;
        return addr != 0;
    }
    return false;
}

bool DbkFreeNonPaged(ULONG64 addr)
{
    return DbkIoctl(IOCTL_CE_FREE_NONPAGED, &addr, sizeof(addr), NULL, 0, NULL);
}

bool DbkAllocProcessMem(ULONG pid, ULONG64 size, ULONG64* out)
{
    if (out) *out = 0;
    DBK_ALLOC_PROCESS req = {};
    req.ProcessId = pid;
    req.BaseAddress = 0;
    req.Size = size;
    req.AllocationType = 0x3000;             // MEM_COMMIT | MEM_RESERVE
    req.Protect = 0x40;                      // PAGE_EXECUTE_READWRITE
    ULONG64 addr = 0;
    if (DbkIoctl(IOCTL_CE_ALLOCATEMEM, &req, sizeof(req), &addr, sizeof(addr))) {
        if (out) *out = addr;
        return addr != 0;
    }
    return false;
}

bool DbkSuspendProcess(ULONG pid)
{
    return DbkIoctl(IOCTL_CE_SUSPENDPROCESS, &pid, sizeof(pid), NULL, 0, NULL);
}

bool DbkResumeProcess(ULONG pid)
{
    return DbkIoctl(IOCTL_CE_RESUMEPROCESS, &pid, sizeof(pid), NULL, 0, NULL);
}

bool DbkOpenProcessHandle(ULONG pid, ULONG64* handle, UCHAR* special)
{
    if (handle) *handle = 0;
    if (special) *special = 0;
    DBK_OPENPROCESS_OUT out = {};
    if (DbkIoctl(IOCTL_CE_OPENPROCESS, &pid, sizeof(pid), &out, sizeof(out))) {
        if (handle) *handle = out.Handle;
        if (special) *special = out.Special;
        return true;
    }
    return false;
}

bool DbkGetPEPROCESS(ULONG pid, ULONG64* out)
{
    if (out) *out = 0;
    ULONG64 v = 0;
    if (DbkIoctl(IOCTL_CE_GETPEPROCESS, &pid, sizeof(pid), &v, sizeof(v))) { if (out) *out = v; return true; }
    return false;
}

bool DbkQueryVirtualMemory(ULONG pid, ULONG_PTR addr, ULONG_PTR* length, ULONG* protection)
{
    if (length) *length = 0;
    if (protection) *protection = 0;
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0)
        return false;

    // Input and output share the same buffered buffer: the driver reads the
    // {pid, addr} header, then overwrites it with {length, protection}.
    DBK_QUERY_VMEM_INOUT buf = {};
    buf.In.ProcessId = pid;
    buf.In.StartAddress = addr;

    if (!DbkIoctl(IOCTL_CE_QUERY_VIRTUAL_MEMORY, &buf, sizeof(buf), &buf, sizeof(buf)))
        return false;

    if (length) *length = (ULONG_PTR)buf.Out.Length;
    if (protection) *protection = buf.Out.Protection;
    return true;
}

// =====================================================================
//  Freeze / Cheat Table Loop
// =====================================================================
void FreezeLoop()
{
    while (g_FreezeRunning) {
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            std::lock_guard<std::mutex> lock(g_CheatTableLock);
            for (auto& item : g_CheatTable) {
                if (item.Enabled && item.Pid != 0) {
                    WriteMemory(item.Pid, item.Address, item.Value64, item.DataType);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// =====================================================================
//  Process & Module Enumeration (user-mode Toolhelp, no driver needed)
// =====================================================================
void RefreshProcessList()
{
    g_ProcessList.clear();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info;
            info.ProcessId = pe.th32ProcessID;
            memset(info.Name, 0, sizeof(info.Name));
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, info.Name, (int)sizeof(info.Name) - 1, NULL, NULL);
            g_ProcessList.push_back(info);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

void RefreshModules()
{
    if (g_SelectedPid == 0) {
        g_LoadedModules.clear();
        return;
    }

    // When connected to Conquer.exe (or when stealth kernel mode is active and driver is loaded),
    // enumerate modules purely through kernel memory without opening any user-mode handle.
    if (g_hDriver != INVALID_HANDLE_VALUE && g_ConquerTrackedPid == g_SelectedPid) {
        RefreshModulesStealth(g_SelectedPid, &g_SelectedIs64);
        return;
    }

    g_LoadedModules.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_SelectedPid);
    if (snap == INVALID_HANDLE_VALUE) {
        if (g_hDriver != INVALID_HANDLE_VALUE)
            RefreshModulesStealth(g_SelectedPid, &g_SelectedIs64);
        return;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            ModuleInfo info;
            memset(&info, 0, sizeof(info));
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, info.ModuleName, (int)sizeof(info.ModuleName) - 1, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, info.FullPath, (int)sizeof(info.FullPath) - 1, NULL, NULL);
            info.BaseAddress = (ULONG_PTR)me.modBaseAddr;
            info.Size = me.modBaseSize;
            g_LoadedModules.push_back(info);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

// Parse a PE image header at `baseAddr` purely via DBK64 kernel memory reads (zero handles opened).
static bool TryReadPeModuleStealth(ULONG pid, ULONG_PTR baseAddr, ModuleInfo* outMod, bool* outIs64, bool* outIsExe)
{
    if (!baseAddr || (baseAddr & 0xFFFF) != 0)
        return false;

    BYTE hdr[1024] = { 0 };
    if (!DbkReadBytes(pid, baseAddr, hdr, sizeof(hdr)))
        return false;

    if (hdr[0] != 'M' || hdr[1] != 'Z')
        return false;

    LONG lfanew = *(LONG*)(hdr + 0x3C);
    if (lfanew < 0x40 || lfanew > (LONG)(sizeof(hdr) - sizeof(IMAGE_NT_HEADERS64)))
        return false;

    if (*(DWORD*)(hdr + lfanew) != IMAGE_NT_SIGNATURE)
        return false;

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(hdr + lfanew + 4);
    WORD magic = *(WORD*)(hdr + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));

    ULONG sizeOfImage = 0;
    ULONG sectionAlignment = 0;
    ULONG exportRva = 0;
    ULONG exportSize = 0;
    bool is64 = true;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32* opt32 = (IMAGE_OPTIONAL_HEADER32*)(hdr + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
        sizeOfImage = opt32->SizeOfImage;
        sectionAlignment = opt32->SectionAlignment;
        if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exportRva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        is64 = false;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64* opt64 = (IMAGE_OPTIONAL_HEADER64*)(hdr + lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
        sizeOfImage = opt64->SizeOfImage;
        sectionAlignment = opt64->SectionAlignment;
        if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            exportRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        is64 = true;
    }
    else {
        return false;
    }

    if (sizeOfImage < 0x1000 || sizeOfImage > 0x40000000 ||
        sectionAlignment < 0x1000 || (sectionAlignment & (sectionAlignment - 1)) != 0)
        return false;

    bool isDll = (fh->Characteristics & IMAGE_FILE_DLL) != 0;
    if (outIs64) *outIs64 = is64;
    if (outIsExe) *outIsExe = !isDll;

    if (outMod) {
        memset(outMod, 0, sizeof(ModuleInfo));
        outMod->BaseAddress = baseAddr;
        outMod->Size = sizeOfImage;

        if (exportRva != 0 && exportRva + sizeof(IMAGE_EXPORT_DIRECTORY) <= sizeOfImage && exportSize >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
            IMAGE_EXPORT_DIRECTORY expDir = {};
            if (DbkReadBytes(pid, baseAddr + exportRva, &expDir, sizeof(expDir)) &&
                expDir.Name != 0 && expDir.Name < sizeOfImage) {
                char modName[128] = { 0 };
                if (DbkReadBytes(pid, baseAddr + expDir.Name, modName, sizeof(modName) - 1)) {
                    modName[sizeof(modName) - 1] = '\0';
                    bool validAscii = (modName[0] >= 0x21 && modName[0] < 0x7F);
                    for (size_t i = 0; i < sizeof(modName) && modName[i] != '\0'; ++i) {
                        if ((unsigned char)modName[i] < 0x20 || (unsigned char)modName[i] >= 0x7F) {
                            validAscii = false;
                            break;
                        }
                    }
                    if (validAscii) {
                        strcpy_s(outMod->ModuleName, sizeof(outMod->ModuleName), modName);
                    }
                }
            }
        }

        if (outMod->ModuleName[0] == '\0') {
            if (!isDll) {
                const char* procName = NULL;
                for (const auto& p : g_ProcessList) {
                    if (p.ProcessId == pid) { procName = p.Name; break; }
                }
                if (procName && procName[0] != '\0')
                    strcpy_s(outMod->ModuleName, sizeof(outMod->ModuleName), procName);
                else
                    strcpy_s(outMod->ModuleName, sizeof(outMod->ModuleName), "Conquer.exe");
            }
            else {
                snprintf(outMod->ModuleName, sizeof(outMod->ModuleName), "Module_0x%llX.dll", (unsigned long long)baseAddr);
            }
        }
        snprintf(outMod->FullPath, sizeof(outMod->FullPath), "[Stealth Kernel PE @ 0x%llX]", (unsigned long long)baseAddr);
    }

    return true;
}

// Stealth module enumeration: walks virtual memory in Ring-0 (DbkQueryVirtualMemory + DbkReadBytes)
// without calling OpenProcess or CreateToolhelp32Snapshot(TH32CS_SNAPMODULE).
void RefreshModulesStealth(ULONG pid, bool* outIs64)
{
    g_LoadedModules.clear();
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0)
        return;

    bool detected32Bit = false;
    bool foundMainExe = false;
    ULONG mainExeSize = 0;

    // 1) Check standard 32-bit image base (0x400000, used by Conquer.exe) directly first
    {
        ModuleInfo mod = {};
        bool modIs64 = true;
        bool isExe = false;
        if (TryReadPeModuleStealth(pid, 0x400000, &mod, &modIs64, &isExe)) {
            g_LoadedModules.push_back(mod);
            if (!modIs64) detected32Bit = true;
            if (isExe) foundMainExe = true;
            mainExeSize = mod.Size;
        }
    }

    // 2) Walk readable regions via Ring-0 page tables and probe 64 KB allocation boundaries
    //    to find all loaded PE images (even if adjacent read-only regions are merged by the page walker).
    ULONG_PTR cursor = 0x10000;
    ULONG_PTR maxAddr = (foundMainExe && detected32Bit) ? 0xFFFE0000ULL : 0x7FFFFFFF0000ULL;
    ULONG guard = 0;

    while (cursor < maxAddr && ++guard < 65536 && g_LoadedModules.size() < 256) {
        ULONG_PTR length = 0;
        ULONG protection = 0;
        if (!DbkQueryVirtualMemory(pid, cursor, &length, &protection) || length == 0)
            break;

        ULONG_PTR base = cursor & ~(ULONG_PTR)0xFFF;
        ULONG_PTR end = base + length;
        if (end <= base)
            break;

        if (protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE) {
            ULONG_PTR probe = (base + 0xFFFFULL) & ~(ULONG_PTR)0xFFFFULL;
            while (probe < end && probe < maxAddr && g_LoadedModules.size() < 256) {
                if (probe == 0x400000 && mainExeSize != 0) {
                    ULONG_PTR step = ((ULONG_PTR)mainExeSize + 0xFFFFULL) & ~(ULONG_PTR)0xFFFFULL;
                    probe += (step > 0 ? step : 0x10000ULL);
                    continue;
                }

                ModuleInfo mod = {};
                bool modIs64 = true;
                bool isExe = false;
                if (TryReadPeModuleStealth(pid, probe, &mod, &modIs64, &isExe)) {
                    if (!modIs64 && probe < 0x80000000ULL) detected32Bit = true;
                    if (isExe && !foundMainExe) {
                        g_LoadedModules.insert(g_LoadedModules.begin(), mod);
                        foundMainExe = true;
                    }
                    else {
                        g_LoadedModules.push_back(mod);
                    }
                    ULONG_PTR step = ((ULONG_PTR)mod.Size + 0xFFFFULL) & ~(ULONG_PTR)0xFFFFULL;
                    probe += (step > 0 ? step : 0x10000ULL);
                }
                else {
                    probe += 0x10000ULL;
                }
            }
        }

        cursor = end;
    }

    if (outIs64) {
        *outIs64 = !detected32Bit;
    }
}

void FormatCurrentLocalTime(char* outBuf, size_t maxLen)
{
    if (!outBuf || maxLen == 0) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(outBuf, maxLen, "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
}

void FormatElapsedDuration(ULONGLONG startTick, char* outBuf, size_t maxLen)
{
    if (!outBuf || maxLen == 0) return;
    if (startTick == 0) {
        snprintf(outBuf, maxLen, "00:00:00");
        return;
    }
    ULONGLONG now = GetTickCount64();
    ULONGLONG totalSec = (now >= startTick) ? ((now - startTick) / 1000ULL) : 0ULL;
    ULONGLONG hours = totalSec / 3600ULL;
    ULONGLONG mins = (totalSec % 3600ULL) / 60ULL;
    ULONGLONG secs = totalSec % 60ULL;
    snprintf(outBuf, maxLen, "%02llu:%02llu:%02llu", hours, mins, secs);
}

void ConnectToProcess(ULONG pid)
{
    ULONG prevPid = g_SelectedPid;
    if (pid != prevPid) {
        {
            std::lock_guard<std::mutex> lock(g_ScanResultsLock);
            g_ScanResults.clear();
        }
        g_ScanVersion++;
        g_ScanTruncated = false;
        g_ResolvedAddress = 0;
        g_ResolvedValue = 0;
        g_LastResolved = ResolvedPointer{};
    }

    if (pid == 0) {
        g_SelectedPid = 0;
        g_ProcessConnectTick = 0;
        g_ProcessConnectTimeStr[0] = '\0';
        g_LoadedModules.clear();
        return;
    }

    bool isConquer = false;
    for (const auto& p : g_ProcessList) {
        if (p.ProcessId == pid && _stricmp(p.Name, "Conquer.exe") == 0) {
            isConquer = true;
            break;
        }
    }

    g_SelectedPid = pid;
    g_ProcessConnectTick = GetTickCount64();
    FormatCurrentLocalTime(g_ProcessConnectTimeStr, sizeof(g_ProcessConnectTimeStr));

    if (isConquer) {
        // Passive initial tracking: do NOT open any handle or touch Conquer.exe memory yet;
        // the Stealth Kernel Re-Attach will execute automatically after 0.5s (500ms).
        g_LoadedModules.clear();
        g_AutoConnectConquer = true;
        g_SelectedIs64 = false; // Conquer.exe is 32-bit; refined stealthily at +0.5s
        std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
        g_ConquerTrackedPid = pid;
        g_ConquerConnectTick = g_ProcessConnectTick;
        strcpy_s(g_ConquerConnectTimeStr, sizeof(g_ConquerConnectTimeStr), g_ProcessConnectTimeStr);
        g_ConquerReattachPending = true;
        g_ConquerReattachTargetTick = g_ProcessConnectTick + CONQUER_REATTACH_DELAY_MS;
        g_ConquerReattachedAfterDelay = false;
        return;
    }

    // Manual selection of a non-Conquer process: cancel any pending Conquer re-attach timer
    {
        std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
        g_ConquerReattachPending = false;
        g_ConquerReattachedAfterDelay = false;
    }

    g_SelectedIs64 = IsTarget64Bit(pid);
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        ULONG64 peProc = 0;
        DbkGetPEPROCESS(pid, &peProc);
    }
    RefreshModules();
}

void ConquerWatchLoop()
{
    std::vector<ULONG> prevConquerPids;
    ULONG lastKnownConquerPid = 0;

    while (g_ConquerWatchRunning) {
        if (!g_AutoConnectConquer) {
            prevConquerPids.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            continue;
        }

        std::vector<ULONG> currentConquerPids;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"Conquer.exe") == 0) {
                        currentConquerPids.push_back(pe.th32ProcessID);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        ULONG     trackedPid = 0;
        bool      reattachPending = false;
        ULONGLONG reattachTargetTick = 0;
        {
            std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
            trackedPid = g_ConquerTrackedPid;
            reattachPending = g_ConquerReattachPending;
            reattachTargetTick = g_ConquerReattachTargetTick;
        }

        // Detect any newly spawned Conquer.exe instance
        ULONG newSpawnedPid = 0;
        for (ULONG pid : currentConquerPids) {
            bool seenBefore = false;
            for (ULONG oldPid : prevConquerPids) {
                if (oldPid == pid) { seenBefore = true; break; }
            }
            if (!seenBefore) {
                newSpawnedPid = pid;
            }
        }

        // Check whether the currently tracked Conquer.exe PID is still alive
        bool trackedStillAlive = false;
        if (trackedPid != 0) {
            for (ULONG pid : currentConquerPids) {
                if (pid == trackedPid) { trackedStillAlive = true; break; }
            }
        }

        ULONG targetPid = 0;
        if (newSpawnedPid != 0) {
            targetPid = newSpawnedPid;
        }
        else if (!trackedStillAlive && !currentConquerPids.empty()) {
            targetPid = currentConquerPids.back();
        }

        ULONGLONG nowTick = GetTickCount64();

        // Case 1: Initial Conquer.exe detection -> passively record PID (zero touch on the game process)
        //         and arm the 0.5s (500ms) Stealth Kernel Re-Attach.
        if (targetPid != 0 && targetPid != trackedPid) {
            char timeBuf[32] = "";
            FormatCurrentLocalTime(timeBuf, sizeof(timeBuf));

            if (trackedPid != 0)
                lastKnownConquerPid = trackedPid;

            {
                std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
                g_ConquerTrackedPid = targetPid;
                g_ConquerConnectTick = nowTick;
                strcpy_s(g_ConquerConnectTimeStr, sizeof(g_ConquerConnectTimeStr), timeBuf);
                g_ConquerReattachPending = true;
                g_ConquerReattachTargetTick = nowTick + CONQUER_REATTACH_DELAY_MS;
                g_ConquerReattachedAfterDelay = false;
            }
            g_ConquerEventSeq++;
            if (g_hWnd) PostMessageA(g_hWnd, WM_NULL, 0, 0);
        }
        // Case 2: 0.5 seconds (500ms) elapsed -> perform Stealth Kernel Re-Attach:
        //         - ZERO OpenProcess calls
        //         - ZERO CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) calls
        //         - ZERO ObOpenObjectByPointer (IOCTL_CE_OPENPROCESS) handle creations
        //         - Uses only Ring-0 PsLookupProcessByProcessId + KeAttachProcess via DBK64
        else if (reattachPending && nowTick >= reattachTargetTick && !currentConquerPids.empty()) {
            ULONG reattachPid = trackedStillAlive ? trackedPid : currentConquerPids.back();
            char timeBuf[32] = "";
            FormatCurrentLocalTime(timeBuf, sizeof(timeBuf));

            if (g_hDriver != INVALID_HANDLE_VALUE) {
                ULONG64 peProc = 0;
                ULONG64 cr3 = 0;
                DbkGetPEPROCESS(reattachPid, &peProc);
                DbkGetCR3(reattachPid, &cr3);
                g_PeProcess = peProc;
                g_KernelCR3 = cr3;
            }

            {
                std::lock_guard<std::mutex> ctLock(g_CheatTableLock);
                for (auto& item : g_CheatTable) {
                    if (item.Pid == trackedPid || item.Pid == g_SelectedPid ||
                        (lastKnownConquerPid != 0 && item.Pid == lastKnownConquerPid)) {
                        item.Pid = reattachPid;
                    }
                }
            }
            lastKnownConquerPid = reattachPid;

            {
                std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
                g_ConquerTrackedPid = reattachPid;
                g_ConquerConnectTick = nowTick;
                strcpy_s(g_ConquerConnectTimeStr, sizeof(g_ConquerConnectTimeStr), timeBuf);
                g_ConquerReattachPending = false;
                g_ConquerReattachedAfterDelay = true;
            }
            g_ConquerReconnectCount++;
            g_ConquerEventSeq++;
            if (g_hWnd) PostMessageA(g_hWnd, WM_NULL, 0, 0);
        }
        // Case 3: Conquer.exe closed completely; clear tracked PID and wait for next launch
        else if (trackedPid != 0 && !trackedStillAlive && currentConquerPids.empty()) {
            lastKnownConquerPid = trackedPid;
            {
                std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
                g_ConquerTrackedPid = 0;
                g_ConquerConnectTick = 0;
                g_ConquerConnectTimeStr[0] = '\0';
                g_ConquerReattachPending = false;
                g_ConquerReattachedAfterDelay = false;
            }
            g_ConquerEventSeq++;
            if (g_hWnd) PostMessageA(g_hWnd, WM_NULL, 0, 0);
        }

        prevConquerPids = std::move(currentConquerPids);
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

// =====================================================================
//  Memory region enumeration & scanning
//  Regions are enumerated through the DBK64 driver (IOCTL_CE_QUERY_VIRTUAL_MEMORY)
//  so protected processes (svchost/PPL) and guarded games (anti-cheat) are
//  scanned too; the same driver performs the actual reads.
// =====================================================================
struct RegionInfo {
    ULONG_PTR Start;
    ULONG_PTR End;
};

static ULONG_PTR MaxAddr(ULONG_PTR a, ULONG_PTR b) { return a > b ? a : b; }
static ULONG_PTR MinAddr(ULONG_PTR a, ULONG_PTR b) { return a < b ? a : b; }

// Kernel-reported protection values (see FindFirstDifferentAddress in memscan.c)
static bool IsReadableProtect(DWORD protect)
{
    // PAGE_EXECUTE_READ (0x20) and PAGE_EXECUTE_READWRITE (0x40) are readable;
    // PAGE_NOACCESS (0x01) / unknown are not.
    return (protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE);
}

// Enumerate readable regions by walking the target's page tables in the kernel.
static std::vector<RegionInfo> EnumerateRegions(ULONG pid, ULONG_PTR rangeStart, ULONG_PTR rangeEnd)
{
    std::vector<RegionInfo> regions;

    ULONG_PTR cursor = rangeStart & ~(ULONG_PTR)0xFFF; // page-aligned start
    ULONG guard = 0;

    while (cursor < rangeEnd) {
        if (++guard > 1 << 22) break; // safety: ~4M queries max

        ULONG_PTR length = 0;
        ULONG protection = 0;
        if (!DbkQueryVirtualMemory(pid, cursor, &length, &protection))
            break; // no more regions (or driver call failed)

        if (length == 0)
            break;

        ULONG_PTR base = cursor & ~(ULONG_PTR)0xFFF;
        ULONG_PTR end = base + length;
        if (end <= base)
            break; // overflow / wrapped past end of address space

        if (IsReadableProtect(protection)) {
            ULONG_PTR s = MaxAddr(base, rangeStart);
            ULONG_PTR e = MinAddr(end, rangeEnd);
            if (s < e) regions.push_back({ s, e });
        }

        cursor = end;
    }

    return regions;
}

// User-mode fallback when the kernel walker returns nothing (e.g. querying the
// kernel page tables is unavailable on this OS build).
static std::vector<RegionInfo> EnumerateRegionsUserMode(ULONG pid, ULONG_PTR rangeStart, ULONG_PTR rangeEnd)
{
    std::vector<RegionInfo> regions;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return regions;

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = rangeStart;
    while (addr < rangeEnd) {
        SIZE_T queried = VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (!queried) break;

        ULONG_PTR regionEnd = (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize;
        bool readable = (mbi.State == MEM_COMMIT) &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (readable) {
            ULONG_PTR s = MaxAddr((ULONG_PTR)mbi.BaseAddress, rangeStart);
            ULONG_PTR e = MinAddr(regionEnd, rangeEnd);
            if (s < e) regions.push_back({ s, e });
        }

        if (regionEnd <= (ULONG_PTR)mbi.BaseAddress) break; // overflow guard
        addr = regionEnd;
    }

    CloseHandle(h);
    return regions;
}

void AsyncFirstScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, bool useRange, ULONG_PTR rangeStart, ULONG_PTR rangeEnd, bool allowUnaligned)
{
    g_IsScanning = true;
    g_ScanProgress = 0;
    g_ScanTruncated = false;
    {
        std::lock_guard<std::mutex> lock(g_ScanResultsLock);
        g_ScanResults.clear();
    }

    if (g_hDriver == INVALID_HANDLE_VALUE || targetPid == 0) {
        g_ScanVersion++;   // results were cleared above; let the UI refresh to empty
        g_IsScanning = false;
        return;
    }

    ULONG sz = GetDataSize(dataType);
    ULONG_PTR defaultEnd = IsTarget64Bit(targetPid) ? 0x7FFFFFFFFFFFULL : 0xFFFFFFFFULL;
    ULONG_PTR rStart = useRange ? rangeStart : 0x10000;
    ULONG_PTR rEnd = useRange ? rangeEnd : defaultEnd;

    ULONG conquerPid = 0;
    {
        std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
        conquerPid = g_ConquerTrackedPid;
    }

    std::vector<RegionInfo> regions = EnumerateRegions(targetPid, rStart, rEnd);
    // Never fall back to user-mode OpenProcess when scanning Conquer.exe
    if (regions.empty() && targetPid != conquerPid)
        regions = EnumerateRegionsUserMode(targetPid, rStart, rEnd);

    std::vector<ULONG_PTR> results;
    std::vector<BYTE> chunk(DBK_MAX_IO_SIZE);   // max the driver can read per IOCTL
    ULONG64 totalBytes = 0, doneBytes = 0;
    for (auto& r : regions) totalBytes += (ULONG64)(r.End - r.Start);

    for (auto& r : regions) {
        ULONG_PTR cur = r.Start;
        while (cur < r.End) {
            if (!g_FreezeRunning) goto scan_done; // abort cleanly if app is closing
            ULONG_PTR remaining = r.End - cur;
            ULONG chunkSize = (ULONG)MinAddr(remaining, (ULONG_PTR)chunk.size());

            if (DbkReadBytes(targetPid, cur, chunk.data(), chunkSize)) {
                ULONG maxOff = (chunkSize >= sz) ? (chunkSize - sz + 1) : 0;
                ULONG step = allowUnaligned ? 1 : sz;
                for (ULONG off = 0; off < maxOff; off += step) {
                    if (memcmp(&chunk[off], &searchVal64, sz) == 0) {
                        results.push_back(cur + off);
                        if (results.size() >= MAX_SCAN_RESULTS) {
                            g_ScanTruncated = true;
                            goto scan_done;
                        }
                    }
                }
            }

            cur += chunkSize;
            doneBytes += chunkSize;
            g_ScanProgress = totalBytes ? (int)(doneBytes * 100 / totalBytes) : 100;
        }
    }

scan_done:
    {
        std::lock_guard<std::mutex> lock(g_ScanResultsLock);
        g_ScanResults = std::move(results);
    }
    g_ScanVersion++;
    g_ScanProgress = 100;
    g_IsScanning = false;
}

void AsyncNextScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, std::vector<ULONG_PTR> prevResults)
{
    g_IsScanning = true;
    g_ScanProgress = 0;
    g_ScanTruncated = false;

    if (g_hDriver == INVALID_HANDLE_VALUE || prevResults.empty()) {
        g_IsScanning = false;
        return;
    }

    ULONG sz = GetDataSize(dataType);
    std::vector<ULONG_PTR> results;
    results.reserve(prevResults.size());

    ULONG64 total = (ULONG64)prevResults.size(), done = 0;
    for (auto a : prevResults) {
        if (!g_FreezeRunning) break; // abort cleanly if app is closing
        ULONG64 v = 0;
        if (DbkReadBytes(targetPid, a, &v, sz) && memcmp(&v, &searchVal64, sz) == 0)
            results.push_back(a);
        done++;
        g_ScanProgress = total ? (int)(done * 100 / total) : 100;
    }

    {
        std::lock_guard<std::mutex> lock(g_ScanResultsLock);
        g_ScanResults = std::move(results);
    }
    g_ScanVersion++;
    g_ScanProgress = 100;
    g_IsScanning = false;
}

void StartFirstScan()
{
    if (g_SelectedPid == 0 || g_IsScanning) return;
    ULONG64 val64 = ParseInputToValue(g_ScanValueInput, g_SelectedDataType);
    g_ResultsDataType = g_SelectedDataType;
    ULONG_PTR rStart = 0x10000;
    ULONG_PTR rEnd = g_SelectedIs64 ? 0x7FFFFFFFFFFFULL : 0xFFFFFFFFULL;
    if (g_UseScanRange) {
        rStart = (ULONG_PTR)_strtoui64(g_ScanRangeStart, NULL, 0);
        rEnd = (ULONG_PTR)_strtoui64(g_ScanRangeEnd, NULL, 0);
    }
    std::thread(AsyncFirstScanWorker, g_SelectedPid, g_SelectedDataType, val64, g_UseScanRange, rStart, rEnd, g_AllowUnaligned).detach();
}

void StartNextScan()
{
    if (g_SelectedPid == 0 || g_IsScanning) return;

    std::vector<ULONG_PTR> currentCopy;
    {
        std::lock_guard<std::mutex> lock(g_ScanResultsLock);
        currentCopy = g_ScanResults;
    }
    if (currentCopy.empty()) return;

    ULONG64 val64 = ParseInputToValue(g_ScanValueInput, g_SelectedDataType);
    g_ResultsDataType = g_SelectedDataType;
    std::thread(AsyncNextScanWorker, g_SelectedPid, g_SelectedDataType, val64, currentCopy).detach();
}

void ExportResultsToFile()
{
    std::vector<ULONG_PTR> copy;
    {
        std::lock_guard<std::mutex> lock(g_ScanResultsLock);
        copy = g_ScanResults;
    }

    std::ofstream outFile("ScanResultsExport.txt");
    if (!outFile.is_open()) return;
    for (auto addr : copy) {
        outFile << "0x" << std::hex << addr << "\n";
    }
    outFile.close();
}

// =====================================================================
//  Kernel tab helpers (UI actions)
// =====================================================================
static void FormatPhysDump(const BYTE* data, ULONG size, ULONG64 baseAddr, char* out, size_t outMax)
{
    std::stringstream ss;
    for (ULONG row = 0; row < size; row += 16) {
        char ascii[17] = "................";
        ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << (baseAddr + row) << "  ";

        ULONG lineLen = (size - row) < 16 ? (size - row) : 16;
        for (ULONG i = 0; i < 16; i++) {
            if (i < lineLen) {
                ss << std::setw(2) << (unsigned)data[row + i] << " ";
                BYTE c = data[row + i];
                if (c >= 0x20 && c < 0x7F) ascii[i] = (char)c;
            }
            else {
                ss << "   ";
            }
        }
        ss << " |" << ascii << "|";
        if (row + 16 < size) ss << "\n";
    }
    strncpy_s(out, outMax, ss.str().c_str(), _TRUNCATE);
}

// =====================================================================
//  WinMain / Entry Point
// =====================================================================
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    EnableSeDebugPrivilege();

    LoadAndStartDriver();
    bool driverConnected = ConnectDriver();
    if (!driverConnected) {
        char msg[1408];
        snprintf(msg, sizeof(msg),
            "Failed to connect to the DBK64 kernel driver!\n\n"
            "%s\n\n"
            "General requirements:\n"
            "  - Run Imno as Administrator (SeDebugPrivilege is required)\n"
            "  - DBK64.sys must be next to Imno.exe\n"
            "  - The driver must be SIGNED (x64): test-sign + "
            "bcdedit /set testsigning on (reboot), Secure Boot off,\n"
            "    Memory Integrity / Core isolation (HVCI) off\n\n"
            "Use the Reconnect button in the top bar to retry after fixing this.",
            g_KernelStatus[0] ? g_KernelStatus : "(no detailed driver status available)");
        MessageBoxA(NULL, msg, "DBK64 driver not available", MB_OK | MB_ICONWARNING);
    }

    if (!glfwInit()) return 1;

    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Imno - DBK64 Kernel Suite", NULL, NULL);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    g_Window = window;
    g_hWnd = glfwGetWin32Window(window);

    // Setup Direct3D 11
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    ID3D11Device* pd3dDevice = NULL;
    ID3D11DeviceContext* pd3dDeviceContext = NULL;
    IDXGISwapChain* pSwapChain = NULL;

    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2,
        D3D11_SDK_VERSION, &sd, &pSwapChain, &pd3dDevice, &featureLevel, &pd3dDeviceContext) != S_OK)
    {
        glfwDestroyWindow(window);
        glfwTerminate();
        return 1;
    }

    ID3D11RenderTargetView* mainRenderTargetView = NULL;
    auto CreateRT = [&]() {
        if (mainRenderTargetView) { mainRenderTargetView->Release(); mainRenderTargetView = NULL; }
        ID3D11Texture2D* pBackBuffer = NULL;
        pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
        pBackBuffer->Release();
    };
    CreateRT();

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOther(window, true);
    ImGui_ImplDX11_Init(pd3dDevice, pd3dDeviceContext);

    // Initial fetch of processes & kernel info
    RefreshProcessList();
    if (driverConnected) {
        DbkGetVersion(&g_KernelVersion);
    }

    g_FreezeThread = std::thread(FreezeLoop);
    g_ConquerWatchThread = std::thread(ConquerWatchLoop);

    int lastWidth = 0, lastHeight = 0;
    glfwGetFramebufferSize(window, &lastWidth, &lastHeight);

    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        // Handle resize - unbind RTV before ResizeBuffers
        int fbWidth, fbHeight;
        glfwGetFramebufferSize(window, &fbWidth, &fbHeight);
        if (fbWidth > 0 && fbHeight > 0 && (fbWidth != lastWidth || fbHeight != lastHeight)) {
            lastWidth = fbWidth;
            lastHeight = fbHeight;
            pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
            if (mainRenderTargetView) { mainRenderTargetView->Release(); mainRenderTargetView = NULL; }
            ImGui_ImplDX11_InvalidateDeviceObjects();
            pSwapChain->ResizeBuffers(0, (UINT)fbWidth, (UINT)fbHeight, DXGI_FORMAT_UNKNOWN, 0);
            CreateRT();
            ImGui_ImplDX11_CreateDeviceObjects();
        }
        if (fbWidth == 0 || fbHeight == 0) {
            Sleep(10);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2((float)fbWidth, (float)fbHeight), ImGuiCond_Always);
        ImGui::Begin("Imno - DBK64 Kernel Suite", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar);

        // Sync with ConquerWatchLoop (passive initial detection -> Stealth Kernel Re-Attach at +0.5s)
        static unsigned s_LastConquerSeq = 0;
        unsigned curConquerSeq = g_ConquerEventSeq.load();
        if (curConquerSeq != s_LastConquerSeq) {
            s_LastConquerSeq = curConquerSeq;
            ULONG     cPid = 0;
            ULONGLONG cTick = 0;
            char      cTime[32] = "";
            bool      reattachPending = false;
            bool      reattachedAfterDelay = false;
            {
                std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
                cPid = g_ConquerTrackedPid;
                cTick = g_ConquerConnectTick;
                strcpy_s(cTime, sizeof(cTime), g_ConquerConnectTimeStr);
                reattachPending = g_ConquerReattachPending;
                reattachedAfterDelay = g_ConquerReattachedAfterDelay;
            }
            if (cPid != 0) {
                if (g_SelectedPid != cPid) {
                    std::lock_guard<std::mutex> lock(g_ScanResultsLock);
                    g_ScanResults.clear();
                    g_ScanVersion++;
                    g_ScanTruncated = false;
                }
                RefreshProcessList();
                g_SelectedPid = cPid;
                g_ProcessConnectTick = cTick;
                strcpy_s(g_ProcessConnectTimeStr, sizeof(g_ProcessConnectTimeStr), cTime);

                if (reattachedAfterDelay && !reattachPending) {
                    // +0.5s Stealth Kernel Re-Attach: resolve modules & bitness purely via Ring-0 memory reads
                    // (zero OpenProcess, zero CreateToolhelp32Snapshot(TH32CS_SNAPMODULE), zero handles)
                    if (g_hDriver != INVALID_HANDLE_VALUE) {
                        RefreshModulesStealth(cPid, &g_SelectedIs64);
                    }
                    else {
                        g_SelectedIs64 = false;
                    }
                }
                else {
                    // Initial 0.5s window: stay completely silent / invisible to the game
                    g_LoadedModules.clear();
                    g_SelectedIs64 = false;
                }
            }
            else if (g_AutoConnectConquer) {
                ConnectToProcess(0);
            }
        }

        // Top Bar: Driver Status Active/Inactive & Process Combo
        driverConnected = (g_hDriver != INVALID_HANDLE_VALUE);
        if (driverConnected) {
            ImGui::TextColored({ 0.0f, 1.0f, 0.0f, 1.0f }, "[DBK64 Driver: ACTIVE]");
        }
        else {
            ImGui::TextColored({ 1.0f, 0.0f, 0.0f, 1.0f }, "[DBK64 Driver: INACTIVE]");
            ImGui::SameLine();
            if (ImGui::Button("Reconnect")) {
                LoadAndStartDriver();
                driverConnected = ConnectDriver();
                if (driverConnected) {
                    DbkGetVersion(&g_KernelVersion);
                    RefreshProcessList();
                    if (g_SelectedPid != 0) {
                        ConnectToProcess(g_SelectedPid);
                    }
                }
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Refresh", ImVec2(80, 25))) {
            RefreshProcessList();
        }

        ImGui::SameLine();
        ImGui::SetNextItemWidth(130);
        ImGui::InputText("Filter", g_ProcessFilter, sizeof(g_ProcessFilter));
        ImGui::SameLine();

        ImGui::SetNextItemWidth(230);
        char comboLabel[128];
        const char* selectedProcName = NULL;
        strcpy_s(comboLabel, sizeof(comboLabel), "Select Target Process...");
        if (g_SelectedPid != 0) {
            for (const auto& p : g_ProcessList) {
                if (p.ProcessId == g_SelectedPid) { selectedProcName = p.Name; break; }
            }
            if (selectedProcName) sprintf_s(comboLabel, sizeof(comboLabel), "%s (%u)", selectedProcName, g_SelectedPid);
            else sprintf_s(comboLabel, sizeof(comboLabel), "PID %u", g_SelectedPid);
        }
        if (ImGui::BeginCombo("##proccombo", comboLabel)) {
            for (const auto& p : g_ProcessList) {
                if (g_ProcessFilter[0] != '\0' && strstr(p.Name, g_ProcessFilter) == NULL) continue;
                char label[128];
                sprintf_s(label, sizeof(label), "%s (%u)", p.Name, p.ProcessId);
                bool isSelected = (g_SelectedPid == p.ProcessId);
                if (ImGui::Selectable(label, isSelected)) {
                    ConnectToProcess(p.ProcessId);
                }
                if (isSelected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::SameLine();
        ImGui::Checkbox("Auto Conquer.exe", &g_AutoConnectConquer);

        ImGui::SameLine();
        static ULONGLONG s_LastTitleUpdate = 0;
        static ULONG     s_LastTitlePid = 0;
        if (g_SelectedPid != 0) {
            ULONG uiConquerPid = 0;
            bool  uiReattachPending = false;
            bool  uiReattachedAfterDelay = false;
            {
                std::lock_guard<std::mutex> lock(g_ConquerWatchLock);
                uiConquerPid = g_ConquerTrackedPid;
                uiReattachPending = g_ConquerReattachPending;
                uiReattachedAfterDelay = g_ConquerReattachedAfterDelay;
            }

            char elapsedStr[32];
            FormatElapsedDuration(g_ProcessConnectTick, elapsedStr, sizeof(elapsedStr));

            ImGui::TextColored({ 0.0f, 1.0f, 0.0f, 1.0f }, "PID: %u", g_SelectedPid);
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", g_SelectedIs64 ? "64-bit" : "32-bit");
            if (ImGui::GetContentRegionAvail().x > 260.0f) {
                ImGui::SameLine();
                ImGui::TextDisabled("|");
                ImGui::SameLine();
            }
            ImGui::TextColored({ 0.3f, 0.9f, 1.0f, 1.0f }, "Connected: %s", g_ProcessConnectTimeStr);
            ImGui::SameLine();
            ImGui::TextColored({ 1.0f, 0.85f, 0.2f, 1.0f }, "[Elapsed: %s]", elapsedStr);
            if (uiConquerPid == g_SelectedPid) {
                ImGui::SameLine();
                if (uiReattachPending)
                    ImGui::TextColored({ 1.0f, 0.6f, 0.2f, 1.0f }, "(Stealth Re-attach in 0.5s...)");
                else if (uiReattachedAfterDelay)
                    ImGui::TextColored({ 0.2f, 1.0f, 0.4f, 1.0f }, "(Stealth Re-attached +0.5s)");
            }

            ULONGLONG nowTick = GetTickCount64();
            if (s_LastTitlePid != g_SelectedPid || (nowTick - s_LastTitleUpdate >= 1000)) {
                s_LastTitleUpdate = nowTick;
                s_LastTitlePid = g_SelectedPid;
                char winTitle[256];
                if (uiConquerPid == g_SelectedPid) {
                    // Stealth window title: avoid exposing "Conquer.exe" or "DBK64" to window-title scanners
                    snprintf(winTitle, sizeof(winTitle),
                        "Imno | Connected: %s [Elapsed: %s]",
                        g_ProcessConnectTimeStr,
                        elapsedStr);
                }
                else {
                    snprintf(winTitle, sizeof(winTitle),
                        "Imno - DBK64 Kernel Suite | %s (%u) - Connected: %s [%s]",
                        selectedProcName ? selectedProcName : "Process",
                        g_SelectedPid,
                        g_ProcessConnectTimeStr,
                        elapsedStr);
                }
                glfwSetWindowTitle(window, winTitle);
            }
        }
        else {
            if (g_AutoConnectConquer) {
                ImGui::TextColored({ 1.0f, 0.85f, 0.2f, 1.0f }, "[Waiting for Conquer.exe...]");
            }
            if (s_LastTitlePid != 0) {
                s_LastTitlePid = 0;
                glfwSetWindowTitle(window, "Imno - DBK64 Kernel Suite");
            }
        }

        ImGui::Separator();

        // Tabs
        if (ImGui::BeginTabBar("ImnoTabs"))
        {
            // TAB 1: MEMORY SCANNER
            if (ImGui::BeginTabItem("Memory Scanner"))
            {
                ImGui::Text("Data Type:");
                ImGui::SameLine();
                ImGui::RadioButton("4 Bytes", &g_SelectedDataType, 4); ImGui::SameLine();
                ImGui::RadioButton("2 Bytes", &g_SelectedDataType, 2); ImGui::SameLine();
                ImGui::RadioButton("1 Byte", &g_SelectedDataType, 3); ImGui::SameLine();
                ImGui::RadioButton("Float", &g_SelectedDataType, 1); ImGui::SameLine();
                ImGui::RadioButton("Double", &g_SelectedDataType, 5); ImGui::SameLine();
                ImGui::RadioButton("8 Bytes", &g_SelectedDataType, 0);

                ImGui::Spacing();
                ImGui::Text("Scan Value:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(200);
                ImGui::InputText("##scanval", g_ScanValueInput, sizeof(g_ScanValueInput));
                ImGui::SameLine();

                if (!g_IsScanning) {
                    if (ImGui::Button("First Scan", ImVec2(110, 30))) {
                        StartFirstScan();
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Next Scan", ImVec2(110, 30))) {
                        StartNextScan();
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Export Results", ImVec2(120, 30))) {
                        ExportResultsToFile();
                    }
                }
                else {
                    ImGui::TextDisabled("Scanning in progress...");
                }

                ImGui::Checkbox("Unaligned Scan (slower)", &g_AllowUnaligned);
                ImGui::SameLine();
                ImGui::Checkbox("Scan Range", &g_UseScanRange);
                if (g_UseScanRange) {
                    ImGui::SetNextItemWidth(140);
                    ImGui::InputText("Start", g_ScanRangeStart, sizeof(g_ScanRangeStart));
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(140);
                    ImGui::InputText("End", g_ScanRangeEnd, sizeof(g_ScanRangeEnd));
                }

                if (g_IsScanning) {
                    ImGui::ProgressBar((float)g_ScanProgress / 100.0f, ImVec2(-1, 0), "Scanning Process Memory (kernel reads)...");
                }

                ImGui::Spacing();
                ImGui::Separator();

                // UI-side snapshot of the scan results
                static std::vector<ULONG_PTR> s_DisplayAddrs;
                static std::vector<ULONG64>   s_DisplayVals;
                static unsigned               s_DisplayVersion = 0xFFFFFFFF;
                static bool                   s_NeedValueRefresh = true;
                static ULONGLONG              s_LastValueRefresh = 0;

                if (!g_IsScanning && s_DisplayVersion != g_ScanVersion) {
                    std::lock_guard<std::mutex> lock(g_ScanResultsLock);
                    s_DisplayAddrs = g_ScanResults;
                    s_DisplayVersion = g_ScanVersion;
                    s_DisplayVals.assign(s_DisplayAddrs.size(), 0);
                    s_NeedValueRefresh = true;
                }

                ImGui::Text("Scan Results Found: %zu", s_DisplayAddrs.size());
                if (!g_IsScanning && g_ScanTruncated) {
                    ImGui::TextColored({ 1.0f, 0.6f, 0.0f, 1.0f },
                        "Results truncated at %d - use Next Scan or a narrower range!", MAX_SCAN_RESULTS);
                }

                ImGui::BeginChild("ResultsChild", ImVec2(0, 350), true);
                {
                    bool doRefresh = !g_IsScanning &&
                        (s_NeedValueRefresh || (GetTickCount64() - s_LastValueRefresh > 400));

                    ImGuiListClipper clipper;
                    clipper.Begin((int)s_DisplayAddrs.size());
                    while (clipper.Step())
                    {
                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                            if (doRefresh) {
                                ReadMemory(g_SelectedPid, s_DisplayAddrs[i], &s_DisplayVals[i], g_ResultsDataType);
                            }

                            char valStr[64];
                            FormatValueToString(s_DisplayVals[i], g_ResultsDataType, valStr, sizeof(valStr));

                            char label[160];
                            sprintf_s(label, sizeof(label), "0x%llX : %s##res%d", s_DisplayAddrs[i], valStr, i);
                            if (ImGui::Selectable(label)) {
                                std::lock_guard<std::mutex> lock(g_CheatTableLock);
                                std::string autoDesc = GetAutoOffsetForAddress(s_DisplayAddrs[i]);
                                g_CheatTable.push_back({ s_DisplayAddrs[i], s_DisplayVals[i], false, g_ResultsDataType, g_SelectedPid, "" });
                                strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), autoDesc.c_str());
                            }
                        }
                    }
                    if (doRefresh) {
                        s_LastValueRefresh = GetTickCount64();
                        s_NeedValueRefresh = false;
                    }
                }
                ImGui::EndChild();

                ImGui::EndTabItem();
            }

            // TAB 2: CHEAT TABLE
            if (ImGui::BeginTabItem("Cheat Table"))
            {
                ImGui::Text("Cheat Table (Active Freeze & Patches):");

                ImGui::BeginChild("CheatTableChild", ImVec2(0, 300), true);
                {
                    std::lock_guard<std::mutex> lock(g_CheatTableLock);
                    for (int i = 0; i < (int)g_CheatTable.size(); i++) {
                        ImGui::PushID(i);

                        bool isEnabled = g_CheatTable[i].Enabled;
                        if (ImGui::Checkbox("##en", &isEnabled)) {
                            g_CheatTable[i].Enabled = isEnabled;
                        }
                        ImGui::SameLine();

                        ImGui::Text("0x%llX [PID %u]", g_CheatTable[i].Address, g_CheatTable[i].Pid);
                        ImGui::SameLine(220);

                        char valStr[64];
                        FormatValueToString(g_CheatTable[i].Value64, g_CheatTable[i].DataType, valStr, sizeof(valStr));

                        ImGui::SetNextItemWidth(140);
                        if (ImGui::InputText("##val", valStr, sizeof(valStr))) {
                            g_CheatTable[i].Value64 = ParseInputToValue(valStr, g_CheatTable[i].DataType);
                        }

                        ImGui::SameLine(380);
                        ImGui::SetNextItemWidth(180);
                        ImGui::InputText("##desc", g_CheatTable[i].Description, sizeof(g_CheatTable[i].Description));

                        ImGui::SameLine(570);
                        if (ImGui::Button("Remove")) {
                            g_CheatTable.erase(g_CheatTable.begin() + i--);
                        }

                        ImGui::PopID();
                    }
                }
                ImGui::EndChild();

                ImGui::EndTabItem();
            }

            // TAB 3: MODULES
            if (ImGui::BeginTabItem("Modules"))
            {
                if (ImGui::Button("Refresh Modules", ImVec2(150, 30))) {
                    RefreshModules();
                }
                ImGui::SameLine();
                ImGui::SetNextItemWidth(250);
                ImGui::InputText("Filter Modules", g_ModuleFilter, sizeof(g_ModuleFilter));

                ImGui::BeginChild("ModulesChild", ImVec2(0, 400), true);
                for (const auto& mod : g_LoadedModules) {
                    if (g_ModuleFilter[0] != '\0' && strstr(mod.ModuleName, g_ModuleFilter) == NULL) continue;
                    ImGui::Text("%s | Base: 0x%llX | Size: 0x%X", mod.ModuleName, mod.BaseAddress, mod.Size);
                    ImGui::TextWrapped("Path: %s", mod.FullPath);
                    ImGui::Separator();
                }
                ImGui::EndChild();

                ImGui::EndTabItem();
            }

            // TAB 4: PATCHER & POINTERS
            if (ImGui::BeginTabItem("Patcher & Pointers"))
            {
                ImGui::Text("Byte Patcher (reads/disassembles and overwrites bytes at an address):");
                ImGui::SetNextItemWidth(220);
                ImGui::InputText("##patchaddr", g_PatchAddressInput, sizeof(g_PatchAddressInput));
                ImGui::SameLine();
                if (ImGui::Button("Read Bytes", ImVec2(110, 25)) && g_SelectedPid != 0) {
                    ULONG_PTR addr = ParseAddressInput(g_PatchAddressInput);
                    if (addr) {
                        std::string bytes = GetZydisDisassembledBytes(addr, 1);
                        strcpy_s(g_PatchPatternInput, sizeof(g_PatchPatternInput), bytes.c_str());
                    }
                }

                ImGui::SetNextItemWidth(340);
                ImGui::InputText("##patchpattern", g_PatchPatternInput, sizeof(g_PatchPatternInput));
                ImGui::SameLine();
                if (ImGui::Button("Patch Memory", ImVec2(120, 25)) && g_SelectedPid != 0) {
                    ULONG_PTR addr = ParseAddressInput(g_PatchAddressInput);
                    UCHAR bytes[32];
                    ULONG byteCount = 0;
                    if (addr && ParseHexBytes(g_PatchPatternInput, bytes, sizeof(bytes), &byteCount)) {
                        PatchMemory(addr, bytes, byteCount);
                    }
                }

                ImGui::Spacing();
                ImGui::Separator();

                ImGui::Text("Smart Pointer Resolver (address + comma-separated offsets):");
                ImGui::TextWrapped("Enter any address (e.g. module+offset or raw 0x...). Base module auto-detected.");
                ImGui::SetNextItemWidth(220);
                ImGui::InputText("Address", g_PointerBaseInput, sizeof(g_PointerBaseInput));
                ImGui::SameLine();
                ImGui::SetNextItemWidth(340);
                ImGui::InputText("Offsets (e.g. 0x10, 0x24, 0x8)", g_PointerOffsetInput, sizeof(g_PointerOffsetInput));
                ImGui::SameLine();
                if (ImGui::Button("Resolve", ImVec2(100, 25)) && g_SelectedPid != 0) {
                    g_LastResolved = ResolvePointerSmart(g_SelectedPid, g_PointerBaseInput, g_PointerOffsetInput);
                    if (g_LastResolved.Success) {
                        g_ResolvedAddress = g_LastResolved.FinalAddress;
                        g_ResolvedValue = g_LastResolved.FinalValue;
                    }
                    else {
                        g_ResolvedAddress = 0;
                        g_ResolvedValue = 0;
                    }
                }

                if (g_ResolvedAddress && g_LastResolved.Success) {
                    ImGui::Separator();
                    ImGui::Text("Base Module: %s", g_LastResolved.BaseModule.c_str());
                    ImGui::Text("Base Offset: 0x%llX", g_LastResolved.BaseOffset);
                    ImGui::Text("Offsets: ");
                    ImGui::SameLine();
                    for (size_t i = 0; i < g_LastResolved.Offsets.size(); ++i) {
                        if (i > 0) ImGui::SameLine(); ImGui::Text("0x%X", g_LastResolved.Offsets[i]);
                    }
                    ImGui::Text("Final Address: 0x%llX", g_ResolvedAddress);
                    char resolvedStr[64];
                    FormatValueToString(g_ResolvedValue, 0, resolvedStr, sizeof(resolvedStr));
                    ImGui::Text("Value: %s (0x%llX)", resolvedStr, g_ResolvedValue);
                }

                ImGui::EndTabItem();
            }

            // TAB 5: KERNEL (DBK64 full feature set)
            if (ImGui::BeginTabItem("Kernel"))
            {
                ImGui::BeginChild("KernelChild", ImVec2(0, 0), false);

                if (ImGui::CollapsingHeader("Driver Info", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Text("Driver version: %u (expected %u)", g_KernelVersion, DBK_VERSION_EXPECTED);
                    if (ImGui::Button("Re-read version", ImVec2(140, 24))) {
                        DbkGetVersion(&g_KernelVersion);
                    }
                }

                if (ImGui::CollapsingHeader("Control Registers", ImGuiTreeNodeFlags_DefaultOpen)) {
                    if (ImGui::Button("Read CR0/CR3/CR4", ImVec2(140, 24))) {
                        DbkGetCR0(&g_KernelCR0);
                        DbkGetCR4(&g_KernelCR4);
                        DbkGetCR3(g_SelectedPid ? g_SelectedPid : GetCurrentProcessId(), &g_KernelCR3);
                    }
                    ImGui::Text("CR0: 0x%llX", g_KernelCR0);
                    ImGui::Text("CR3: 0x%llX (selected process)", g_KernelCR3);
                    ImGui::Text("CR4: 0x%llX", g_KernelCR4);
                }

                if (ImGui::CollapsingHeader("MSR (Model Specific Registers)")) {
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("MSR index##read", g_MsrReadInput, sizeof(g_MsrReadInput));
                    ImGui::SameLine();
                    if (ImGui::Button("Read MSR", ImVec2(90, 24))) {
                        ULONG msr = (ULONG)_strtoui64(g_MsrReadInput, NULL, 0);
                        DbkReadMsr(msr, &g_KernelMsrValue);
                    }
                    ImGui::Text("Read value: 0x%llX", g_KernelMsrValue);

                    ImGui::Separator();
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("MSR index##write", g_MsrWriteMsr, sizeof(g_MsrWriteMsr));
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("New value", g_MsrWriteValue, sizeof(g_MsrWriteValue));
                    ImGui::SameLine();
                    if (ImGui::Button("Write MSR", ImVec2(90, 24))) {
                        ULONG64 msr = _strtoui64(g_MsrWriteMsr, NULL, 0);
                        ULONG64 val = _strtoui64(g_MsrWriteValue, NULL, 0);
                        if (DbkWriteMsr(msr, val))
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "MSR written OK");
                        else
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "MSR write failed");
                    }
                    if (g_KernelStatus[0]) ImGui::Text("%s", g_KernelStatus);
                }

                if (ImGui::CollapsingHeader("IDT / GDT")) {
                    if (ImGui::Button("Read IDT & GDT", ImVec2(140, 24))) {
                        DbkGetIdt(&g_KernelIdt.Limit, &g_KernelIdt.Base);
                        DbkGetGdt(&g_KernelGdt.Limit, &g_KernelGdt.Base);
                    }
                    ImGui::Text("IDT: limit 0x%X, base 0x%llX", g_KernelIdt.Limit, g_KernelIdt.Base);
                    ImGui::Text("GDT: limit 0x%X, base 0x%llX", g_KernelGdt.Limit, g_KernelGdt.Base);
                }

                if (ImGui::CollapsingHeader("Physical Memory")) {
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("Physical address##read", g_PhysReadAddr, sizeof(g_PhysReadAddr));
                    ImGui::SetNextItemWidth(120);
                    ImGui::InputText("Bytes", g_PhysReadSize, sizeof(g_PhysReadSize));
                    ImGui::SameLine();
                    if (ImGui::Button("Read Physical", ImVec2(110, 24))) {
                        ULONG64 addr = _strtoui64(g_PhysReadAddr, NULL, 0);
                        ULONG size = (ULONG)_strtoui64(g_PhysReadSize, NULL, 0);
                        if (size > 0x2000) size = 0x2000;
                        std::vector<BYTE> buf(size ? size : 0x100);
                        if (DbkReadPhysical(addr, buf.data(), (ULONG)buf.size()))
                            FormatPhysDump(buf.data(), (ULONG)buf.size(), addr, g_PhysReadDump, sizeof(g_PhysReadDump));
                        else
                            strcpy_s(g_PhysReadDump, sizeof(g_PhysReadDump), "Physical read failed");
                    }
                    ImGui::TextWrapped("%s", g_PhysReadDump);

                    ImGui::Separator();
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("Physical address##write", g_PhysWriteAddr, sizeof(g_PhysWriteAddr));
                    ImGui::SetNextItemWidth(340);
                    ImGui::InputText("Hex bytes (0x90, 0x90 ...)", g_PhysWriteHex, sizeof(g_PhysWriteHex));
                    ImGui::SameLine();
                    if (ImGui::Button("Write Physical", ImVec2(110, 24))) {
                        ULONG64 addr = _strtoui64(g_PhysWriteAddr, NULL, 0);
                        UCHAR bytes[512];
                        ULONG count = 0;
                        if (ParseHexBytes(g_PhysWriteHex, bytes, sizeof(bytes), &count) && count <= 0x2000) {
                            if (DbkWritePhysical(addr, bytes, count))
                                strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Physical write OK");
                            else
                                strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Physical write failed");
                        }
                    }
                }

                if (ImGui::CollapsingHeader("Kernel Memory Allocation")) {
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("Nonpaged size", g_AllocNonPagedSize, sizeof(g_AllocNonPagedSize));
                    ImGui::SameLine();
                    if (ImGui::Button("Allocate kernel", ImVec2(120, 24))) {
                        ULONG size = (ULONG)_strtoui64(g_AllocNonPagedSize, NULL, 0);
                        DbkAllocNonPaged(size, &g_AllocNonPagedAddr);
                    }
                    ImGui::Text("Kernel addr: 0x%llX", g_AllocNonPagedAddr);
                    ImGui::SameLine();
                    if (ImGui::Button("Free kernel", ImVec2(90, 24)) && g_AllocNonPagedAddr) {
                        DbkFreeNonPaged(g_AllocNonPagedAddr);
                        g_AllocNonPagedAddr = 0;
                    }

                    ImGui::Separator();
                    ImGui::SetNextItemWidth(200);
                    ImGui::InputText("Process alloc size", g_AllocProcessSize, sizeof(g_AllocProcessSize));
                    ImGui::SameLine();
                    if (ImGui::Button("Allocate in process", ImVec2(140, 24)) && g_SelectedPid != 0) {
                        ULONG64 size = _strtoui64(g_AllocProcessSize, NULL, 0);
                        DbkAllocProcessMem(g_SelectedPid, size, &g_AllocProcessAddr);
                    }
                    ImGui::Text("Process addr: 0x%llX", g_AllocProcessAddr);
                }

                if (ImGui::CollapsingHeader("Process Control")) {
                    if (ImGui::Button("Suspend Process", ImVec2(130, 24)) && g_SelectedPid != 0) {
                        if (DbkSuspendProcess(g_SelectedPid))
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Process suspended");
                        else
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Suspend failed");
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Resume Process", ImVec2(130, 24)) && g_SelectedPid != 0) {
                        if (DbkResumeProcess(g_SelectedPid))
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Process resumed");
                        else
                            strcpy_s(g_KernelStatus, sizeof(g_KernelStatus), "Resume failed");
                    }

                    ImGui::Separator();
                    if (ImGui::Button("Open kernel handle", ImVec2(140, 24)) && g_SelectedPid != 0) {
                        UCHAR special = 0;
                        DbkOpenProcessHandle(g_SelectedPid, &g_OpenProcessHandle, &special);
                    }
                    ImGui::Text("Kernel handle: 0x%llX", g_OpenProcessHandle);

                    ImGui::Separator();
                    if (ImGui::Button("Get PEPROCESS", ImVec2(140, 24)) && g_SelectedPid != 0) {
                        DbkGetPEPROCESS(g_SelectedPid, &g_PeProcess);
                    }
                    ImGui::Text("PEPROCESS: 0x%llX", g_PeProcess);
                }

                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::End();

        ImGui::Render();
        const float clear_color[4] = { 0.08f, 0.08f, 0.10f, 1.00f };
        pd3dDeviceContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
        pd3dDeviceContext->ClearRenderTargetView(mainRenderTargetView, clear_color);
        D3D11_VIEWPORT vp{};
        vp.Width = (FLOAT)fbWidth;
        vp.Height = (FLOAT)fbHeight;
        vp.MinDepth = 0.0f;
        vp.MaxDepth = 1.0f;
        vp.TopLeftX = 0;
        vp.TopLeftY = 0;
        pd3dDeviceContext->RSSetViewports(1, &vp);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        pSwapChain->Present(1, 0);
    }

    // Cleanup
    g_FreezeRunning = false;
    g_ConquerWatchRunning = false;
    if (g_FreezeThread.joinable()) g_FreezeThread.join();
    if (g_ConquerWatchThread.joinable()) g_ConquerWatchThread.join();
    for (int waitIdx = 0; waitIdx < 200 && g_IsScanning; ++waitIdx) {
        Sleep(10);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (mainRenderTargetView) mainRenderTargetView->Release();
    if (pSwapChain) pSwapChain->Release();
    if (pd3dDeviceContext) pd3dDeviceContext->Release();
    if (pd3dDevice) pd3dDevice->Release();

    glfwDestroyWindow(window);
    glfwTerminate();

    DisconnectDriver();
    StopAndUnloadDriver();

    return 0;
}
