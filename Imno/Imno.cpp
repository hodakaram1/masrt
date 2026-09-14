#include "Imno.h"

#include <cstdarg>
#include <cstdio>

// Direct Link Libraries for D3D11 & DXGI
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "advapi32.lib")

// Globals - simplified (only Memory Scanner, Cheat Table)
HWND g_hWnd = NULL;
GLFWwindow* g_Window = NULL;
HANDLE g_hDriver = INVALID_HANDLE_VALUE;
bool   g_DriverConnected = false;

std::vector<ProcessInfo> g_ProcessList;
ULONG g_SelectedPid = 0;
char  g_ProcessFilter[64] = "";

// Scan State
int   g_SelectedDataType = 4; // 4 = 4 Bytes
char  g_ScanValueInput[128] = "";
char  g_ScanRangeStart[64] = "0x10000";
char  g_ScanRangeEnd[64] = "0x7FFFFFFFFFFF";
bool  g_UseScanRange = false;
bool  g_AllowUnaligned = false;

std::vector<ULONG_PTR> g_ScanResults;
std::mutex             g_ScanResultsLock;
std::atomic<bool>      g_IsScanning(false);
std::atomic<int>       g_ScanProgress(0);
std::atomic<bool>      g_ScanTruncated(false);
std::atomic<unsigned>  g_ScanVersion(0);
int                    g_ResultsDataType = 4;
bool                   g_SelectedIs64 = true;

// Cheat Table & Freeze
std::vector<CheatItem> g_CheatTable;
std::mutex g_CheatTableLock;
std::atomic<bool> g_FreezeRunning(true);
std::thread g_FreezeThread;

// Kernel status (for driver messages)
ULONG     g_KernelVersion = 0;
char      g_KernelStatus[256] = "";

// =====================================================================
//  Privilege & Driver Control Helpers
// =====================================================================
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
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), out, (DWORD)outLen, NULL);
    return out;
}

static bool HasSeDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    std::vector<BYTE> buf(needed);
    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)buf.data();
    bool found = false;
    if (GetTokenInformation(hToken, TokenPrivileges, buf.data(), needed, &needed)) {
        LUID seDebug;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &seDebug)) {
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                if (tp->Privileges[i].Luid.LowPart == seDebug.LowPart && tp->Privileges[i].Luid.HighPart == seDebug.HighPart) { found = true; break; }
            }
        }
    }
    CloseHandle(hToken);
    return found;
}

bool EnableSeDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    TOKEN_PRIVILEGES tp = {}; LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool held = HasSeDebugPrivilege();
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    bool ok = held && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

static bool DriverFail(const char* stage, DWORD err)
{
    char etext[512]; DriverWin32ErrorText(err, etext, sizeof(etext));
    char msg[1024]; snprintf(msg, sizeof(msg), "%s failed (error %lu):\n%s", stage, err, etext);
    DriverMessage("%s", msg); return false;
}

static bool DriverWriteRegistryValues()
{
    HKEY hKey = NULL;
    DWORD err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, DBK_SERVICE_REG_KEY, 0, KEY_SET_VALUE, &hKey);
    if (err != ERROR_SUCCESS) { char etext[512]; DriverWin32ErrorText(err, etext, sizeof(etext)); char msg[1024]; snprintf(msg, sizeof(msg), "Could not open the DBK64 service key for writing:\n(error %lu: %s)", err, etext); DriverMessage("%s", msg); return false; }
    const WCHAR* vals[4] = { DBK_DEVICE_NAME, DBK_SYMLINK_NAME, DBK_PROCESS_EVENT, DBK_THREAD_EVENT };
    const WCHAR* names[4] = { L"A", L"B", L"C", L"D" };
    for (int i = 0; i < 4; i++) {
        err = RegSetValueExW(hKey, names[i], 0, REG_SZ, (const BYTE*)vals[i], (DWORD)((wcslen(vals[i]) + 1) * sizeof(WCHAR)));
        if (err != ERROR_SUCCESS) { char etext[512]; DriverWin32ErrorText(err, etext, sizeof(etext)); RegCloseKey(hKey); char msg[1024]; snprintf(msg, sizeof(msg), "RegSetValueExW(\"%S\") failed (error %lu):\n%s", names[i], err, etext); DriverMessage("%s", msg); return false; }
    }
    RegCloseKey(hKey); return true;
}

static bool DriverQueryServiceStatus(SC_HANDLE hService, SERVICE_STATUS_PROCESS* out)
{
    DWORD needed = 0; QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
    std::vector<BYTE> buf(needed);
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, buf.data(), needed, &needed)) return false;
    memcpy(out, buf.data(), sizeof(SERVICE_STATUS_PROCESS)); return true;
}
static DWORD DriverQueryServiceState(SC_HANDLE hService) { SERVICE_STATUS_PROCESS ssp = {}; if (!DriverQueryServiceStatus(hService, &ssp)) return 0; return ssp.dwCurrentState; }

bool LoadAndStartDriver()
{
    WCHAR sysPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH)) return DriverFail("GetModuleFileNameW", GetLastError());
    wchar_t* lastSlash = wcsrchr(sysPath, L'\\'); if (lastSlash) *(lastSlash + 1) = L'\0'; else return DriverFail("locating the exe folder", ERROR_PATH_NOT_FOUND);
    wcscat_s(sysPath, MAX_PATH, DBK_DRIVER_FILE);
    if (GetFileAttributesW(sysPath) == INVALID_FILE_ATTRIBUTES) { char msg[1024]; snprintf(msg, sizeof(msg), "DBK64.sys not found next to Imno.exe.\nExpected: %S\nRebuild with build.bat (Release x64)", sysPath); DriverMessage("%s", msg); return false; }
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); if (!hSCM) return DriverFail("OpenSCManagerW (run Imno as Administrator)", GetLastError());
    SC_HANDLE hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) { for (int i = 0; i < 100; i++) { Sleep(100); hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS); if (hService) break; err = GetLastError(); if (err != ERROR_SERVICE_MARKED_FOR_DELETE && err != ERROR_SERVICE_DOES_NOT_EXIST) break; } }
        if (!hService && err == ERROR_SERVICE_DOES_NOT_EXIST) {
            hService = CreateServiceW(hSCM, DBK_SERVICE_NAME, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, sysPath, NULL, NULL, NULL, NULL, NULL);
            if (!hService) { CloseServiceHandle(hSCM); return DriverFail("CreateServiceW (DBK64)", GetLastError()); }
        } else if (!hService) { CloseServiceHandle(hSCM); return DriverFail("OpenServiceW (DBK64)", err); }
    }
    if (!ChangeServiceConfigW(hService, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, sysPath, NULL, NULL, NULL, NULL, NULL, DBK_SERVICE_NAME)) { DWORD err = GetLastError(); CloseServiceHandle(hService); CloseServiceHandle(hSCM); return DriverFail("ChangeServiceConfigW (DBK64 image path)", err); }
    if (!DriverWriteRegistryValues()) { CloseServiceHandle(hService); CloseServiceHandle(hSCM); return false; }
    DWORD state = DriverQueryServiceState(hService);
    if (state == SERVICE_RUNNING || state == SERVICE_START_PENDING) { SERVICE_STATUS ss = {}; ControlService(hService, SERVICE_CONTROL_STOP, &ss); for (int i = 0; i < 100; i++) { if (DriverQueryServiceState(hService) == SERVICE_STOPPED) break; Sleep(100); } }
    if (!StartServiceW(hService, 0, NULL)) { DWORD err = GetLastError(); if (err != ERROR_SERVICE_ALREADY_RUNNING) { CloseServiceHandle(hService); CloseServiceHandle(hSCM); return DriverFail("StartServiceW (DBK64)", err); } }
    bool running = false; for (int i = 0; i < 100; i++) { DWORD st = DriverQueryServiceState(hService); if (st == SERVICE_RUNNING) { running = true; break; } if (st == SERVICE_STOPPED) break; Sleep(100); }
    if (!running) {
        SERVICE_STATUS_PROCESS ssp = {}; DriverQueryServiceStatus(hService, &ssp); DWORD win32 = ssp.dwWin32ExitCode; DWORD svc = ssp.dwServiceSpecificExitCode;
        char etext[512]; DriverWin32ErrorText(win32 ? win32 : ERROR_DRIVER_BLOCKED, etext, sizeof(etext)); char svctext[64] = ""; if (svc) snprintf(svctext, sizeof(svctext), "\n  Service-specific code = %lu", svc);
        char msg[1024]; snprintf(msg, sizeof(msg), "DBK64 failed to load:\n  Win32 exit code = %lu (%s)%s\n\nThis is almost always a DRIVER SIGNING problem:\n  - test-sign + bcdedit /set testsigning on (reboot)\n  - Secure Boot OFF, HVCI OFF", win32 ? win32 : ERROR_DRIVER_BLOCKED, etext, svctext);
        DriverMessage("%s", msg); CloseServiceHandle(hService); CloseServiceHandle(hSCM); return false;
    }
    CloseServiceHandle(hService); CloseServiceHandle(hSCM); return true;
}

void StopAndUnloadDriver()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); if (!hSCM) return;
    SC_HANDLE hService = OpenServiceW(hSCM, DBK_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService) { SERVICE_STATUS status; ControlService(hService, SERVICE_CONTROL_STOP, &status); for (int i = 0; i < 100; i++) { if (DriverQueryServiceState(hService) == SERVICE_STOPPED) break; Sleep(100); } DeleteService(hService); CloseServiceHandle(hService); }
    HKEY hKey = NULL; if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, DBK_SERVICE_REG_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) { RegDeleteValueW(hKey, L"A"); RegDeleteValueW(hKey, L"B"); RegDeleteValueW(hKey, L"C"); RegDeleteValueW(hKey, L"D"); RegCloseKey(hKey); }
    CloseServiceHandle(hSCM);
}

bool ConnectDriver()
{
    DisconnectDriver();
    g_hDriver = CreateFileW(DBK_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDriver == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError(); char etext[512]; DriverWin32ErrorText(err, etext, sizeof(etext));
        char msg[1024]; snprintf(msg, sizeof(msg), "Could not open the DBK64 device (%S):\n(error %lu: %s)", DBK_DEVICE_PATH, err, etext); DriverMessage("%s", msg); return false;
    }
    g_DriverConnected = true;
    if (!DbkGetVersion(&g_KernelVersion)) { g_KernelVersion = 0; DriverMessage("Opened DBK64 but could not read its version. Expected %u.", DBK_VERSION_EXPECTED); }
    return true;
}
void DisconnectDriver() { if (g_hDriver != INVALID_HANDLE_VALUE) { CloseHandle(g_hDriver); g_hDriver = INVALID_HANDLE_VALUE; } g_DriverConnected = false; }

// =====================================================================
//  Low-level DBK64 IOCTL helpers
// =====================================================================
bool DbkIoctl(ULONG code, const void* in, ULONG inSize, void* out, ULONG outSize, ULONG* returned)
{
    if (g_hDriver == INVALID_HANDLE_VALUE) return false;
    DWORD br = 0; BOOL ok = DeviceIoControl(g_hDriver, code, (LPVOID)in, inSize, out, outSize, &br, NULL);
    if (returned) *returned = br; return ok != FALSE;
}
bool DbkReadBytes(ULONG pid, ULONG_PTR addr, void* out, ULONG size)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0 || size == 0 || size > DBK_MAX_IO_SIZE || out == NULL) return false;
    DBK_READ_REQUEST req; req.ProcessId = pid; req.Address = addr; req.BytesToRead = (USHORT)size;
    ULONG returned = 0; return DbkIoctl(IOCTL_CE_READMEMORY, &req, sizeof(req), out, size, &returned) && returned == size;
}
bool DbkWriteBytes(ULONG pid, ULONG_PTR addr, const void* in, ULONG size)
{
    if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0 || size == 0 || size > DBK_MAX_IO_SIZE || in == NULL) return false;
    ULONG total = DBK_WRITE_HEADER_SIZE + size; std::vector<BYTE> buf(total, 0);
    *(ULONG64*)(&buf[0]) = pid; *(ULONG64*)(&buf[8]) = addr; *(USHORT*)(&buf[16]) = (USHORT)size;
    memcpy(&buf[DBK_WRITE_HEADER_SIZE], in, size);
    return DbkIoctl(IOCTL_CE_WRITEMEMORY, buf.data(), total, NULL, 0, NULL);
}

// =====================================================================
//  Memory Operations
// =====================================================================
ULONG GetDataSize(int dataType) {
    switch (dataType) { case 3: return 1; case 2: return 2; case 4: return 4; case 1: return 4; case 0: return 8; case 5: return 8; default: return 4; }
}
void WriteMemory(ULONG pid, ULONG_PTR addr, ULONG64 val64, int dataType) { if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) return; ULONG sz = GetDataSize(dataType); DbkWriteBytes(pid, addr, &val64, sz); }
void ReadMemory(ULONG pid, ULONG_PTR addr, ULONG64* outVal, int dataType) { if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) { *outVal = 0; return; } ULONG sz = GetDataSize(dataType); ULONG64 v = 0; if (!DbkReadBytes(pid, addr, &v, sz)) v = 0; *outVal = v; }
ULONG64 ParseInputToValue(const char* str, int dataType) {
    if (dataType == 1) { float f = (float)atof(str); ULONG tmp; memcpy(&tmp, &f, sizeof(float)); return (ULONG64)tmp; }
    else if (dataType == 5) { double d = atof(str); ULONG64 tmp; memcpy(&tmp, &d, sizeof(double)); return tmp; }
    else { return _strtoui64(str, NULL, 0); }
}
void FormatValueToString(ULONG64 val64, int dataType, char* outBuf, size_t maxLen) {
    if (dataType == 1) { ULONG tmp = (ULONG)val64; float f; memcpy(&f, &tmp, sizeof(float)); sprintf_s(outBuf, maxLen, "%.2f", f); }
    else if (dataType == 5) { double d; memcpy(&d, &val64, sizeof(double)); sprintf_s(outBuf, maxLen, "%.2lf", d); }
    else if (dataType == 0) { sprintf_s(outBuf, maxLen, "%lld", (long long)val64); }
    else if (dataType == 3) { sprintf_s(outBuf, maxLen, "%u", (unsigned char)val64); }
    else if (dataType == 2) { sprintf_s(outBuf, maxLen, "%u", (unsigned short)val64); }
    else { sprintf_s(outBuf, maxLen, "%lu", (unsigned long)val64); }
}

bool DbkGetVersion(ULONG* version) { if (version) *version = 0; ULONG v = 0; if (DbkIoctl(IOCTL_CE_GETVERSION, NULL, 0, &v, sizeof(v))) { if (version) *version = v; return true; } return false; }
bool DbkAllocProcessMem(ULONG pid, ULONG64 size, ULONG64* out) {
    if (out) *out = 0; DBK_ALLOC_PROCESS req = {}; req.ProcessId = pid; req.BaseAddress = 0; req.Size = size; req.AllocationType = 0x3000; req.Protect = 0x40;
    ULONG64 addr = 0; if (DbkIoctl(IOCTL_CE_ALLOCATEMEM, &req, sizeof(req), &addr, sizeof(addr))) { if (out) *out = addr; return addr != 0; } return false;
}
bool DbkSuspendProcess(ULONG pid) { return DbkIoctl(IOCTL_CE_SUSPENDPROCESS, &pid, sizeof(pid), NULL, 0, NULL); }
bool DbkResumeProcess(ULONG pid) { return DbkIoctl(IOCTL_CE_RESUMEPROCESS, &pid, sizeof(pid), NULL, 0, NULL); }
bool DbkSuspendThread(ULONG tid) { return DbkIoctl(IOCTL_CE_SUSPENDTHREAD, &tid, sizeof(tid), NULL, 0, NULL); }
bool DbkResumeThread(ULONG tid) { return DbkIoctl(IOCTL_CE_RESUMETHREAD, &tid, sizeof(tid), NULL, 0, NULL); }
bool DbkOpenProcessHandle(ULONG pid, ULONG64* handle, UCHAR* special) {
    if (handle) *handle = 0; if (special) *special = 0; DBK_OPENPROCESS_OUT out = {};
    if (DbkIoctl(IOCTL_CE_OPENPROCESS, &pid, sizeof(pid), &out, sizeof(out))) { if (handle) *handle = out.Handle; if (special) *special = out.Special; return true; } return false;
}
bool DbkGetPEPROCESS(ULONG pid, ULONG64* out) { if (out) *out = 0; ULONG64 v = 0; if (DbkIoctl(IOCTL_CE_GETPEPROCESS, &pid, sizeof(pid), &v, sizeof(v))) { if (out) *out = v; return true; } return false; }
bool DbkGetPeb(ULONG64 peprocess, ULONG64* outPeb) { if (outPeb) *outPeb = 0; ULONG64 v = 0; if (DbkIoctl(IOCTL_CE_GET_PEB, &peprocess, sizeof(peprocess), &v, sizeof(v))) { if (outPeb) *outPeb = v; return v != 0; } return false; }
bool DbkGetWow64Peb(ULONG pid, ULONG64* outWow64Peb) {
    if (outWow64Peb) *outWow64Peb = 0; if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) return false;
#pragma pack(push, 1)
    struct QIP_IN { ULONG64 processid; ULONG64 ProcessInformationAddress; ULONG64 ProcessInformationClass; ULONG64 ProcessInformationLength; };
    struct QIP_OUT { ULONG64 result; ULONG64 returnLength; ULONG64 data; };
#pragma pack(pop)
    QIP_IN inp{}; inp.processid = pid; inp.ProcessInformationAddress = 1; inp.ProcessInformationClass = 26; inp.ProcessInformationLength = sizeof(ULONG64);
    QIP_OUT out{}; ULONG returned = 0;
    if (!DbkIoctl(IOCTL_CE_QUERYINFORMATIONPROCESS, &inp, sizeof(inp), &out, sizeof(out), &returned)) return false;
    if (out.result != 0) { if (out.data == 0) { if (outWow64Peb) *outWow64Peb = 0; return true; } return false; }
    if (outWow64Peb) *outWow64Peb = out.data; return true;
}
bool DbkQueryVirtualMemory(ULONG pid, ULONG_PTR addr, ULONG_PTR* length, ULONG* protection) {
    if (length) *length = 0; if (protection) *protection = 0; if (g_hDriver == INVALID_HANDLE_VALUE || pid == 0) return false;
    DBK_QUERY_VMEM_INOUT buf = {}; buf.In.ProcessId = pid; buf.In.StartAddress = addr;
    if (!DbkIoctl(IOCTL_CE_QUERY_VIRTUAL_MEMORY, &buf, sizeof(buf), &buf, sizeof(buf))) return false;
    if (length) *length = (ULONG_PTR)buf.Out.Length; if (protection) *protection = buf.Out.Protection; return true;
}

static ULONG64 GetWow64Peb32Imno(ULONG pid) {
    if (g_hDriver != INVALID_HANDLE_VALUE) { ULONG64 wow64 = 0; if (DbkGetWow64Peb(pid, &wow64)) return wow64; }
    typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static PFN_NtQueryInformationProcess pNtQIP = nullptr; static bool tried = false;
    if (!tried) { tried = true; HMODULE ntdll = GetModuleHandleA("ntdll.dll"); if (ntdll) pNtQIP = (PFN_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess"); }
    if (!pNtQIP) return 0; HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (!h) return 0;
    ULONG64 wow64 = 0; ULONG ret = 0; NTSTATUS st = pNtQIP(h, 26, &wow64, sizeof(wow64), &ret); CloseHandle(h); if (st != 0) return 0; return wow64;
}

bool IsTarget64Bit(ULONG pid) {
    if (pid == 0) return true;
    if (g_hDriver != INVALID_HANDLE_VALUE) { ULONG64 wow64 = GetWow64Peb32Imno(pid); if (wow64 != 0) return false; ULONG64 pe = 0; if (DbkGetPEPROCESS(pid, &pe) && pe) { ULONG64 peb = 0; if (DbkGetPeb(pe, &peb) && peb) return true; } }
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (h) { BOOL wow64 = FALSE; BOOL ok = IsWow64Process(h, &wow64); CloseHandle(h); if (ok) return !wow64; }
    return true;
}

// =====================================================================
//  Freeze Loop
// =====================================================================
void FreezeLoop() {
    while (g_FreezeRunning) {
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            std::lock_guard<std::mutex> lock(g_CheatTableLock);
            for (auto& item : g_CheatTable) { if (item.Enabled && item.Pid != 0) WriteMemory(item.Pid, item.Address, item.Value64, item.DataType); }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// =====================================================================
//  Process Enumeration - KERNEL ONLY
// =====================================================================
void RefreshProcessList()
{
    g_ProcessList.clear();
    if (g_hDriver == INVALID_HANDLE_VALUE) return; // kernel only
    typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll"); if (!ntdll) return;
    auto pNtQSI = (PFN_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation"); if (!pNtQSI) return;
    ULONG bufSize = 1 << 20; std::vector<BYTE> buffer; NTSTATUS st = 0; ULONG retLen = 0;
    for (int tries = 0; tries < 5; tries++) { buffer.resize(bufSize); st = pNtQSI(5, buffer.data(), bufSize, &retLen); if (st == 0) break; if (st == 0xC0000004) { bufSize = retLen + (1 << 20); continue; } break; }
    if (st != 0) return;
    struct UNICODE_STRING_NT_IMNO { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
    struct SYSTEM_PROCESS_INFORMATION_K_IMNO { ULONG NextEntryOffset; ULONG NumberOfThreads; LARGE_INTEGER WorkingSetPrivateSize; ULONG HardFaultCount; ULONG NumberOfThreadsHighWatermark; ULONGLONG CycleTime; LARGE_INTEGER CreateTime; LARGE_INTEGER UserTime; LARGE_INTEGER KernelTime; UNICODE_STRING_NT_IMNO ImageName; LONG BasePriority; HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId; };
    ULONG offset = 0;
    while (offset < buffer.size()) {
        auto spi = (SYSTEM_PROCESS_INFORMATION_K_IMNO*)(buffer.data() + offset); ULONG pid = (ULONG)(ULONG_PTR)spi->UniqueProcessId;
        if (pid) { ULONG64 pe = 0; if (DbkGetPEPROCESS(pid, &pe) && pe) { ProcessInfo info{}; info.ProcessId = pid; memset(info.Name, 0, sizeof(info.Name)); if (spi->ImageName.Buffer && spi->ImageName.Length) { int wlen = spi->ImageName.Length / 2; wchar_t wtmp[260] = {0}; wcsncpy_s(wtmp, spi->ImageName.Buffer, wlen); WideCharToMultiByte(CP_UTF8, 0, wtmp, wlen, info.Name, (int)sizeof(info.Name)-1, NULL, NULL); } else { if (pid == 4) strcpy_s(info.Name, sizeof(info.Name), "System"); else sprintf_s(info.Name, sizeof(info.Name), "PID %u", pid); } if (info.Name[0]) g_ProcessList.push_back(info); } }
        if (spi->NextEntryOffset == 0) break; offset += spi->NextEntryOffset;
    }
}

// =====================================================================
//  Memory region enumeration & scanning - KERNEL ONLY
// =====================================================================
struct RegionInfo { ULONG_PTR Start; ULONG_PTR End; };
static ULONG_PTR MaxAddr(ULONG_PTR a, ULONG_PTR b) { return a > b ? a : b; }
static ULONG_PTR MinAddr(ULONG_PTR a, ULONG_PTR b) { return a < b ? a : b; }
static bool IsReadableProtectKernel(DWORD protect) { return (protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE); }
static std::vector<RegionInfo> EnumerateRegions(ULONG pid, ULONG_PTR rangeStart, ULONG_PTR rangeEnd) {
    std::vector<RegionInfo> regions; if (g_hDriver == INVALID_HANDLE_VALUE) return regions;
    ULONG_PTR cursor = rangeStart & ~(ULONG_PTR)0xFFF; ULONG guard = 0;
    while (cursor < rangeEnd) {
        if (++guard > 1 << 22) break; ULONG_PTR length = 0; ULONG protection = 0;
        if (!DbkQueryVirtualMemory(pid, cursor, &length, &protection)) break; if (length == 0) break;
        ULONG_PTR base = cursor & ~(ULONG_PTR)0xFFF; ULONG_PTR end = base + length; if (end <= base) break;
        if (IsReadableProtectKernel(protection)) { ULONG_PTR s = MaxAddr(base, rangeStart); ULONG_PTR e = MinAddr(end, rangeEnd); if (s < e) regions.push_back({s,e}); }
        cursor = end;
    }
    return regions;
}

void AsyncFirstScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, bool useRange, ULONG_PTR rangeStart, ULONG_PTR rangeEnd, bool allowUnaligned)
{
    g_IsScanning = true; g_ScanProgress = 0; g_ScanTruncated = false;
    { std::lock_guard<std::mutex> lock(g_ScanResultsLock); g_ScanResults.clear(); }
    if (g_hDriver == INVALID_HANDLE_VALUE || targetPid == 0) { g_ScanVersion++; g_IsScanning = false; return; }
    ULONG sz = GetDataSize(dataType); ULONG_PTR rStart = useRange ? rangeStart : 0x10000; ULONG_PTR rEnd = useRange ? rangeEnd : 0x7FFFFFFFFFFFULL;
    std::vector<RegionInfo> regions = EnumerateRegions(targetPid, rStart, rEnd);
    std::vector<ULONG_PTR> results; std::vector<BYTE> chunk(DBK_MAX_IO_SIZE); ULONG64 totalBytes = 0, doneBytes = 0;
    for (auto& r : regions) totalBytes += (ULONG64)(r.End - r.Start);
    for (auto& r : regions) {
        ULONG_PTR cur = r.Start;
        while (cur < r.End) {
            ULONG_PTR remaining = r.End - cur; ULONG chunkSize = (ULONG)MinAddr(remaining, (ULONG_PTR)chunk.size());
            if (DbkReadBytes(targetPid, cur, chunk.data(), chunkSize)) {
                ULONG maxOff = (chunkSize >= sz) ? (chunkSize - sz + 1) : 0; ULONG step = allowUnaligned ? 1 : sz;
                for (ULONG off = 0; off < maxOff; off += step) {
                    if (memcmp(&chunk[off], &searchVal64, sz) == 0) { results.push_back(cur + off); if (results.size() >= MAX_SCAN_RESULTS) { g_ScanTruncated = true; goto scan_done; } }
                }
            }
            cur += chunkSize; doneBytes += chunkSize; g_ScanProgress = totalBytes ? (int)(doneBytes * 100 / totalBytes) : 100;
        }
    }
scan_done:
    { std::lock_guard<std::mutex> lock(g_ScanResultsLock); g_ScanResults = std::move(results); }
    g_ScanVersion++; g_ScanProgress = 100; g_IsScanning = false;
}
void AsyncNextScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, std::vector<ULONG_PTR> prevResults)
{
    g_IsScanning = true; g_ScanProgress = 0; g_ScanTruncated = false;
    if (g_hDriver == INVALID_HANDLE_VALUE || prevResults.empty()) { g_IsScanning = false; return; }
    ULONG sz = GetDataSize(dataType); std::vector<ULONG_PTR> results; results.reserve(prevResults.size());
    ULONG64 total = (ULONG64)prevResults.size(), done = 0;
    for (auto a : prevResults) { ULONG64 v = 0; if (DbkReadBytes(targetPid, a, &v, sz) && memcmp(&v, &searchVal64, sz) == 0) results.push_back(a); done++; g_ScanProgress = total ? (int)(done * 100 / total) : 100; }
    { std::lock_guard<std::mutex> lock(g_ScanResultsLock); g_ScanResults = std::move(results); }
    g_ScanVersion++; g_ScanProgress = 100; g_IsScanning = false;
}
void StartFirstScan() {
    if (g_SelectedPid == 0 || g_IsScanning) return; ULONG64 val64 = ParseInputToValue(g_ScanValueInput, g_SelectedDataType); g_ResultsDataType = g_SelectedDataType;
    ULONG_PTR rStart = 0x10000; ULONG_PTR rEnd = 0x7FFFFFFFFFFFULL; if (g_UseScanRange) { rStart = (ULONG_PTR)_strtoui64(g_ScanRangeStart, NULL, 0); rEnd = (ULONG_PTR)_strtoui64(g_ScanRangeEnd, NULL, 0); }
    std::thread(AsyncFirstScanWorker, g_SelectedPid, g_SelectedDataType, val64, g_UseScanRange, rStart, rEnd, g_AllowUnaligned).detach();
}
void StartNextScan() {
    if (g_SelectedPid == 0 || g_IsScanning) return; std::vector<ULONG_PTR> currentCopy; { std::lock_guard<std::mutex> lock(g_ScanResultsLock); currentCopy = g_ScanResults; } if (currentCopy.empty()) return;
    ULONG64 val64 = ParseInputToValue(g_ScanValueInput, g_SelectedDataType); g_ResultsDataType = g_SelectedDataType;
    std::thread(AsyncNextScanWorker, g_SelectedPid, g_SelectedDataType, val64, currentCopy).detach();
}
void ExportResultsToFile() {
    std::vector<ULONG_PTR> copy; { std::lock_guard<std::mutex> lock(g_ScanResultsLock); copy = g_ScanResults; }
    std::ofstream outFile("ScanResultsExport.txt"); if (!outFile.is_open()) return;
    for (auto addr : copy) outFile << "0x" << std::hex << addr << "\n"; outFile.close();
}

// =====================================================================
//  WinMain - simplified to 2 tabs only (Memory Scanner, Cheat Table)
// =====================================================================
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance); UNREFERENCED_PARAMETER(hPrevInstance); UNREFERENCED_PARAMETER(lpCmdLine); UNREFERENCED_PARAMETER(nCmdShow);
    EnableSeDebugPrivilege();
    LoadAndStartDriver();
    bool driverConnected = ConnectDriver();
    if (!driverConnected) {
        char msg[1408]; snprintf(msg, sizeof(msg), "Failed to connect to the DBK64 kernel driver!\n\n%s\n\nGeneral requirements:\n  - Run Imno as Administrator\n  - DBK64.sys must be next to Imno.exe\n  - Driver must be SIGNED: test-sign + bcdedit /set testsigning on, Secure Boot OFF, HVCI OFF\n\nUse Reconnect to retry.", g_KernelStatus[0] ? g_KernelStatus : "(no detailed status)");
        MessageBoxA(NULL, msg, "DBK64 driver not available", MB_OK | MB_ICONWARNING);
    }
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Imno - DBK64 (Kernel Only)", NULL, NULL);
    if (!window) { glfwTerminate(); return 1; }
    g_Window = window; g_hWnd = glfwGetWin32Window(window);

    DXGI_SWAP_CHAIN_DESC sd; ZeroMemory(&sd, sizeof(sd)); sd.BufferCount = 2; sd.BufferDesc.Width = 0; sd.BufferDesc.Height = 0; sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM; sd.BufferDesc.RefreshRate.Numerator = 60; sd.BufferDesc.RefreshRate.Denominator = 1; sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH; sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT; sd.OutputWindow = g_hWnd; sd.SampleDesc.Count = 1; sd.SampleDesc.Quality = 0; sd.Windowed = TRUE; sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    UINT createDeviceFlags = 0; D3D_FEATURE_LEVEL featureLevel; const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    ID3D11Device* pd3dDevice = NULL; ID3D11DeviceContext* pd3dDeviceContext = NULL; IDXGISwapChain* pSwapChain = NULL;
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &pSwapChain, &pd3dDevice, &featureLevel, &pd3dDeviceContext) != S_OK) { glfwDestroyWindow(window); glfwTerminate(); return 1; }
    ID3D11RenderTargetView* mainRenderTargetView = NULL;
    auto CreateRT = [&]() { if (mainRenderTargetView) { mainRenderTargetView->Release(); mainRenderTargetView = NULL; } ID3D11Texture2D* pBackBuffer = NULL; pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer)); pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView); pBackBuffer->Release(); };
    CreateRT();
    IMGUI_CHECKVERSION(); ImGui::CreateContext(); ImGuiIO& io = ImGui::GetIO(); (void)io; io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOther(window, true); ImGui_ImplDX11_Init(pd3dDevice, pd3dDeviceContext);
    if (driverConnected) { RefreshProcessList(); DbkGetVersion(&g_KernelVersion); }
    g_FreezeThread = std::thread(FreezeLoop);
    int lastWidth = 0, lastHeight = 0; glfwGetFramebufferSize(window, &lastWidth, &lastHeight);
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        int fbWidth, fbHeight; glfwGetFramebufferSize(window, &fbWidth, &fbHeight);
        if (fbWidth > 0 && fbHeight > 0 && (fbWidth != lastWidth || fbHeight != lastHeight)) {
            lastWidth = fbWidth; lastHeight = fbHeight;
            pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
            if (mainRenderTargetView) { mainRenderTargetView->Release(); mainRenderTargetView = NULL; }
            ImGui_ImplDX11_InvalidateDeviceObjects(); pSwapChain->ResizeBuffers(0, (UINT)fbWidth, (UINT)fbHeight, DXGI_FORMAT_UNKNOWN, 0); CreateRT(); ImGui_ImplDX11_CreateDeviceObjects();
        }
        if (fbWidth == 0 || fbHeight == 0) { Sleep(10); continue; }
        ImGui_ImplDX11_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always); ImGui::SetNextWindowSize(ImVec2((float)fbWidth, (float)fbHeight), ImGuiCond_Always);
        ImGui::Begin("Imno - DBK64 (Kernel Only)", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar);

        driverConnected = (g_hDriver != INVALID_HANDLE_VALUE);
        if (driverConnected) ImGui::TextColored({0.0f, 1.0f, 0.0f, 1.0f}, "[DBK64 Driver: ACTIVE] [KERNEL MODE]");
        else { ImGui::TextColored({1.0f, 0.0f, 0.0f, 1.0f}, "[DBK64 Driver: INACTIVE]"); ImGui::SameLine(); if (ImGui::Button("Reconnect")) { LoadAndStartDriver(); driverConnected = ConnectDriver(); if (driverConnected) RefreshProcessList(); } }
        ImGui::SameLine(); if (ImGui::Button("Refresh", ImVec2(80, 25))) RefreshProcessList();
        ImGui::SameLine(); ImGui::SetNextItemWidth(150); ImGui::InputText("Filter", g_ProcessFilter, sizeof(g_ProcessFilter)); ImGui::SameLine();
        ImGui::SetNextItemWidth(260);
        char comboLabel[128]; strcpy_s(comboLabel, sizeof(comboLabel), "Select Target Process...");
        if (g_SelectedPid != 0) { const char* foundName = NULL; for (const auto& p : g_ProcessList) { if (p.ProcessId == g_SelectedPid) { foundName = p.Name; break; } } if (foundName) sprintf_s(comboLabel, sizeof(comboLabel), "%s (%u)", foundName, g_SelectedPid); else sprintf_s(comboLabel, sizeof(comboLabel), "PID %u", g_SelectedPid); }
        if (ImGui::BeginCombo("##proccombo", comboLabel)) {
            for (const auto& p : g_ProcessList) {
                if (g_ProcessFilter[0] != '\0' && strstr(p.Name, g_ProcessFilter) == NULL) continue;
                char label[128]; sprintf_s(label, sizeof(label), "%s (%u)", p.Name, p.ProcessId);
                bool isSelected = (g_SelectedPid == p.ProcessId);
                if (ImGui::Selectable(label, isSelected)) { g_SelectedPid = p.ProcessId; g_SelectedIs64 = IsTarget64Bit(p.ProcessId); }
                if (isSelected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::SameLine(); if (g_SelectedPid != 0) { ImGui::TextColored({0.0f, 1.0f, 0.0f, 1.0f}, "PID: %u", g_SelectedPid); ImGui::SameLine(); ImGui::TextDisabled("(%s)", g_SelectedIs64 ? "64-bit" : "32-bit"); }
        ImGui::Separator();

        if (ImGui::BeginTabBar("ImnoTabs")) {
            if (ImGui::BeginTabItem("Memory Scanner")) {
                ImGui::Text("Data Type:"); ImGui::SameLine();
                ImGui::RadioButton("4 Bytes", &g_SelectedDataType, 4); ImGui::SameLine();
                ImGui::RadioButton("2 Bytes", &g_SelectedDataType, 2); ImGui::SameLine();
                ImGui::RadioButton("1 Byte", &g_SelectedDataType, 3); ImGui::SameLine();
                ImGui::RadioButton("Float", &g_SelectedDataType, 1); ImGui::SameLine();
                ImGui::RadioButton("Double", &g_SelectedDataType, 5); ImGui::SameLine();
                ImGui::RadioButton("8 Bytes", &g_SelectedDataType, 0);
                ImGui::Spacing(); ImGui::Text("Scan Value:"); ImGui::SameLine(); ImGui::SetNextItemWidth(200); ImGui::InputText("##scanval", g_ScanValueInput, sizeof(g_ScanValueInput)); ImGui::SameLine();
                if (!g_IsScanning) {
                    if (ImGui::Button("First Scan", ImVec2(110, 30))) StartFirstScan(); ImGui::SameLine();
                    if (ImGui::Button("Next Scan", ImVec2(110, 30))) StartNextScan(); ImGui::SameLine();
                    if (ImGui::Button("Export Results", ImVec2(120, 30))) ExportResultsToFile();
                } else ImGui::TextDisabled("Scanning in progress...");
                ImGui::Checkbox("Unaligned Scan (slower)", &g_AllowUnaligned); ImGui::SameLine(); ImGui::Checkbox("Scan Range", &g_UseScanRange);
                if (g_UseScanRange) { ImGui::SetNextItemWidth(140); ImGui::InputText("Start", g_ScanRangeStart, sizeof(g_ScanRangeStart)); ImGui::SameLine(); ImGui::SetNextItemWidth(140); ImGui::InputText("End", g_ScanRangeEnd, sizeof(g_ScanRangeEnd)); }
                if (g_IsScanning) ImGui::ProgressBar((float)g_ScanProgress / 100.0f, ImVec2(-1, 0), "Scanning Process Memory (kernel reads)...");
                ImGui::Spacing(); ImGui::Separator();
                static std::vector<ULONG_PTR> s_DisplayAddrs; static std::vector<ULONG64> s_DisplayVals; static unsigned s_DisplayVersion = 0xFFFFFFFF; static bool s_NeedValueRefresh = true; static ULONGLONG s_LastValueRefresh = 0;
                if (!g_IsScanning && s_DisplayVersion != g_ScanVersion) { std::lock_guard<std::mutex> lock(g_ScanResultsLock); s_DisplayAddrs = g_ScanResults; s_DisplayVersion = g_ScanVersion; s_DisplayVals.assign(s_DisplayAddrs.size(), 0); s_NeedValueRefresh = true; }
                ImGui::Text("Scan Results Found: %zu", s_DisplayAddrs.size());
                if (!g_IsScanning && g_ScanTruncated) ImGui::TextColored({1.0f, 0.6f, 0.0f, 1.0f}, "Results truncated at %d - use Next Scan or a narrower range!", MAX_SCAN_RESULTS);
                ImGui::BeginChild("ResultsChild", ImVec2(0, 350), true);
                {
                    bool doRefresh = !g_IsScanning && (s_NeedValueRefresh || (GetTickCount64() - s_LastValueRefresh > 400));
                    ImGuiListClipper clipper; clipper.Begin((int)s_DisplayAddrs.size());
                    while (clipper.Step()) { for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) { if (doRefresh) ReadMemory(g_SelectedPid, s_DisplayAddrs[i], &s_DisplayVals[i], g_ResultsDataType); char valStr[64]; FormatValueToString(s_DisplayVals[i], g_ResultsDataType, valStr, sizeof(valStr)); char label[160]; sprintf_s(label, sizeof(label), "0x%llX : %s##res%d", s_DisplayAddrs[i], valStr, i); if (ImGui::Selectable(label)) { std::lock_guard<std::mutex> lock(g_CheatTableLock); char desc[64]; sprintf_s(desc, sizeof(desc), "0x%llX", s_DisplayAddrs[i]); g_CheatTable.push_back({s_DisplayAddrs[i], s_DisplayVals[i], false, g_ResultsDataType, g_SelectedPid, ""}); strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc); } } }
                    if (doRefresh) { s_LastValueRefresh = GetTickCount64(); s_NeedValueRefresh = false; }
                }
                ImGui::EndChild(); ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Cheat Table")) {
                ImGui::Text("Cheat Table (Active Freeze & Patches):");
                ImGui::BeginChild("CheatTableChild", ImVec2(0, 300), true);
                {
                    std::lock_guard<std::mutex> lock(g_CheatTableLock);
                    for (int i = 0; i < (int)g_CheatTable.size(); i++) {
                        ImGui::PushID(i); bool isEnabled = g_CheatTable[i].Enabled; if (ImGui::Checkbox("##en", &isEnabled)) g_CheatTable[i].Enabled = isEnabled; ImGui::SameLine();
                        ImGui::Text("0x%llX [PID %u]", g_CheatTable[i].Address, g_CheatTable[i].Pid); ImGui::SameLine(220);
                        char valStr[64]; FormatValueToString(g_CheatTable[i].Value64, g_CheatTable[i].DataType, valStr, sizeof(valStr));
                        ImGui::SetNextItemWidth(140); if (ImGui::InputText("##val", valStr, sizeof(valStr))) g_CheatTable[i].Value64 = ParseInputToValue(valStr, g_CheatTable[i].DataType);
                        ImGui::SameLine(380); ImGui::SetNextItemWidth(180); ImGui::InputText("##desc", g_CheatTable[i].Description, sizeof(g_CheatTable[i].Description));
                        ImGui::SameLine(570); if (ImGui::Button("Remove")) g_CheatTable.erase(g_CheatTable.begin() + i--);
                        ImGui::PopID();
                    }
                }
                ImGui::EndChild(); ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::End();
        ImGui::Render();
        const float clear_color[4] = {0.08f, 0.08f, 0.10f, 1.00f};
        pd3dDeviceContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL); pd3dDeviceContext->ClearRenderTargetView(mainRenderTargetView, clear_color);
        D3D11_VIEWPORT vp{}; vp.Width = (FLOAT)fbWidth; vp.Height = (FLOAT)fbHeight; vp.MinDepth = 0.0f; vp.MaxDepth = 1.0f; vp.TopLeftX = 0; vp.TopLeftY = 0; pd3dDeviceContext->RSSetViewports(1, &vp);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        pSwapChain->Present(1, 0);
    }
    g_FreezeRunning = false; if (g_FreezeThread.joinable()) g_FreezeThread.join();
    ImGui_ImplDX11_Shutdown(); ImGui_ImplGlfw_Shutdown(); ImGui::DestroyContext();
    if (mainRenderTargetView) mainRenderTargetView->Release(); if (pSwapChain) pSwapChain->Release(); if (pd3dDeviceContext) pd3dDeviceContext->Release(); if (pd3dDevice) pd3dDevice->Release();
    glfwDestroyWindow(window); glfwTerminate();
    DisconnectDriver(); StopAndUnloadDriver(); return 0;
}
