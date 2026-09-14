#pragma once

#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <d3d11.h>
#include <TlHelp32.h>
#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_dx11.h"
#include "Resource.h"

// =====================================================================
//  DBK64 Kernel Driver Configuration
// =====================================================================
#define DBK_SERVICE_NAME     L"DBK64"
#define DBK_SERVICE_REG_KEY  L"SYSTEM\\CurrentControlSet\\Services\\DBK64"
#define DBK_DEVICE_NAME      L"\\Device\\DBK64"
#define DBK_SYMLINK_NAME     L"\\DosDevices\\DBK64"
#define DBK_PROCESS_EVENT    L"\\BaseNamedObjects\\DBKProcList"
#define DBK_THREAD_EVENT     L"\\BaseNamedObjects\\DBKThreadList"
#define DBK_DEVICE_PATH      L"\\\\.\\DBK64"
#define DBK_DRIVER_FILE      L"DBK64.sys"

#define DBK_VERSION_EXPECTED 2000027

// =====================================================================
//  IOCTL Codes (must be identical to DBKKernel/IOPLDispatcher.h)
// =====================================================================
#define IOCTL_UNKNOWN_BASE            FILE_DEVICE_UNKNOWN

#define IOCTL_CE_READMEMORY           CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_WRITEMEMORY          CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_OPENPROCESS          CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_QUERY_VIRTUAL_MEMORY CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETPEPROCESS         CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_READPHYSICALMEMORY   CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_WRITEPHYSICALMEMORY  CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETPHYSICALADDRESS   CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETCR3               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x080a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETIDT               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x080f, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETVERSION           CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0816, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETCR4               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0817, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_ALLOCATEMEM          CTL_CODE(IOCTL_UNKNOWN_BASE, 0x081f, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_SUSPENDTHREAD        CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0822, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_RESUMETHREAD         CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0823, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_SUSPENDPROCESS       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0824, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_RESUMEPROCESS        CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0825, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_ALLOCATEMEM_NONPAGED CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0826, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETGDT               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x082a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETCR0               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x082e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_READMSR              CTL_CODE(IOCTL_UNKNOWN_BASE, 0x083f, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_WRITEMSR             CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0840, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_FREE_NONPAGED        CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084c, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GET_PEB              CTL_CODE(IOCTL_UNKNOWN_BASE, 0x085d, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_QUERYINFORMATIONPROCESS CTL_CODE(IOCTL_UNKNOWN_BASE, 0x085e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define MAX_SCAN_RESULTS 200000

// =====================================================================
//  DBK64 Request / Response structures
// =====================================================================
#pragma pack(push, 1)
typedef struct _DBK_READ_REQUEST {
    ULONG64 ProcessId;
    ULONG64 Address;
    USHORT  BytesToRead;
} DBK_READ_REQUEST, *PDBK_READ_REQUEST;

typedef struct _DBK_WRITE_HEADER {
    ULONG64 ProcessId;
    ULONG64 Address;
    USHORT  BytesToWrite;
} DBK_WRITE_HEADER, *PDBK_WRITE_HEADER;
#define DBK_WRITE_HEADER_SIZE 24

typedef struct _DBK_PHYS_RW {
    ULONG64 Address;
    ULONG64 Bytes;
} DBK_PHYS_RW, *PDBK_PHYS_RW;

typedef struct _DBK_MSR_WRITE {
    ULONG64 Msr;
    ULONG64 Value;
} DBK_MSR_WRITE, *PDBK_MSR_WRITE;

typedef struct _DBK_ALLOC_PROCESS {
    ULONG64 ProcessId;
    ULONG64 BaseAddress;
    ULONG64 Size;
    ULONG64 AllocationType;
    ULONG64 Protect;
} DBK_ALLOC_PROCESS, *PDBK_ALLOC_PROCESS;

typedef struct _DBK_OPENPROCESS_OUT {
    ULONG64 Handle;
    UCHAR   Special;
} DBK_OPENPROCESS_OUT, *PDBK_OPENPROCESS_OUT;

typedef struct _DBK_VA_TO_PA {
    ULONG64 ProcessId;
    ULONG64 BaseAddress;
} DBK_VA_TO_PA, *PDBK_VA_TO_PA;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _DBK_QUERY_VMEM {
    ULONG64 ProcessId;
    ULONG64 StartAddress;
} DBK_QUERY_VMEM, *PDBK_QUERY_VMEM;

typedef struct _DBK_QUERY_VMEM_OUT {
    ULONG64 Length;
    ULONG   Protection;
} DBK_QUERY_VMEM_OUT, *PDBK_QUERY_VMEM_OUT;

typedef struct _DBK_QUERY_VMEM_INOUT {
    union {
        DBK_QUERY_VMEM     In;
        DBK_QUERY_VMEM_OUT Out;
    };
} DBK_QUERY_VMEM_INOUT, *PDBK_QUERY_VMEM_INOUT;
#pragma pack(pop)

#define DBK_MAX_IO_SIZE 0xFFFF

#pragma pack(push, 2)
typedef struct _DBK_SEG_TABLE {
    USHORT     Limit;
    ULONG_PTR  Base;
} DBK_SEG_TABLE, *PDBK_SEG_TABLE;
#pragma pack(pop)

// =====================================================================
//  Process / Module info
// =====================================================================
#pragma pack(push, 1)
typedef struct _ProcessInfo {
    ULONG ProcessId;
    CHAR  Name[64];
} ProcessInfo, *PProcessInfo;

typedef struct _ModuleInfo {
    CHAR      ModuleName[128];
    CHAR      FullPath[260];
    ULONG_PTR BaseAddress;
    ULONG     Size;
} ModuleInfo, *PModuleInfo;
#pragma pack(pop)

// =====================================================================
//  CE Freeze System - cloned from MemoryRecordUnit.pas TFreezeType
//  ftFrozen = exact freeze, ftAllowIncrease = allow increase (freeze if below), ftAllowDecrease = allow decrease (freeze if above)
//  + Freeze Trigger system (user requested: speed control + trigger)
// =====================================================================
enum class CEFreezeType {
    Frozen = 0,          // ftFrozen - exact freeze (CE default)
    AllowIncrease = 1,   // ftAllowIncrease - value can increase, but not decrease below frozen
    AllowDecrease = 2    // ftAllowDecrease - value can decrease, but not increase above frozen
};

enum class CEFreezeTrigger {
    Always = 0,          // freeze in loop always (CE default)
    ManualOnly = 1,      // only when manual trigger button pressed
    OnHotkey = 2,        // only while global hotkey held
    OnValueChanged = 3,  // trigger when current value != frozen (watchdog)
    Once = 4             // freeze once then auto-disable (one-shot)
};

enum class CEFreezeMode {
    Continuous = 0,      // continuous loop at interval
    ManualOnly = 1,      // manual trigger only - loop does nothing
    WhileKeyPressed = 2  // only freeze while trigger key held
};

struct CheatItem {
    ULONG_PTR Address = 0;          // Real address or base for pointer
    ULONG64   Value64 = 0;          // Frozen value (CE: FrozenValue)
    bool      Enabled = false;      // Active (CE: fActive)
    int       DataType = 4;         // 0=8bytes,1=float,2=2bytes,3=1byte,4=4bytes,5=double
    ULONG     Pid = 0;
    char      Description[64] = {0};

    // CE Freeze extensions (TFreezeType clone)
    CEFreezeType FreezeType = CEFreezeType::Frozen; // ftFrozen/ftAllowIncrease/ftAllowDecrease
    bool      AllowIncrease = false;
    bool      AllowDecrease = false;

    // Freeze Trigger extensions (user requested)
    CEFreezeTrigger Trigger = CEFreezeTrigger::Always;
    bool      OneShotDone = false; // for Once trigger
    ULONGLONG LastTriggerTick = 0;

    // Pointer support (CE: fpointeroffsets)
    bool      IsPointer = false;
    ULONG_PTR BaseAddress = 0; // if pointer, this is base (e.g. module base)
    std::vector<int> Offsets; // offsets chain
    ULONG_PTR RealAddress = 0; // resolved real address (CE: RealAddress)
    ULONG_PTR BaseAddressResolved = 0; // last resolved base

    // Tracking (CE: LastSeenValue, CurrentValue, FrozenValue string)
    ULONG64   LastSeenValue = 0;
    char      CurrentValueStr[64] = {0};
    char      FrozenValueStr[64] = {0};

    // Timing (CE: OnlyUpdateAfterInterval / update interval per offset)
    DWORD     UpdateInterval = 500; // ms, how often to re-resolve pointer
    ULONGLONG LastUpdateTick = 0;

    // Helpers
    void UpdateAllowFlags() {
        AllowIncrease = (FreezeType == CEFreezeType::AllowIncrease);
        AllowDecrease = (FreezeType == CEFreezeType::AllowDecrease);
    }
};

// =====================================================================
//  Driver Control
// =====================================================================
bool EnableSeDebugPrivilege();
bool LoadAndStartDriver();
void StopAndUnloadDriver();
bool ConnectDriver();
void DisconnectDriver();

// =====================================================================
//  Low-level DBK64 helpers
// =====================================================================
bool DbkIoctl(ULONG code, const void* in, ULONG inSize, void* out, ULONG outSize, ULONG* returned = NULL);
bool DbkReadBytes(ULONG pid, ULONG_PTR addr, void* out, ULONG size);
bool DbkWriteBytes(ULONG pid, ULONG_PTR addr, const void* in, ULONG size);

// =====================================================================
//  Memory Operations - simplified
// =====================================================================
ULONG GetDataSize(int dataType);
void WriteMemory(ULONG pid, ULONG_PTR addr, ULONG64 val64, int dataType);
void ReadMemory(ULONG pid, ULONG_PTR addr, ULONG64* outVal, int dataType);
bool IsTarget64Bit(ULONG pid);
ULONG64 ParseInputToValue(const char* str, int dataType);
void FormatValueToString(ULONG64 val64, int dataType, char* outBuf, size_t maxLen);

// =====================================================================
//  DBK64 core helpers - only what Scanner needs
// =====================================================================
bool DbkGetVersion(ULONG* version);
bool DbkAllocProcessMem(ULONG pid, ULONG64 size, ULONG64* out);
bool DbkSuspendProcess(ULONG pid);
bool DbkResumeProcess(ULONG pid);
bool DbkSuspendThread(ULONG tid);
bool DbkResumeThread(ULONG tid);
bool DbkOpenProcessHandle(ULONG pid, ULONG64* handle, UCHAR* special);
bool DbkGetPEPROCESS(ULONG pid, ULONG64* out);
bool DbkGetPeb(ULONG64 peprocess, ULONG64* outPeb);
bool DbkGetWow64Peb(ULONG pid, ULONG64* outWow64Peb);
bool DbkQueryVirtualMemory(ULONG pid, ULONG_PTR addr, ULONG_PTR* length, ULONG* protection);

// =====================================================================
//  Workers / UI - Memory Scanner, Cheat Table, Memory View, Freeze
// =====================================================================
void FreezeLoop();
bool ResolvePointerAddress(ULONG pid, ULONG_PTR base, const std::vector<int>& offsets, bool is64, ULONG_PTR* outReal);
bool GetRealAddressForItem(CheatItem& item, bool is64, ULONG_PTR* outAddr);
void ApplyFreezeForItem(CheatItem& item, bool is64); // CE TMemoryRecord.ApplyFreeze clone
void TriggerFreezeNow(bool ignoreTriggerFilter = false); // user requested freeze trigger
void TriggerFreezeSingle(int index); // trigger single item
void RefreshProcessList();
void AsyncFirstScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, bool useRange, ULONG_PTR rangeStart, ULONG_PTR rangeEnd, bool allowUnaligned);
void AsyncNextScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, std::vector<ULONG_PTR> prevResults);
void StartFirstScan();
void StartNextScan();
void ExportResultsToFile();

// =====================================================================
//  Globals (shared with MemoryView)
// =====================================================================
extern HWND g_hWnd;
extern HANDLE g_hDriver;
extern bool g_DriverConnected;
extern std::vector<ProcessInfo> g_ProcessList;
extern ULONG g_SelectedPid;
extern bool g_SelectedIs64;
extern std::vector<CheatItem> g_CheatTable;
extern std::mutex g_CheatTableLock;

// Freeze speed + trigger globals (user requested GUI control)
extern std::atomic<int>  g_FreezeIntervalMs;      // speed control 10-2000ms, default 50
extern std::atomic<bool> g_FreezeEnabled;         // global enable
extern std::atomic<int>  g_FreezeMode;            // CEFreezeMode as int
extern std::atomic<int>  g_FreezeTriggerKey;      // VK code for trigger key (default VK_F6 = 0x75)
extern std::atomic<bool> g_FreezeManualTrigger;   // set true for one manual pulse
extern std::atomic<int>  g_FreezeCount;           // how many freezes done
extern std::atomic<int>  g_FreezeLastMs;          // last loop duration
extern char g_FreezeTriggerKeyName[32];           // display name for key
