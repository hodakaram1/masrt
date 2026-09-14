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

// Zydis (vendored in third_party/) for instruction decoding.
#include <Zydis/Zydis.h>

// =====================================================================
//  DBK64 Kernel Driver Configuration
//
//  The DBK64 driver (Cheat Engine's DBKKernel) reads four registry
//  values from its own service key when DriverEntry runs:
//      A  -> device object name     (IoCreateDevice)
//      B  -> symbolic link name     (IoCreateSymbolicLink)  -> "\\\\.\\..."
//      C  -> process-event name     (process watch)
//      D  -> thread-event name      (thread watch)
//
//  The values below are written by LoadAndStartDriver() and MUST match
//  the name this GUI opens with ConnectDriver().
// =====================================================================
#define DBK_SERVICE_NAME     L"DBK64"
#define DBK_SERVICE_REG_KEY  L"SYSTEM\\CurrentControlSet\\Services\\DBK64"
#define DBK_DEVICE_NAME      L"\\Device\\DBK64"            // registry value "A"
#define DBK_SYMLINK_NAME     L"\\DosDevices\\DBK64"        // registry value "B"
#define DBK_PROCESS_EVENT    L"\\BaseNamedObjects\\DBKProcList"   // registry value "C"
#define DBK_THREAD_EVENT     L"\\BaseNamedObjects\\DBKThreadList" // registry value "D"
#define DBK_DEVICE_PATH      L"\\\\.\\DBK64"               // user-mode open path
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
#define IOCTL_CE_SUSPENDPROCESS       CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0824, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_RESUMEPROCESS        CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0825, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_ALLOCATEMEM_NONPAGED CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0826, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETGDT               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x082a, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_GETCR0               CTL_CODE(IOCTL_UNKNOWN_BASE, 0x082e, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_READMSR              CTL_CODE(IOCTL_UNKNOWN_BASE, 0x083f, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_WRITEMSR             CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0840, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CE_FREE_NONPAGED        CTL_CODE(IOCTL_UNKNOWN_BASE, 0x084c, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// Maximum addresses kept from a first scan (scanner reports truncation past this)
#define MAX_SCAN_RESULTS 200000

// =====================================================================
//  DBK64 Request / Response structures (byte-exact for the driver)
// =====================================================================
#pragma pack(push, 1)
typedef struct _DBK_READ_REQUEST {
    ULONG64 ProcessId;      // offset 0
    ULONG64 Address;        // offset 8
    USHORT  BytesToRead;    // offset 16
} DBK_READ_REQUEST, *PDBK_READ_REQUEST;

typedef struct _DBK_WRITE_HEADER {
    ULONG64 ProcessId;      // offset 0
    ULONG64 Address;        // offset 8
    USHORT  BytesToWrite;   // offset 16  (driver pads this struct to 24 bytes)
} DBK_WRITE_HEADER, *PDBK_WRITE_HEADER;
// The driver's "sizeof(struct input)" == 24 (default alignment). Data follows at +24.
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

// IOCTL_CE_QUERY_VIRTUAL_MEMORY (0x0803):
//   input  { UINT64 ProcessId; UINT64 StartAddress; }
//   output { UINT64 Length; ULONG Protection; }   (same buffer, returned in place)
// Length is the byte count from StartAddress (page-aligned down) until the
// page-table state changes; Protection is PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_READ
// / PAGE_NOACCESS. Enumerated fully from the kernel, so it works on protected
// processes and 32-bit targets that user-mode VirtualQueryEx cannot open.
#pragma pack(push, 1)
typedef struct _DBK_QUERY_VMEM {
    ULONG64 ProcessId;
    ULONG64 StartAddress;
} DBK_QUERY_VMEM, *PDBK_QUERY_VMEM;

typedef struct _DBK_QUERY_VMEM_OUT {
    ULONG64 Length;
    ULONG   Protection;
} DBK_QUERY_VMEM_OUT, *PDBK_QUERY_VMEM_OUT;

// Input/output share one buffered buffer (in-place): the driver overwrites
// the 16-byte input header with the 12-byte output.
typedef struct _DBK_QUERY_VMEM_INOUT {
    union {
        DBK_QUERY_VMEM     In;
        DBK_QUERY_VMEM_OUT Out;
    };
} DBK_QUERY_VMEM_INOUT, *PDBK_QUERY_VMEM_INOUT;
#pragma pack(pop)

// Max bytes the driver can read/write in one IOCTL (WORD size field).
#define DBK_MAX_IO_SIZE 0xFFFF

// IDT / GDT are returned by the driver as: WORD limit (offset 0) + pointer (offset 2)
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
//  Cheat Table Item Structure
// =====================================================================
struct CheatItem {
    ULONG_PTR Address;
    ULONG64   Value64;
    bool      Enabled;
    int       DataType;   // size/type captured when the item was added
    ULONG     Pid;        // process captured when the item was added
    char      Description[64];
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
//  Memory & Patch Operations
// =====================================================================
ULONG GetDataSize(int dataType);
void WriteMemory(ULONG pid, ULONG_PTR addr, ULONG64 val64, int dataType);
void ReadMemory(ULONG pid, ULONG_PTR addr, ULONG64* outVal, int dataType);
void PatchMemory(ULONG_PTR addr, const UCHAR* pattern, ULONG size);

// Process bitness / pointer size (32-bit targets use 4-byte pointers)
bool IsTarget64Bit(ULONG pid);
ULONG GetPointerSize(ULONG pid);
// Parses "module.exe+0x123", "module.exe-0x10" or a raw "0x..." / decimal address.
ULONG_PTR ParseAddressInput(const char* str);

ULONG64 ParseInputToValue(const char* str, int dataType);
void FormatValueToString(ULONG64 val64, int dataType, char* outBuf, size_t maxLen);
ULONG_PTR ResolvePointerPath(ULONG pid, ULONG_PTR baseAddress, const std::vector<LONG>& offsets);
struct ResolvedPointer;
ResolvedPointer ResolvePointerSmart(ULONG pid, const char* addressInput, const char* offsetsInput);
std::string GetAutoOffsetForAddress(ULONG_PTR targetAddr);
std::string GetZydisDisassembledBytes(ULONG_PTR targetAddr, ULONG instructionCount);

// =====================================================================
//  DBK64 feature helpers (Kernel tab)
// =====================================================================
bool DbkGetVersion(ULONG* version);
bool DbkGetCR0(ULONG64* out);
bool DbkGetCR3(ULONG pid, ULONG64* out);
bool DbkGetCR4(ULONG64* out);
bool DbkReadMsr(ULONG msr, ULONG64* out);
bool DbkWriteMsr(ULONG64 msr, ULONG64 value);
bool DbkGetIdt(USHORT* limit, ULONG_PTR* base);
bool DbkGetGdt(USHORT* limit, ULONG_PTR* base);
bool DbkReadPhysical(ULONG64 addr, void* out, ULONG size);
bool DbkWritePhysical(ULONG64 addr, const void* in, ULONG size);
bool DbkAllocNonPaged(ULONG size, ULONG64* out);
bool DbkFreeNonPaged(ULONG64 addr);
bool DbkAllocProcessMem(ULONG pid, ULONG64 size, ULONG64* out);
bool DbkSuspendProcess(ULONG pid);
bool DbkResumeProcess(ULONG pid);
bool DbkOpenProcessHandle(ULONG pid, ULONG64* handle, UCHAR* special);
bool DbkGetPEPROCESS(ULONG pid, ULONG64* out);
bool DbkQueryVirtualMemory(ULONG pid, ULONG_PTR addr, ULONG_PTR* length, ULONG* protection);

// =====================================================================
//  Workers / UI
// =====================================================================
void FreezeLoop();
void RefreshProcessList();
void RefreshModules();

void AsyncFirstScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, bool useRange, ULONG_PTR rangeStart, ULONG_PTR rangeEnd, bool allowUnaligned);
void AsyncNextScanWorker(ULONG targetPid, int dataType, ULONG64 searchVal64, std::vector<ULONG_PTR> prevResults);
void StartFirstScan();
void StartNextScan();
void ExportResultsToFile();
