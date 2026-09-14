// =====================================================================
//  CEServer.cpp — Cheat Engine CEServer bridge for Imno
//
//  Implements the server side of the CEServer TCP protocol so a real
//  Cheat Engine can connect and use Imno + DBK64 as its memory backend.
//
//  Protocol reference: Cheat Engine source
//    - Cheat Engine/ceserver/ceserver.h   (command IDs & structs)
//    - Cheat Engine/networkInterface.pas   (client wire format)
//
//  Framing: no handshake and no per-packet header. The client sends a
//  single command byte followed by command-specific payload (little-endian,
//  packed). Responses are command-specific. Network handles are plain
//  integers; Cheat Engine ORs 0xCE000000 on its side.
//
//  Compression: Cheat Engine's `networkcompression` global defaults to 0,
//  so the client never requests compressed reads; we answer uncompressed.
// =====================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <chrono>
#include <memory>
#include <utility>
#include <map>
#include <set>
#include <deque>

#include "Imno.h"
#include "CEServer.h"

#pragma comment(lib, "Ws2_32.lib")

extern HANDLE g_hDriver; // DBK64 device handle (Imno.cpp)

// ---------------------------------------------------------------------
//  Protocol constants (must match Cheat Engine exactly)
// ---------------------------------------------------------------------
enum
{
    CMD_GETVERSION                    = 0,
    CMD_CLOSECONNECTION               = 1,
    CMD_TERMINATESERVER               = 2,
    CMD_OPENPROCESS                   = 3,
    CMD_CREATETOOLHELP32SNAPSHOT      = 4,
    CMD_PROCESS32FIRST                = 5,
    CMD_PROCESS32NEXT                 = 6,
    CMD_CLOSEHANDLE                   = 7,
    CMD_VIRTUALQUERYEX                = 8,
    CMD_READPROCESSMEMORY             = 9,
    CMD_WRITEPROCESSMEMORY            = 10,
    CMD_STARTDEBUG                    = 11,
    CMD_STOPDEBUG                     = 12,
    CMD_WAITFORDEBUGEVENT             = 13,
    CMD_CONTINUEFROMDEBUGEVENT        = 14,
    CMD_SETBREAKPOINT                 = 15,
    CMD_REMOVEBREAKPOINT              = 16,
    CMD_SUSPENDTHREAD                 = 17,
    CMD_RESUMETHREAD                  = 18,
    CMD_GETTHREADCONTEXT              = 19,
    CMD_SETTHREADCONTEXT              = 20,
    CMD_GETARCHITECTURE               = 21,
    CMD_MODULE32FIRST                 = 22,
    CMD_MODULE32NEXT                  = 23,
    CMD_GETSYMBOLLISTFROMFILE         = 24,
    CMD_LOADEXTENSION                 = 25,
    CMD_ALLOC                         = 26,
    CMD_FREE                          = 27,
    CMD_CREATETHREAD                  = 28,
    CMD_LOADMODULE                    = 29,
    CMD_SPEEDHACK_SETSPEED            = 30,
    CMD_VIRTUALQUERYEXFULL            = 31,
    CMD_GETREGIONINFO                 = 32,
    CMD_GETABI                        = 33,
    CMD_SET_CONNECTION_NAME           = 34,
    CMD_CREATETOOLHELP32SNAPSHOTEX    = 35,
    CMD_CHANGEMEMORYPROTECTION        = 36,
    CMD_GETOPTIONS                    = 37,
    CMD_GETOPTION                     = 38,
    CMD_SETOPTION                     = 39,
    CMD_PTRACE_MMAP                   = 40,
    CMD_OPENNAMEDPIPE                 = 41,
    CMD_PIPEREAD                      = 42,
    CMD_PIPEWRITE                     = 43,
    CMD_GETCESERVERPATH               = 44,
    CMD_ISANDROID                     = 45,
    CMD_LOADMODULEEX                  = 46,
    CMD_SETCURRENTPATH                = 47,
    CMD_GETCURRENTPATH                = 48,
    CMD_ENUMFILES                     = 49,
    CMD_GETFILEPERMISSIONS            = 50,
    CMD_SETFILEPERMISSIONS            = 51,
    CMD_GETFILE                       = 52,
    CMD_PUTFILE                       = 53,
    CMD_CREATEDIR                     = 54,
    CMD_DELETEFILE                    = 55,
    CMD_AOBSCAN                       = 200,
    CMD_COMMANDLIST2                  = 255,
};

#define CESERVERVERSION 6
static const char kVersionString[] = "CHEATENGINE Network 2.3";

// Toolhelp snapshot flags
#ifndef TH32CS_SNAPMODULE32
#define TH32CS_SNAPMODULE32 0x10
#endif
#ifndef TH32CS_SNAPFIRSTMODULE
#define TH32CS_SNAPFIRSTMODULE 0x40000000
#endif

// ---------------------------------------------------------------------
//  Server state
// ---------------------------------------------------------------------
static std::atomic<bool>   g_running(false);
static std::atomic<int>    g_port(0);
static std::atomic<int>    g_clientCount(0);
static SOCKET              g_listenSocket = INVALID_SOCKET;
static std::thread         g_acceptThread;

static std::mutex          g_socketsMtx;
static std::set<SOCKET>    g_clientSockets;

static std::mutex          g_logMtx;
static std::deque<std::string> g_log; // capped ring buffer

static void CE_Log(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(g_logMtx);
    g_log.push_back(buf);
    while (g_log.size() > 256) g_log.pop_front();
}

// ---------------------------------------------------------------------
//  Socket helpers
// ---------------------------------------------------------------------
static bool SockSendAll(SOCKET s, const void* buf, int len)
{
    const char* p = (const char*)buf;
    while (len > 0)
    {
        int r = send(s, p, len, 0);
        if (r == SOCKET_ERROR) return false;
        p += r;
        len -= r;
    }
    return true;
}

static bool SockRecvAll(SOCKET s, void* buf, int len)
{
    char* p = (char*)buf;
    while (len > 0)
    {
        int r = recv(s, p, len, 0);
        if (r <= 0) return false; // closed or error
        p += r;
        len -= r;
    }
    return true;
}

// string16 = u16 length + bytes (Cheat Engine receiveString16)
static bool SendString16(SOCKET s, const std::string& str)
{
    uint16_t l = (uint16_t)(str.size() > 0xFFFF ? 0xFFFF : str.size());
    return SockSendAll(s, &l, sizeof(l)) &&
           (l == 0 || SockSendAll(s, str.data(), l));
}

static bool RecvString16(SOCKET s, std::string& out)
{
    uint16_t l = 0;
    if (!SockRecvAll(s, &l, sizeof(l))) return false;
    out.clear();
    if (l)
    {
        out.resize(l);
        if (!SockRecvAll(s, &out[0], l)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------
//  Handle table (network handle -> entry)
// ---------------------------------------------------------------------
struct CSProcessInfo { ULONG pid; std::string name; };
struct CSModuleInfo  { ULONG_PTR base; ULONG size; ULONG part; ULONG fileoffset; std::string name; };

enum CSEntryType { CS_PROCESS = 0, CS_SNAP_PROC = 1, CS_SNAP_MOD = 2, CS_SNAP_THREAD = 3 };

struct CSEntry
{
    CSEntryType type;
    ULONG       pid;
    bool        is64;
    std::vector<CSProcessInfo> procs;
    std::vector<CSModuleInfo>  mods;
    std::vector<ULONG>         threads;
    size_t                     iter = 0;
};

static std::mutex              g_handlesMtx;
static std::map<ULONG, std::shared_ptr<CSEntry>> g_handles;
static ULONG                   g_nextHandle = 1;

static ULONG AllocHandle(std::shared_ptr<CSEntry> e)
{
    std::lock_guard<std::mutex> lk(g_handlesMtx);
    ULONG h = g_nextHandle++;
    if (h == 0 || h > 0xFFFFFF) h = g_nextHandle = 1;
    g_handles[h] = std::move(e);
    return h;
}

// Returns a shared_ptr copy so the entry stays alive even if another thread
// closes the handle concurrently.
static std::shared_ptr<CSEntry> GetHandle(ULONG h)
{
    std::lock_guard<std::mutex> lk(g_handlesMtx);
    auto it = g_handles.find(h);
    return it == g_handles.end() ? nullptr : it->second;
}

static void DropHandle(ULONG h)
{
    std::lock_guard<std::mutex> lk(g_handlesMtx);
    g_handles.erase(h);
}

static void ClearHandles()
{
    std::lock_guard<std::mutex> lk(g_handlesMtx);
    g_handles.clear();
    g_nextHandle = 1;
}

// ---------------------------------------------------------------------
//  Process / module / thread enumeration (Toolhelp32, user-mode list only)
// ---------------------------------------------------------------------
static std::vector<CSProcessInfo> EnumProcesses()
{
    std::vector<CSProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            CSProcessInfo p;
            p.pid = pe.th32ProcessID;
            char name[256];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, (int)sizeof(name), NULL, NULL);
            p.name = name;
            out.push_back(std::move(p));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static std::vector<CSModuleInfo> EnumModules(ULONG pid)
{
    std::vector<CSModuleInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return out;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do
        {
            CSModuleInfo m;
            m.base = (ULONG_PTR)me.modBaseAddr;
            m.size = me.modBaseSize;
            m.part = 0;
            m.fileoffset = 0;
            char name[256];
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, name, (int)sizeof(name), NULL, NULL);
            m.name = name;
            out.push_back(std::move(m));
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

static std::vector<ULONG> EnumThreads(ULONG pid)
{
    std::vector<ULONG> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid)
                out.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------
//  Memory backend: DBK64 driver first, user-mode fallback
// ---------------------------------------------------------------------
static bool DriverUp()
{
    return g_hDriver != INVALID_HANDLE_VALUE;
}

static size_t CE_ReadMemory(ULONG pid, ULONG_PTR addr, void* buf, size_t size)
{
    size_t done = 0;
    const ULONG chunk = 0x1000;
    while (done < size)
    {
        ULONG n = (ULONG)((size - done) < chunk ? (size - done) : chunk);
        if (DriverUp())
        {
            if (!DbkReadBytes(pid, addr + done, (char*)buf + done, n))
                break;
        }
        else
        {
            HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (!h) break;
            SIZE_T got = 0;
            BOOL ok = ReadProcessMemory(h, (LPCVOID)(addr + done), (char*)buf + done, n, &got);
            CloseHandle(h);
            if (!ok || got != n) break;
        }
        done += n;
    }
    return done;
}

static size_t CE_WriteMemory(ULONG pid, ULONG_PTR addr, const void* buf, size_t size)
{
    size_t done = 0;
    const ULONG chunk = 0x1000;
    while (done < size)
    {
        ULONG n = (ULONG)((size - done) < chunk ? (size - done) : chunk);
        if (DriverUp())
        {
            if (!DbkWriteBytes(pid, addr + done, (const char*)buf + done, n))
                break;
        }
        else
        {
            HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
            if (!h) break;
            SIZE_T wrote = 0;
            BOOL ok = WriteProcessMemory(h, (LPVOID)(addr + done), (const char*)buf + done, n, &wrote);
            CloseHandle(h);
            if (!ok || wrote != n) break;
        }
        done += n;
    }
    return done;
}

// Query a single region. prot receives a Windows PAGE_* value.
static bool CE_QueryMemory(ULONG pid, ULONG_PTR addr, ULONG_PTR* len, ULONG* prot)
{
    if (DriverUp())
        return DbkQueryVirtualMemory(pid, addr, len, prot);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return false;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T q = VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi));
    CloseHandle(h);
    if (!q) return false;
    if (len) *len = (ULONG_PTR)mbi.RegionSize;
    if (prot)
    {
        if (mbi.State != MEM_COMMIT) *prot = PAGE_NOACCESS;
        else *prot = (mbi.Protect & 0xFF);
    }
    return true;
}

static bool IsReadableProtect(ULONG prot)
{
    return prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_READONLY || prot == PAGE_READWRITE ||
           prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_WRITECOPY;
}

// Full region walk (kernel page-table enumeration via DBK when available).
static std::vector<std::pair<ULONG_PTR, ULONG_PTR>> CE_EnumRegions(ULONG pid, bool is64)
{
    std::vector<std::pair<ULONG_PTR, ULONG_PTR>> out;
#ifdef _WIN64
    ULONG_PTR maxAddr = is64 ? (ULONG_PTR)0x7FFFFFFFFFFFULL : (ULONG_PTR)0x7FFFFFFFULL;
#else
    ULONG_PTR maxAddr = (ULONG_PTR)0x7FFFFFFFULL;
    (void)is64;
#endif

    ULONG_PTR cursor = 0;
    ULONG guard = 0;
    while (cursor < maxAddr)
    {
        if (++guard > (1 << 22)) break; // safety cap
        ULONG_PTR len = 0;
        ULONG prot = 0;
        if (!CE_QueryMemory(pid, cursor, &len, &prot)) break;
        if (len == 0) break;

        ULONG_PTR base = cursor & ~(ULONG_PTR)0xFFF;
        ULONG_PTR end = base + len;
        if (end <= base) break;

        if (IsReadableProtect(prot) && base < maxAddr)
            out.push_back({ base, end < maxAddr ? end : maxAddr });

        cursor = end;
    }
    return out;
}

// ---------------------------------------------------------------------
//  Command dispatch (returns false when the connection must be dropped)
// ---------------------------------------------------------------------
static const char* CmdName(unsigned char c)
{
    switch (c)
    {
    case CMD_GETVERSION: return "GETVERSION";
    case CMD_CLOSECONNECTION: return "CLOSECONNECTION";
    case CMD_TERMINATESERVER: return "TERMINATESERVER";
    case CMD_OPENPROCESS: return "OPENPROCESS";
    case CMD_CREATETOOLHELP32SNAPSHOT: return "CREATETOOLHELP32SNAPSHOT";
    case CMD_PROCESS32FIRST: return "PROCESS32FIRST";
    case CMD_PROCESS32NEXT: return "PROCESS32NEXT";
    case CMD_CLOSEHANDLE: return "CLOSEHANDLE";
    case CMD_VIRTUALQUERYEX: return "VIRTUALQUERYEX";
    case CMD_READPROCESSMEMORY: return "READPROCESSMEMORY";
    case CMD_WRITEPROCESSMEMORY: return "WRITEPROCESSMEMORY";
    case CMD_STARTDEBUG: return "STARTDEBUG";
    case CMD_STOPDEBUG: return "STOPDEBUG";
    case CMD_WAITFORDEBUGEVENT: return "WAITFORDEBUGEVENT";
    case CMD_CONTINUEFROMDEBUGEVENT: return "CONTINUEFROMDEBUGEVENT";
    case CMD_SETBREAKPOINT: return "SETBREAKPOINT";
    case CMD_REMOVEBREAKPOINT: return "REMOVEBREAKPOINT";
    case CMD_SUSPENDTHREAD: return "SUSPENDTHREAD";
    case CMD_RESUMETHREAD: return "RESUMETHREAD";
    case CMD_GETTHREADCONTEXT: return "GETTHREADCONTEXT";
    case CMD_SETTHREADCONTEXT: return "SETTHREADCONTEXT";
    case CMD_GETARCHITECTURE: return "GETARCHITECTURE";
    case CMD_MODULE32FIRST: return "MODULE32FIRST";
    case CMD_MODULE32NEXT: return "MODULE32NEXT";
    case CMD_GETSYMBOLLISTFROMFILE: return "GETSYMBOLLISTFROMFILE";
    case CMD_LOADEXTENSION: return "LOADEXTENSION";
    case CMD_ALLOC: return "ALLOC";
    case CMD_FREE: return "FREE";
    case CMD_CREATETHREAD: return "CREATETHREAD";
    case CMD_LOADMODULE: return "LOADMODULE";
    case CMD_SPEEDHACK_SETSPEED: return "SPEEDHACK_SETSPEED";
    case CMD_VIRTUALQUERYEXFULL: return "VIRTUALQUERYEXFULL";
    case CMD_GETREGIONINFO: return "GETREGIONINFO";
    case CMD_GETABI: return "GETABI";
    case CMD_SET_CONNECTION_NAME: return "SET_CONNECTION_NAME";
    case CMD_CREATETOOLHELP32SNAPSHOTEX: return "CREATETOOLHELP32SNAPSHOTEX";
    case CMD_CHANGEMEMORYPROTECTION: return "CHANGEMEMORYPROTECTION";
    case CMD_GETOPTIONS: return "GETOPTIONS";
    case CMD_GETOPTION: return "GETOPTION";
    case CMD_SETOPTION: return "SETOPTION";
    case CMD_PTRACE_MMAP: return "PTRACE_MMAP";
    case CMD_OPENNAMEDPIPE: return "OPENNAMEDPIPE";
    case CMD_PIPEREAD: return "PIPEREAD";
    case CMD_PIPEWRITE: return "PIPEWRITE";
    case CMD_GETCESERVERPATH: return "GETCESERVERPATH";
    case CMD_ISANDROID: return "ISANDROID";
    case CMD_LOADMODULEEX: return "LOADMODULEEX";
    case CMD_SETCURRENTPATH: return "SETCURRENTPATH";
    case CMD_GETCURRENTPATH: return "GETCURRENTPATH";
    case CMD_ENUMFILES: return "ENUMFILES";
    case CMD_GETFILEPERMISSIONS: return "GETFILEPERMISSIONS";
    case CMD_SETFILEPERMISSIONS: return "SETFILEPERMISSIONS";
    case CMD_GETFILE: return "GETFILE";
    case CMD_PUTFILE: return "PUTFILE";
    case CMD_CREATEDIR: return "CREATEDIR";
    case CMD_DELETEFILE: return "DELETEFILE";
    case CMD_AOBSCAN: return "AOBSCAN";
    case CMD_COMMANDLIST2: return "COMMANDLIST2";
    default: return "UNKNOWN";
    }
}

static int DispatchCommand(SOCKET s, unsigned char cmd)
{
    switch (cmd)
    {
    case CMD_GETVERSION:
    {
        int version = CESERVERVERSION;
        uint8_t len = (uint8_t)strlen(kVersionString);
        SockSendAll(s, &version, sizeof(version));
        SockSendAll(s, &len, sizeof(len));
        SockSendAll(s, kVersionString, len);
        return 1;
    }

    case CMD_CLOSECONNECTION:
        CE_Log("client disconnected");
        return 0;

    case CMD_TERMINATESERVER:
        CE_Log("client requested server shutdown");
        return 0; // connection dropped; the stop flag is handled by the caller

    case CMD_OPENPROCESS:
    {
        int32_t pid = 0;
        if (!SockRecvAll(s, &pid, sizeof(pid))) return 0;
        int32_t h = 0;
        if (pid > 0)
        {
            CSEntry e;
            e.type = CS_PROCESS;
            e.pid = (ULONG)pid;
            e.is64 = IsTarget64Bit((ULONG)pid);
            h = (int32_t)AllocHandle(std::make_shared<CSEntry>(std::move(e)));
        }
        SockSendAll(s, &h, sizeof(h));
        CE_Log("OpenProcess(%d) -> handle %d", pid, h);
        return 1;
    }

    case CMD_CREATETOOLHELP32SNAPSHOT:      // legacy (cmd 4)
    case CMD_CREATETOOLHELP32SNAPSHOTEX:    // modern (cmd 35)
    {
        uint32_t flags = 0, pid = 0;
        if (!SockRecvAll(s, &flags, sizeof(flags))) return 0;
        if (!SockRecvAll(s, &pid, sizeof(pid))) return 0;

        if (cmd == CMD_CREATETOOLHELP32SNAPSHOTEX)
        {
            if (flags & TH32CS_SNAPTHREAD)
            {
                // stream: {count:i32}{count x threadid:i32}
                std::vector<ULONG> threads = EnumThreads(pid);
                int32_t n = (int32_t)threads.size();
                SockSendAll(s, &n, sizeof(n));
                if (n) SockSendAll(s, threads.data(), (int)(n * sizeof(ULONG)));
                return 1;
            }
            if (flags & TH32CS_SNAPMODULE)
            {
                // stream: repeated CeModuleEntry until result != 1
                std::vector<CSModuleInfo> mods = EnumModules(pid);
                for (auto& m : mods)
                {
                    int32_t result = 1;
                    int64_t mbase = (int64_t)m.base;
                    int32_t mpart = (int32_t)m.part;
                    int32_t msize = (int32_t)m.size;
                    uint32_t moff = (uint32_t)m.fileoffset;
                    int32_t nlen = (int32_t)m.name.size();
                    SockSendAll(s, &result, sizeof(result));
                    SockSendAll(s, &mbase, sizeof(mbase));
                    SockSendAll(s, &mpart, sizeof(mpart));
                    SockSendAll(s, &msize, sizeof(msize));
                    SockSendAll(s, &moff, sizeof(moff));
                    SockSendAll(s, &nlen, sizeof(nlen));
                    if (nlen) SockSendAll(s, m.name.data(), nlen);
                }
                // terminator entry
                int32_t result = 0, mpart = 0, msize = 0, nlen = 0;
                int64_t mbase = 0; uint32_t moff = 0;
                SockSendAll(s, &result, sizeof(result));
                SockSendAll(s, &mbase, sizeof(mbase));
                SockSendAll(s, &mpart, sizeof(mpart));
                SockSendAll(s, &msize, sizeof(msize));
                SockSendAll(s, &moff, sizeof(moff));
                SockSendAll(s, &nlen, sizeof(nlen));
                return 1;
            }
        }

        // Legacy path (cmd 4), TH32CS_SNAPPROCESS, or TH32CS_SNAPFIRSTMODULE:
        // return a server handle.
        CSEntry e;
        if ((flags & TH32CS_SNAPMODULE) || (flags & TH32CS_SNAPFIRSTMODULE))
        {
            e.type = CS_SNAP_MOD;
            e.pid = pid;
            e.is64 = true;
            e.mods = EnumModules(pid);
        }
        else
        {
            e.type = CS_SNAP_PROC;
            e.pid = 0;
            e.is64 = true;
            e.procs = EnumProcesses();
        }
        size_t entryCount = (e.type == CS_SNAP_PROC ? e.procs.size() : e.mods.size());
        int32_t h = (int32_t)AllocHandle(std::make_shared<CSEntry>(std::move(e)));
        CE_Log("snapshot(flags=0x%X, pid=%u) -> handle %d, %zu entries",
            flags, pid, h, entryCount);
        SockSendAll(s, &h, sizeof(h));
        return 1;
    }

    case CMD_PROCESS32FIRST:
    case CMD_PROCESS32NEXT:
    {
        uint32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        auto e = GetHandle(h);
        if (!e || e->type != CS_SNAP_PROC)
        {
            int32_t result = 0, pid = 0, nlen = 0;
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &pid, sizeof(pid));
            SockSendAll(s, &nlen, sizeof(nlen));
            return 1;
        }
        if (cmd == CMD_PROCESS32FIRST) e->iter = 0;

        if (e->iter < e->procs.size())
        {
            const CSProcessInfo& p = e->procs[e->iter++];
            int32_t result = 1;
            uint32_t pid = p.pid;
            int32_t nlen = (int32_t)p.name.size();
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &pid, sizeof(pid));
            SockSendAll(s, &nlen, sizeof(nlen));
            if (nlen) SockSendAll(s, p.name.data(), nlen);
        }
        else
        {
            int32_t result = 0, pid = 0, nlen = 0;
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &pid, sizeof(pid));
            SockSendAll(s, &nlen, sizeof(nlen));
        }
        return 1;
    }

    case CMD_MODULE32FIRST:
    case CMD_MODULE32NEXT:
    {
        uint32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        auto e = GetHandle(h);
        // Modules snapshots are usually streamed via SNAPSHOTEX, but support
        // the legacy server-handle path as well.
        if (!e || e->type != CS_SNAP_MOD)
        {
            // Lazily convert an unknown handle is not possible; report end.
            int32_t result = 0, mpart = 0, msize = 0, nlen = 0;
            int64_t mbase = 0; uint32_t moff = 0;
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &mbase, sizeof(mbase));
            SockSendAll(s, &mpart, sizeof(mpart));
            SockSendAll(s, &msize, sizeof(msize));
            SockSendAll(s, &moff, sizeof(moff));
            SockSendAll(s, &nlen, sizeof(nlen));
            return 1;
        }
        if (cmd == CMD_MODULE32FIRST) e->iter = 0;

        if (e->iter < e->mods.size())
        {
            const CSModuleInfo& m = e->mods[e->iter++];
            int32_t result = 1;
            int64_t mbase = (int64_t)m.base;
            int32_t mpart = (int32_t)m.part;
            int32_t msize = (int32_t)m.size;
            uint32_t moff = (uint32_t)m.fileoffset;
            int32_t nlen = (int32_t)m.name.size();
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &mbase, sizeof(mbase));
            SockSendAll(s, &mpart, sizeof(mpart));
            SockSendAll(s, &msize, sizeof(msize));
            SockSendAll(s, &moff, sizeof(moff));
            SockSendAll(s, &nlen, sizeof(nlen));
            if (nlen) SockSendAll(s, m.name.data(), nlen);
        }
        else
        {
            int32_t result = 0, mpart = 0, msize = 0, nlen = 0;
            int64_t mbase = 0; uint32_t moff = 0;
            SockSendAll(s, &result, sizeof(result));
            SockSendAll(s, &mbase, sizeof(mbase));
            SockSendAll(s, &mpart, sizeof(mpart));
            SockSendAll(s, &msize, sizeof(msize));
            SockSendAll(s, &moff, sizeof(moff));
            SockSendAll(s, &nlen, sizeof(nlen));
        }
        return 1;
    }

    case CMD_CLOSEHANDLE:
    {
        uint32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        DropHandle(h);
        int32_t r = 1;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_VIRTUALQUERYEX:
    case CMD_GETREGIONINFO:
    {
        int32_t h = 0;
        uint64_t addr = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        auto e = GetHandle((ULONG)h);

        uint8_t result = 0;
        uint32_t prot = 0, type = 0;
        uint64_t base = 0, size = 0;
        if (e && e->type == CS_PROCESS)
        {
            ULONG_PTR len = 0; ULONG p = 0;
            if (CE_QueryMemory(e->pid, (ULONG_PTR)addr, &len, &p))
            {
                result = 1;
                prot = (uint32_t)p;
                type = (p == PAGE_NOACCESS) ? 0 : 0x20000 /*MEM_PRIVATE*/;
                base = (uint64_t)((ULONG_PTR)addr & ~(ULONG_PTR)0xFFF);
                size = (uint64_t)len;
            }
        }
        SockSendAll(s, &result, sizeof(result));
        SockSendAll(s, &prot, sizeof(prot));
        SockSendAll(s, &type, sizeof(type));
        SockSendAll(s, &base, sizeof(base));
        SockSendAll(s, &size, sizeof(size));

        if (cmd == CMD_GETREGIONINFO)
        {
            uint8_t mapslinesize = 0; // Windows has no /proc/maps line
            SockSendAll(s, &mapslinesize, sizeof(mapslinesize));
        }
        return 1;
    }

    case CMD_READPROCESSMEMORY:
    {
        uint32_t h = 0;
        uint64_t addr = 0;
        uint32_t size = 0;
        uint8_t compress = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (!SockRecvAll(s, &compress, sizeof(compress))) return 0;

        const uint32_t kMaxIoSize = 1u << 23; // 8 MiB allocation cap
        if (size > kMaxIoSize) size = kMaxIoSize;

        auto e = GetHandle(h);
        std::vector<char> buf(size);
        int32_t read = 0;
        if (e && e->type == CS_PROCESS && size > 0)
            read = (int32_t)CE_ReadMemory(e->pid, (ULONG_PTR)addr, buf.data(), size);

        if (compress == 0)
        {
            SockSendAll(s, &read, sizeof(read));
            if (read > 0) SockSendAll(s, buf.data(), read);
        }
        else
        {
            // Cheat Engine never enables compression by default; send the
            // plain framing as a defensive fallback (treated as 0 read).
            read = 0;
            SockSendAll(s, &read, sizeof(read));
        }
        return 1;
    }

    case CMD_WRITEPROCESSMEMORY:
    {
        int32_t h = 0;
        int64_t addr = 0;
        int32_t size = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (size < 0 || size > (1 << 23)) return 0; // drop; can't safely consume

        int32_t written = 0;
        if (size > 0)
        {
            std::vector<char> buf(size);
            if (SockRecvAll(s, buf.data(), size))
            {
                auto e = GetHandle((ULONG)h);
                if (e && e->type == CS_PROCESS)
                    written = (int32_t)CE_WriteMemory(e->pid, (ULONG_PTR)addr, buf.data(), size);
            }
            else return 0;
        }
        SockSendAll(s, &written, sizeof(written));
        return 1;
    }

    case CMD_ALLOC:
    {
        int32_t h = 0;
        uint64_t prefBase = 0;
        int32_t size = 0;
        int32_t protection = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &prefBase, sizeof(prefBase))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (!SockRecvAll(s, &protection, sizeof(protection))) return 0;

        uint64_t addr = 0;
        auto e = GetHandle((ULONG)h);
        if (e && e->type == CS_PROCESS && size > 0)
        {
            ULONG64 out = 0;
            if (DbkAllocProcessMem(e->pid, (ULONG64)size, &out))
                addr = (uint64_t)out;
        }
        SockSendAll(s, &addr, sizeof(addr));
        return 1;
    }

    case CMD_FREE:
    {
        int32_t h = 0;
        uint64_t addr = 0;
        int32_t size = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        uint32_t result = 0; // DBK has no free-process-memory IOCTL
        SockSendAll(s, &result, sizeof(result));
        return 1;
    }

    case CMD_CHANGEMEMORYPROTECTION:
    {
        int32_t h = 0;
        uint64_t addr = 0;
        uint32_t size = 0, newprot = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (!SockRecvAll(s, &newprot, sizeof(newprot))) return 0;

        // DBK writes bypass page protection; report success with a permissive
        // old protection so Cheat Engine proceeds with the write.
        uint32_t result = 0;
        uint32_t oldprot = PAGE_EXECUTE_READWRITE;
        SockSendAll(s, &result, sizeof(result));
        SockSendAll(s, &oldprot, sizeof(oldprot));
        return 1;
    }

    case CMD_VIRTUALQUERYEXFULL:
    {
        int32_t h = 0;
        uint8_t flags = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &flags, sizeof(flags))) return 0;

        auto e = GetHandle((ULONG)h);
        uint32_t count = 0;
        if (e && e->type == CS_PROCESS)
        {
            auto regions = CE_EnumRegions(e->pid, e->is64);
            count = (uint32_t)regions.size();
            SockSendAll(s, &count, sizeof(count));
            for (auto& r : regions)
            {
                uint64_t base = (uint64_t)r.first;
                uint64_t size = (uint64_t)(r.second - r.first);
                uint32_t prot = PAGE_EXECUTE_READWRITE;
                uint32_t type = 0x20000;
                SockSendAll(s, &base, sizeof(base));
                SockSendAll(s, &size, sizeof(size));
                SockSendAll(s, &prot, sizeof(prot));
                SockSendAll(s, &type, sizeof(type));
            }
        }
        else
        {
            SockSendAll(s, &count, sizeof(count));
        }
        return 1;
    }

    case CMD_GETARCHITECTURE:
    {
        uint32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        // 0 = i386, 1 = x86_64
        uint8_t arch = 1;
        auto e = GetHandle(h);
        if (e && e->type == CS_PROCESS && !e->is64) arch = 0;
        SockSendAll(s, &arch, sizeof(arch));
        return 1;
    }

    case CMD_GETABI:
    {
        uint8_t abi = 0; // 0 = Windows
        SockSendAll(s, &abi, sizeof(abi));
        return 1;
    }

    case CMD_SET_CONNECTION_NAME:
    {
        uint32_t nlen = 0;
        if (!SockRecvAll(s, &nlen, sizeof(nlen))) return 0;
        if (nlen)
        {
            std::string name;
            name.resize(nlen);
            if (!SockRecvAll(s, &name[0], nlen)) return 0;
            CE_Log("connection name: %s", name.c_str());
        }
        return 1; // no response
    }

    case CMD_GETOPTIONS:
    {
        uint16_t count = 0;
        SockSendAll(s, &count, sizeof(count));
        return 1;
    }

    case CMD_GETOPTION:
    {
        std::string name;
        if (!RecvString16(s, name)) return 0;
        std::string empty;
        SendString16(s, empty);
        return 1;
    }

    case CMD_SETOPTION:
    {
        std::string name, value;
        if (!RecvString16(s, name)) return 0;
        if (!RecvString16(s, value)) return 0;
        return 1; // no response
    }

    // ---- Debug commands: not supported (return 0 = failure) ----
    case CMD_STARTDEBUG:
    case CMD_STOPDEBUG:
    {
        int32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_WAITFORDEBUGEVENT:
    {
        int32_t h = 0, timeout = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &timeout, sizeof(timeout))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_CONTINUEFROMDEBUGEVENT:
    {
        int32_t h = 0, method = 0;
        uint32_t tid = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        if (!SockRecvAll(s, &method, sizeof(method))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_SETBREAKPOINT:
    {
        int32_t h = 0, tid = 0, dr = 0, bt = 0, bs = 0;
        uint64_t addr = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        if (!SockRecvAll(s, &dr, sizeof(dr))) return 0;
        if (!SockRecvAll(s, &addr, sizeof(addr))) return 0;
        if (!SockRecvAll(s, &bt, sizeof(bt))) return 0;
        if (!SockRecvAll(s, &bs, sizeof(bs))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_REMOVEBREAKPOINT:
    {
        int32_t h = 0, tid = 0, dr = 0, wp = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        if (!SockRecvAll(s, &dr, sizeof(dr))) return 0;
        if (!SockRecvAll(s, &wp, sizeof(wp))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_SUSPENDTHREAD:
    case CMD_RESUMETHREAD:
    {
        int32_t h = 0, tid = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        int32_t r = 0; // not supported; Cheat Engine tolerates failure
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_GETTHREADCONTEXT:
    {
        uint32_t h = 0, tid = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        int32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_SETTHREADCONTEXT:
    {
        uint32_t h = 0, tid = 0, csize = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &tid, sizeof(tid))) return 0;
        if (!SockRecvAll(s, &csize, sizeof(csize))) return 0;
        if (csize)
        {
            std::vector<char> c(csize);
            if (!SockRecvAll(s, c.data(), csize)) return 0;
        }
        uint32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    // ---- Injection / speedhack: not supported ----
    case CMD_CREATETHREAD:
    {
        int32_t h = 0;
        uint64_t start = 0, param = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &start, sizeof(start))) return 0;
        if (!SockRecvAll(s, &param, sizeof(param))) return 0;
        int32_t th = 0;
        SockSendAll(s, &th, sizeof(th));
        return 1;
    }

    case CMD_LOADEXTENSION:
    {
        uint32_t h = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        uint32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_LOADMODULE:
    {
        uint32_t h = 0, plen = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &plen, sizeof(plen))) return 0;
        if (plen)
        {
            std::vector<char> p(plen);
            if (!SockRecvAll(s, p.data(), plen)) return 0;
        }
        uint64_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_LOADMODULEEX:
    {
        uint32_t h = 0, plen = 0;
        uint64_t dlopenaddr = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &dlopenaddr, sizeof(dlopenaddr))) return 0;
        if (!SockRecvAll(s, &plen, sizeof(plen))) return 0;
        if (plen)
        {
            std::vector<char> p(plen);
            if (!SockRecvAll(s, p.data(), plen)) return 0;
        }
        uint64_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_SPEEDHACK_SETSPEED:
    {
        uint32_t h = 0;
        float speed = 1.0f;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &speed, sizeof(speed))) return 0;
        uint32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_GETSYMBOLLISTFROMFILE:
    {
        uint32_t fileoffset = 0, plen = 0;
        if (!SockRecvAll(s, &fileoffset, sizeof(fileoffset))) return 0;
        if (!SockRecvAll(s, &plen, sizeof(plen))) return 0;
        if (plen)
        {
            std::vector<char> p(plen);
            if (!SockRecvAll(s, p.data(), plen)) return 0;
        }
        uint32_t isexe = 0;
        uint32_t compressedsize = 0;
        SockSendAll(s, &isexe, sizeof(isexe));
        SockSendAll(s, &compressedsize, sizeof(compressedsize));
        return 1;
    }

    // ---- Misc / filesystem / pipes: minimal graceful responses ----
    case CMD_GETCESERVERPATH:
    {
        char exe[MAX_PATH] = "";
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        std::string path(exe);
        size_t slash = path.find_last_of("\\/");
        if (slash != std::string::npos) path.resize(slash + 1);
        SendString16(s, path);
        return 1;
    }

    case CMD_ISANDROID:
    {
        uint8_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_OPENNAMEDPIPE:
    {
        std::string name;
        if (!RecvString16(s, name)) return 0;
        uint32_t timeout = 0;
        if (!SockRecvAll(s, &timeout, sizeof(timeout))) return 0;
        uint32_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_PIPEREAD:
    {
        uint32_t h = 0, size = 0, timeout = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (!SockRecvAll(s, &timeout, sizeof(timeout))) return 0;
        int32_t actualsize = 0;
        SockSendAll(s, &actualsize, sizeof(actualsize));
        return 1;
    }

    case CMD_PIPEWRITE:
    {
        uint32_t h = 0, size = 0, timeout = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (!SockRecvAll(s, &timeout, sizeof(timeout))) return 0;
        if (size)
        {
            std::vector<char> d(size);
            if (!SockRecvAll(s, d.data(), size)) return 0;
        }
        int32_t c = 0;
        SockSendAll(s, &c, sizeof(c));
        return 1;
    }

    case CMD_SETCURRENTPATH:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        uint8_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_GETCURRENTPATH:
    {
        std::string empty;
        SendString16(s, empty);
        return 1;
    }

    case CMD_ENUMFILES:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        std::string empty;
        SendString16(s, empty); // terminator entry
        return 1;
    }

    case CMD_GETFILEPERMISSIONS:
    case CMD_SETFILEPERMISSIONS:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        if (cmd == CMD_SETFILEPERMISSIONS)
        {
            uint32_t perms = 0;
            if (!SockRecvAll(s, &perms, sizeof(perms))) return 0;
        }
        uint8_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_GETFILE:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        uint32_t filelength = 0xFFFFFFFF; // fail
        SockSendAll(s, &filelength, sizeof(filelength));
        return 1;
    }

    case CMD_PUTFILE:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        uint32_t size = 0;
        if (!SockRecvAll(s, &size, sizeof(size))) return 0;
        if (size)
        {
            std::vector<char> d(size);
            if (!SockRecvAll(s, d.data(), size)) return 0;
        }
        uint8_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_CREATEDIR:
    case CMD_DELETEFILE:
    {
        std::string path;
        if (!RecvString16(s, path)) return 0;
        uint8_t r = 0;
        SockSendAll(s, &r, sizeof(r));
        return 1;
    }

    case CMD_AOBSCAN:
    {
        // CeAobScanInput = { u32 handle; u64 start; u64 end; i32 inc;
        //                    i32 protection; i32 scansize; } + scansize bytes.
        uint32_t h = 0;
        uint64_t start = 0, end = 0;
        int32_t inc = 0, protection = 0, scansize = 0;
        if (!SockRecvAll(s, &h, sizeof(h))) return 0;
        if (!SockRecvAll(s, &start, sizeof(start))) return 0;
        if (!SockRecvAll(s, &end, sizeof(end))) return 0;
        if (!SockRecvAll(s, &inc, sizeof(inc))) return 0;
        if (!SockRecvAll(s, &protection, sizeof(protection))) return 0;
        if (!SockRecvAll(s, &scansize, sizeof(scansize))) return 0;
        if (scansize > 0)
        {
            if (scansize > (1 << 23)) return 0; // absurd; drop
            std::vector<char> pattern(scansize);
            if (!SockRecvAll(s, pattern.data(), scansize)) return 0;
        }
        uint32_t count = 0; // AoB scan not implemented; no matches
        SockSendAll(s, &count, sizeof(count));
        return 1;
    }

    case CMD_PTRACE_MMAP:
    {
        // Linux-only ptrace mmap helper; Windows has no equivalent.
        uint64_t fail = 0;
        SockSendAll(s, &fail, sizeof(fail));
        return 1;
    }

    default:
        // Unknown command: drop the connection to avoid stream desync.
        CE_Log("unknown command %d, dropping connection", (int)cmd);
        return 0;
    }
}

// ---------------------------------------------------------------------
//  Client thread
// ---------------------------------------------------------------------
static void ClientThread(SOCKET s)
{
    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag, sizeof(flag));

    {
        std::lock_guard<std::mutex> lk(g_socketsMtx);
        g_clientSockets.insert(s);
    }
    g_clientCount.fetch_add(1);
    CE_Log("client connected");

    for (;;)
    {
        unsigned char cmd = 0;
        if (!SockRecvAll(s, &cmd, sizeof(cmd)))
            break;
        CE_Log("recv cmd %d (%s)", (int)cmd, CmdName(cmd));
        if (!DispatchCommand(s, cmd))
            break;
        if (cmd == CMD_TERMINATESERVER)
        {
            // graceful: stop the whole server
            CEServerStop();
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_socketsMtx);
        g_clientSockets.erase(s);
    }
    g_clientCount.fetch_sub(1);
    closesocket(s);
}

// ---------------------------------------------------------------------
//  Accept thread
// ---------------------------------------------------------------------
static void AcceptThread()
{
    CE_Log("server listening on port %d", (int)g_port.load());
    while (g_running.load())
    {
        SOCKET client = accept(g_listenSocket, NULL, NULL);
        if (client == INVALID_SOCKET)
        {
            if (!g_running.load()) break; // stopped
            CE_Log("accept failed: %d", WSAGetLastError());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        std::thread(ClientThread, client).detach();
    }
}

// ---------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------
bool CEServerStart(int port)
{
    if (g_running.load())
        CEServerStop();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        CE_Log("WSAStartup failed");
        return false;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET)
    {
        CE_Log("socket() failed: %d", WSAGetLastError());
        WSACleanup();
        return false;
    }

    int reuse = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((u_short)port);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        CE_Log("bind() on port %d failed: %d (port already in use?)", port, WSAGetLastError());
        closesocket(ls);
        WSACleanup();
        return false;
    }

    if (listen(ls, SOMAXCONN) == SOCKET_ERROR)
    {
        CE_Log("listen() failed: %d", WSAGetLastError());
        closesocket(ls);
        WSACleanup();
        return false;
    }

    g_listenSocket = ls;
    g_port.store(port);
    g_running.store(true);
    g_acceptThread = std::thread(AcceptThread);
    return true;
}

void CEServerStop()
{
    if (!g_running.exchange(false))
        return;

    if (g_listenSocket != INVALID_SOCKET)
    {
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
    }

    // Unblock every client thread.
    {
        std::lock_guard<std::mutex> lk(g_socketsMtx);
        for (SOCKET c : g_clientSockets)
            shutdown(c, SD_BOTH);
    }

    if (g_acceptThread.joinable())
        g_acceptThread.join();

    // Give client threads a moment to exit, then drop remaining sockets.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    {
        std::lock_guard<std::mutex> lk(g_socketsMtx);
        for (SOCKET c : g_clientSockets)
            closesocket(c);
        g_clientSockets.clear();
    }

    ClearHandles();
    WSACleanup();
    CE_Log("server stopped");
}

bool CEServerIsRunning() { return g_running.load(); }
int  CEServerPort()     { return g_port.load(); }
int  CEServerClientCount() { return g_clientCount.load(); }

void CEServerGetLog(std::vector<std::string>& out)
{
    out.clear();
    std::lock_guard<std::mutex> lk(g_logMtx);
    for (auto& l : g_log) out.push_back(l);
}
