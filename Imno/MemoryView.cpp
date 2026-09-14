#include "MemoryView.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

MemViewState g_MemView;

// Helpers
static bool IsHexChar(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

static std::string ToLowerStr(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

static bool StrContainsCI(const char* hay, const char* needle) {
    if (!needle || !needle[0]) return true;
    std::string h = ToLowerStr(hay);
    std::string n = ToLowerStr(needle);
    return h.find(n) != std::string::npos;
}

// ------------------------------------------------------------------
// Zydis init
// ------------------------------------------------------------------
static void EnsureZydisInit(bool is64) {
    if (g_MemView.zydisInitialized && g_MemView.is64BitMode == is64) return;
    ZydisMachineMode mode = is64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    ZydisStackWidth width = is64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    ZydisDecoderInit(&g_MemView.decoder, mode, width);
    ZydisFormatterInit(&g_MemView.formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    // Show absolute addresses for branches
    ZydisFormatterSetProperty(&g_MemView.formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&g_MemView.formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_FALSE);
    g_MemView.machineMode = mode;
    g_MemView.stackWidth = width;
    g_MemView.is64BitMode = is64;
    g_MemView.zydisInitialized = true;
}

// ------------------------------------------------------------------
// Address parser: supports hex like 0x1234, 1234, module+offset, module.dll+1234
// ------------------------------------------------------------------
bool MemoryView_ParseAddress(const char* str, ULONG pid, ULONG_PTR* outAddr) {
    if (!str || !outAddr) return false;
    // Trim
    std::string s = str;
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    if (s.empty()) return false;

    // Check for module+offset pattern
    size_t plusPos = s.find('+');
    if (plusPos != std::string::npos) {
        std::string modPart = s.substr(0, plusPos);
        std::string offPart = s.substr(plusPos + 1);
        // Trim modPart
        modPart.erase(0, modPart.find_first_not_of(" \t"));
        modPart.erase(modPart.find_last_not_of(" \t") + 1);
        offPart.erase(0, offPart.find_first_not_of(" \t"));
        offPart.erase(offPart.find_last_not_of(" \t") + 1);
        ULONG_PTR off = 0;
        try {
            off = (ULONG_PTR)std::stoull(offPart, nullptr, 0);
        } catch (...) { off = 0; }
        // Find module base
        for (auto& m : g_MemView.modules) {
            if (_stricmp(m.name, modPart.c_str()) == 0 || _stricmp(m.path, modPart.c_str()) == 0 || StrContainsCI(m.name, modPart.c_str())) {
                *outAddr = m.base + off;
                return true;
            }
        }
        // If not found in our cached list, try to refresh modules once
        if (g_MemView.modules.empty()) {
            MemoryView_RefreshModules();
            for (auto& m : g_MemView.modules) {
                if (_stricmp(m.name, modPart.c_str()) == 0 || StrContainsCI(m.name, modPart.c_str())) {
                    *outAddr = m.base + off;
                    return true;
                }
            }
        }
        // Fallback: treat modPart as address itself? No
        // Try parsing modPart as hex and add offset
        ULONG_PTR base = 0;
        try { base = (ULONG_PTR)std::stoull(modPart, nullptr, 0); } catch (...) { return false; }
        *outAddr = base + off;
        return true;
    }

    // Plain hex / dec
    try {
        // Remove 0x prefix handled by stoull with base 0
        ULONG_PTR v = (ULONG_PTR)std::stoull(s, nullptr, 0);
        *outAddr = v;
        return true;
    } catch (...) {
        return false;
    }
}

std::string MemoryView_GetModuleNameForAddr(ULONG_PTR addr, ULONG_PTR* outModuleBase) {
    for (auto& m : g_MemView.modules) {
        if (addr >= m.base && addr < m.base + m.size) {
            if (outModuleBase) *outModuleBase = m.base;
            char buf[256];
            sprintf_s(buf, "%s+0x%llX", m.name, (unsigned long long)(addr - m.base));
            return std::string(buf);
        }
    }
    return "";
}

const char* MemoryView_ProtectToString(ULONG protect) {
    switch (protect) {
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "R";
        case PAGE_READWRITE: return "RW";
        case PAGE_WRITECOPY: return "WC";
        case PAGE_EXECUTE: return "X";
        case PAGE_EXECUTE_READ: return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "WCX";
        case PAGE_GUARD: return "G";
        default: {
            // Check combinations
            static char buf[64];
            buf[0] = 0;
            if (protect & PAGE_GUARD) strcat_s(buf, sizeof(buf), "G+");
            if (protect & PAGE_NOACCESS) strcat_s(buf, sizeof(buf), "NA");
            else {
                if (protect & PAGE_EXECUTE) {
                    if (protect & PAGE_READWRITE) strcat_s(buf, sizeof(buf), "RWX");
                    else if (protect & PAGE_READONLY) strcat_s(buf, sizeof(buf), "RX");
                    else strcat_s(buf, sizeof(buf), "X");
                } else {
                    if (protect & PAGE_READWRITE) strcat_s(buf, sizeof(buf), "RW");
                    else if (protect & PAGE_READONLY) strcat_s(buf, sizeof(buf), "R");
                    else strcat_s(buf, sizeof(buf), "?");
                }
            }
            return buf;
        }
    }
}

// ------------------------------------------------------------------
// Disassembly
// ------------------------------------------------------------------
void MemoryView_RefreshDisasm() {
    if (g_SelectedPid == 0 || g_hDriver == INVALID_HANDLE_VALUE) {
        g_MemView.disasmLines.clear();
        return;
    }
    EnsureZydisInit(g_MemView.is64BitMode);
    g_MemView.disasmLines.clear();
    g_MemView.disasmLines.reserve(g_MemView.disasmLineCount);

    const size_t chunkSize = 4096;
    std::vector<BYTE> chunk(chunkSize);
    ULONG_PTR curAddr = g_MemView.disasmAddr;
    int linesDecoded = 0;
    int attempts = 0;
    // To avoid infinite loop on unreadable memory, limit attempts
    while (linesDecoded < g_MemView.disasmLineCount && attempts < 20) {
        // Read chunk
        size_t toRead = chunkSize;
        if (!DbkReadBytes(g_SelectedPid, curAddr, chunk.data(), (ULONG)toRead)) {
            // Try smaller read or skip to next region
            // Try to find next readable region via query
            ULONG_PTR len = 0; ULONG prot = 0;
            if (DbkQueryVirtualMemory(g_SelectedPid, curAddr, &len, &prot)) {
                if (len == 0) break;
                curAddr = (curAddr & ~0xFFFULL) + len;
                attempts++;
                continue;
            } else {
                break;
            }
        }

        size_t offset = 0;
        while (offset < chunkSize && linesDecoded < g_MemView.disasmLineCount) {
            ZydisDecodedInstruction instr;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            ZyanStatus status = ZydisDecoderDecodeFull(&g_MemView.decoder, chunk.data() + offset, chunkSize - offset, &instr, operands);
            DisasmLine line;
            line.address = curAddr + offset;
            line.isValid = ZYAN_SUCCESS(status);
            if (!line.isValid) {
                // Invalid: treat as 1 byte db
                line.length = 1;
                line.bytes[0] = chunk[offset];
                sprintf_s(line.bytesStr, "%02X", line.bytes[0]);
                sprintf_s(line.text, "db 0x%02X", line.bytes[0]);
                strcpy_s(line.mnemonic, sizeof(line.mnemonic), "db");
                offset += 1;
                g_MemView.disasmLines.push_back(line);
                linesDecoded++;
                continue;
            }

            line.length = instr.length;
            memcpy(line.bytes, chunk.data() + offset, line.length);
            // bytes string
            char* p = line.bytesStr;
            size_t rem = sizeof(line.bytesStr);
            p[0] = 0;
            for (int i = 0; i < line.length; i++) {
                int w = snprintf(p, rem, "%02X ", line.bytes[i]);
                if (w < 0) break;
                p += w; rem -= w;
                if (rem <= 1) break;
            }
            // Trim trailing space
            size_t blen = strlen(line.bytesStr);
            if (blen && line.bytesStr[blen - 1] == ' ') line.bytesStr[blen - 1] = 0;

            // Format instruction
            char fmtBuf[256];
            ZydisFormatterFormatInstruction(&g_MemView.formatter, &instr, operands, instr.operand_count_visible, fmtBuf, sizeof(fmtBuf), line.address, ZYAN_NULL);
            strcpy_s(line.text, sizeof(line.text), fmtBuf);
            // Mnemonic
            const char* mn = ZydisMnemonicGetString(instr.mnemonic);
            if (mn) strcpy_s(line.mnemonic, sizeof(line.mnemonic), mn);
            else strcpy_s(line.mnemonic, sizeof(line.mnemonic), "???");

            // Branch detection
            line.isBranch = false;
            line.isJump = false;
            line.isCall = false;
            line.isRet = false;
            if (instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
                instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                line.isJump = true;
                line.isBranch = true;
            }
            if (instr.meta.category == ZYDIS_CATEGORY_CALL) {
                line.isCall = true;
                line.isBranch = true;
            }
            if (instr.meta.category == ZYDIS_CATEGORY_RET) {
                line.isRet = true;
            }
            // Try to get absolute branch target
            if (line.isBranch) {
                for (int i = 0; i < instr.operand_count_visible; i++) {
                    if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
                        ZyanU64 absAddr = 0;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[i], line.address, &absAddr))) {
                            line.hasBranchTarget = true;
                            line.branchTarget = (ULONG_PTR)absAddr;
                        }
                        break;
                    }
                }
            }

            offset += line.length;
            g_MemView.disasmLines.push_back(line);
            linesDecoded++;
        }
        curAddr += offset;
    }

    g_MemView.disasmNeedsRefresh = false;
}

void MemoryView_RefreshHex() {
    if (g_SelectedPid == 0 || g_hDriver == INVALID_HANDLE_VALUE) {
        g_MemView.hexBuffer.clear();
        return;
    }
    const size_t bufSize = 4096; // 4KB view
    g_MemView.hexBuffer.resize(bufSize);
    g_MemView.hexBufferBase = g_MemView.hexAddr & ~0xFULL; // align to 16
    if (!DbkReadBytes(g_SelectedPid, g_MemView.hexBufferBase, g_MemView.hexBuffer.data(), (ULONG)bufSize)) {
        // Try to zero on failure
        memset(g_MemView.hexBuffer.data(), 0, bufSize);
        // Try smaller read to detect if unreadable
        // Keep buffer but mark as invalid? For now keep zeroed
    }
    g_MemView.hexBufferSize = bufSize;
}

void MemoryView_RefreshRegions() {
    g_MemView.regions.clear();
    if (g_SelectedPid == 0 || g_hDriver == INVALID_HANDLE_VALUE) return;

    ULONG_PTR maxAddr = g_MemView.is64BitMode ? 0x7FFFFFFFFFFFULL : 0x7FFFFFFFULL;
    ULONG_PTR cursor = 0x10000;
    int guard = 0;
    while (cursor < maxAddr) {
        if (++guard > 50000) break; // safety
        ULONG_PTR length = 0;
        ULONG prot = 0;
        if (!DbkQueryVirtualMemory(g_SelectedPid, cursor, &length, &prot)) break;
        if (length == 0) break;
        ULONG_PTR base = cursor & ~0xFFFULL;
        ULONG_PTR end = base + length;
        if (end <= base) break;

        MemRegionFull r;
        r.base = base;
        r.size = length;
        r.protect = prot;
        strcpy_s(r.protectStr, sizeof(r.protectStr), MemoryView_ProtectToString(prot));
        r.readable = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        r.writable = (prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        r.executable = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        strcpy_s(r.stateStr, sizeof(r.stateStr), "COMMIT");
        strcpy_s(r.typeStr, sizeof(r.typeStr), "PRIVATE");
        g_MemView.regions.push_back(r);

        cursor = end;
    }
    g_MemView.regionsNeedRefresh = false;
}

// Helper to read UNICODE_STRING from target
struct UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    ULONG_PTR Buffer; // for 64-bit, for 32-bit it's 32-bit but we use 64
};

static bool ReadUnicodeString(ULONG pid, ULONG_PTR strAddr, bool is32, std::string& out) {
    out.clear();
    if (is32) {
        // 32-bit UNICODE_STRING: Length 2, Max 2, Buffer 4
#pragma pack(push,1)
        struct US32 { USHORT Length; USHORT Max; ULONG Buffer; };
#pragma pack(pop)
        US32 us{};
        if (!DbkReadBytes(pid, strAddr, &us, sizeof(us))) return false;
        if (us.Length == 0 || us.Buffer == 0) return false;
        if (us.Length > 512) us.Length = 512;
        std::vector<wchar_t> wbuf((us.Length / 2) + 1);
        if (!DbkReadBytes(pid, us.Buffer, wbuf.data(), us.Length)) return false;
        wbuf[us.Length / 2] = 0;
        char mb[1024] = {0};
        WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), us.Length / 2, mb, sizeof(mb)-1, NULL, NULL);
        out = mb;
        return true;
    } else {
        UNICODE_STRING_T us{};
        // Actually UNICODE_STRING64 is 16 bytes: Length 2, Max 2, padding 4, Buffer 8
        // We read 16 bytes
        struct US64 { USHORT Length; USHORT Max; ULONG pad; ULONG64 Buffer; };
        US64 us64{};
        if (!DbkReadBytes(pid, strAddr, &us64, sizeof(us64))) return false;
        if (us64.Length == 0 || us64.Buffer == 0) return false;
        if (us64.Length > 512) us64.Length = 512;
        std::vector<wchar_t> wbuf((us64.Length / 2) + 1);
        if (!DbkReadBytes(pid, us64.Buffer, wbuf.data(), us64.Length)) return false;
        wbuf[us64.Length / 2] = 0;
        char mb[1024] = {0};
        WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), us64.Length / 2, mb, sizeof(mb)-1, NULL, NULL);
        out = mb;
        return true;
    }
}

void MemoryView_RefreshModules() {
    g_MemView.modules.clear();
    if (g_SelectedPid == 0) return;

    // Try ToolHelp first (works for non-protected)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_SelectedPid);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(hSnap, &me)) {
            do {
                ModuleInfoFull mod{};
                mod.base = (ULONG_PTR)me.modBaseAddr;
                mod.size = me.modBaseSize;
                // Convert WCHAR to UTF8
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, mod.name, sizeof(mod.name), NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, mod.path, sizeof(mod.path), NULL, NULL);
                g_MemView.modules.push_back(mod);
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
        if (!g_MemView.modules.empty()) {
            g_MemView.modulesNeedRefresh = false;
            return;
        }
    }

    // Fallback: kernel PEB walk via driver
    if (g_hDriver == INVALID_HANDLE_VALUE) return;

    bool is32 = !g_MemView.is64BitMode;
    ULONG64 pe = 0;
    if (!DbkGetPEPROCESS(g_SelectedPid, &pe) || pe == 0) return;
    ULONG64 pebAddr = 0;
    if (!DbkGetPeb(pe, &pebAddr) || pebAddr == 0) {
        // Try WOW64 PEB for 32-bit
        if (is32) {
            ULONG64 wow64Peb = 0;
            if (DbkGetWow64Peb(g_SelectedPid, &wow64Peb) && wow64Peb) {
                pebAddr = wow64Peb;
            } else {
                return;
            }
        } else {
            return;
        }
    }

    // PEB -> Ldr
    ULONG_PTR ldrPtr = 0;
    if (is32) {
        // PEB32: Ldr at 0x0C
        ULONG ldr32 = 0;
        if (!DbkReadBytes(g_SelectedPid, pebAddr + 0x0C, &ldr32, sizeof(ldr32))) return;
        ldrPtr = ldr32;
    } else {
        // PEB64: Ldr at 0x18
        ULONG64 ldr64 = 0;
        if (!DbkReadBytes(g_SelectedPid, pebAddr + 0x18, &ldr64, sizeof(ldr64))) return;
        ldrPtr = (ULONG_PTR)ldr64;
    }
    if (!ldrPtr) return;

    // LDR -> InLoadOrderModuleList
    ULONG_PTR listHead = 0;
    if (is32) {
        ULONG list32 = 0;
        if (!DbkReadBytes(g_SelectedPid, ldrPtr + 0x0C, &list32, sizeof(list32))) return;
        listHead = ldrPtr + 0x0C;
        // Actually InLoadOrderModuleList is at LDR+0x0C (LIST_ENTRY)
        // We'll walk
        ULONG_PTR cur = 0;
        if (!DbkReadBytes(g_SelectedPid, listHead, &cur, sizeof(ULONG))) return;
        // cur is Flink
        ULONG_PTR flink = cur;
        int count = 0;
        while (flink && flink != listHead && count < 512) {
            // LDR_DATA_TABLE_ENTRY32 layout:
            // 0x00 InLoadOrderLinks (8 bytes)
            // 0x08 InMemoryOrderLinks
            // 0x10 InInitializationOrderLinks
            // 0x18 DllBase (4)
            // 0x1C EntryPoint (4)
            // 0x20 SizeOfImage (4)
            // 0x24 FullDllName (8) UNICODE_STRING32
            // 0x2C BaseDllName (8)
            ULONG dllBase = 0; ULONG size = 0;
            if (!DbkReadBytes(g_SelectedPid, flink + 0x18, &dllBase, sizeof(dllBase))) break;
            if (!DbkReadBytes(g_SelectedPid, flink + 0x20, &size, sizeof(size))) break;
            std::string full, baseName;
            ReadUnicodeString(g_SelectedPid, flink + 0x24, true, full);
            ReadUnicodeString(g_SelectedPid, flink + 0x2C, true, baseName);
            if (dllBase) {
                ModuleInfoFull mod{};
                mod.base = dllBase;
                mod.size = size;
                strcpy_s(mod.name, sizeof(mod.name), baseName.c_str());
                strcpy_s(mod.path, sizeof(mod.path), full.c_str());
                g_MemView.modules.push_back(mod);
            }
            // Next
            ULONG next = 0;
            if (!DbkReadBytes(g_SelectedPid, flink, &next, sizeof(next))) break;
            if (next == flink) break;
            flink = next;
            count++;
        }
    } else {
        // 64-bit
        ULONG64 flink = 0;
        if (!DbkReadBytes(g_SelectedPid, ldrPtr + 0x10, &flink, sizeof(flink))) return; // InLoadOrderModuleList.Flink at LDR+0x10
        ULONG_PTR listHeadAddr = ldrPtr + 0x10;
        int count = 0;
        while (flink && flink != listHeadAddr && count < 512) {
            ULONG64 dllBase = 0; ULONG size = 0;
            if (!DbkReadBytes(g_SelectedPid, flink + 0x30, &dllBase, sizeof(dllBase))) break;
            if (!DbkReadBytes(g_SelectedPid, flink + 0x40, &size, sizeof(size))) break;
            std::string full, baseName;
            ReadUnicodeString(g_SelectedPid, flink + 0x48, false, full);
            ReadUnicodeString(g_SelectedPid, flink + 0x58, false, baseName);
            if (dllBase) {
                ModuleInfoFull mod{};
                mod.base = (ULONG_PTR)dllBase;
                mod.size = size;
                strcpy_s(mod.name, sizeof(mod.name), baseName.c_str());
                strcpy_s(mod.path, sizeof(mod.path), full.c_str());
                g_MemView.modules.push_back(mod);
            }
            ULONG64 next = 0;
            if (!DbkReadBytes(g_SelectedPid, flink, &next, sizeof(next))) break;
            if (next == flink) break;
            flink = next;
            count++;
        }
    }

    g_MemView.modulesNeedRefresh = false;
}

void MemoryView_ScanStrings() {
    g_MemView.strings.clear();
    if (g_SelectedPid == 0 || g_hDriver == INVALID_HANDLE_VALUE) return;
    if (g_MemView.regions.empty()) MemoryView_RefreshRegions();

    int minLen = g_MemView.stringMinLen;
    if (minLen < 3) minLen = 3;

    std::vector<BYTE> buf(4096);
    for (auto& r : g_MemView.regions) {
        if (!r.readable) continue;
        if (r.size > 0x1000000) continue; // skip huge regions for performance (optional)
        ULONG_PTR cur = r.base;
        ULONG_PTR end = r.base + r.size;
        std::string curStr;
        ULONG_PTR curStrStart = 0;
        while (cur < end) {
            ULONG_PTR toRead = std::min<ULONG_PTR>(buf.size(), end - cur);
            if (!DbkReadBytes(g_SelectedPid, cur, buf.data(), (ULONG)toRead)) { cur += toRead; curStr.clear(); continue; }
            for (ULONG_PTR i = 0; i < toRead; i++) {
                BYTE b = buf[i];
                if (b >= 32 && b <= 126) { // printable ASCII
                    if (curStr.empty()) curStrStart = cur + i;
                    curStr.push_back((char)b);
                } else {
                    if ((int)curStr.size() >= minLen) {
                        StringRef sr{};
                        sr.address = curStrStart;
                        sr.length = (int)curStr.size();
                        strncpy_s(sr.text, curStr.c_str(), sizeof(sr.text)-1);
                        g_MemView.strings.push_back(sr);
                        if (g_MemView.strings.size() > 10000) goto done; // limit
                    }
                    curStr.clear();
                }
            }
            cur += toRead;
        }
        // flush remaining
        if ((int)curStr.size() >= minLen) {
            StringRef sr{};
            sr.address = curStrStart;
            sr.length = (int)curStr.size();
            strncpy_s(sr.text, curStr.c_str(), sizeof(sr.text)-1);
            g_MemView.strings.push_back(sr);
        }
    }
done:
    g_MemView.stringsNeedScan = false;
}

// Pattern search with wildcards: "48 8B 05 ? ? ? ?" or "48 8B ??"
void MemoryView_SearchPattern(const char* pattern) {
    g_MemView.searchResults.clear();
    if (!pattern || !pattern[0] || g_SelectedPid == 0) return;
    g_MemView.isSearching = true;
    g_MemView.searchProgress = 0;

    // Parse pattern into bytes and mask
    std::vector<BYTE> patBytes;
    std::vector<bool> patMask; // true = must match, false = wildcard
    std::string patStr = pattern;
    // Tokenize by space
    std::istringstream iss(patStr);
    std::string token;
    while (iss >> token) {
        if (token == "?" || token == "??") {
            patBytes.push_back(0);
            patMask.push_back(false);
        } else {
            // hex byte
            try {
                int v = std::stoi(token, nullptr, 16);
                patBytes.push_back((BYTE)v);
                patMask.push_back(true);
            } catch (...) {
                // ignore invalid
            }
        }
    }
    if (patBytes.empty()) { g_MemView.isSearching = false; return; }

    if (g_MemView.regions.empty()) MemoryView_RefreshRegions();

    std::vector<BYTE> buf(65536);
    size_t totalRegions = g_MemView.regions.size();
    size_t curRegion = 0;
    for (auto& r : g_MemView.regions) {
        curRegion++;
        g_MemView.searchProgress = (int)(curRegion * 100 / totalRegions);
        if (!r.readable) continue;
        if (r.size < patBytes.size()) continue;
        ULONG_PTR cur = r.base;
        ULONG_PTR end = r.base + r.size;
        while (cur < end) {
            ULONG_PTR toRead = std::min<ULONG_PTR>(buf.size(), end - cur);
            if (!DbkReadBytes(g_SelectedPid, cur, buf.data(), (ULONG)toRead)) { cur += toRead; continue; }
            // Search in buf
            for (size_t i = 0; i + patBytes.size() <= toRead; i++) {
                bool match = true;
                for (size_t j = 0; j < patBytes.size(); j++) {
                    if (patMask[j] && buf[i + j] != patBytes[j]) { match = false; break; }
                }
                if (match) {
                    g_MemView.searchResults.push_back(cur + i);
                    if (g_MemView.searchResults.size() > 10000) { g_MemView.isSearching = false; g_MemView.searchProgress = 100; return; }
                }
            }
            cur += toRead;
        }
    }
    g_MemView.isSearching = false;
    g_MemView.searchProgress = 100;
}

// ------------------------------------------------------------------
// Navigation
// ------------------------------------------------------------------
void MemoryView_GoTo(ULONG_PTR addr, bool addToHistory) {
    if (addToHistory && g_MemView.disasmAddr != 0 && g_MemView.disasmAddr != addr) {
        g_MemView.backHistory.push_back(g_MemView.disasmAddr);
        if (g_MemView.backHistory.size() > 100) g_MemView.backHistory.pop_front();
        g_MemView.forwardHistory.clear();
    }
    g_MemView.disasmAddr = addr;
    g_MemView.hexAddr = addr;
    sprintf_s(g_MemView.addrInput, "0x%llX", (unsigned long long)addr);
    sprintf_s(g_MemView.hexAddrInput, "0x%llX", (unsigned long long)addr);
    g_MemView.disasmNeedsRefresh = true;
    MemoryView_RefreshDisasm();
    MemoryView_RefreshHex();
}

void MemoryView_GoToHex(ULONG_PTR addr) {
    g_MemView.hexAddr = addr;
    sprintf_s(g_MemView.hexAddrInput, "0x%llX", (unsigned long long)addr);
    MemoryView_RefreshHex();
}

// ------------------------------------------------------------------
// Init / Shutdown / PID change
// ------------------------------------------------------------------
void MemoryView_Init() {
    g_MemView = MemViewState(); // reset via default ctor
    g_MemView.disasmAddr = 0x00400000;
    g_MemView.hexAddr = 0x00400000;
    strcpy_s(g_MemView.addrInput, sizeof(g_MemView.addrInput), "0x00400000");
    strcpy_s(g_MemView.hexAddrInput, sizeof(g_MemView.hexAddrInput), "0x00400000");
    strcpy_s(g_MemView.allocSizeInput, sizeof(g_MemView.allocSizeInput), "0x1000");
    strcpy_s(g_MemView.searchPatternInput, sizeof(g_MemView.searchPatternInput), "");
    strcpy_s(g_MemView.asmInput, sizeof(g_MemView.asmInput), "nop");
    g_MemView.disasmLineCount = 80;
    g_MemView.bytesPerRow = 16;
    g_MemView.stringMinLen = 5;
    g_MemView.is64BitMode = true;
    g_MemView.hexBuffer.resize(4096);
    g_MemView.disasmNeedsRefresh = true;
    g_MemView.regionsNeedRefresh = true;
    g_MemView.modulesNeedRefresh = true;
    g_MemView.stringsNeedScan = true;
    g_MemView.hexSelectedOffset = -1;
    g_MemView.selectedDisasmIdx = -1;
}

void MemoryView_Shutdown() {
    // nothing
}

void MemoryView_OnPidChanged(ULONG newPid, bool is64) {
    g_MemView.is64BitMode = is64;
    g_MemView.disasmNeedsRefresh = true;
    g_MemView.regionsNeedRefresh = true;
    g_MemView.modulesNeedRefresh = true;
    g_MemView.stringsNeedScan = true;
    g_MemView.backHistory.clear();
    g_MemView.forwardHistory.clear();
    g_MemView.disasmLines.clear();
    g_MemView.regions.clear();
    g_MemView.modules.clear();
    g_MemView.strings.clear();
    g_MemView.searchResults.clear();
    g_MemView.bookmarks.clear();
    // Try to set disasmAddr to main module base if available
    // Will be refreshed after modules enumeration
    g_MemView.disasmAddr = is64 ? 0x0000000140000000ULL : 0x00400000;
    g_MemView.hexAddr = g_MemView.disasmAddr;
    sprintf_s(g_MemView.addrInput, "0x%llX", (unsigned long long)g_MemView.disasmAddr);
    sprintf_s(g_MemView.hexAddrInput, "0x%llX", (unsigned long long)g_MemView.hexAddr);
}

// ------------------------------------------------------------------
// UI Rendering
// ------------------------------------------------------------------
static void RenderDisasmLine(const DisasmLine& line, int idx, bool isSelected) {
    ImGui::PushID(idx);
    // Color based on type
    ImVec4 col = ImVec4(1, 1, 1, 1);
    if (line.isJump) col = ImVec4(0.6f, 0.8f, 1.0f, 1.0f);
    else if (line.isCall) col = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
    else if (line.isRet) col = ImVec4(1.0f, 0.4f, 0.4f, 1.0f);

    bool selected = (g_MemView.selectedDisasmIdx == idx);
    if (ImGui::Selectable("", selected, ImGuiSelectableFlags_SpanAllColumns)) {
        g_MemView.selectedDisasmIdx = idx;
    }
    // Context menu
    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem("Copy Address")) {
            char buf[64]; sprintf_s(buf, "0x%llX", (unsigned long long)line.address);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Copy Bytes")) {
            ImGui::SetClipboardText(line.bytesStr);
        }
        if (ImGui::MenuItem("Copy Disassembly")) {
            ImGui::SetClipboardText(line.text);
        }
        if (ImGui::MenuItem("Go to Address")) {
            g_MemView.showGotoPopup = true;
            sprintf_s(g_MemView.gotoInput, "0x%llX", (unsigned long long)line.address);
        }
        if (line.hasBranchTarget) {
            char label[128];
            sprintf_s(label, "Follow %s -> 0x%llX", line.isCall ? "Call" : "Jump", (unsigned long long)line.branchTarget);
            if (ImGui::MenuItem(label)) {
                MemoryView_GoTo(line.branchTarget);
            }
        }
        if (ImGui::MenuItem("Show in Hex View")) {
            MemoryView_GoToHex(line.address);
        }
        if (ImGui::MenuItem("Add to Cheat Table")) {
            std::lock_guard<std::mutex> lock(g_CheatTableLock);
            char desc[64]; sprintf_s(desc, "0x%llX", (unsigned long long)line.address);
            g_CheatTable.push_back({line.address, 0, false, 4, g_SelectedPid, ""});
            strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc);
        }
        if (ImGui::MenuItem("NOP this instruction")) {
            std::vector<BYTE> nops(line.length, 0x90);
            DbkWriteBytes(g_SelectedPid, line.address, nops.data(), (ULONG)nops.size());
            g_MemView.disasmNeedsRefresh = true;
        }
        if (ImGui::MenuItem("Assemble...")) {
            g_MemView.asmAddr = line.address;
            strcpy_s(g_MemView.asmInput, sizeof(g_MemView.asmInput), line.text);
            g_MemView.showAsmPopup = true;
        }
        if (ImGui::MenuItem("Bookmark this address")) {
            Bookmark bm{}; bm.address = line.address; sprintf_s(bm.desc, "0x%llX", (unsigned long long)line.address);
            g_MemView.bookmarks.push_back(bm);
        }
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    // Address
    ImGui::TextColored(col, "0x%08llX", (unsigned long long)line.address);
    ImGui::SameLine(140);
    if (g_MemView.showBytes) {
        ImGui::TextDisabled("%s", line.bytesStr);
        ImGui::SameLine(320);
    } else {
        ImGui::SameLine(140);
    }
    // Mnemonic colored
    ImGui::TextColored(col, "%s", line.text);
    // Show module+offset as comment
    if (g_MemView.showModuleNames) {
        std::string modName = MemoryView_GetModuleNameForAddr(line.address);
        if (!modName.empty()) {
            ImGui::SameLine(600);
            ImGui::TextDisabled("; %s", modName.c_str());
        }
        if (line.hasBranchTarget) {
            std::string tgtMod = MemoryView_GetModuleNameForAddr(line.branchTarget);
            if (!tgtMod.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("-> %s", tgtMod.c_str());
            } else {
                ImGui::SameLine();
                ImGui::TextDisabled("-> 0x%llX", (unsigned long long)line.branchTarget);
            }
        }
    }

    // Double-click to follow
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
        if (line.hasBranchTarget) {
            MemoryView_GoTo(line.branchTarget);
        } else {
            // Try to parse immediate address from text? For simplicity, go to next
            MemoryView_GoTo(line.address + line.length, false);
        }
    }

    ImGui::PopID();
}

void MemoryView_Render() {
    if (g_SelectedPid == 0) {
        ImGui::TextDisabled("Select a target process to use Memory View (kernel reads).");
        return;
    }

    // Top bar: address + navigation
    ImGui::BeginGroup();
    if (ImGui::Button("<- Back")) {
        if (!g_MemView.backHistory.empty()) {
            ULONG_PTR prev = g_MemView.backHistory.back();
            g_MemView.backHistory.pop_back();
            g_MemView.forwardHistory.push_back(g_MemView.disasmAddr);
            MemoryView_GoTo(prev, false);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Forward ->")) {
        if (!g_MemView.forwardHistory.empty()) {
            ULONG_PTR nxt = g_MemView.forwardHistory.back();
            g_MemView.forwardHistory.pop_back();
            g_MemView.backHistory.push_back(g_MemView.disasmAddr);
            MemoryView_GoTo(nxt, false);
        }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    if (ImGui::InputText("##addrInput", g_MemView.addrInput, sizeof(g_MemView.addrInput), ImGuiInputTextFlags_EnterReturnsTrue)) {
        ULONG_PTR addr = 0;
        if (MemoryView_ParseAddress(g_MemView.addrInput, g_SelectedPid, &addr)) {
            MemoryView_GoTo(addr);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Go")) {
        ULONG_PTR addr = 0;
        if (MemoryView_ParseAddress(g_MemView.addrInput, g_SelectedPid, &addr)) {
            MemoryView_GoTo(addr);
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        g_MemView.disasmNeedsRefresh = true;
        g_MemView.regionsNeedRefresh = true;
        g_MemView.modulesNeedRefresh = true;
        MemoryView_RefreshDisasm();
        MemoryView_RefreshHex();
        MemoryView_RefreshRegions();
        MemoryView_RefreshModules();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Show Bytes", &g_MemView.showBytes);
    ImGui::SameLine();
    ImGui::Checkbox("Show Modules", &g_MemView.showModuleNames);
    ImGui::SameLine();
    ImGui::TextDisabled("%s", g_MemView.is64BitMode ? "64-bit" : "32-bit");
    ImGui::EndGroup();

    ImGui::Separator();

    if (ImGui::BeginTabBar("MemViewTabs")) {
        // --- Disassembler + Hex combined ---
        if (ImGui::BeginTabItem("Disassembler & Hex")) {
            // Split into two children: disasm top, hex bottom
            float availH = ImGui::GetContentRegionAvail().y;
            float disasmH = availH * 0.60f;
            float hexH = availH * 0.40f - 10;

            // Disasm child
            ImGui::BeginChild("DisasmChild", ImVec2(0.0f, disasmH), true);
            if (g_MemView.disasmNeedsRefresh) MemoryView_RefreshDisasm();

            // Header
            ImGui::TextDisabled("Address       Bytes               Disassembly");
            ImGui::Separator();
            ImGuiListClipper clipper;
            clipper.Begin((int)g_MemView.disasmLines.size());
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    RenderDisasmLine(g_MemView.disasmLines[i], i, g_MemView.selectedDisasmIdx == i);
                }
            }
            ImGui::EndChild();

            // Hex child
            ImGui::BeginChild("HexChild", ImVec2(0.0f, hexH), true);
            // Hex controls
            ImGui::SetNextItemWidth(200);
            if (ImGui::InputText("Hex Addr", g_MemView.hexAddrInput, sizeof(g_MemView.hexAddrInput), ImGuiInputTextFlags_EnterReturnsTrue)) {
                ULONG_PTR a = 0;
                if (MemoryView_ParseAddress(g_MemView.hexAddrInput, g_SelectedPid, &a)) MemoryView_GoToHex(a);
            }
            ImGui::SameLine();
            if (ImGui::Button("Go Hex")) {
                ULONG_PTR a = 0;
                if (MemoryView_ParseAddress(g_MemView.hexAddrInput, g_SelectedPid, &a)) MemoryView_GoToHex(a);
            }
            ImGui::SameLine();
            if (ImGui::Button("Sync with Disasm")) MemoryView_GoToHex(g_MemView.disasmAddr);
            ImGui::SameLine();
            ImGui::TextDisabled("Bytes per row: %d", g_MemView.bytesPerRow);

            ImGui::Separator();

            // Hex dump
            if (g_MemView.hexBuffer.empty()) MemoryView_RefreshHex();
            // Show hex dump
            int rows = (int)(g_MemView.hexBufferSize / g_MemView.bytesPerRow);
            ImGuiListClipper hexClipper;
            hexClipper.Begin(rows);
            while (hexClipper.Step()) {
                for (int r = hexClipper.DisplayStart; r < hexClipper.DisplayEnd; r++) {
                    ULONG_PTR rowAddr = g_MemView.hexBufferBase + r * g_MemView.bytesPerRow;
                    ImGui::PushID(r);
                    ImGui::Text("0x%08llX", (unsigned long long)rowAddr);
                    ImGui::SameLine(120);
                    // Hex bytes
                    for (int c = 0; c < g_MemView.bytesPerRow; c++) {
                        int idx = r * g_MemView.bytesPerRow + c;
                        if (idx >= (int)g_MemView.hexBufferSize) break;
                        BYTE b = g_MemView.hexBuffer[idx];
                        bool selected = (g_MemView.hexSelectedOffset == idx);
                        char label[8]; sprintf_s(label, "%02X", b);
                        if (selected) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 0, 1));
                        if (ImGui::Selectable(label, selected, 0, ImVec2(24.0f, 0.0f))) {
                            g_MemView.hexSelectedOffset = idx;
                            sprintf_s(g_MemView.hexEditInput, "%02X", b);
                            g_MemView.hexEditActive = true;
                        }
                        if (selected) ImGui::PopStyleColor();
                        // Context
                        if (ImGui::BeginPopupContextItem()) {
                            if (ImGui::MenuItem("Copy Byte")) {
                                char cb[8]; sprintf_s(cb, "%02X", b);
                                ImGui::SetClipboardText(cb);
                            }
                            if (ImGui::MenuItem("Edit Byte")) {
                                g_MemView.hexSelectedOffset = idx;
                                g_MemView.hexEditActive = true;
                            }
                            if (ImGui::MenuItem("Show in Disassembler")) {
                                MemoryView_GoTo(rowAddr + c);
                            }
                            if (ImGui::MenuItem("Add to Cheat Table")) {
                                std::lock_guard<std::mutex> lock(g_CheatTableLock);
                                char desc[64]; sprintf_s(desc, "0x%llX", (unsigned long long)(rowAddr + c));
                                g_CheatTable.push_back({rowAddr + c, b, false, 3, g_SelectedPid, ""});
                                strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc);
                            }
                            ImGui::EndPopup();
                        }
                        ImGui::SameLine();
                    }
                    ImGui::SameLine(120 + g_MemView.bytesPerRow * 26);
                    // ASCII
                    char ascii[32] = {0};
                    for (int c = 0; c < g_MemView.bytesPerRow; c++) {
                        int idx = r * g_MemView.bytesPerRow + c;
                        if (idx >= (int)g_MemView.hexBufferSize) break;
                        BYTE b = g_MemView.hexBuffer[idx];
                        ascii[c] = (b >= 32 && b <= 126) ? (char)b : '.';
                    }
                    ImGui::TextDisabled("%s", ascii);
                    ImGui::PopID();
                }
            }

            // Hex edit popup inline
            if (g_MemView.hexEditActive && g_MemView.hexSelectedOffset >= 0) {
                ImGui::Separator();
                ImGui::Text("Edit byte at 0x%llX: ", (unsigned long long)(g_MemView.hexBufferBase + g_MemView.hexSelectedOffset));
                ImGui::SameLine();
                ImGui::SetNextItemWidth(60);
                if (ImGui::InputText("##hexEdit", g_MemView.hexEditInput, sizeof(g_MemView.hexEditInput), ImGuiInputTextFlags_EnterReturnsTrue)) {
                    // Parse hex
                    try {
                        int v = std::stoi(g_MemView.hexEditInput, nullptr, 16);
                        BYTE bv = (BYTE)v;
                        ULONG_PTR addr = g_MemView.hexBufferBase + g_MemView.hexSelectedOffset;
                        if (DbkWriteBytes(g_SelectedPid, addr, &bv, 1)) {
                            g_MemView.hexBuffer[g_MemView.hexSelectedOffset] = bv;
                            g_MemView.disasmNeedsRefresh = true;
                        }
                        g_MemView.hexEditActive = false;
                    } catch (...) {}
                }
                ImGui::SameLine();
                if (ImGui::Button("Write")) {
                    try {
                        int v = std::stoi(g_MemView.hexEditInput, nullptr, 16);
                        BYTE bv = (BYTE)v;
                        ULONG_PTR addr = g_MemView.hexBufferBase + g_MemView.hexSelectedOffset;
                        if (DbkWriteBytes(g_SelectedPid, addr, &bv, 1)) {
                            g_MemView.hexBuffer[g_MemView.hexSelectedOffset] = bv;
                            g_MemView.disasmNeedsRefresh = true;
                        }
                        g_MemView.hexEditActive = false;
                    } catch (...) {}
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel")) g_MemView.hexEditActive = false;
            }

            // Data interpreter at selected offset (like CE)
            if (g_MemView.hexSelectedOffset >= 0 && g_MemView.hexSelectedOffset < (int)g_MemView.hexBufferSize) {
                ImGui::Separator();
                ImGui::Text("Data Interpreter at 0x%llX:", (unsigned long long)(g_MemView.hexBufferBase + g_MemView.hexSelectedOffset));
                BYTE* p = g_MemView.hexBuffer.data() + g_MemView.hexSelectedOffset;
                size_t remain = g_MemView.hexBufferSize - g_MemView.hexSelectedOffset;
                if (remain >= 1) {
                    ImGui::Text("Int8: %d | UInt8: %u | Char: '%c'", (int8_t)p[0], p[0], (p[0] >= 32 && p[0] <= 126) ? p[0] : '.');
                }
                if (remain >= 2) {
                    int16_t v; memcpy(&v, p, 2); ImGui::SameLine(); ImGui::Text("| Int16: %d | UInt16: %u", v, (uint16_t)v);
                }
                if (remain >= 4) {
                    int32_t v; memcpy(&v, p, 4); float f; memcpy(&f, p, 4);
                    ImGui::Text("Int32: %d | UInt32: %u | Float: %f", v, (uint32_t)v, f);
                }
                if (remain >= 8) {
                    int64_t v; memcpy(&v, p, 8); double d; memcpy(&d, p, 8);
                    ImGui::Text("Int64: %lld | UInt64: %llu | Double: %lf", (long long)v, (unsigned long long)v, d);
                }
            }

            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // --- Memory Regions ---
        if (ImGui::BeginTabItem("Memory Regions")) {
            if (g_MemView.regionsNeedRefresh) MemoryView_RefreshRegions();
            ImGui::SetNextItemWidth(200);
            ImGui::InputText("Filter", g_MemView.regionFilter, sizeof(g_MemView.regionFilter));
            ImGui::SameLine();
            if (ImGui::Button("Refresh Regions")) MemoryView_RefreshRegions();
            ImGui::SameLine();
            ImGui::TextDisabled("%zu regions", g_MemView.regions.size());

            ImGui::BeginChild("RegionsChild", ImVec2(0.0f, 0.0f), true);
            ImGui::Columns(5, "regionsCols");
            ImGui::Text("Base"); ImGui::NextColumn();
            ImGui::Text("Size"); ImGui::NextColumn();
            ImGui::Text("Protect"); ImGui::NextColumn();
            ImGui::Text("Info"); ImGui::NextColumn();
            ImGui::Text("Action"); ImGui::NextColumn();
            ImGui::Separator();
            for (size_t i = 0; i < g_MemView.regions.size(); i++) {
                auto& r = g_MemView.regions[i];
                if (g_MemView.regionFilter[0] && !StrContainsCI(r.protectStr, g_MemView.regionFilter)) {
                    // simple filter, also check base
                    char baseStr[32]; sprintf_s(baseStr, "%llX", (unsigned long long)r.base);
                    if (!StrContainsCI(baseStr, g_MemView.regionFilter)) continue;
                }
                char baseBuf[32]; sprintf_s(baseBuf, "0x%llX", (unsigned long long)r.base);
                if (ImGui::Selectable(baseBuf, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    MemoryView_GoTo(r.base);
                }
                ImGui::NextColumn();
                ImGui::Text("0x%llX (%llu KB)", (unsigned long long)r.size, (unsigned long long)(r.size / 1024));
                ImGui::NextColumn();
                ImVec4 col = r.executable ? ImVec4(1, 0.6f, 0.2f, 1) : (r.writable ? ImVec4(0.4f, 1, 0.4f, 1) : ImVec4(0.6f, 0.6f, 1, 1));
                ImGui::TextColored(col, "%s", r.protectStr);
                ImGui::NextColumn();
                ImGui::Text("%s %s", r.readable ? "R" : "-", r.executable ? "X" : "-");
                ImGui::NextColumn();
                ImGui::PushID((int)i);
                if (ImGui::SmallButton("Go")) MemoryView_GoTo(r.base);
                ImGui::SameLine();
                if (ImGui::SmallButton("Hex")) MemoryView_GoToHex(r.base);
                ImGui::PopID();
                ImGui::NextColumn();
            }
            ImGui::Columns(1);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // --- Modules ---
        if (ImGui::BeginTabItem("Modules")) {
            if (g_MemView.modulesNeedRefresh) MemoryView_RefreshModules();
            ImGui::SetNextItemWidth(200);
            ImGui::InputText("Filter", g_MemView.moduleFilter, sizeof(g_MemView.moduleFilter));
            ImGui::SameLine();
            if (ImGui::Button("Refresh Modules")) MemoryView_RefreshModules();
            ImGui::SameLine();
            ImGui::TextDisabled("%zu modules", g_MemView.modules.size());

            ImGui::BeginChild("ModulesChild", ImVec2(0.0f, 0.0f), true);
            ImGui::Columns(4, "modulesCols");
            ImGui::Text("Name"); ImGui::NextColumn();
            ImGui::Text("Base"); ImGui::NextColumn();
            ImGui::Text("Size"); ImGui::NextColumn();
            ImGui::Text("Path"); ImGui::NextColumn();
            ImGui::Separator();
            for (size_t i = 0; i < g_MemView.modules.size(); i++) {
                auto& m = g_MemView.modules[i];
                if (g_MemView.moduleFilter[0] && !StrContainsCI(m.name, g_MemView.moduleFilter) && !StrContainsCI(m.path, g_MemView.moduleFilter)) continue;
                if (ImGui::Selectable(m.name, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    MemoryView_GoTo(m.base);
                }
                ImGui::NextColumn();
                char buf[32]; sprintf_s(buf, "0x%llX", (unsigned long long)m.base);
                ImGui::Text("%s", buf);
                ImGui::NextColumn();
                ImGui::Text("0x%X (%u KB)", m.size, m.size / 1024);
                ImGui::NextColumn();
                ImGui::TextDisabled("%s", m.path);
                ImGui::NextColumn();
            }
            ImGui::Columns(1);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // --- Strings ---
        if (ImGui::BeginTabItem("Referenced Strings")) {
            ImGui::SetNextItemWidth(100);
            ImGui::InputInt("Min Length", &g_MemView.stringMinLen);
            ImGui::SameLine();
            if (ImGui::Button("Scan Strings")) {
                g_MemView.stringsNeedScan = true;
                std::thread([](){ MemoryView_ScanStrings(); }).detach();
            }
            ImGui::SameLine();
            ImGui::SetNextItemWidth(150);
            ImGui::InputText("Filter", g_MemView.stringFilter, sizeof(g_MemView.stringFilter));
            ImGui::SameLine();
            ImGui::TextDisabled("%zu strings", g_MemView.strings.size());

            if (g_MemView.stringsNeedScan && g_MemView.strings.empty()) {
                ImGui::TextDisabled("No strings scanned yet. Click Scan Strings.");
            }

            ImGui::BeginChild("StringsChild", ImVec2(0.0f, 0.0f), true);
            ImGuiListClipper clipper;
            clipper.Begin((int)g_MemView.strings.size());
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    auto& s = g_MemView.strings[i];
                    if (g_MemView.stringFilter[0] && !StrContainsCI(s.text, g_MemView.stringFilter)) continue;
                    ImGui::PushID(i);
                    char label[256];
                    sprintf_s(label, "0x%08llX : %s", (unsigned long long)s.address, s.text);
                    if (ImGui::Selectable(label)) {
                        MemoryView_GoTo(s.address);
                    }
                    if (ImGui::BeginPopupContextItem()) {
                        if (ImGui::MenuItem("Go to Disasm")) MemoryView_GoTo(s.address);
                        if (ImGui::MenuItem("Go to Hex")) MemoryView_GoToHex(s.address);
                        if (ImGui::MenuItem("Copy Address")) {
                            char buf[32]; sprintf_s(buf, "0x%llX", (unsigned long long)s.address);
                            ImGui::SetClipboardText(buf);
                        }
                        if (ImGui::MenuItem("Copy String")) ImGui::SetClipboardText(s.text);
                        ImGui::EndPopup();
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // --- Bookmarks ---
        if (ImGui::BeginTabItem("Bookmarks")) {
            ImGui::Text("Bookmarks: %zu", g_MemView.bookmarks.size());
            ImGui::SameLine();
            if (ImGui::Button("Clear All")) g_MemView.bookmarks.clear();
            ImGui::BeginChild("BookmarksChild", ImVec2(0.0f, 0.0f), true);
            for (size_t i = 0; i < g_MemView.bookmarks.size(); i++) {
                auto& bm = g_MemView.bookmarks[i];
                ImGui::PushID((int)i);
                char label[128];
                sprintf_s(label, "0x%08llX - %s", (unsigned long long)bm.address, bm.desc);
                if (ImGui::Selectable(label)) MemoryView_GoTo(bm.address);
                ImGui::SameLine();
                if (ImGui::SmallButton("X")) {
                    g_MemView.bookmarks.erase(g_MemView.bookmarks.begin() + i);
                    ImGui::PopID();
                    break;
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        // --- Tools ---
        if (ImGui::BeginTabItem("Tools")) {
            // Allocate memory
            ImGui::Text("Allocate Memory (VirtualAllocEx via DBK64):");
            ImGui::SetNextItemWidth(150);
            ImGui::InputText("Size", g_MemView.allocSizeInput, sizeof(g_MemView.allocSizeInput));
            ImGui::SameLine();
            if (ImGui::Button("Allocate")) {
                ULONG_PTR sz = 0;
                try { sz = (ULONG_PTR)std::stoull(g_MemView.allocSizeInput, nullptr, 0); } catch (...) { sz = 0x1000; }
                ULONG64 out = 0;
                if (DbkAllocProcessMem(g_SelectedPid, sz, &out) && out) {
                    g_MemView.lastAllocAddr = (ULONG_PTR)out;
                } else {
                    g_MemView.lastAllocAddr = 0;
                }
            }
            if (g_MemView.lastAllocAddr) {
                ImGui::TextColored(ImVec4(0,1,0,1), "Allocated at: 0x%llX", (unsigned long long)g_MemView.lastAllocAddr);
                ImGui::SameLine();
                if (ImGui::Button("Go to Alloc")) MemoryView_GoTo(g_MemView.lastAllocAddr);
            }
            ImGui::Separator();

            // Search pattern (AOB)
            ImGui::Text("AOB / Pattern Search (e.g. \"48 8B 05 ? ? ? ?\" ):");
            ImGui::SetNextItemWidth(300);
            ImGui::InputText("Pattern", g_MemView.searchPatternInput, sizeof(g_MemView.searchPatternInput));
            ImGui::SameLine();
            if (ImGui::Button("Search")) {
                std::thread([pat = std::string(g_MemView.searchPatternInput)](){ MemoryView_SearchPattern(pat.c_str()); }).detach();
            }
            if (g_MemView.isSearching) {
                ImGui::SameLine();
                ImGui::TextDisabled("Searching... %d%%", g_MemView.searchProgress);
                ImGui::ProgressBar((float)g_MemView.searchProgress / 100.0f, ImVec2(200.0f, 0.0f));
            } else {
                if (!g_MemView.searchResults.empty()) {
                    ImGui::Text("Found %zu results:", g_MemView.searchResults.size());
                    ImGui::BeginChild("SearchResultsChild", ImVec2(0.0f, 150.0f), true);
                    ImGuiListClipper clipper;
                    clipper.Begin((int)g_MemView.searchResults.size());
                    while (clipper.Step()) {
                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                            char label[64]; sprintf_s(label, "0x%08llX", (unsigned long long)g_MemView.searchResults[i]);
                            ImGui::PushID(i);
                            if (ImGui::Selectable(label)) MemoryView_GoTo(g_MemView.searchResults[i]);
                            ImGui::PopID();
                        }
                    }
                    ImGui::EndChild();
                }
            }
            ImGui::Separator();

            // Dissect code: find CALLs in current region
            ImGui::Text("Dissect Code (find CALLs/JMPs in current disasm view):");
            if (ImGui::Button("List CALLs in view")) {
                // Already have disasmLines, just filter
            }
            ImGui::BeginChild("CallsChild", ImVec2(0.0f, 150.0f), true);
            for (auto& line : g_MemView.disasmLines) {
                if (line.isCall && line.hasBranchTarget) {
                    char buf[256];
                    std::string mod = MemoryView_GetModuleNameForAddr(line.branchTarget);
                    sprintf_s(buf, "0x%08llX: %s -> 0x%08llX %s", (unsigned long long)line.address, line.text, (unsigned long long)line.branchTarget, mod.c_str());
                    if (ImGui::Selectable(buf)) MemoryView_GoTo(line.branchTarget);
                }
            }
            ImGui::EndChild();

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    // Popups
    if (g_MemView.showGotoPopup) {
        ImGui::OpenPopup("Go to Address");
        g_MemView.showGotoPopup = false;
    }
    if (ImGui::BeginPopupModal("Go to Address", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Address", g_MemView.gotoInput, sizeof(g_MemView.gotoInput));
        ImGui::TextDisabled("Supports: 0x1234, 1234, module+0x1234 (e.g. conquer.exe+0x1234)");
        if (ImGui::Button("Go")) {
            ULONG_PTR a = 0;
            if (MemoryView_ParseAddress(g_MemView.gotoInput, g_SelectedPid, &a)) {
                MemoryView_GoTo(a);
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (g_MemView.showAsmPopup) {
        ImGui::OpenPopup("Assemble");
        g_MemView.showAsmPopup = false;
    }
    if (ImGui::BeginPopupModal("Assemble", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Address: 0x%08llX", (unsigned long long)g_MemView.asmAddr);
        ImGui::InputText("Assembly", g_MemView.asmInput, sizeof(g_MemView.asmInput));
        ImGui::TextDisabled("Example: mov rax, rcx | nop | ret | jmp 0x12345678");
        // Simple assembler: we only support nop and ret and simple mov for now via manual encoding
        // For full assembler we would need Keystone, but we have Zydis encoder
        if (ImGui::Button("Assemble & Write")) {
            // Very simplified: handle "nop" and "ret" and "int3"
            std::string asmLower = ToLowerStr(g_MemView.asmInput);
            std::vector<BYTE> encoded;
            if (asmLower == "nop") {
                encoded = {0x90};
            } else if (asmLower == "ret") {
                encoded = {0xC3};
            } else if (asmLower == "int3") {
                encoded = {0xCC};
            } else {
                // Try Zydis encoder for generic - we need to parse mnemonic
                // For now, we will attempt to use ZydisEncoderEncodeInstruction if we can map
                // This is complex, so we fallback to manual: if user entered hex bytes like "90 90"
                // Try parse as hex bytes
                std::istringstream iss(g_MemView.asmInput);
                std::string tok;
                bool isHex = true;
                std::vector<BYTE> hexBytes;
                while (iss >> tok) {
                    try {
                        int v = std::stoi(tok, nullptr, 16);
                        if (v < 0 || v > 255) { isHex = false; break; }
                        hexBytes.push_back((BYTE)v);
                    } catch (...) { isHex = false; break; }
                }
                if (isHex && !hexBytes.empty()) encoded = hexBytes;
            }

            if (!encoded.empty()) {
                DbkWriteBytes(g_SelectedPid, g_MemView.asmAddr, encoded.data(), (ULONG)encoded.size());
                g_MemView.disasmNeedsRefresh = true;
                ImGui::CloseCurrentPopup();
            } else {
                // Show error
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}
