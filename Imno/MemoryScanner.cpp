#include "MemoryScanner.h"
#include "MemoryView.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <memory>
#include <Psapi.h>

#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#pragma warning(disable:4305)

CEScannerState g_Scanner;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
static std::string ToLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}
static bool ContainsCI(const char* hay, const char* needle) {
    if (!needle || !needle[0]) return true;
    std::string h = ToLower(hay ? hay : "");
    std::string n = ToLower(needle);
    return h.find(n) != std::string::npos;
}
static void Trim(std::string& s) {
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    if (!s.empty()) s.erase(s.find_last_not_of(" \t\r\n") + 1);
}

const char* ScanTypeToString(CEScanType t) {
    switch (t) {
        case CEScanType::ExactValue: return "Exact Value";
        case CEScanType::BiggerThan: return "Bigger than...";
        case CEScanType::SmallerThan: return "Smaller than...";
        case CEScanType::ValueBetween: return "Value between...";
        case CEScanType::IncreasedValue: return "Increased value";
        case CEScanType::IncreasedBy: return "Increased value by...";
        case CEScanType::DecreasedValue: return "Decreased value";
        case CEScanType::DecreasedBy: return "Decreased value by...";
        case CEScanType::Changed: return "Changed value";
        case CEScanType::Unchanged: return "Unchanged value";
        case CEScanType::UnknownInitial: return "Unknown initial value";
        case CEScanType::SameAsFirstScan: return "Same as first scan";
        case CEScanType::NotSameAsFirst: return "Not same as first";
        default: return "Exact Value";
    }
}
const char* ValueTypeToString(CEValueType t) {
    switch (t) {
        case CEValueType::Byte: return "1 Byte";
        case CEValueType::Word: return "2 Bytes";
        case CEValueType::DWord: return "4 Bytes";
        case CEValueType::QWord: return "8 Bytes";
        case CEValueType::Single: return "Float";
        case CEValueType::Double: return "Double";
        case CEValueType::String: return "String";
        case CEValueType::UnicodeString: return "Unicode String";
        case CEValueType::ByteArray: return "Array of byte";
        case CEValueType::Grouped: return "Grouped";
        case CEValueType::All: return "All";
        case CEValueType::Custom: return "Custom";
        default: return "4 Bytes";
    }
}

static int GetValueTypeSize(CEValueType vt) {
    switch (vt) {
        case CEValueType::Byte: return 1;
        case CEValueType::Word: return 2;
        case CEValueType::DWord: return 4;
        case CEValueType::QWord: return 8;
        case CEValueType::Single: return 4;
        case CEValueType::Double: return 8;
        case CEValueType::String: return 0; // variable
        case CEValueType::UnicodeString: return 0;
        case CEValueType::ByteArray: return 0;
        case CEValueType::Grouped: return 0;
        case CEValueType::All: return 4;
        default: return 4;
    }
}

// ------------------------------------------------------------------
// Value parsing
// ------------------------------------------------------------------
bool MemoryScanner_ParseValue(CEValueType vt, const char* input, bool hex, std::vector<BYTE>& outBytes, ULONG64* outInt, double* outFloat) {
    outBytes.clear();
    if (!input) return false;
    std::string s = input;
    Trim(s);
    if (s.empty()) return false;

    try {
        switch (vt) {
            case CEValueType::Byte: {
                ULONG64 v = hex ? std::stoull(s, nullptr, 16) : std::stoull(s, nullptr, 0);
                outBytes.push_back((BYTE)(v & 0xFF));
                if (outInt) *outInt = v & 0xFF;
                if (outFloat) *outFloat = (double)(v & 0xFF);
                return true;
            }
            case CEValueType::Word: {
                ULONG64 v = hex ? std::stoull(s, nullptr, 16) : std::stoull(s, nullptr, 0);
                outBytes.push_back((BYTE)(v & 0xFF));
                outBytes.push_back((BYTE)((v >> 8) & 0xFF));
                if (outInt) *outInt = v & 0xFFFF;
                if (outFloat) *outFloat = (double)(v & 0xFFFF);
                return true;
            }
            case CEValueType::DWord: {
                ULONG64 v = hex ? std::stoull(s, nullptr, 16) : std::stoull(s, nullptr, 0);
                for (int i = 0; i < 4; i++) outBytes.push_back((BYTE)((v >> (i * 8)) & 0xFF));
                if (outInt) *outInt = v & 0xFFFFFFFFULL;
                if (outFloat) *outFloat = (double)(v & 0xFFFFFFFFULL);
                return true;
            }
            case CEValueType::QWord: {
                ULONG64 v = hex ? std::stoull(s, nullptr, 16) : std::stoull(s, nullptr, 0);
                for (int i = 0; i < 8; i++) outBytes.push_back((BYTE)((v >> (i * 8)) & 0xFF));
                if (outInt) *outInt = v;
                if (outFloat) *outFloat = (double)v;
                return true;
            }
            case CEValueType::Single: {
                float f = std::stof(s);
                ULONG u; memcpy(&u, &f, 4);
                for (int i = 0; i < 4; i++) outBytes.push_back((BYTE)((u >> (i * 8)) & 0xFF));
                if (outFloat) *outFloat = f;
                if (outInt) *outInt = u;
                return true;
            }
            case CEValueType::Double: {
                double d = std::stod(s);
                ULONG64 u; memcpy(&u, &d, 8);
                for (int i = 0; i < 8; i++) outBytes.push_back((BYTE)((u >> (i * 8)) & 0xFF));
                if (outFloat) *outFloat = d;
                if (outInt) *outInt = u;
                return true;
            }
            case CEValueType::String: {
                // ANSI string, case sensitive handled later
                for (char c : s) outBytes.push_back((BYTE)c);
                return !outBytes.empty();
            }
            case CEValueType::UnicodeString: {
                // UTF16LE
                std::wstring ws;
                // Convert from UTF8 to wide
                int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
                if (len > 0) {
                    std::vector<wchar_t> wbuf(len);
                    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, wbuf.data(), len);
                    for (int i = 0; i < len - 1; i++) { // exclude null
                        wchar_t wc = wbuf[i];
                        outBytes.push_back((BYTE)(wc & 0xFF));
                        outBytes.push_back((BYTE)((wc >> 8) & 0xFF));
                    }
                }
                return !outBytes.empty();
            }
            case CEValueType::ByteArray: {
                std::vector<BYTE> b; std::vector<bool> m;
                if (MemoryScanner_ParseAOB(s.c_str(), b, m)) {
                    outBytes = b;
                    return true;
                }
                return false;
            }
            case CEValueType::All:
            case CEValueType::Grouped:
            case CEValueType::Custom: {
                // Try parse as int first
                ULONG64 v = 0;
                try { v = std::stoull(s, nullptr, hex ? 16 : 0); } catch (...) { v = 0; }
                for (int i = 0; i < 4; i++) outBytes.push_back((BYTE)((v >> (i * 8)) & 0xFF));
                if (outInt) *outInt = v;
                return true;
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

bool MemoryScanner_ParseAOB(const char* input, std::vector<BYTE>& outBytes, std::vector<bool>& outMask) {
    outBytes.clear(); outMask.clear();
    if (!input) return false;
    std::string s = input;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??" || tok == "*") {
            outBytes.push_back(0);
            outMask.push_back(false);
        } else {
            try {
                int v = std::stoi(tok, nullptr, 16);
                if (v < 0 || v > 255) return false;
                outBytes.push_back((BYTE)v);
                outMask.push_back(true);
            } catch (...) {
                return false;
            }
        }
    }
    return !outBytes.empty();
}

bool MemoryScanner_ParseGrouped(const char* input, std::vector<CEScannerState::GroupedEntry>& outEntries, int& outBlockSize) {
    outEntries.clear(); outBlockSize = 0;
    if (!input) return false;
    std::string s = input;
    // Example: "4:100 4:200" or "b:10 w:20 4:30 f:3.14"
    std::istringstream iss(s);
    std::string token;
    int currentOffset = 0;
    while (iss >> token) {
        if (token.empty()) continue;
        // Skip + offset tokens? For simplicity, if token starts with + or -, it's offset
        if (token[0] == '+' || token[0] == '-') {
            try {
                int off = std::stoi(token, nullptr, 0);
                currentOffset += off;
                continue;
            } catch (...) { continue; }
        }
        size_t colon = token.find(':');
        if (colon == std::string::npos) continue;
        std::string typeStr = token.substr(0, colon);
        std::string valStr = token.substr(colon + 1);
        Trim(typeStr); Trim(valStr);
        if (typeStr.empty() || valStr.empty()) continue;

        CEValueType vt = CEValueType::DWord;
        std::string tl = ToLower(typeStr);
        if (tl == "b" || tl == "1" || tl == "byte") vt = CEValueType::Byte;
        else if (tl == "w" || tl == "2" || tl == "word") vt = CEValueType::Word;
        else if (tl == "4" || tl == "d" || tl == "dword") vt = CEValueType::DWord;
        else if (tl == "8" || tl == "q" || tl == "qword") vt = CEValueType::QWord;
        else if (tl == "f" || tl == "float" || tl == "single") vt = CEValueType::Single;
        else if (tl == "d" || tl == "double") vt = CEValueType::Double;
        else {
            try { int sz = std::stoi(typeStr); if (sz == 1) vt = CEValueType::Byte; else if (sz == 2) vt = CEValueType::Word; else if (sz == 4) vt = CEValueType::DWord; else if (sz == 8) vt = CEValueType::QWord; } catch (...) {}
        }

        std::vector<BYTE> bytes;
        if (!MemoryScanner_ParseValue(vt, valStr.c_str(), false, bytes)) continue;

        CEScannerState::GroupedEntry e;
        e.type = vt;
        e.bytes = bytes;
        e.offset = currentOffset;
        outEntries.push_back(e);
        currentOffset += (int)bytes.size();
    }
    outBlockSize = currentOffset;
    return !outEntries.empty();
}

// ------------------------------------------------------------------
// Protection helpers
// ------------------------------------------------------------------
static bool IsWritableProt(ULONG prot) {
    return (prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}
static bool IsExecutableProt(ULONG prot) {
    return (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}
static bool IsCopyOnWriteProt(ULONG prot) {
    return (prot & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
}
static bool CheckTriState(TriState ts, bool flag) {
    if (ts == TriState::DontCare) return true;
    if (ts == TriState::IncludeOnly) return flag;
    if (ts == TriState::Exclude) return !flag;
    return true;
}

// ------------------------------------------------------------------
// Fast scan helpers
// ------------------------------------------------------------------
static std::vector<int> ParseLastDigits(const char* input) {
    std::vector<int> out;
    if (!input) return out;
    std::string s = input;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        try {
            int v = std::stoi(tok, nullptr, 16);
            out.push_back(v & 0xF); // only last hex digit
        } catch (...) {}
    }
    return out;
}
static bool CheckFastScan(ULONG_PTR addr, bool fastScan, bool aligned, int alignment, const std::vector<int>& lastDigits) {
    if (!fastScan) return true;
    if (aligned) {
        if (alignment <= 1) return true;
        return (addr % alignment) == 0;
    } else {
        if (lastDigits.empty()) return true;
        int last = addr & 0xF;
        for (int d : lastDigits) if (last == d) return true;
        return false;
    }
}

// ------------------------------------------------------------------
// Value comparison for next scan
// ------------------------------------------------------------------
static bool CompareIntValues(ULONG64 cur, ULONG64 prev, ULONG64 search, ULONG64 search2, CEScanType st) {
    switch (st) {
        case CEScanType::ExactValue: return cur == search;
        case CEScanType::BiggerThan: return cur > search;
        case CEScanType::SmallerThan: return cur < search;
        case CEScanType::ValueBetween: return cur >= search && cur <= search2;
        case CEScanType::IncreasedValue: return cur > prev;
        case CEScanType::IncreasedBy: return cur == prev + search;
        case CEScanType::DecreasedValue: return cur < prev;
        case CEScanType::DecreasedBy: return cur == prev - search;
        case CEScanType::Changed: return cur != prev;
        case CEScanType::Unchanged: return cur == prev;
        case CEScanType::SameAsFirstScan: return true; // handled elsewhere
        default: return cur == search;
    }
}
static bool CompareFloatValues(double cur, double prev, double search, double search2, CEScanType st) {
    const double eps = 0.00001;
    switch (st) {
        case CEScanType::ExactValue: return fabs(cur - search) < eps;
        case CEScanType::BiggerThan: return cur > search;
        case CEScanType::SmallerThan: return cur < search;
        case CEScanType::ValueBetween: return cur >= search && cur <= search2;
        case CEScanType::IncreasedValue: return cur > prev;
        case CEScanType::IncreasedBy: return fabs(cur - (prev + search)) < eps;
        case CEScanType::DecreasedValue: return cur < prev;
        case CEScanType::DecreasedBy: return fabs(cur - (prev - search)) < eps;
        case CEScanType::Changed: return fabs(cur - prev) >= eps;
        case CEScanType::Unchanged: return fabs(cur - prev) < eps;
        default: return fabs(cur - search) < eps;
    }
}

// ------------------------------------------------------------------
// First scan worker - scans regions
// ------------------------------------------------------------------
struct ScanRegion {
    ULONG_PTR base;
    ULONG_PTR size;
    ULONG prot;
};

static std::vector<ScanRegion> EnumerateScanRegions(ULONG pid, ULONG_PTR start, ULONG_PTR stop, TriState writable, TriState executable, TriState cow) {
    std::vector<ScanRegion> out;
    ULONG_PTR cursor = start;
    int guard = 0;
    while (cursor < stop) {
        if (++guard > 100000) break;
        ULONG_PTR len = 0; ULONG prot = 0;
        if (!DbkQueryVirtualMemory(pid, cursor, &len, &prot)) break;
        if (len == 0) break;
        ULONG_PTR base = cursor & ~0xFFFULL;
        ULONG_PTR end = base + len;
        if (end <= base) break;
        if (end > stop) { len = stop - base; end = stop; }
        if (base < start) {
            // adjust
            ULONG_PTR diff = start - base;
            if (diff >= len) { cursor = end; continue; }
            base = start;
            len -= diff;
        }
        bool isW = IsWritableProt(prot);
        bool isX = IsExecutableProt(prot);
        bool isC = IsCopyOnWriteProt(prot);
        if (!CheckTriState(writable, isW)) { cursor = end; continue; }
        if (!CheckTriState(executable, isX)) { cursor = end; continue; }
        if (!CheckTriState(cow, isC)) { cursor = end; continue; }

        // Only scan if readable? At least not NOACCESS
        if (prot == PAGE_NOACCESS || prot == PAGE_GUARD) { cursor = end; continue; }

        ScanRegion r; r.base = base; r.size = len; r.prot = prot;
        out.push_back(r);
        cursor = end;
    }
    return out;
}

static void FirstScanWorkerThread(std::vector<ScanRegion> regions, CEScanParams params, ULONG pid, std::vector<CEFoundResult>& localResults, std::atomic<int>& progressCounter, int totalRegions) {
    // Parse search bytes
    std::vector<BYTE> searchBytes, searchBytes2;
    std::vector<bool> searchMask;
    std::vector<CEScannerState::GroupedEntry> groupedEntries;
    int groupedBlockSize = 0;
    ULONG64 searchInt = 0, searchInt2 = 0;
    double searchFloat = 0, searchFloat2 = 0;

    bool isString = (params.valueType == CEValueType::String || params.valueType == CEValueType::UnicodeString);
    bool isAOB = (params.valueType == CEValueType::ByteArray);
    bool isGrouped = (params.valueType == CEValueType::Grouped);

    if (isAOB) {
        MemoryScanner_ParseAOB(params.valueInput, searchBytes, searchMask);
    } else if (isGrouped) {
        MemoryScanner_ParseGrouped(params.valueInput, groupedEntries, groupedBlockSize);
    } else {
        MemoryScanner_ParseValue(params.valueType, params.valueInput, params.hex, searchBytes, &searchInt, &searchFloat);
        if (params.scanType == CEScanType::ValueBetween) {
            MemoryScanner_ParseValue(params.valueType, params.value2Input, params.hex, searchBytes2, &searchInt2, &searchFloat2);
        }
    }

    int alignment = 1;
    try { alignment = std::stoi(params.alignmentInput); } catch (...) { alignment = GetValueTypeSize(params.valueType); if (alignment == 0) alignment = 1; }
    if (alignment <= 0) alignment = 1;
    std::vector<int> lastDigits = ParseLastDigits(params.lastDigitsInput);

    std::vector<BYTE> chunk(65536);

    for (auto& reg : regions) {
        if (g_Scanner.isScanning == false) break; // cancelled?

        ULONG_PTR cur = reg.base;
        ULONG_PTR end = reg.base + reg.size;

        while (cur < end) {
            if (localResults.size() >= MAX_SCAN_RESULTS) {
                g_Scanner.truncated = true;
                goto finish;
            }
            ULONG_PTR toRead = std::min<ULONG_PTR>(chunk.size(), end - cur);
            ULONG_PTR chunkRead = toRead;
            if (chunkRead > DBK_MAX_IO_SIZE) chunkRead = DBK_MAX_IO_SIZE;
            if (!DbkReadBytes(pid, cur, chunk.data(), (ULONG)chunkRead)) {
                cur += chunkRead;
                continue;
            }

            // Now scan this chunk
            if (params.scanType == CEScanType::UnknownInitial) {
                // Collect all aligned addresses
                int step = params.fastScan ? alignment : GetValueTypeSize(params.valueType);
                if (step == 0) step = 1;
                for (ULONG_PTR off = 0; off + step <= chunkRead; off += step) {
                    ULONG_PTR addr = cur + off;
                    if (!CheckFastScan(addr, params.fastScan, params.fastScanAligned, alignment, lastDigits)) continue;
                    CEFoundResult r;
                    r.address = addr;
                    int vsz = GetValueTypeSize(params.valueType);
                    if (vsz == 0) vsz = 4;
                    r.currentBytes.assign(chunk.data() + off, chunk.data() + off + std::min<int>(vsz, (int)(chunkRead - off)));
                    // Parse int/float for display
                    if (r.currentBytes.size() >= 1) {
                        ULONG64 v = 0;
                        memcpy(&v, r.currentBytes.data(), std::min<size_t>(r.currentBytes.size(), 8));
                        r.currentValueInt = v;
                        if (r.currentBytes.size() >= 4) {
                            float f; memcpy(&f, r.currentBytes.data(), 4); r.currentValueFloat = f;
                        }
                    }
                    localResults.push_back(std::move(r));
                    if (localResults.size() >= 50000) {
                        // flush to global to avoid huge local
                        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
                        g_Scanner.results.insert(g_Scanner.results.end(), localResults.begin(), localResults.end());
                        localResults.clear();
                        if (g_Scanner.results.size() >= MAX_SCAN_RESULTS) { g_Scanner.truncated = true; goto finish; }
                    }
                }
            } else if (isString) {
                // String search
                std::string searchStr = params.valueInput;
                // For case insensitive, we need to lower both
                std::string searchLower = ToLower(searchStr);
                size_t slen = searchBytes.size();
                if (slen == 0) { cur += chunkRead; continue; }
                for (ULONG_PTR off = 0; off + slen <= chunkRead; off++) {
                    ULONG_PTR addr = cur + off;
                    if (!CheckFastScan(addr, params.fastScan, params.fastScanAligned, alignment, lastDigits)) continue;
                    bool match = false;
                    if (params.caseSensitive) {
                        match = memcmp(chunk.data() + off, searchBytes.data(), slen) == 0;
                    } else {
                        // case insensitive for ASCII
                        match = true;
                        for (size_t i = 0; i < slen; i++) {
                            char a = tolower(chunk[off + i]);
                            char b = tolower(searchBytes[i]);
                            if (a != b) { match = false; break; }
                        }
                    }
                    if (match) {
                        CEFoundResult r; r.address = addr; r.currentBytes = searchBytes; r.stringValue = searchStr;
                        localResults.push_back(std::move(r));
                    }
                }
            } else if (isAOB) {
                size_t patLen = searchBytes.size();
                if (patLen == 0) { cur += chunkRead; continue; }
                for (ULONG_PTR off = 0; off + patLen <= chunkRead; off++) {
                    ULONG_PTR addr = cur + off;
                    if (!CheckFastScan(addr, params.fastScan, params.fastScanAligned, alignment, lastDigits)) continue;
                    bool match = true;
                    for (size_t i = 0; i < patLen; i++) {
                        if (searchMask[i] && chunk[off + i] != searchBytes[i]) { match = false; break; }
                    }
                    if (match) {
                        CEFoundResult r; r.address = addr; r.currentBytes.assign(chunk.data() + off, chunk.data() + off + patLen);
                        localResults.push_back(std::move(r));
                    }
                }
            } else if (isGrouped) {
                if (groupedEntries.empty() || groupedBlockSize == 0) { cur += chunkRead; continue; }
                for (ULONG_PTR off = 0; off + groupedBlockSize <= chunkRead; off++) {
                    ULONG_PTR baseAddr = cur + off;
                    if (!CheckFastScan(baseAddr, params.fastScan, params.fastScanAligned, alignment, lastDigits)) continue;
                    bool allMatch = true;
                    for (auto& ge : groupedEntries) {
                        ULONG_PTR checkAddr = baseAddr + ge.offset;
                        size_t checkOff = off + ge.offset;
                        if (checkOff + ge.bytes.size() > chunkRead) { allMatch = false; break; }
                        if (memcmp(chunk.data() + checkOff, ge.bytes.data(), ge.bytes.size()) != 0) { allMatch = false; break; }
                    }
                    if (allMatch) {
                        CEFoundResult r; r.address = baseAddr; r.currentBytes.assign(chunk.data() + off, chunk.data() + off + groupedBlockSize);
                        localResults.push_back(std::move(r));
                    }
                }
            } else {
                // Integer / Float exact / bigger / smaller / between
                int typeSize = GetValueTypeSize(params.valueType);
                if (typeSize == 0) typeSize = 4;
                int step = params.fastScan ? alignment : 1;
                if (step == 0) step = 1;
                // For fast scan aligned, step = alignment, else 1
                // But for exact value, we should still check every alignment
                for (ULONG_PTR off = 0; off + typeSize <= chunkRead; off += step) {
                    ULONG_PTR addr = cur + off;
                    if (!CheckFastScan(addr, params.fastScan, params.fastScanAligned, alignment, lastDigits)) continue;

                    bool match = false;
                    if (params.valueType == CEValueType::Single || params.valueType == CEValueType::Double) {
                        double curVal = 0;
                        if (params.valueType == CEValueType::Single) { float f; memcpy(&f, chunk.data() + off, 4); curVal = f; }
                        else { double d; memcpy(&d, chunk.data() + off, 8); curVal = d; }

                        switch (params.scanType) {
                            case CEScanType::ExactValue: match = CompareFloatValues(curVal, 0, searchFloat, 0, CEScanType::ExactValue); break;
                            case CEScanType::BiggerThan: match = curVal > searchFloat; break;
                            case CEScanType::SmallerThan: match = curVal < searchFloat; break;
                            case CEScanType::ValueBetween: match = curVal >= searchFloat && curVal <= searchFloat2; break;
                            default: match = CompareFloatValues(curVal, 0, searchFloat, 0, CEScanType::ExactValue); break;
                        }
                        if (match) {
                            CEFoundResult r; r.address = addr; r.currentBytes.assign(chunk.data() + off, chunk.data() + off + typeSize); r.currentValueFloat = curVal;
                            localResults.push_back(std::move(r));
                        }
                    } else {
                        ULONG64 curVal = 0;
                        memcpy(&curVal, chunk.data() + off, std::min<int>(typeSize, 8));

                        switch (params.scanType) {
                            case CEScanType::ExactValue: match = (curVal == searchInt); break;
                            case CEScanType::BiggerThan: match = (curVal > searchInt); break;
                            case CEScanType::SmallerThan: match = (curVal < searchInt); break;
                            case CEScanType::ValueBetween: match = (curVal >= searchInt && curVal <= searchInt2); break;
                            default: match = (curVal == searchInt); break;
                        }
                        if (match) {
                            CEFoundResult r; r.address = addr; r.currentBytes.assign(chunk.data() + off, chunk.data() + off + typeSize); r.currentValueInt = curVal;
                            localResults.push_back(std::move(r));
                        }
                    }
                }
            }

            cur += chunkRead;
        }
        progressCounter++;
        g_Scanner.progress = (int)((progressCounter * 100) / totalRegions);
    }
finish:
    // flush remaining
    if (!localResults.empty()) {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        g_Scanner.results.insert(g_Scanner.results.end(), localResults.begin(), localResults.end());
    }
}

// ------------------------------------------------------------------
// Next scan worker - scans previous results
// ------------------------------------------------------------------
static void NextScanWorkerThread(std::vector<CEFoundResult> prevResults, CEScanParams params, ULONG pid, std::vector<CEFoundResult>& localResults, std::atomic<int>& progressCounter, int total) {
    std::vector<BYTE> searchBytes, searchBytes2;
    ULONG64 searchInt = 0, searchInt2 = 0;
    double searchFloat = 0, searchFloat2 = 0;

    bool isFloat = (params.valueType == CEValueType::Single || params.valueType == CEValueType::Double);
    bool isString = (params.valueType == CEValueType::String || params.valueType == CEValueType::UnicodeString);
    bool isAOB = (params.valueType == CEValueType::ByteArray);
    bool isGrouped = (params.valueType == CEValueType::Grouped);

    if (!isString && !isAOB && !isGrouped) {
        MemoryScanner_ParseValue(params.valueType, params.valueInput, params.hex, searchBytes, &searchInt, &searchFloat);
        if (params.scanType == CEScanType::ValueBetween || params.scanType == CEScanType::IncreasedBy || params.scanType == CEScanType::DecreasedBy) {
            MemoryScanner_ParseValue(params.valueType, params.value2Input, params.hex, searchBytes2, &searchInt2, &searchFloat2);
            if (params.scanType == CEScanType::IncreasedBy || params.scanType == CEScanType::DecreasedBy) {
                // searchInt is delta
            }
        }
    } else if (isAOB) {
        std::vector<bool> mask;
        MemoryScanner_ParseAOB(params.valueInput, searchBytes, mask);
    } else if (isString) {
        MemoryScanner_ParseValue(params.valueType, params.valueInput, false, searchBytes);
    }

    std::vector<BYTE> readBuf(32);

    for (size_t i = 0; i < prevResults.size(); i++) {
        if (g_Scanner.isScanning == false) break;
        auto& prev = prevResults[i];
        ULONG_PTR addr = prev.address;

        int typeSize = GetValueTypeSize(params.valueType);
        if (typeSize == 0) {
            if (isString || isAOB) typeSize = (int)searchBytes.size();
            else if (isGrouped) typeSize = 4;
            else typeSize = 4;
        }
        if (typeSize > (int)readBuf.size()) readBuf.resize(typeSize);
        if (!DbkReadBytes(pid, addr, readBuf.data(), typeSize)) continue;

        bool match = false;
        if (isString || isAOB) {
            if (isString) {
                if (params.caseSensitive) match = memcmp(readBuf.data(), searchBytes.data(), searchBytes.size()) == 0;
                else {
                    match = true;
                    for (size_t k = 0; k < searchBytes.size(); k++) {
                        if (tolower(readBuf[k]) != tolower(searchBytes[k])) { match = false; break; }
                    }
                }
            } else {
                // AOB exact for next scan (ignore wildcards? use exact)
                match = memcmp(readBuf.data(), searchBytes.data(), searchBytes.size()) == 0;
            }
        } else if (isFloat) {
            double curVal = 0, prevVal = prev.currentValueFloat;
            if (params.valueType == CEValueType::Single) { float f; memcpy(&f, readBuf.data(), 4); curVal = f; }
            else { double d; memcpy(&d, readBuf.data(), 8); curVal = d; }

            // For next scan, if scanType is Exact etc, use search value, else use prev
            if (params.scanType == CEScanType::ExactValue || params.scanType == CEScanType::BiggerThan || params.scanType == CEScanType::SmallerThan || params.scanType == CEScanType::ValueBetween) {
                match = CompareFloatValues(curVal, prevVal, searchFloat, searchFloat2, params.scanType);
            } else {
                // Increased, Decreased, Changed, Unchanged, IncreasedBy, DecreasedBy
                match = CompareFloatValues(curVal, prevVal, searchFloat, searchFloat2, params.scanType);
            }
            if (match) {
                CEFoundResult r = prev;
                r.previousBytes = r.currentBytes;
                r.previousValueFloat = r.currentValueFloat;
                r.previousValueInt = r.currentValueInt;
                r.currentBytes.assign(readBuf.data(), readBuf.data() + typeSize);
                r.currentValueFloat = curVal;
                r.hasPrevious = true;
                localResults.push_back(std::move(r));
            }
            progressCounter++;
            if (i % 1000 == 0) g_Scanner.progress = (int)((progressCounter * 100) / total);
            continue;
        } else {
            ULONG64 curVal = 0;
            memcpy(&curVal, readBuf.data(), std::min<int>(typeSize, 8));
            ULONG64 prevVal = prev.currentValueInt;

            if (params.scanType == CEScanType::ExactValue || params.scanType == CEScanType::BiggerThan || params.scanType == CEScanType::SmallerThan || params.scanType == CEScanType::ValueBetween) {
                match = CompareIntValues(curVal, prevVal, searchInt, searchInt2, params.scanType);
            } else {
                match = CompareIntValues(curVal, prevVal, searchInt, searchInt2, params.scanType);
            }
        }

        if (match) {
            CEFoundResult r = prev;
            r.previousBytes = r.currentBytes;
            r.previousValueInt = r.currentValueInt;
            r.previousValueFloat = r.currentValueFloat;
            r.currentBytes.assign(readBuf.data(), readBuf.data() + typeSize);
            if (!isString && !isAOB) {
                if (isFloat) {
                    // already handled above? but we are in int path
                } else {
                    ULONG64 curVal = 0; memcpy(&curVal, readBuf.data(), std::min<int>(typeSize, 8));
                    r.currentValueInt = curVal;
                }
            }
            r.hasPrevious = true;
            localResults.push_back(std::move(r));
        }

        progressCounter++;
        if (i % 2000 == 0) g_Scanner.progress = (int)((progressCounter * 100) / total);
    }
}

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------
void MemoryScanner_Init() {
    // Cannot assign whole CEScannerState because it contains mutex/atomic (deleted copy)
    // Manually reset fields
    {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        g_Scanner.results.clear();
        g_Scanner.displayCache.clear();
        g_Scanner.undoStack.clear();
        g_Scanner.previousResultsBackup.clear();
    }
    g_Scanner.params = CEScanParams(); // CEScanParams is trivially copyable
    strcpy_s(g_Scanner.params.valueInput, sizeof(g_Scanner.params.valueInput), "0");
    strcpy_s(g_Scanner.params.value2Input, sizeof(g_Scanner.params.value2Input), "0");
    strcpy_s(g_Scanner.params.alignmentInput, sizeof(g_Scanner.params.alignmentInput), "4");
    strcpy_s(g_Scanner.params.lastDigitsInput, sizeof(g_Scanner.params.lastDigitsInput), "0");
    strcpy_s(g_Scanner.params.startAddrInput, sizeof(g_Scanner.params.startAddrInput), "0x00000000");
    strcpy_s(g_Scanner.params.stopAddrInput, sizeof(g_Scanner.params.stopAddrInput), "0x7FFFFFFFFFFF");
    g_Scanner.params.valueType = CEValueType::DWord;
    g_Scanner.params.scanType = CEScanType::ExactValue;
    g_Scanner.params.fastScan = true;
    g_Scanner.params.fastScanAligned = true;
    g_Scanner.params.writable = TriState::IncludeOnly;
    g_Scanner.params.executable = TriState::DontCare;
    g_Scanner.params.copyOnWrite = TriState::DontCare;
    g_Scanner.params.pauseWhileScanning = false;
    g_Scanner.params.hex = false;
    g_Scanner.params.unicode = false;
    g_Scanner.params.caseSensitive = false;

    g_Scanner.isScanning = false;
    g_Scanner.progress = 0;
    g_Scanner.truncated = false;
    g_Scanner.version = 0;
    g_Scanner.displayVersion = 0xFFFFFFFF;
    g_Scanner.selectedResultIdx = -1;
    g_Scanner.resultFilter[0] = '\0';
    strcpy_s(g_Scanner.foundCountText, sizeof(g_Scanner.foundCountText), "0");
    g_Scanner.scanStart = 0x10000;
    g_Scanner.scanStop = 0x7FFFFFFFFFFFULL;
}

void MemoryScanner_Shutdown() {}

void MemoryScanner_OnPidChanged(ULONG pid, bool is64) {
    // Reset scanner on PID change? Keep results? CE keeps but we reset for safety
    // We will not clear automatically, but update scan range defaults
    if (is64) {
        strcpy_s(g_Scanner.params.startAddrInput, sizeof(g_Scanner.params.startAddrInput), "0x00000000");
        strcpy_s(g_Scanner.params.stopAddrInput, sizeof(g_Scanner.params.stopAddrInput), "0x7FFFFFFFFFFF");
    } else {
        strcpy_s(g_Scanner.params.startAddrInput, sizeof(g_Scanner.params.startAddrInput), "0x00000000");
        strcpy_s(g_Scanner.params.stopAddrInput, sizeof(g_Scanner.params.stopAddrInput), "0x7FFFFFFF");
    }
}

void MemoryScanner_FirstScan() {
    if (g_SelectedPid == 0 || g_Scanner.isScanning) return;
    if (g_hDriver == INVALID_HANDLE_VALUE) return;

    // Backup for undo
    {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        if (!g_Scanner.results.empty()) {
            g_Scanner.undoStack.push_back(g_Scanner.results);
            if (g_Scanner.undoStack.size() > 5) g_Scanner.undoStack.pop_front();
        }
        g_Scanner.results.clear();
    }

    g_Scanner.isScanning = true;
    g_Scanner.progress = 0;
    g_Scanner.truncated = false;

    // Parse start/stop
    ULONG_PTR start = 0x10000, stop = 0x7FFFFFFFFFFFULL;
    try { start = (ULONG_PTR)std::stoull(g_Scanner.params.startAddrInput, nullptr, 0); } catch (...) {}
    try { stop = (ULONG_PTR)std::stoull(g_Scanner.params.stopAddrInput, nullptr, 0); } catch (...) {}

    auto regions = EnumerateScanRegions(g_SelectedPid, start, stop, g_Scanner.params.writable, g_Scanner.params.executable, g_Scanner.params.copyOnWrite);

    bool pause = g_Scanner.params.pauseWhileScanning;
    if (pause) DbkSuspendProcess(g_SelectedPid);

    int threadCount = std::thread::hardware_concurrency();
    if (threadCount <= 0) threadCount = 4;
    if (threadCount > 8) threadCount = 8;

    // Split regions among threads
    auto splitsPtr = std::make_shared<std::vector<std::vector<ScanRegion>>>(threadCount);
    for (size_t i = 0; i < regions.size(); i++) (*splitsPtr)[i % threadCount].push_back(regions[i]);

    auto localResultsPtr = std::make_shared<std::vector<std::vector<CEFoundResult>>>(threadCount);
    auto progressPtr = std::make_shared<std::atomic<int>>(0);
    int totalRegions = (int)regions.size();
    CEScanParams paramsCopy = g_Scanner.params;
    ULONG pidCopy = g_SelectedPid;

    auto workersPtr = std::make_shared<std::vector<std::thread>>();
    workersPtr->reserve(threadCount);
    for (int t = 0; t < threadCount; t++) {
        workersPtr->emplace_back([t, splitsPtr, localResultsPtr, progressPtr, totalRegions, paramsCopy, pidCopy]() {
            FirstScanWorkerThread((*splitsPtr)[t], paramsCopy, pidCopy, (*localResultsPtr)[t], *progressPtr, totalRegions);
        });
    }

    // Monitor thread to wait and finalize
    std::thread([workersPtr, localResultsPtr, pause]() mutable {
        for (auto& th : *workersPtr) if (th.joinable()) th.join();
        // Merge results into global
        {
            std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
            for (auto& lr : *localResultsPtr) {
                g_Scanner.results.insert(g_Scanner.results.end(), lr.begin(), lr.end());
                if (g_Scanner.results.size() >= MAX_SCAN_RESULTS) { g_Scanner.truncated = true; break; }
            }
        }
        if (pause) DbkResumeProcess(g_SelectedPid);
        g_Scanner.progress = 100;
        g_Scanner.isScanning = false;
        g_Scanner.version++;
        sprintf_s(g_Scanner.foundCountText, sizeof(g_Scanner.foundCountText), "%zu", g_Scanner.results.size());
    }).detach();
}

void MemoryScanner_NextScan() {
    if (g_SelectedPid == 0 || g_Scanner.isScanning) return;
    if (g_hDriver == INVALID_HANDLE_VALUE) return;

    std::vector<CEFoundResult> prevCopy;
    {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        if (g_Scanner.results.empty()) return;
        prevCopy = g_Scanner.results;
        g_Scanner.undoStack.push_back(g_Scanner.results);
        if (g_Scanner.undoStack.size() > 5) g_Scanner.undoStack.pop_front();
        g_Scanner.results.clear();
    }

    g_Scanner.isScanning = true;
    g_Scanner.progress = 0;
    g_Scanner.truncated = false;

    bool pause = g_Scanner.params.pauseWhileScanning;
    if (pause) DbkSuspendProcess(g_SelectedPid);

    int threadCount = std::thread::hardware_concurrency();
    if (threadCount <= 0) threadCount = 4;
    if (threadCount > 8) threadCount = 8;

    auto splitsPtr = std::make_shared<std::vector<std::vector<CEFoundResult>>>(threadCount);
    for (size_t i = 0; i < prevCopy.size(); i++) (*splitsPtr)[i % threadCount].push_back(prevCopy[i]);

    auto localResultsPtr = std::make_shared<std::vector<std::vector<CEFoundResult>>>(threadCount);
    auto progressPtr = std::make_shared<std::atomic<int>>(0);
    int total = (int)prevCopy.size();
    CEScanParams paramsCopy = g_Scanner.params;
    ULONG pidCopy = g_SelectedPid;

    auto workersPtr = std::make_shared<std::vector<std::thread>>();
    workersPtr->reserve(threadCount);
    for (int t = 0; t < threadCount; t++) {
        workersPtr->emplace_back([t, splitsPtr, localResultsPtr, progressPtr, total, paramsCopy, pidCopy]() {
            NextScanWorkerThread((*splitsPtr)[t], paramsCopy, pidCopy, (*localResultsPtr)[t], *progressPtr, total);
        });
    }

    std::thread([workersPtr, localResultsPtr, pause]() mutable {
        for (auto& th : *workersPtr) if (th.joinable()) th.join();
        // Merge
        {
            std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
            for (auto& lr : *localResultsPtr) {
                g_Scanner.results.insert(g_Scanner.results.end(), lr.begin(), lr.end());
                if (g_Scanner.results.size() >= MAX_SCAN_RESULTS) { g_Scanner.truncated = true; break; }
            }
        }
        if (pause) DbkResumeProcess(g_SelectedPid);
        g_Scanner.progress = 100;
        g_Scanner.isScanning = false;
        g_Scanner.version++;
        sprintf_s(g_Scanner.foundCountText, sizeof(g_Scanner.foundCountText), "%zu", g_Scanner.results.size());
    }).detach();
}

void MemoryScanner_NewScan() {
    if (g_Scanner.isScanning) return;
    {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        if (!g_Scanner.results.empty()) {
            g_Scanner.undoStack.push_back(g_Scanner.results);
            if (g_Scanner.undoStack.size() > 5) g_Scanner.undoStack.pop_front();
        }
        g_Scanner.results.clear();
        g_Scanner.displayCache.clear();
    }
    g_Scanner.progress = 0;
    g_Scanner.version++;
    strcpy_s(g_Scanner.foundCountText, sizeof(g_Scanner.foundCountText), "0");
}

void MemoryScanner_Undo() {
    if (g_Scanner.isScanning) return;
    std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
    if (g_Scanner.undoStack.empty()) return;
    g_Scanner.results = g_Scanner.undoStack.back();
    g_Scanner.undoStack.pop_back();
    g_Scanner.version++;
    sprintf_s(g_Scanner.foundCountText, "%zu", g_Scanner.results.size());
}

// ------------------------------------------------------------------
// UI Rendering - CE MainForm style clone
// ------------------------------------------------------------------
static const char* TriStateToString(TriState ts) {
    switch (ts) {
        case TriState::DontCare: return "Don't care";
        case TriState::IncludeOnly: return "Include only";
        case TriState::Exclude: return "Exclude";
        default: return "Don't care";
    }
}

void MemoryScanner_Render() {
    if (g_SelectedPid == 0) {
        ImGui::TextDisabled("No process selected. Select a process to scan (kernel mode).");
        return;
    }

    // Top: Found count + Found list (like CE)
    ImGui::Text("Found: %s", g_Scanner.foundCountText);
    ImGui::SameLine();
    ImGui::TextDisabled("(Max %d)", MAX_SCAN_RESULTS);
    if (g_Scanner.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 0.6f, 0, 1), "Truncated!");
    }
    if (g_Scanner.isScanning) {
        ImGui::SameLine();
        ImGui::ProgressBar((float)g_Scanner.progress / 100.0f, ImVec2(200.0f, 0.0f));
        ImGui::SameLine();
        ImGui::TextDisabled("Scanning %d%%", (int)g_Scanner.progress);
    }

    // Split: Left found list, Right controls (CE layout)
    float totalW = ImGui::GetContentRegionAvail().x;
    float leftW = totalW * 0.55f;
    float rightW = totalW * 0.45f - 10.0f;

    ImGui::BeginGroup();
    // Left side
    ImGui::BeginChild("FoundListChild", ImVec2(leftW, 420.0f), true);

    // Filter for results
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputText("Filter", g_Scanner.resultFilter, sizeof(g_Scanner.resultFilter));
    ImGui::SameLine();
    if (ImGui::Button("Add Selected to List")) {
        // Add selected? For now add all filtered? We'll add selected idx if valid
        if (g_Scanner.selectedResultIdx >= 0 && g_Scanner.selectedResultIdx < (int)g_Scanner.results.size()) {
            std::lock_guard<std::mutex> lock(g_CheatTableLock);
            auto& r = g_Scanner.results[g_Scanner.selectedResultIdx];
            int dataType = 4;
            switch (g_Scanner.params.valueType) {
                case CEValueType::Byte: dataType = 3; break;
                case CEValueType::Word: dataType = 2; break;
                case CEValueType::DWord: dataType = 4; break;
                case CEValueType::QWord: dataType = 0; break;
                case CEValueType::Single: dataType = 1; break;
                case CEValueType::Double: dataType = 5; break;
                default: dataType = 4; break;
            }
            ULONG64 val = r.currentValueInt;
            if (g_Scanner.params.valueType == CEValueType::Single || g_Scanner.params.valueType == CEValueType::Double) {
                // val already in currentValueInt? Use float
                // For simplicity use int
            }
            char desc[64]; sprintf_s(desc, "0x%llX", (unsigned long long)r.address);
            g_CheatTable.push_back({r.address, val, false, dataType, g_SelectedPid, ""});
            strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy All to List")) {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        std::lock_guard<std::mutex> lock2(g_CheatTableLock);
        int dataType = 4;
        switch (g_Scanner.params.valueType) {
            case CEValueType::Byte: dataType = 3; break;
            case CEValueType::Word: dataType = 2; break;
            case CEValueType::DWord: dataType = 4; break;
            case CEValueType::QWord: dataType = 0; break;
            case CEValueType::Single: dataType = 1; break;
            case CEValueType::Double: dataType = 5; break;
            default: dataType = 4; break;
        }
        for (auto& r : g_Scanner.results) {
            if (g_Scanner.resultFilter[0] && !ContainsCI(std::to_string(r.address).c_str(), g_Scanner.resultFilter)) {
                // simple filter, check address string
                char addrStr[32]; sprintf_s(addrStr, "%llX", (unsigned long long)r.address);
                if (!ContainsCI(addrStr, g_Scanner.resultFilter)) continue;
            }
            g_CheatTable.push_back({r.address, r.currentValueInt, false, dataType, g_SelectedPid, ""});
            char desc[64]; sprintf_s(desc, "0x%llX", (unsigned long long)r.address);
            strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc);
        }
    }

    // Found list virtual
    // Update display cache if version changed
    if (g_Scanner.displayVersion != g_Scanner.version) {
        std::lock_guard<std::mutex> lock(g_Scanner.resultsLock);
        g_Scanner.displayCache = g_Scanner.results;
        g_Scanner.displayVersion = g_Scanner.version;
    }

    ImGui::BeginChild("FoundListInner", ImVec2(0, 0), false);
    ImGuiListClipper clipper;
    clipper.Begin((int)g_Scanner.displayCache.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
            auto& r = g_Scanner.displayCache[i];
            if (g_Scanner.resultFilter[0]) {
                char addrStr[32]; sprintf_s(addrStr, "%llX", (unsigned long long)r.address);
                if (!ContainsCI(addrStr, g_Scanner.resultFilter)) continue;
            }
            ImGui::PushID(i);
            char label[256];
            // Format value depending on type
            if (g_Scanner.params.valueType == CEValueType::Single) {
                sprintf_s(label, "0x%08llX : %f", (unsigned long long)r.address, r.currentValueFloat);
            } else if (g_Scanner.params.valueType == CEValueType::Double) {
                sprintf_s(label, "0x%08llX : %lf", (unsigned long long)r.address, r.currentValueFloat);
            } else if (g_Scanner.params.valueType == CEValueType::String || g_Scanner.params.valueType == CEValueType::UnicodeString) {
                sprintf_s(label, "0x%08llX : %s", (unsigned long long)r.address, r.stringValue.c_str());
            } else {
                sprintf_s(label, "0x%08llX : %llu (0x%llX)", (unsigned long long)r.address, (unsigned long long)r.currentValueInt, (unsigned long long)r.currentValueInt);
                if (r.hasPrevious) {
                    char prev[64]; sprintf_s(prev, " prev: %llu", (unsigned long long)r.previousValueInt);
                    strcat_s(label, sizeof(label), prev);
                }
            }

            bool sel = (g_Scanner.selectedResultIdx == i);
            if (ImGui::Selectable(label, sel)) g_Scanner.selectedResultIdx = i;

            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Browse this address (Memory View)")) {
                    MemoryView_GoTo(r.address);
                }
                if (ImGui::MenuItem("Add to address list")) {
                    std::lock_guard<std::mutex> lock(g_CheatTableLock);
                    int dataType = 4;
                    switch (g_Scanner.params.valueType) {
                        case CEValueType::Byte: dataType = 3; break;
                        case CEValueType::Word: dataType = 2; break;
                        case CEValueType::DWord: dataType = 4; break;
                        case CEValueType::QWord: dataType = 0; break;
                        case CEValueType::Single: dataType = 1; break;
                        case CEValueType::Double: dataType = 5; break;
                        default: dataType = 4; break;
                    }
                    g_CheatTable.push_back({r.address, r.currentValueInt, false, dataType, g_SelectedPid, ""});
                    char desc[64]; sprintf_s(desc, "0x%llX", (unsigned long long)r.address);
                    strcpy_s(g_CheatTable.back().Description, sizeof(g_CheatTable.back().Description), desc);
                }
                if (ImGui::MenuItem("Copy address")) {
                    char buf[32]; sprintf_s(buf, "0x%llX", (unsigned long long)r.address);
                    ImGui::SetClipboardText(buf);
                }
                if (ImGui::MenuItem("Show in Hex View")) {
                    MemoryView_GoToHex(r.address);
                }
                ImGui::EndPopup();
            }
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                MemoryView_GoTo(r.address);
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::EndGroup();

    ImGui::SameLine();

    // Right side - Scan controls (CE MainForm style)
    ImGui::BeginGroup();
    ImGui::BeginChild("ScanControlsChild", ImVec2(rightW, 420.0f), true);

    // Scan Type
    ImGui::Text("Scan Type:");
    const char* scanTypes[] = { "Exact Value", "Bigger than...", "Smaller than...", "Value between...", "Increased value", "Increased by...", "Decreased value", "Decreased by...", "Changed", "Unchanged", "Unknown initial value" };
    int currentScanType = (int)g_Scanner.params.scanType;
    if (currentScanType > 10) currentScanType = 0;
    ImGui::SetNextItemWidth(rightW - 20.0f);
    if (ImGui::Combo("##scanType", &currentScanType, scanTypes, IM_ARRAYSIZE(scanTypes))) {
        g_Scanner.params.scanType = (CEScanType)currentScanType;
    }

    // Value Type
    ImGui::Text("Value Type:");
    const char* valueTypes[] = { "1 Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "String", "Unicode String", "Array of byte", "All", "Grouped", "Custom" };
    int currentValueType = (int)g_Scanner.params.valueType;
    ImGui::SetNextItemWidth(rightW - 20.0f);
    if (ImGui::Combo("##valueType", &currentValueType, valueTypes, IM_ARRAYSIZE(valueTypes))) {
        g_Scanner.params.valueType = (CEValueType)currentValueType;
        // Update alignment default
        int sz = GetValueTypeSize(g_Scanner.params.valueType);
        if (sz > 0) sprintf_s(g_Scanner.params.alignmentInput, "%d", sz);
    }

    // Value input
    ImGui::Text("Value:");
    ImGui::SetNextItemWidth(rightW - 20.0f);
    ImGui::InputText("##scanValue", g_Scanner.params.valueInput, sizeof(g_Scanner.params.valueInput));

    if (g_Scanner.params.scanType == CEScanType::ValueBetween || g_Scanner.params.scanType == CEScanType::IncreasedBy || g_Scanner.params.scanType == CEScanType::DecreasedBy) {
        ImGui::Text(g_Scanner.params.scanType == CEScanType::ValueBetween ? "and" : "by");
        ImGui::SetNextItemWidth(rightW - 20.0f);
        ImGui::InputText("##scanValue2", g_Scanner.params.value2Input, sizeof(g_Scanner.params.value2Input));
    }

    // Checkboxes: Hex, Unicode, Case sensitive
    ImGui::Checkbox("Hex", &g_Scanner.params.hex);
    if (g_Scanner.params.valueType == CEValueType::String || g_Scanner.params.valueType == CEValueType::UnicodeString) {
        ImGui::SameLine();
        ImGui::Checkbox("Unicode", &g_Scanner.params.unicode);
        ImGui::SameLine();
        ImGui::Checkbox("Case sensitive", &g_Scanner.params.caseSensitive);
    }

    ImGui::Separator();

    // Buttons: New Scan, First Scan, Next Scan, Undo
    bool hasResults = !g_Scanner.results.empty();
    if (ImGui::Button("New Scan", ImVec2((rightW - 30.0f) / 2, 25.0f))) {
        MemoryScanner_NewScan();
    }
    ImGui::SameLine();
    if (ImGui::Button(g_Scanner.isScanning ? "Cancel" : "First Scan", ImVec2((rightW - 30.0f) / 2, 25.0f))) {
        if (g_Scanner.isScanning) {
            g_Scanner.isScanning = false;
        } else {
            MemoryScanner_FirstScan();
        }
    }

    ImGui::BeginDisabled(!hasResults || g_Scanner.isScanning);
    if (ImGui::Button("Next Scan", ImVec2((rightW - 30.0f) / 2, 25.0f))) {
        MemoryScanner_NextScan();
    }
    ImGui::SameLine();
    if (ImGui::Button("Undo Scan", ImVec2((rightW - 30.0f) / 2, 25.0f))) {
        MemoryScanner_Undo();
    }
    ImGui::EndDisabled();

    ImGui::Separator();

    // Memory Scan Options GroupBox (like CE gbScanOptions)
    if (ImGui::CollapsingHeader("Memory Scan Options", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("Start:");
        ImGui::SetNextItemWidth(rightW - 60.0f);
        ImGui::InputText("##startAddr", g_Scanner.params.startAddrInput, sizeof(g_Scanner.params.startAddrInput));
        ImGui::Text("Stop:");
        ImGui::SetNextItemWidth(rightW - 60.0f);
        ImGui::InputText("##stopAddr", g_Scanner.params.stopAddrInput, sizeof(g_Scanner.params.stopAddrInput));

        // Tristate checkboxes: Writable, Executable, CopyOnWrite (CE uses AllowGrayed)
        ImGui::Text("Protection:");
        // Writable
        int wState = (int)g_Scanner.params.writable;
        const char* wLabels[] = { "Writable: Don't care", "Writable: Include only", "Writable: Exclude" };
        ImGui::SetNextItemWidth(rightW - 20.0f);
        if (ImGui::Combo("##writable", &wState, wLabels, 3)) g_Scanner.params.writable = (TriState)wState;

        int xState = (int)g_Scanner.params.executable;
        const char* xLabels[] = { "Executable: Don't care", "Executable: Include only", "Executable: Exclude" };
        ImGui::SetNextItemWidth(rightW - 20.0f);
        if (ImGui::Combo("##executable", &xState, xLabels, 3)) g_Scanner.params.executable = (TriState)xState;

        int cState = (int)g_Scanner.params.copyOnWrite;
        const char* cLabels[] = { "CopyOnWrite: Don't care", "CopyOnWrite: Include only", "CopyOnWrite: Exclude" };
        ImGui::SetNextItemWidth(rightW - 20.0f);
        if (ImGui::Combo("##cow", &cState, cLabels, 3)) g_Scanner.params.copyOnWrite = (TriState)cState;

        ImGui::Separator();

        // Fast Scan
        ImGui::Checkbox("Fast Scan", &g_Scanner.params.fastScan);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(60.0f);
        ImGui::InputText("##align", g_Scanner.params.alignmentInput, sizeof(g_Scanner.params.alignmentInput));
        ImGui::SameLine();
        int fastMode = g_Scanner.params.fastScanAligned ? 0 : 1;
        if (ImGui::RadioButton("Aligned", &fastMode, 0)) g_Scanner.params.fastScanAligned = true;
        ImGui::SameLine();
        if (ImGui::RadioButton("Last Digits", &fastMode, 1)) g_Scanner.params.fastScanAligned = false;
        if (!g_Scanner.params.fastScanAligned) {
            ImGui::SetNextItemWidth(80.0f);
            ImGui::InputText("##lastDigits", g_Scanner.params.lastDigitsInput, sizeof(g_Scanner.params.lastDigitsInput));
            ImGui::SameLine();
            ImGui::TextDisabled("(e.g. 0 4 8 C)");
        }

        ImGui::Checkbox("Pause the game while scanning", &g_Scanner.params.pauseWhileScanning);
    }

    ImGui::EndChild();
    ImGui::EndGroup();
}

#pragma warning(pop)
