#pragma once
#include "Imno.h"
#include <deque>
#include <map>

// CE-style scan types
enum class CEScanType {
    ExactValue = 0,
    BiggerThan,
    SmallerThan,
    ValueBetween,
    IncreasedValue,
    IncreasedBy,
    DecreasedValue,
    DecreasedBy,
    Changed,
    Unchanged,
    UnknownInitial,
    SameAsFirstScan,
    NotSameAsFirst
};

enum class CEValueType {
    Byte = 0,      // 1 byte
    Word,          // 2 bytes
    DWord,         // 4 bytes
    QWord,         // 8 bytes
    Single,        // float 4
    Double,        // double 8
    String,        // ANSI string
    UnicodeString, // Wide string
    ByteArray,     // AOB
    All,           // all types (search as bytes?)
    Grouped,       // grouped scan: e.g. 4:100 4:200
    Custom         // custom type (not implemented, fallback to bytes)
};

enum class TriState {
    DontCare = 0,
    IncludeOnly = 1,
    Exclude = 2
};

struct CEFoundResult {
    ULONG_PTR address = 0;
    std::vector<BYTE> currentBytes; // up to 16 bytes
    std::vector<BYTE> previousBytes; // for next scan compare
    ULONG64 currentValueInt = 0;
    ULONG64 previousValueInt = 0;
    double currentValueFloat = 0;
    double previousValueFloat = 0;
    std::string stringValue;
    bool hasPrevious = false;
};

struct CEScanParams {
    CEValueType valueType = CEValueType::DWord;
    CEScanType scanType = CEScanType::ExactValue;
    char valueInput[256] = "0";
    char value2Input[256] = "0"; // for between
    bool hex = false;
    bool unicode = false;
    bool caseSensitive = false;
    bool fastScan = true;
    char alignmentInput[16] = "4"; // alignment or last digits
    bool fastScanAligned = true; // true = aligned, false = last digits
    char lastDigitsInput[16] = "0";
    TriState writable = TriState::IncludeOnly; // CE default: writable checked
    TriState executable = TriState::DontCare;
    TriState copyOnWrite = TriState::DontCare;
    char startAddrInput[32] = "0x00000000";
    char stopAddrInput[32] = "0x7FFFFFFFFFFF";
    bool pauseWhileScanning = false;
    bool scanWritableOnly = true;
};

struct CEScannerState {
    CEScanParams params;

    std::vector<CEFoundResult> results;
    std::vector<CEFoundResult> previousResultsBackup; // for undo
    std::deque<std::vector<CEFoundResult>> undoStack; // up to 5 undo

    std::mutex resultsLock;
    std::atomic<bool> isScanning{false};
    std::atomic<int> progress{0};
    std::atomic<bool> truncated{false};
    std::atomic<unsigned> version{0};

    ULONG_PTR scanStart = 0x10000;
    ULONG_PTR scanStop = 0x7FFFFFFFFFFFULL;

    char foundCountText[32] = "0";

    // Display cache for virtual list
    std::vector<CEFoundResult> displayCache;
    unsigned displayVersion = 0xFFFFFFFF;

    // Search value parsed
    std::vector<BYTE> searchBytes;
    std::vector<BYTE> searchBytes2;
    std::vector<bool> searchMask; // for AOB wildcards
    std::vector<BYTE> groupedValues; // for grouped scan
    struct GroupedEntry {
        CEValueType type;
        std::vector<BYTE> bytes;
        int offset; // relative offset from previous
    };
    std::vector<GroupedEntry> groupedEntries;
    int groupedBlockSize = 0;

    // UI
    int selectedResultIdx = -1;
    char resultFilter[64] = "";
};

extern CEScannerState g_Scanner;

// API
void MemoryScanner_Init();
void MemoryScanner_Shutdown();
void MemoryScanner_OnPidChanged(ULONG pid, bool is64);
void MemoryScanner_Render(); // full CE-style UI

bool MemoryScanner_ParseValue(CEValueType vt, const char* input, bool hex, std::vector<BYTE>& outBytes, ULONG64* outInt = nullptr, double* outFloat = nullptr);
bool MemoryScanner_ParseAOB(const char* input, std::vector<BYTE>& outBytes, std::vector<bool>& outMask);
bool MemoryScanner_ParseGrouped(const char* input, std::vector<CEScannerState::GroupedEntry>& outEntries, int& outBlockSize);

void MemoryScanner_FirstScan();
void MemoryScanner_NextScan();
void MemoryScanner_NewScan();
void MemoryScanner_Undo();

const char* ScanTypeToString(CEScanType t);
const char* ValueTypeToString(CEValueType t);
