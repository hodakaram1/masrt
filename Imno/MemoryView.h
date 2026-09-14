#pragma once
#include "Imno.h"
#include <Zydis/Zydis.h>
#include <map>
#include <deque>

// Forward decls
struct DisasmLine {
    ULONG_PTR address = 0;
    uint8_t   bytes[15] = {0};
    uint8_t   length = 0;
    char      bytesStr[48] = {0};
    char      text[256] = {0};          // full disassembly
    char      mnemonic[32] = {0};
    bool      isJump = false;
    bool      isCall = false;
    bool      isRet = false;
    bool      isBranch = false;
    bool      hasBranchTarget = false;
    ULONG_PTR branchTarget = 0;
    bool      isValid = false;
};

struct MemRegionFull {
    ULONG_PTR base = 0;
    ULONG_PTR size = 0;
    ULONG     protect = 0;
    char      protectStr[32] = {0};
    char      stateStr[16] = {0};
    char      typeStr[16] = {0};
    bool      readable = false;
    bool      writable = false;
    bool      executable = false;
};

struct ModuleInfoFull {
    ULONG_PTR base = 0;
    ULONG     size = 0;
    char      name[128] = {0};
    char      path[260] = {0};
};

struct Bookmark {
    ULONG_PTR address = 0;
    char      desc[64] = {0};
};

struct StringRef {
    ULONG_PTR address = 0;
    char      text[128] = {0};
    int       length = 0;
};

struct MemViewState {
    // Navigation
    ULONG_PTR disasmAddr = 0x00400000;
    ULONG_PTR hexAddr = 0x00400000;
    std::deque<ULONG_PTR> backHistory;
    std::deque<ULONG_PTR> forwardHistory;
    char addrInput[128] = "0x00400000";
    char hexAddrInput[128] = "0x00400000";

    // Disasm
    std::vector<DisasmLine> disasmLines;
    int selectedDisasmIdx = -1;
    bool disasmNeedsRefresh = true;
    bool is64BitMode = true;
    int disasmLineCount = 80; // how many lines to show
    bool showBytes = true;
    bool showModuleNames = true;
    bool followJumps = true;

    // Hex
    std::vector<BYTE> hexBuffer;
    ULONG_PTR hexBufferBase = 0;
    size_t hexBufferSize = 0;
    int hexSelectedOffset = -1; // offset in buffer
    char hexEditInput[8] = "";
    bool hexEditActive = false;
    int bytesPerRow = 16;
    char hexAscii[16] = {0};

    // Regions / Modules
    std::vector<MemRegionFull> regions;
    std::vector<ModuleInfoFull> modules;
    bool regionsNeedRefresh = true;
    bool modulesNeedRefresh = true;
    char regionFilter[64] = "";
    char moduleFilter[64] = "";

    // Bookmarks
    std::vector<Bookmark> bookmarks;

    // Strings
    std::vector<StringRef> strings;
    bool stringsNeedScan = true;
    char stringFilter[64] = "";
    int stringMinLen = 5;

    // Tools
    char allocSizeInput[32] = "0x1000";
    ULONG_PTR lastAllocAddr = 0;
    char searchPatternInput[256] = "";
    std::vector<ULONG_PTR> searchResults;
    bool isSearching = false;
    int searchProgress = 0;
    char asmInput[256] = "nop";
    ULONG_PTR asmAddr = 0;
    char asmBytesPreview[64] = "";

    // Assembler popup
    bool showAsmPopup = false;
    // Go to popup
    bool showGotoPopup = false;
    char gotoInput[128] = "";

    // Comments
    std::map<ULONG_PTR, std::string> comments;

    // Zydis
    ZydisDecoder decoder;
    ZydisFormatter formatter;
    bool zydisInitialized = false;
    ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LONG_64;
    ZydisStackWidth stackWidth = ZYDIS_STACK_WIDTH_64;
};

extern MemViewState g_MemView;

// API
void MemoryView_Init();
void MemoryView_Shutdown();
void MemoryView_OnPidChanged(ULONG newPid, bool is64);
void MemoryView_Render(); // call inside ImGui tab
bool MemoryView_ParseAddress(const char* str, ULONG pid, ULONG_PTR* outAddr);
void MemoryView_GoTo(ULONG_PTR addr, bool addToHistory = true);
void MemoryView_GoToHex(ULONG_PTR addr);
void MemoryView_RefreshDisasm();
void MemoryView_RefreshHex();
void MemoryView_RefreshRegions();
void MemoryView_RefreshModules();
void MemoryView_ScanStrings();
void MemoryView_SearchPattern(const char* pattern);
std::string MemoryView_GetModuleNameForAddr(ULONG_PTR addr, ULONG_PTR* outModuleBase = nullptr);
const char* MemoryView_ProtectToString(ULONG protect);
