// ============================================================================
//  Stale-Handle TOCTOU Bypass (خداع اللقطة القديمة)
//  Language : C++17 | Pure Win32 API | MSVC (/utf-8 /DUNICODE /D_UNICODE)
//  Encoding : UTF-8 with BOM
// ============================================================================

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include <atomic>
#include <string>
#include "resource.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")

// ============================================================================
//  [TRICK#1] صلاحيات دنيا (Minimal Access)
//  لا نستخدم PROCESS_ALL_ACCESS مطلقاً لتجنب قواعد الكشف المباشرة على القناع
//  0x1FFFFF، ونكتفي بالحد الأدنى اللازم للقراءة/الكتابة والاستعلام.
// ============================================================================
constexpr DWORD kMinimalAccess =
    PROCESS_VM_READ |
    PROCESS_VM_WRITE |
    PROCESS_VM_OPERATION |
    PROCESS_QUERY_INFORMATION; // TRICK#1

// ============================================================================
//  المتغيرات العامة (Global State)
// ============================================================================
HWND                g_hDlg          = nullptr;
DWORD               g_targetPid     = 0;
HANDLE              g_hProc         = nullptr;       // يُستخدم فقط عند إيقاف وضع الشبح
CRITICAL_SECTION    g_csHandle;                      // حماية g_hProc بين الخيوط
std::atomic<bool>   g_stealth{ true };               // TRICK#6: وضع الشبح مفعل افتراضياً
std::atomic<bool>   g_lost{ false };                 // TRICK#4: علامة فقدان الاتصال
std::atomic<bool>   g_fastDropActive{ false };       // تشغيل/إيقاف خيط Fast Drop
std::atomic<bool>   g_appRunning{ true };
HANDLE              g_hFastDropThread = nullptr;
wchar_t             g_targetName[MAX_PATH] = L"Conquer.exe";

// إعدادات خيط Fast Drop (تُقرأ من الواجهة)
std::atomic<uintptr_t> g_fastDropAddr{ 0x00400000 };
std::atomic<float>     g_fastDropSpeed{ 2.5f };
std::atomic<int>       g_fastDropInterval{ 25 };

// ============================================================================
//  دالة مساعدة لطباعة الرسائل مع الوقت في مربع الـ Log
// ============================================================================
void AppendLog(const wchar_t* fmt, ...)
{
    if (!g_hDlg || !IsWindow(g_hDlg))
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t msgBody[512] = {};
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msgBody, _countof(msgBody), _TRUNCATE, fmt, args);
    va_end(args);

    wchar_t fullLine[640] = {};
    _snwprintf_s(
        fullLine, _countof(fullLine), _TRUNCATE,
        L"[%02u:%02u:%02u.%03u] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msgBody);

    HWND hEdit = GetDlgItem(g_hDlg, IDC_EDIT_LOG);
    if (hEdit && IsWindow(hEdit)) {
        int len = GetWindowTextLengthW(hEdit);
        SendMessageW(hEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)fullLine);
        SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
    }
}

// ============================================================================
//  فحص صلاحية الأداة الحالية: IsElevated عبر TokenElevation
// ============================================================================
bool IsElevated()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elev = {};
    DWORD retLen = 0;
    BOOL ok = GetTokenInformation(
        hToken, TokenElevation, &elev, sizeof(elev), &retLen);
    CloseHandle(hToken);
    return (ok && elev.TokenIsElevated != 0);
}

// ============================================================================
//  فحص مستوى نزاهة العملية الهدف (Integrity Level RID)
//  0x1000 = Low | 0x2000 = Medium | 0x3000 = High (مدير) | 0x4000 = System
// ============================================================================
DWORD GetIntegrityRID(DWORD pid)
{
    if (pid == 0)
        return 0;

    // نفتح العملية بصلاحية استعلام محدودة فقط لقراءة التوكن ثم نغلقها فوراً
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc)
            return 0;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return 0;
    }

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return 0;
    }

    BYTE* buffer = new (std::nothrow) BYTE[needed];
    DWORD rid = 0;
    if (buffer) {
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buffer, needed, &needed)) {
            auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer);
            PUCHAR countPtr = GetSidSubAuthorityCount(pTIL->Label.Sid);
            if (countPtr && *countPtr > 0) {
                PDWORD ridPtr = GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*countPtr - 1));
                if (ridPtr)
                    rid = *ridPtr;
            }
        }
        delete[] buffer;
    }

    CloseHandle(hToken);
    CloseHandle(hProc);
    return rid;
}

// ============================================================================
//  البحث عن معرف العملية الهدف FindTargetPID
// ============================================================================
DWORD FindTargetPID(const wchar_t* processName)
{
    if (!processName || !processName[0])
        return 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD foundPid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                foundPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return foundPid;
}

// ============================================================================
//  [TRICK#4] عند فشل القراءة أو الكتابة:
//  وضع علامة g_lost=true وإرسال رسالة WM_APP_RECONNECT لإعادة الاتصال بعد ثانيتين
// ============================================================================
void MarkLost()
{
    bool expected = false;
    // TRICK#4: نضمن عدم إغراق طابور الرسائل إذا كانت العلامة موضوعة بالفعل
    if (g_lost.compare_exchange_strong(expected, true)) {
        if (g_hDlg && IsWindow(g_hDlg)) {
            PostMessageW(g_hDlg, WM_APP_RECONNECT, 0, 0); // TRICK#4
        }
    }
}

// ============================================================================
//  [TRICK#2] Handle Cycling / Hit & Run (وضع الشبح)
//  افتح Handle بصلاحيات دنيا -> نفذ العملية -> أغلقه فوراً بـ CloseHandle
//  عمر الـ Handle أقل من 1 ميلي ثانية لتفادي لقطات SystemHandleInformation
// ============================================================================
bool CycleRead(uintptr_t addr, void* buf, size_t size)
{
    DWORD pid = g_targetPid;
    if (pid == 0 || !buf || size == 0)
        return false;

    // TRICK#1 + TRICK#2: فتح بالصلاحيات الدنيا فقط ثم إغلاق فوري
    HANDLE h = OpenProcess(kMinimalAccess, FALSE, pid); // TRICK#1, TRICK#2
    if (!h) {
        MarkLost(); // TRICK#4
        return false;
    }

    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(
        h, reinterpret_cast<LPCVOID>(addr), buf, size, &bytesRead);

    CloseHandle(h); // TRICK#2: إغلاق فوري (< 1ms)

    if (!ok || bytesRead != size) {
        MarkLost(); // TRICK#4
        return false;
    }
    return true;
}

bool CycleWrite(uintptr_t addr, const void* buf, size_t size)
{
    DWORD pid = g_targetPid;
    if (pid == 0 || !buf || size == 0)
        return false;

    // TRICK#1 + TRICK#2: فتح بالصلاحيات الدنيا فقط ثم إغلاق فوري
    HANDLE h = OpenProcess(kMinimalAccess, FALSE, pid); // TRICK#1, TRICK#2
    if (!h) {
        MarkLost(); // TRICK#4
        return false;
    }

    SIZE_T bytesWritten = 0;
    BOOL ok = WriteProcessMemory(
        h, reinterpret_cast<LPVOID>(addr), buf, size, &bytesWritten);

    CloseHandle(h); // TRICK#2: إغلاق فوري (< 1ms)

    if (!ok || bytesWritten != size) {
        MarkLost(); // TRICK#4
        return false;
    }
    return true;
}

// ============================================================================
//  RawRead / RawWrite: توجيه القراءة والكتابة حسب حالة g_stealth (TRICK#6)
// ============================================================================
bool RawRead(uintptr_t addr, void* buf, size_t size)
{
    if (g_stealth.load()) { // TRICK#6
        return CycleRead(addr, buf, size); // TRICK#2
    }

    EnterCriticalSection(&g_csHandle);
    if (!g_hProc && g_targetPid != 0) {
        g_hProc = OpenProcess(kMinimalAccess, FALSE, g_targetPid); // TRICK#1
    }
    HANDLE h = g_hProc;
    SIZE_T bytesRead = 0;
    BOOL ok = (h != nullptr) && ReadProcessMemory(
        h, reinterpret_cast<LPCVOID>(addr), buf, size, &bytesRead);
    LeaveCriticalSection(&g_csHandle);

    if (!ok || bytesRead != size) {
        MarkLost(); // TRICK#4
        return false;
    }
    return true;
}

bool RawWrite(uintptr_t addr, const void* buf, size_t size)
{
    if (g_stealth.load()) { // TRICK#6
        return CycleWrite(addr, buf, size); // TRICK#2
    }

    EnterCriticalSection(&g_csHandle);
    if (!g_hProc && g_targetPid != 0) {
        g_hProc = OpenProcess(kMinimalAccess, FALSE, g_targetPid); // TRICK#1
    }
    HANDLE h = g_hProc;
    SIZE_T bytesWritten = 0;
    BOOL ok = (h != nullptr) && WriteProcessMemory(
        h, reinterpret_cast<LPVOID>(addr), buf, size, &bytesWritten);
    LeaveCriticalSection(&g_csHandle);

    if (!ok || bytesWritten != size) {
        MarkLost(); // TRICK#4
        return false;
    }
    return true;
}

// ============================================================================
//  تحديث عناصر الواجهة الخاصة بـ PID وصلاحيات الأداة والعملية الهدف
// ============================================================================
void UpdateStatusUI()
{
    if (!g_hDlg || !IsWindow(g_hDlg))
        return;

    bool elev = IsElevated();
    SetDlgItemTextW(
        g_hDlg, IDC_STATIC_ELEV,
        elev ? L"صلاحية الأداة: مدير (Elevated = نعم)"
             : L"صلاحية الأداة: مستخدم عادي (Elevated = لا)");

    if (g_targetPid != 0) {
        wchar_t pidBuf[64] = {};
        _snwprintf_s(pidBuf, _countof(pidBuf), _TRUNCATE, L"PID: %lu", g_targetPid);
        SetDlgItemTextW(g_hDlg, IDC_STATIC_PID, pidBuf);

        DWORD rid = GetIntegrityRID(g_targetPid);
        const wchar_t* levelDesc = L"غير معروف";
        if (rid >= 0x4000)      levelDesc = L"System";
        else if (rid >= 0x3000) levelDesc = L"High = مدير";
        else if (rid >= 0x2000) levelDesc = L"Medium = عادي";
        else if (rid >= 0x1000) levelDesc = L"Low = منخفض";

        wchar_t integBuf[128] = {};
        _snwprintf_s(
            integBuf, _countof(integBuf), _TRUNCATE,
            L"صلاحية الهدف: 0x%04lX (%s)", rid, levelDesc);
        SetDlgItemTextW(g_hDlg, IDC_STATIC_INTEG, integBuf);
    }
    else {
        SetDlgItemTextW(g_hDlg, IDC_STATIC_PID, L"PID: غير متصل");
        SetDlgItemTextW(g_hDlg, IDC_STATIC_INTEG, L"صلاحية الهدف (Integrity): غير متصل");
    }
}

// ============================================================================
//  [TRICK#3] ReAttach(verbose): تبديل الـ Handle بمدة عشوائية (قتل اللقطة القديمة)
//  1) إغلاق الـ Handle الحالي فوراً.
//  2) انتظار عشوائي Sleep(60 + rand()%120) ميلي ثانية حتى تصبح لقطة الحماية ميتة.
//  3) فتح Handle جديد بالصلاحيات الدنيا (أو تفعيل وضع الشبح Hit & Run).
// ============================================================================
bool ReAttach(bool verbose)
{
    // 1. إغلاق أي Handle مفتوح حالياً لقتل اللقطة المحفوظة لدى الحماية
    EnterCriticalSection(&g_csHandle);
    if (g_hProc) {
        CloseHandle(g_hProc); // TRICK#3
        g_hProc = nullptr;
    }
    LeaveCriticalSection(&g_csHandle);

    // 2. انتظار عشوائي بين 60 و 179 ميلي ثانية (TRICK#3)
    DWORD randomDelay = 60 + (rand() % 120); // TRICK#3
    if (verbose) {
        AppendLog(L"[TRICK#3] تم إغلاق الـ Handle القديم، انتظار عشوائي %lu ms لقتل اللقطة القديمة...", randomDelay);
    }
    Sleep(randomDelay); // TRICK#3

    // 3. إعادة البحث عن PID العملية الهدف
    GetDlgItemTextW(g_hDlg, IDC_EDIT_PROC, g_targetName, _countof(g_targetName));
    g_targetPid = FindTargetPID(g_targetName);
    if (g_targetPid == 0) {
        UpdateStatusUI();
        if (verbose) {
            AppendLog(L"[!] لم يتم العثور على العملية: %s", g_targetName);
        }
        return false;
    }

    // 4. إذا كان وضع الشبح مفعلًا (TRICK#6): نختبر الوصول بفتح/إغلاق لحظي دون الاحتفاظ بـ Handle دائم
    if (g_stealth.load()) { // TRICK#6
        HANDLE hTest = OpenProcess(kMinimalAccess, FALSE, g_targetPid); // TRICK#1, TRICK#2
        if (!hTest) {
            UpdateStatusUI();
            if (verbose) {
                AppendLog(L"[!] فشل الوصول إلى العملية (PID=%lu) برمز خطأ %lu", g_targetPid, GetLastError());
            }
            MarkLost(); // TRICK#4
            return false;
        }
        CloseHandle(hTest); // TRICK#2: إغلاق فوري
        g_lost.store(false);
        UpdateStatusUI();
        if (verbose) {
            AppendLog(
                L"[+] تم الاتصال بنجاح في وضع الشبح (PID=%lu) - لا يوجد Handle دائم مفتوح.",
                g_targetPid);
        }
        return true;
    }

    // 5. إذا كان وضع الشبح متوقفاً: نفتح Handle جديد بالصلاحيات الدنيا فقط (TRICK#1 + TRICK#3)
    EnterCriticalSection(&g_csHandle);
    g_hProc = OpenProcess(kMinimalAccess, FALSE, g_targetPid); // TRICK#1, TRICK#3
    HANDLE hNew = g_hProc;
    LeaveCriticalSection(&g_csHandle);

    if (!hNew) {
        UpdateStatusUI();
        if (verbose) {
            AppendLog(L"[!] فشل فتح Handle جديد (PID=%lu) برمز خطأ %lu", g_targetPid, GetLastError());
        }
        MarkLost(); // TRICK#4
        return false;
    }

    g_lost.store(false);
    UpdateStatusUI();
    if (verbose) {
        AppendLog(
            L"[+] تم تبديل الـ Handle بنجاح (Handle=0x%p, PID=%lu) بالصلاحيات الدنيا (0x%04lX).",
            hNew, g_targetPid, kMinimalAccess);
    }
    return true;
}

// ============================================================================
//  [TRICK#5] خيط العمل الدوري النموذجي (Fast Drop Thread) مع Jitter عشوائي
//  يقرأ قيمة float من العنوان عبر RawRead، يضيف السرعة، ثم يكتبها عبر RawWrite
//  مع نوم عشوائي: Sleep(interval + (rand()%5) - 2) لكسر البصمة الإحصائية.
// ============================================================================
DWORD WINAPI FastDropThreadProc(LPVOID)
{
    srand(static_cast<unsigned int>(GetTickCount64() ^ GetCurrentThreadId()));

    while (g_appRunning.load()) {
        if (g_fastDropActive.load() && g_targetPid != 0 && !g_lost.load()) {
            uintptr_t addr  = g_fastDropAddr.load();
            float     speed = g_fastDropSpeed.load();

            float currentVal = 0.0f;
            if (RawRead(addr, &currentVal, sizeof(currentVal))) {
                currentVal += speed;
                RawWrite(addr, &currentVal, sizeof(currentVal));
            }
        }

        int interval = g_fastDropInterval.load();
        if (interval < 5)
            interval = 5;

        // TRICK#5: إضافة اهتزاز عشوائي (Jitter) لزمن النوم: interval + (rand()%5) - 2
        int jitteredSleep = interval + (rand() % 5) - 2; // TRICK#5
        if (jitteredSleep < 1)
            jitteredSleep = 1;
        Sleep(static_cast<DWORD>(jitteredSleep)); // TRICK#5
    }
    return 0;
}

// ============================================================================
//  قراءة إعدادات Fast Drop من الحقول النصية في الواجهة
// ============================================================================
void SyncFastDropParamsFromUI(HWND hDlg)
{
    wchar_t buf[64] = {};

    GetDlgItemTextW(hDlg, IDC_EDIT_ADDR, buf, _countof(buf));
    uintptr_t parsedAddr = static_cast<uintptr_t>(_wcstoui64(buf, nullptr, 16));
    if (parsedAddr != 0)
        g_fastDropAddr.store(parsedAddr);

    GetDlgItemTextW(hDlg, IDC_EDIT_SPEED, buf, _countof(buf));
    float parsedSpeed = static_cast<float>(_wtof(buf));
    g_fastDropSpeed.store(parsedSpeed);

    GetDlgItemTextW(hDlg, IDC_EDIT_INTERVAL, buf, _countof(buf));
    int parsedInterval = _wtoi(buf);
    if (parsedInterval >= 5)
        g_fastDropInterval.store(parsedInterval);
}

// ============================================================================
//  إجراء نافذة الحوار الرئيسية (DialogProc)
// ============================================================================
INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {
    case WM_INITDIALOG:
    {
        g_hDlg = hDlg;
        SetDlgItemTextW(hDlg, IDC_EDIT_PROC, g_targetName);
        SetDlgItemTextW(hDlg, IDC_EDIT_ADDR, L"00400000");
        SetDlgItemTextW(hDlg, IDC_EDIT_SPEED, L"2.5");
        SetDlgItemTextW(hDlg, IDC_EDIT_INTERVAL, L"25");

        // TRICK#6: تفعيل وضع الشبح افتراضياً على الـ Checkbox
        CheckDlgButton(hDlg, IDC_CHK_STEALTH, g_stealth.load() ? BST_CHECKED : BST_UNCHECKED);

        UpdateStatusUI();
        AppendLog(L"=== تم تشغيل وحدة Stale-Handle TOCTOU Bypass ===");
        AppendLog(L"[TRICK#1] قناع الصلاحيات الدنيا المفعل: 0x%04lX (بدون PROCESS_ALL_ACCESS).", kMinimalAccess);
        AppendLog(L"[TRICK#6] وضع الشبح (Handle Cycling) مفعل افتراضياً (عمر الـ Handle < 1ms).");

        g_hFastDropThread = CreateThread(nullptr, 0, FastDropThreadProc, nullptr, 0, nullptr);
        return TRUE;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam)) {
        case IDC_BTN_CONNECT:
            SyncFastDropParamsFromUI(hDlg);
            GetDlgItemTextW(hDlg, IDC_EDIT_PROC, g_targetName, _countof(g_targetName));
            g_targetPid = FindTargetPID(g_targetName);
            if (g_targetPid == 0) {
                UpdateStatusUI();
                AppendLog(L"[!] العملية (%s) غير موجودة حالياً.", g_targetName);
            }
            else {
                ReAttach(true);
            }
            return TRUE;

        case IDC_BTN_REFRESH:
            // TRICK#3: زر "تحديث" يغلق الـ Handle الحالي، ينتظر 60..179ms، ثم يفتح Handle جديد
            SyncFastDropParamsFromUI(hDlg);
            ReAttach(true); // TRICK#3
            return TRUE;

        case IDC_CHK_STEALTH:
        {
            // TRICK#6: تبديل وضع الشبح من الواجهة
            bool enableStealth = (IsDlgButtonChecked(hDlg, IDC_CHK_STEALTH) == BST_CHECKED);
            g_stealth.store(enableStealth); // TRICK#6

            if (enableStealth) {
                // عند التفعيل: أغلق أي Handle دائم فوراً
                EnterCriticalSection(&g_csHandle);
                if (g_hProc) {
                    CloseHandle(g_hProc); // TRICK#6
                    g_hProc = nullptr;
                }
                LeaveCriticalSection(&g_csHandle);
                AppendLog(L"[TRICK#6] تم تفعيل وضع الشبح: تم إغلاق الـ Handle الدائم، القراءة/الكتابة الآن عبر CycleRead/CycleWrite.");
            }
            else {
                // عند الإلغاء: افتح Handle دائم بالصلاحيات الدنيا
                if (g_targetPid != 0) {
                    EnterCriticalSection(&g_csHandle);
                    if (g_hProc) {
                        CloseHandle(g_hProc);
                    }
                    g_hProc = OpenProcess(kMinimalAccess, FALSE, g_targetPid); // TRICK#1, TRICK#6
                    HANDLE hOpened = g_hProc;
                    LeaveCriticalSection(&g_csHandle);
                    AppendLog(L"[TRICK#6] تم إيقاف وضع الشبح: تم فتح Handle دائم بالصلاحيات الدنيا (0x%p).", hOpened);
                }
                else {
                    AppendLog(L"[TRICK#6] تم إيقاف وضع الشبح (سيتم فتح Handle دائم بالصلاحيات الدنيا عند الاتصال).");
                }
            }
            return TRUE;
        }

        case IDC_CHK_FASTDROP:
        {
            SyncFastDropParamsFromUI(hDlg);
            bool active = (IsDlgButtonChecked(hDlg, IDC_CHK_FASTDROP) == BST_CHECKED);
            g_fastDropActive.store(active);
            AppendLog(
                active ? L"[TRICK#5] تم تشغيل حلقة Fast Drop مع Jitter عشوائي: Sleep(interval + (rand()%%5) - 2)."
                       : L"[TRICK#5] تم إيقاف حلقة Fast Drop.");
            return TRUE;
        }

        case IDC_BTN_CLEARLOG:
            SetDlgItemTextW(hDlg, IDC_EDIT_LOG, L"");
            return TRUE;
        }
        break;
    }

    case WM_APP_RECONNECT:
    {
        // TRICK#4: استجابة لفشل ReadProcessMemory/WriteProcessMemory
        // نضبط مؤقت 2000ms لإعادة الاتصال تلقائياً ونسجل الرسالة المطلوبة بالحرف
        EnterCriticalSection(&g_csHandle);
        if (g_hProc) {
            CloseHandle(g_hProc);
            g_hProc = nullptr;
        }
        LeaveCriticalSection(&g_csHandle);

        AppendLog(L"إعادة المحاولة تلقائياً بعد ثانيتين"); // TRICK#4
        SetTimer(hDlg, IDT_RECONNECT, 2000, nullptr);    // TRICK#4
        return TRUE;
    }

    case WM_TIMER:
    {
        if (wParam == IDT_RECONNECT) {
            KillTimer(hDlg, IDT_RECONNECT); // TRICK#4
            AppendLog(L"[TRICK#4] انتهت مهلة الثانيتين، جاري إعادة فتح الاتصال تلقائياً...");
            if (!ReAttach(true)) {
                // إذا ظلت العملية غير متاحة نعيد جدولة المحاولة بعد ثانيتين
                AppendLog(L"إعادة المحاولة تلقائياً بعد ثانيتين");
                SetTimer(hDlg, IDT_RECONNECT, 2000, nullptr);
            }
            return TRUE;
        }
        break;
    }

    case WM_CLOSE:
        KillTimer(hDlg, IDT_RECONNECT);
        g_fastDropActive.store(false);
        g_appRunning.store(false);
        if (g_hFastDropThread) {
            WaitForSingleObject(g_hFastDropThread, 1000);
            CloseHandle(g_hFastDropThread);
            g_hFastDropThread = nullptr;
        }
        EnterCriticalSection(&g_csHandle);
        if (g_hProc) {
            CloseHandle(g_hProc);
            g_hProc = nullptr;
        }
        LeaveCriticalSection(&g_csHandle);
        EndDialog(hDlg, 0);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
//  نقطة الدخول الرئيسية wWinMain
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int)
{
    srand(static_cast<unsigned int>(GetTickCount64() ^ GetCurrentProcessId()));
    InitializeCriticalSection(&g_csHandle);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAIN_DIALOG), nullptr, MainDialogProc, 0);

    DeleteCriticalSection(&g_csHandle);
    return 0;
}
