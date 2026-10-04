#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>

static const LONG ADDR_THE_CAMERA = 0xB6F028;
static const LONG ADDR_DEFAULT_TARGET = 0xB6EC24;

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static HANDLE g_stopEvent = NULL;
static HANDLE g_worker = NULL;
static HMODULE g_module = NULL;
static volatile LONG g_targetAddr = ADDR_DEFAULT_TARGET;
static volatile LONG g_intervalMs = 10;
static volatile LONG g_enabled = 1;

static bool IEquals(const char* a, const char* b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

static LONG ParseNumber(const char* s)
{
    while (*s == ' ' || *s == '\t') ++s;

    LONG sign = 1;
    if (*s == '-') { sign = -1; ++s; }
    else if (*s == '+') { ++s; }

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        LONG v = 0;
        while (*s) {
            char c = *s;
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            v = v * 16 + d;
            ++s;
        }
        return sign * v;
    }

    LONG v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        ++s;
    }
    return sign * v;
}

static void Log(const char* fmt, ...)
{
    if (g_logFile == INVALID_HANDLE_VALUE)
        return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);

    if (n < 0) n = 0;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;

    DWORD written = 0;
    WriteFile(g_logFile, buf, (DWORD)n, &written, NULL);
}

static void EnsureModule()
{
    if (g_module)
        return;

    HMODULE h = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)(const void*)&EnsureModule, &h)) {
        g_module = h;
    }
}

static void GetPluginDir(char* out, size_t outSize)
{
    out[0] = 0;
    EnsureModule();
    if (!g_module)
        return;

    char path[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(g_module, path, MAX_PATH) == 0)
        return;

    char* slash = strrchr(path, '\\');
    if (slash) slash[1] = 0;
    else path[0] = 0;

    size_t n = strlen(path);
    if (n + 1 >= outSize) return;
    memcpy(out, path, n + 1);
}

static void BuildPath(char* out, size_t outSize, const char* dir, const char* name)
{
    size_t dn = strlen(dir);
    size_t nn = strlen(name);
    if (dn + nn + 2 >= outSize) { out[0] = 0; return; }

    memcpy(out, dir, dn);
    out[dn] = '\\';
    memcpy(out + dn + 1, name, nn + 1);
}

static bool LooksLikeSanAndreas()
{
    char exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0)
        return false;

    const char* base = strrchr(exePath, '\\');
    base = base ? base + 1 : exePath;

    return IEquals(base, "gta-sa.exe") || IEquals(base, "gta_sa.exe");
}

static bool IsAddressUsable(LPCVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || prot == PAGE_GUARD)
        return false;

    if (prot != PAGE_READWRITE && prot != PAGE_WRITECOPY &&
        prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
        return false;

    return true;
}

static void LoadConfig()
{
    char dir[MAX_PATH] = { 0 };
    GetPluginDir(dir, sizeof(dir));
    if (dir[0] == 0)
        return;

    char iniPath[MAX_PATH] = { 0 };
    BuildPath(iniPath, sizeof(iniPath), dir, "NoCamCorrect.ini");
    if (iniPath[0] == 0)
        return;

    FILE* f = fopen(iniPath, "r");
    if (!f) {
        Log("[cfg] no ini found, using defaults addr=0x%08lX interval=%ld\n",
            (unsigned long)g_targetAddr, g_intervalMs);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = 0;
        char* key = line;
        char* val = eq + 1;

        char* end = key + strlen(key);
        while (end > key && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
            *--end = 0;

        if (IEquals(key, "TargetAddress")) {
            g_targetAddr = ParseNumber(val);
            Log("[cfg] TargetAddress = 0x%08lX\n", (unsigned long)g_targetAddr);
        } else if (IEquals(key, "IntervalMs")) {
            g_intervalMs = ParseNumber(val);
            if (g_intervalMs < 1) g_intervalMs = 1;
            if (g_intervalMs > 1000) g_intervalMs = 1000;
            Log("[cfg] IntervalMs = %ld\n", g_intervalMs);
        } else if (IEquals(key, "Enabled")) {
            g_enabled = (ParseNumber(val) != 0) ? 1 : 0;
            Log("[cfg] Enabled = %ld\n", g_enabled);
        }
    }

    fclose(f);
}

static DWORD WINAPI KeeperThread(LPVOID param)
{
    (void)param;

    Log("[keeper] started, target=0x%08lX interval=%ld ms\n",
        (unsigned long)g_targetAddr, g_intervalMs);

    DWORD lastLogged = 0;

    while (WaitForSingleObject(g_stopEvent, g_intervalMs) == WAIT_TIMEOUT) {
        if (!g_enabled)
            continue;

        if (!IsAddressUsable((LPCVOID)g_targetAddr))
            continue;

        DWORD now = GetTickCount();
        InterlockedExchange((LONG volatile*)g_targetAddr, (LONG)now);

        DWORD elapsed = now - lastLogged;
        if (elapsed >= 5000) {
            lastLogged = now;
            DWORD stored = *(volatile DWORD*)g_targetAddr;
            Log("[keeper] now=%lu stored=%lu delta=%lu\n",
                (unsigned long)now, (unsigned long)stored, (unsigned long)(now - stored));
        }
    }

    Log("[keeper] stopped\n");
    return 0;
}

static void OpenLog()
{
    char dir[MAX_PATH] = { 0 };
    GetPluginDir(dir, sizeof(dir));
    if (dir[0] == 0)
        return;

    char logPath[MAX_PATH] = { 0 };
    BuildPath(logPath, sizeof(logPath), dir, "NoCamCorrect.log");
    if (logPath[0] == 0)
        return;

    g_logFile = CreateFileA(logPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void CloseLog()
{
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_DETACH) {
        if (g_stopEvent) SetEvent(g_stopEvent);
        if (g_worker) {
            WaitForSingleObject(g_worker, 2000);
            CloseHandle(g_worker);
            g_worker = NULL;
        }
        if (g_stopEvent) {
            CloseHandle(g_stopEvent);
            g_stopEvent = NULL;
        }
        Log("[exit] unloaded\n");
        CloseLog();
        return TRUE;
    }

    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(module);
    g_module = module;

    OpenLog();
    Log("\n=== NoCamCorrect loaded ===\n");

    char exePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    Log("[init] host: %s\n", exePath);
    Log("[init] ptr size: %u bit\n", (unsigned)(sizeof(void*) * 8));

    if (!LooksLikeSanAndreas()) {
        Log("[init] ABORT: host is not gta-sa.exe\n");
        CloseLog();
        return TRUE;
    }

    LoadConfig();

    if (!IsAddressUsable((LPCVOID)g_targetAddr)) {
        Log("[init] ABORT: target 0x%08lX not writable\n", (unsigned long)g_targetAddr);
        CloseLog();
        return TRUE;
    }

    Log("[init] TheCamera probe 0x%08lX usable=%d\n",
        (unsigned long)ADDR_THE_CAMERA, IsAddressUsable((LPCVOID)ADDR_THE_CAMERA) ? 1 : 0);
    Log("[init] initial target value = %lu\n", (unsigned long)*(volatile DWORD*)g_targetAddr);

    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_stopEvent) {
        Log("[init] ABORT: CreateEvent failed (%lu)\n", GetLastError());
        CloseLog();
        return TRUE;
    }

    g_worker = CreateThread(NULL, 0, KeeperThread, NULL, 0, NULL);
    if (!g_worker) {
        Log("[init] ABORT: CreateThread failed (%lu)\n", GetLastError());
        CloseHandle(g_stopEvent);
        g_stopEvent = NULL;
        CloseLog();
        return TRUE;
    }

    Log("[init] OK\n");
    return TRUE;
}
