#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static HANDLE g_stopEvent = NULL;
static HANDLE g_worker = NULL;
static volatile LONG g_targetAddr = 0xB6EC24;
static volatile LONG g_intervalMs = 10;
static volatile LONG g_enabled = 1;

static void Log(const char* fmt, ...)
{
    if (g_logFile == INVALID_HANDLE_VALUE)
        return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    if (n > 0) {
        DWORD written = 0;
        WriteFile(g_logFile, buf, (DWORD)n, &written, NULL);
    }
}

static void GetPluginDir(char* out, size_t outSize)
{
    char path[MAX_PATH] = { 0 };
    if (GetModuleFileNameA((HMODULE)&__ImageBase, path, MAX_PATH) == 0) {
        out[0] = 0;
        return;
    }

    char* slash = strrchr(path, '\\');
    if (slash)
        slash[1] = 0;
    else
        path[0] = 0;

    strncpy_s(out, outSize, path, _TRUNCATE);
}

static bool LooksLikeSanAndreas()
{
    char exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0)
        return false;

    const char* base = strrchr(exePath, '\\');
    base = base ? base + 1 : exePath;

    return (_stricmp(base, "gta-sa.exe") == 0) || (_stricmp(base, "gta_sa.exe") == 0);
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
    strncpy_s(iniPath, sizeof(iniPath), dir, _TRUNCATE);
    strcat_s(iniPath, "\\NoCamCorrect.ini");

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

        while (*key == ' ' || *key == '\t') key++;
        char* end = key + strlen(key);
        while (end > key && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
            *--end = 0;

        while (*val == ' ' || *val == '\t') val++;

        if (_stricmp(key, "TargetAddress") == 0) {
            g_targetAddr = (LONG)strtoul(val, NULL, 0);
            Log("[cfg] TargetAddress = 0x%08lX\n", (unsigned long)g_targetAddr);
        } else if (_stricmp(key, "IntervalMs") == 0) {
            g_intervalMs = strtol(val, NULL, 0);
            if (g_intervalMs < 1) g_intervalMs = 1;
            if (g_intervalMs > 1000) g_intervalMs = 1000;
            Log("[cfg] IntervalMs = %ld\n", g_intervalMs);
        } else if (_stricmp(key, "Enabled") == 0) {
            g_enabled = (strtol(val, NULL, 0) != 0) ? 1 : 0;
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
    DWORD missCount = 0;

    while (WaitForSingleObject(g_stopEvent, g_intervalMs) == WAIT_TIMEOUT) {
        if (!g_enabled)
            continue;

        if (!IsAddressUsable((LPCVOID)g_targetAddr)) {
            missCount++;
            if (missCount <= 3)
                Log("[keeper] target not writable (miss %lu)\n", (unsigned long)missCount);
            continue;
        }

        DWORD now = GetTickCount();
        InterlockedExchange((LONG volatile*)g_targetAddr, (LONG)now);

        DWORD elapsed = now - lastLogged;
        if (elapsed >= 5000) {
            lastLogged = now;
            DWORD stored = *(volatile DWORD*)g_targetAddr;
            Log("[keeper] tick now=%lu stored=%lu delta=%lu\n",
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
    strncpy_s(logPath, sizeof(logPath), dir, _TRUNCATE);
    strcat_s(logPath, "\\NoCamCorrect.log");

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
        if (g_stopEvent)
            SetEvent(g_stopEvent);
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
        Log("[init] ABORT: default target 0x%08lX is not writable\n", (unsigned long)g_targetAddr);
        CloseLog();
        return TRUE;
    }

    DWORD stored = *(volatile DWORD*)g_targetAddr;
    Log("[init] initial value at target = %lu\n", (unsigned long)stored);

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
