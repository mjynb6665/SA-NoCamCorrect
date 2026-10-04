#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>

// WellBufferMe(float target, float& valueToChange, float& speedSoFar,
//              float topSpeed, float speedStep, bool isAnAngle)
// This is the spring/convergence helper that pulls the camera angle back toward
// the vehicle heading. Mouse look is applied by direct "+=" on the angle fields
// and does NOT go through here, so neutralising this function removes the
// auto-recentre while leaving manual look intact.
static const LONG ADDR_WELL_BUFFER_ME = 0x00509AE0;

static const BYTE PATCH_SIZE = 5;

static HANDLE  g_logFile   = INVALID_HANDLE_VALUE;
static HMODULE g_module    = NULL;
static HANDLE  g_stopEvent = NULL;
static HANDLE  g_retryThread = NULL;

static BYTE  g_origBytes[PATCH_SIZE];
static void* g_stub       = NULL;
static volatile LONG g_patched = 0;
static volatile LONG g_stubIsStdcall = 0;
static volatile LONG g_enabled = 1;
static volatile LONG g_mode = 0;

// cdecl: caller cleans the stack, so a bare ret is correct.
__declspec(naked) static void StubCdecl()
{
    __asm { ret }
}

// stdcall: callee pops the 6 arguments (4 + 4 + 4 + 4 + 4 + 4 = 24 bytes).
__declspec(naked) static void StubStdcall()
{
    __asm { ret 24 }
}

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

static void TrimTrailing(char* s)
{
    char* end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = 0;
}

static void TrimLeading(const char** s)
{
    while (**s == ' ' || **s == '\t') ++(*s);
}

static LONG ParseNumber(const char* s)
{
    TrimLeading(&s);

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
    buf[n] = 0;

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

static bool IsAddressReadable(LPCVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;

    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || prot == PAGE_GUARD)
        return false;

    return prot != 0;
}

static bool WriteBytes(void* addr, const BYTE* data, size_t n)
{
    DWORD oldProtect = 0;
    if (!VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    volatile BYTE* p = (volatile BYTE*)addr;
    for (size_t i = 0; i < n; ++i)
        p[i] = data[i];

    FlushInstructionCache(GetCurrentProcess(), addr, n);

    DWORD ignored;
    VirtualProtect(addr, n, oldProtect, &ignored);
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
        Log("[cfg] no ini found, using defaults mode=%ld stub=cdecl\n", g_mode);
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
        TrimTrailing(key);

        const char* v = val;
        TrimLeading(&v);

        if (IEquals(key, "Enabled")) {
            g_enabled = (ParseNumber(v) != 0) ? 1 : 0;
            Log("[cfg] Enabled = %ld\n", g_enabled);
        } else if (IEquals(key, "Mode")) {
            g_mode = ParseNumber(v);
            Log("[cfg] Mode = %ld\n", g_mode);
        } else if (IEquals(key, "Stub")) {
            char buf[64];
            size_t n = strlen(v);
            if (n >= sizeof(buf)) n = sizeof(buf) - 1;
            memcpy(buf, v, n);
            buf[n] = 0;
            TrimTrailing(buf);
            g_stubIsStdcall = IEquals(buf, "stdcall") ? 1 : 0;
            Log("[cfg] Stub = %s\n", buf);
        }
    }

    fclose(f);
}

static bool LooksLikePrologue(BYTE b)
{
    // Common x86 function entry opcodes: push ebp/ebx/esi/edi, sub esp, mov,
    // push imm8, push imm32, xor, lea.
    switch (b) {
        case 0x55: case 0x53: case 0x56: case 0x57:
        case 0x51: case 0x52:
        case 0x83: case 0x8B: case 0x89: case 0x6A:
        case 0x68: case 0x33: case 0x8D: case 0x81:
            return true;
        default:
            return false;
    }
}

static bool ApplyPatch()
{
    if (!g_enabled)
        return false;
    if (g_mode != 0) {
        Log("[patch] Mode %ld is not implemented yet; falling back to Mode 0\n", g_mode);
        g_mode = 0;
    }

    g_stub = g_stubIsStdcall ? (void*)&StubStdcall : (void*)&StubCdecl;

    BYTE* target = (BYTE*)(ULONG_PTR)ADDR_WELL_BUFFER_ME;

    if (!IsAddressReadable(target)) {
        Log("[patch] 0x%08lX not readable yet\n", (unsigned long)ADDR_WELL_BUFFER_ME);
        return false;
    }

    if (target[0] == 0xE9) {
        Log("[patch] already patched (found JMP), skipping\n");
        g_patched = 1;
        return true;
    }

    memcpy(g_origBytes, target, PATCH_SIZE);
    Log("[patch] original bytes: %02X %02X %02X %02X %02X\n",
        g_origBytes[0], g_origBytes[1], g_origBytes[2], g_origBytes[3], g_origBytes[4]);

    if (!LooksLikePrologue(g_origBytes[0]))
        Log("[patch] WARNING: first byte %02X does not look like a normal prologue.\n"
            "        This may mean the address or the game version is wrong.\n",
            g_origBytes[0]);

    BYTE patch[PATCH_SIZE];
    patch[0] = 0xE9;
    DWORD rel = (DWORD)((ULONG_PTR)g_stub - ((ULONG_PTR)ADDR_WELL_BUFFER_ME + PATCH_SIZE));
    memcpy(patch + 1, &rel, sizeof(rel));

    if (!WriteBytes(target, patch, PATCH_SIZE)) {
        Log("[patch] WriteBytes failed (%lu)\n", GetLastError());
        return false;
    }

    if (memcmp(target, patch, PATCH_SIZE) != 0) {
        Log("[patch] verification failed, rolling back\n");
        WriteBytes(target, g_origBytes, PATCH_SIZE);
        return false;
    }

    g_patched = 1;
    Log("[patch] OK: WellBufferMe (0x%08lX) -> stub %p (%s)\n",
        (unsigned long)ADDR_WELL_BUFFER_ME, g_stub,
        g_stubIsStdcall ? "stdcall, ret 24" : "cdecl, ret");
    return true;
}

static void RemovePatch()
{
    if (!g_patched)
        return;

    if (WriteBytes((void*)(ULONG_PTR)ADDR_WELL_BUFFER_ME, g_origBytes, PATCH_SIZE))
        Log("[patch] original bytes restored\n");
    else
        Log("[patch] WARNING: could not restore original bytes\n");

    g_patched = 0;
}

static DWORD WINAPI RetryThread(LPVOID param)
{
    (void)param;

    Log("[retry] watching for game code at 0x%08lX\n", (unsigned long)ADDR_WELL_BUFFER_ME);

    for (int i = 0; i < 300 && !g_patched; ++i) {
        if (WaitForSingleObject(g_stopEvent, 100) != WAIT_TIMEOUT)
            break;
        ApplyPatch();
    }

    if (!g_patched)
        Log("[retry] gave up after 30s, camera spring left active\n");

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
        if (g_retryThread) {
            WaitForSingleObject(g_retryThread, 3000);
            CloseHandle(g_retryThread);
            g_retryThread = NULL;
        }
        if (g_stopEvent) {
            CloseHandle(g_stopEvent);
            g_stopEvent = NULL;
        }
        RemovePatch();
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

    if (g_patched || ApplyPatch()) {
        Log("[init] OK\n");
        return TRUE;
    }

    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_stopEvent) {
        Log("[init] ABORT: CreateEvent failed (%lu)\n", GetLastError());
        CloseLog();
        return TRUE;
    }

    g_retryThread = CreateThread(NULL, 0, RetryThread, NULL, 0, NULL);
    if (!g_retryThread) {
        Log("[init] ABORT: CreateThread failed (%lu)\n", GetLastError());
        CloseHandle(g_stopEvent);
        g_stopEvent = NULL;
        CloseLog();
        return TRUE;
    }

    Log("[init] deferred to retry thread\n");
    return TRUE;
}
