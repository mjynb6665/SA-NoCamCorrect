#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdarg>

// ---------------------------------------------------------------------------
// NoCamCorrect - disables the GTA SA vehicle camera auto-recentre.
//
// How it works (all addresses/offsets verified against gta-sa.exe 1.0):
//
//   TheCamera            = 0xB6F028
//   m_nActiveCam         = TheCamera + 0x59
//   m_aCams              = TheCamera + 0x180   (0xB6F1A8), stride 0x238
//   active CCam          = m_aCams + activeCam * 0x238
//
//   CCam + 0xAC = m_fVerticalAngle
//   CCam + 0xB0 = m_fAlphaSpeed     <- recentre spring velocity (horizontal)
//   CCam + 0xBC = m_fHorizontalAngle
//   CCam + 0xC0 = m_fBetaSpeed      <- recentre spring velocity (vertical)
//
// The game itself zeroes 0xB0 and 0xC0 in the branch that applies mouse look
// (CCam::Process_FollowCar_SA, 0x525719 / 0x52571F). When there is no look
// input they are left to accumulate and drag the angle back behind the car.
// Mouse look is a separate direct "fadd DWORD PTR [esi+0xbc]" so zeroing the
// two speeds stops the auto-recentre without breaking manual look.
// ---------------------------------------------------------------------------

static HANDLE g_logFile     = INVALID_HANDLE_VALUE;
static HMODULE g_module     = NULL;
static HANDLE g_stopEvent   = NULL;
static HANDLE g_worker      = NULL;

static volatile LONG g_enabled   = 1;
static volatile LONG g_mode      = 1;
static volatile LONG g_interval  = 8;

static volatile LONG g_camArray    = 0x00B6F1A8;
static volatile LONG g_activeCam   = 0x00B6F081;
static volatile LONG g_camStride   = 0x238;
static volatile LONG g_offAlphaSpd = 0xB0;
static volatile LONG g_offBetaSpd  = 0xC0;
static volatile LONG g_offHoriz    = 0xBC;
static volatile LONG g_offVert     = 0xAC;

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

static bool IsReadable(LPCVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;

    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || prot == PAGE_GUARD)
        return false;

    return true;
}

static float ReadFloat(LONG addr)
{
    float v = 0.0f;
    memcpy(&v, (const void*)(ULONG_PTR)addr, sizeof(v));
    return v;
}

static void WriteFloat(LONG addr, float v)
{
    memcpy((void*)(ULONG_PTR)addr, &v, sizeof(v));
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
        Log("[cfg] no ini found, using defaults mode=%ld interval=%ld\n", g_mode, g_interval);
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

        LONG n = ParseNumber(val);
        bool matched = true;

        if      (IEquals(key, "Enabled"))        g_enabled = n;
        else if (IEquals(key, "Mode"))           g_mode = n;
        else if (IEquals(key, "IntervalMs"))     { g_interval = n; if (g_interval < 1) g_interval = 1; }
        else if (IEquals(key, "CamArrayAddress"))    g_camArray = n;
        else if (IEquals(key, "ActiveCamAddress"))   g_activeCam = n;
        else if (IEquals(key, "CamStride"))          g_camStride = n;
        else if (IEquals(key, "OffsetAlphaSpeed"))   g_offAlphaSpd = n;
        else if (IEquals(key, "OffsetBetaSpeed"))    g_offBetaSpd = n;
        else if (IEquals(key, "OffsetHorizontal"))   g_offHoriz = n;
        else if (IEquals(key, "OffsetVertical"))     g_offVert = n;
        else matched = false;

        if (matched)
            Log("[cfg] %s = 0x%lX\n", key, (unsigned long)n);
    }

    fclose(f);
}

static LONG ResolveActiveCam()
{
    BYTE idx = *(volatile BYTE*)(ULONG_PTR)g_activeCam;
    if (idx > 2)
        idx = 2;
    return g_camArray + (LONG)idx * g_camStride;
}

static DWORD WINAPI WorkerThread(LPVOID param)
{
    (void)param;

    Log("[work] started mode=%ld interval=%ld ms\n", g_mode, g_interval);
    Log("[work] camArray=0x%08lX activeCam=0x%08lX stride=0x%lX\n",
        (unsigned long)g_camArray, (unsigned long)g_activeCam, (unsigned long)g_camStride);

    int  ticks = 0;
    bool verified = false;

    while (WaitForSingleObject(g_stopEvent, g_interval) == WAIT_TIMEOUT) {
        if (!g_enabled || g_mode == 0)
            continue;

        LONG cam = ResolveActiveCam();

        LONG aH = cam + g_offHoriz;
        LONG aV = cam + g_offVert;
        LONG aA = cam + g_offAlphaSpd;
        LONG aB = cam + g_offBetaSpd;

        if (!IsReadable((LPCVOID)aH) || !IsReadable((LPCVOID)aA))
            continue;

        float beforeH = ReadFloat(aH);
        float beforeV = ReadFloat(aV);

        if (g_mode == 1) {
            WriteFloat(aA, 0.0f);
            WriteFloat(aB, 0.0f);
        }

        ticks++;
        if (ticks % 12 == 0) {
            float afterH = ReadFloat(aH);
            float afterV = ReadFloat(aV);

            if (!verified) {
                Log("[check] cam base resolved = 0x%08lX\n", (unsigned long)cam);
                Log("[check] horizontalAngle = %.5f (expected roughly -3.2 .. 3.2)\n", afterH);
                Log("[check] verticalAngle   = %.5f (expected roughly -1.6 .. 1.6)\n", afterV);
                Log("[check] alphaSpeed      = %.5f\n", ReadFloat(aA));
                Log("[check] betaSpeed       = %.5f\n", ReadFloat(aB));
                verified = true;
            }

            Log("[tick] cam=0x%08lX idx=%d H %.4f -> %.4f (d%.4f)  V %.4f -> %.4f  aspd %.4f bspd %.4f\n",
                (unsigned long)cam,
                (int)*(volatile BYTE*)(ULONG_PTR)g_activeCam,
                beforeH, afterH, afterH - beforeH,
                beforeV, afterV,
                ReadFloat(aA), ReadFloat(aB));
        }
    }

    Log("[work] stopped\n");
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

    if (g_mode == 0) {
        Log("[init] Mode 0: plugin loaded but doing nothing\n");
        Log("[init] OK\n");
        return TRUE;
    }

    g_stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_stopEvent) {
        Log("[init] ABORT: CreateEvent failed (%lu)\n", GetLastError());
        CloseLog();
        return TRUE;
    }

    g_worker = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
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
