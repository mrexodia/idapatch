#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include "Utf8Ini.h"
#include "patternfind.h"

#define IDP_INTERFACE_VERSION 76
#define PLUGIN_HIDE 0x10
#define idaapi __stdcall
#define PLUGIN_KEEP 2

class plugin_t
{
public:
    int version;
    int flags;
    int (idaapi* init)(void);
    void (idaapi* term)(void);
    void (idaapi* run)(int arg);
    const char* comment;
    const char* help;
    const char* wanted_name;
    const char* wanted_hotkey;
};

static int idaapi IDAP_init(void)
{
    return PLUGIN_KEEP;
}

static void idaapi IDAP_run(int arg)
{
}

extern "C" __declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_HIDE,
    IDAP_init,
    nullptr,
    IDAP_run,
    nullptr,
    nullptr,
    "idapatch",
    nullptr
};

struct Patch
{
    std::string name;
    std::string module;
    std::vector<PatternByte> search;
    std::vector<PatternByte> replaceTr;
    std::string replace;
};

static void dprintf(const char* format, ...)
{
    static char dprintf_msg[2048];
    va_list args;
    va_start(args, format);
    *dprintf_msg = 0;
    vsnprintf_s(dprintf_msg, sizeof(dprintf_msg), format, args);
#ifdef DEBUG
    static auto hasConsole = false;
    if(!hasConsole)
    {
        hasConsole = true;
        AllocConsole();
    }
    DWORD written = 0;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), dprintf_msg, lstrlenA(dprintf_msg), &written, nullptr);
#else
    OutputDebugStringA(dprintf_msg);
#endif //DEBUG
}

static void dputs(const char* text)
{
    dprintf("%s\n", text);
}

static void idapatch(const wchar_t* patchIni)
{
    dputs("- idapatch started -");

    Utf8Ini ini;
    auto hFile = CreateFileW(patchIni, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        auto fileSize = GetFileSize(hFile, nullptr);
        if(fileSize)
        {
            auto iniData = new char[fileSize + 1];
            iniData[fileSize] = '\0';
            DWORD read;
            if(ReadFile(hFile, iniData, fileSize, &read, nullptr))
            {
                int errorLine;
                if(!ini.Deserialize(iniData, errorLine))
                {
                    dprintf("Deserialize failed (line %d)...\n", errorLine);
                    ini.Clear();
                }
            }
            else
                dputs("ReadFile failed...");
            delete[] iniData;
        }
        else
            dputs("GetFileSize failed...");
        CloseHandle(hFile);
    }
    else
        dputs("CreateFileW failed...");

    std::vector<Patch> patches;
    auto sections = ini.Sections();
    patches.reserve(sections.size());
    for(const auto & section : sections)
    {
        Patch patch;
        patch.name = section;
        auto searchData = ini.GetValue(section, "search");
        patch.replace = ini.GetValue(section, "replace");
        auto enabled = ini.GetValue(section, "enabled");
        patch.module = ini.GetValue(section, "module");
        if(!patch.module.length())
            patch.module = "wll";
        if(enabled == "0")
        {
            dprintf("%s disabled...\n", patch.name.c_str());
            continue;
        }
        if(!patterntransform(searchData, patch.search) || !patterntransform(patch.replace, patch.replaceTr))
        {
            dprintf("Invalid data in %s...\n", section.c_str());
            continue;
        }
        dprintf("%s loaded!\n", patch.name.c_str());
        patches.push_back(patch);
    }

    auto patched = 0;
    for(const auto & patch : patches)
    {
        HMODULE hModule;
        if(patch.module == "wll")
        {
            hModule = GetModuleHandleA("ida.wll");
            if(!hModule)
                hModule = GetModuleHandleA("ida64.wll");
        }
        else if(patch.module == "exe")
        {
            hModule = GetModuleHandleA("idaq.exe");
            if(!hModule)
                hModule = GetModuleHandleA("idaq64.exe");
        }
        else
            hModule = GetModuleHandleA(patch.module.c_str());
        if(!hModule)
        {
            dprintf("Failed to find module %s for patch %s...\n", patch.module.c_str(), patch.name.c_str());
            continue;
        }
        MODULEINFO modinfo;
        if(!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo)))
        {
            dprintf("GetModuleInformation failed for module %s (%p)...\n", patch.module.c_str(), hModule);
            continue;
        }
        auto data = (unsigned char*)modinfo.lpBaseOfDll;
        auto datasize = size_t(modinfo.SizeOfImage);
        auto found = patternfind(data, datasize, patch.search);
        if(found == -1)
        {
            dprintf("Failed to find pattern for %s...\n", patch.name.c_str());
            continue;
        }
        auto buffersize = patch.replaceTr.size();
        auto buffer = new unsigned char[buffersize];
        memcpy(buffer, data + found, buffersize);
        patternwrite(buffer, buffersize, patch.replace.c_str());
        SIZE_T written;
        if(WriteProcessMemory(GetCurrentProcess(), data + found, buffer, buffersize, &written))
            patched++;
        else
            dprintf("WriteProcessMemory failed...");
        delete[] buffer;
    }

    dprintf("%d/%d patches successful!\n", patched, int(patches.size()));

    dputs("- idapatch finished -");
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
    {
        char mutexName[32] = "";
        sprintf_s(mutexName, "idapatch%X", GetCurrentProcessId());
        if(CreateMutexA(nullptr, FALSE, mutexName) && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            wchar_t patchIni[MAX_PATH] = L"";
            if(GetModuleFileNameW(hinstDLL, patchIni, _countof(patchIni)))
            {
                *wcsrchr(patchIni, L'\\') = L'\0';
                wcscat_s(patchIni, L"\\idapatch.ini");
                idapatch(patchIni);
            }

        }
    }
    return TRUE;
}