#include "hook.h"
#include <shellapi.h>
#include <tchar.h>
#include <memory>
#include <regex>

using namespace std;

static void LogError(const TCHAR* str)
{
    MessageBox(NULL, str, _T("bzr_launch_hook"), MB_OK);
}

static BOOL WINAPI ShellExecuteExA_Hook(SHELLEXECUTEINFOA *pExecInfo)
{ LogError(_T("ShellExecuteExA_Hook")); return FALSE; }

static BOOL WINAPI ShellExecuteExW_Hook(SHELLEXECUTEINFOW *pExecInfo)
{ LogError(_T("ShellExecuteExW_Hook")); return FALSE; }

static HINSTANCE WINAPI ShellExecuteA_Hook(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
{ LogError(_T("ShellExecuteA_Hook")); return NULL; }

static HINSTANCE WINAPI ShellExecuteW_Hook(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
{ LogError(_T("ShellExecuteW_Hook")); return NULL; }

static BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                       LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
                                       LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{ LogError(_T("CreateProcessA_Hook")); return FALSE; }

static BOOL WINAPI CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                       LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
                                       LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{ LogError(_T("CreateProcessW_Hook")); return FALSE; }

static BOOL foo()
{
    // Grab server ip, port and account name from command line
    // "C:\Turbine\Asheron's Call\acclient.exe" -a MD9NQ8M3NJXJLPDCWY4ANQDNQ -h 74.201.102.237:9000 -rodat off -glsticket
    const TCHAR* commandLine = GetCommandLine();

    basic_regex<TCHAR> serverAddrRegex(_T("-h ([\\d\\.]+):(\\d+)"));
    basic_regex<TCHAR> accountNameRegex(_T("-a ([0-9A-Z]+)"));

    match_results<const TCHAR*> match;
    regex_search(commandLine, match, serverAddrRegex);

    if(match.empty())
    {
        LogError(_T("Failed to match against server address"));
        return FALSE;
    }

    basic_string<TCHAR> serverIp = match[1].str();
    basic_string<TCHAR> serverPort = match[2].str();

    regex_search(commandLine, match, accountNameRegex);

    if(match.empty())
    {
        LogError(_T("Failed to match against account name"));
        return FALSE;
    }

    basic_string<TCHAR> accountName = match[1].str();

    LogError(_T("ZOOP!\n"));

    // Grab ticket from registry
    HKEY registryKey;
    if(RegOpenKey(HKEY_CURRENT_USER, _T("Software\\Turbine\\AC1"), &registryKey) != ERROR_SUCCESS)
    {
        LogError(_T("Failed to open registry key"));
        return FALSE;
    }

    DWORD ticketSize = 0;

    if(RegGetValue(registryKey, NULL, _T("GLSTicket"), RRF_RT_REG_BINARY, NULL, NULL, &ticketSize) != ERROR_SUCCESS)
    {
        LogError(_T("Failed to get ticket size"));
        return FALSE;
    }

    unique_ptr<uint8_t[]> ticket(new uint8_t[ticketSize]);

    if(RegGetValue(registryKey, NULL, _T("GLSTicket"), RRF_RT_REG_BINARY, NULL, ticket.get(), &ticketSize) != ERROR_SUCCESS)
    {
        LogError(_T("Failed to get ticket"));
        return FALSE;
    }

    if(RegDeleteValue(registryKey, _T("GLSTicket")) != ERROR_SUCCESS)
    {
        LogError(_T("Failed to delete ticket"));
        return FALSE;
    }

    RegCloseKey(registryKey);
    return TRUE;
}

static cHookDescriptor g_hooks[] =
{
    { eByName, "shell32.dll", "ShellExecuteA", 0, (DWORD)ShellExecuteA_Hook, 0 },
    //{ eByOrdinal, "shell32.dll", NULL, 433, (DWORD)ShellExecuteA_Hook, 0 },

    //{ eByName, "shell32.dll", "ShellExecuteW", 0, (DWORD)ShellExecuteW_Hook, 0 },
    //{ eByOrdinal, "shell32.dll", NULL, 437, (DWORD)ShellExecuteW_Hook, 0 },

    //{ eByName, "shell32.dll", "ShellExecuteExA", 0, (DWORD)ShellExecuteExA_Hook, 0 },
    //{ eByOrdinal, "shell32.dll", NULL, 435, (DWORD)ShellExecuteExA_Hook, 0 },

    //{ eByName, "shell32.dll", "ShellExecuteExW", 0, (DWORD)ShellExecuteExW_Hook, 0 },
    //{ eByOrdinal, "shell32.dll", NULL, 436, (DWORD)ShellExecuteExW_Hook, 0 },

    //{ eByName, "kernel32.dll", "CreateProcessA", 0, (DWORD)CreateProcessA_Hook, 0 },
    //{ eByOrdinal, "kernel32.dll", NULL, 167, (DWORD)CreateProcessA_Hook, 0 },

    //{ eByName, "kernel32.dll", "CreateProcessW", 0, (DWORD)CreateProcessW_Hook, 0 },
    //{ eByOrdinal, "kernel32.dll", NULL, 171, (DWORD)CreateProcessW_Hook, 0 },
};

static bool tcsendswithi(const TCHAR* s, const TCHAR* p)
{
    size_t slen = _tcslen(s);
    size_t plen = _tcslen(p);

    if(slen < plen)
    {
        return false;
    }

    for(size_t pi = 0; pi < plen; pi++)
    {
        size_t si = slen - plen + pi;

        if(_totlower(s[si]) != p[pi])
        {
            return false;
        }
    }

    return true;
}

extern "C"
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
    {
        TCHAR path[MAX_PATH];
        GetModuleFileName(NULL, path, sizeof(path)/sizeof(TCHAR));

        if(tcsendswithi(path, _T("\\bzr_launch_daemon.exe")))
        {
            return TRUE;
        }

        if(!tcsendswithi(path, _T("\\aclauncher.exe")))
        {
            return FALSE;
        }

        LogError(_T("Hooking!"));

        const size_t hookCount = sizeof(g_hooks)/sizeof(g_hooks[0]);

        if(hookFunctions(g_hooks, hookCount) != hookCount)
        {
            LogError(_T("Failed to hook all functions"));
            // We could have hooked something, so we can't unload at this point
        }
    }

    return TRUE;
}

extern "C" __declspec(dllexport)
void CALLBACK WinEventProc(
    HWINEVENTHOOK hWinEventHook,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwmsEventTime)
{}
