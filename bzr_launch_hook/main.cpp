#include <jansson.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <memory>
#include <regex>

using namespace std;

struct LoginDetails
{
    uint32_t serverIp;
    uint16_t serverPort;
    string accountName;
    string accountTicket;
};

static void gather_login_details(LoginDetails& details)
{
    // Grab server ip, port and account name from command line
    // "C:\Turbine\Asheron's Call\acclient.exe" -a MD9NQ8M3NJXJLPDCWY4ANQDNQ -h 74.201.102.237:9000 -rodat off -glsticket
    const char* commandLine = GetCommandLineA();

    regex serverAddrRegex("-h ([\\d\\.]+):(\\d+)");
    regex accountNameRegex("-a ([0-9A-Z]+)");

    match_results<const char*> match;
    regex_search(commandLine, match, serverAddrRegex);

    if(match.empty())
    {
        throw runtime_error("Failed to match against server address");
    }

    string serverIp = match[1].str();
    string serverPort = match[2].str();

    regex_search(commandLine, match, accountNameRegex);

    if(match.empty())
    {
        throw runtime_error("Failed to match against account name");
    }

    string accountName = match[1].str();

    // Grab ticket from registry
    HKEY registryKey;
    if(RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Turbine\\AC1", &registryKey) != ERROR_SUCCESS)
    {
        throw runtime_error("Failed to open registry key");
    }

    DWORD ticketSize = 0;

    if(RegGetValueA(registryKey, NULL, "GLSTicket", RRF_RT_REG_BINARY, NULL, NULL, &ticketSize) != ERROR_SUCCESS)
    {
        RegCloseKey(registryKey);
        throw runtime_error("Failed to get ticket size");
    }

    unique_ptr<uint8_t[]> ticket(new uint8_t[ticketSize]);

    if(RegGetValueA(registryKey, NULL, "GLSTicket", RRF_RT_REG_BINARY, NULL, ticket.get(), &ticketSize) != ERROR_SUCCESS)
    {
        RegCloseKey(registryKey);
        throw runtime_error("Failed to get ticket");
    }

    if(RegDeleteValueA(registryKey, "GLSTicket") != ERROR_SUCCESS)
    {
        RegCloseKey(registryKey);
        throw runtime_error("Failed to delete ticket");
    }

    RegCloseKey(registryKey);

    IN_ADDR convertedServerIp;

    if(InetPtonA(AF_INET, serverIp.c_str(), &convertedServerIp) != 1)
    {
        throw runtime_error("Failed to convert server ip to binary");
    }

    char* end = nullptr;

    long convertedServerPort = strtol(serverPort.c_str(), &end, 10);

    if(end == nullptr)
    {
        throw runtime_error("Failed to convert server port to binary");
    }

    if(convertedServerPort < 0)
    {
        throw runtime_error("Negative port number");
    }

    for(size_t i = 0; i < ticketSize - 1; i++)
    {
        if(!isgraph(ticket[i]))
        {
            throw runtime_error("Non-graph character in ticket");
        }
    }

    if(ticket[ticketSize - 1] != '\0')
    {
        throw runtime_error("No trailing null in ticket");
    }

    details.serverIp = convertedServerIp.S_un.S_addr;
    details.serverPort = static_cast<uint16_t>(convertedServerPort);
    details.accountName = accountName;
    details.accountTicket = reinterpret_cast<char*>(ticket.get());
}

static string build_login_json_path()
{
    PWSTR roamingAppData;

    if(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &roamingAppData) != S_OK)
    {
        throw runtime_error("Failed to get roaming app data folder");
    }

    wchar_t loginJsonPath[MAX_PATH];
    
    PathCombineW(loginJsonPath, roamingAppData, L"boardwalk");
    PathCombineW(loginJsonPath, loginJsonPath, L"Bael'Zharon's Revenge");
    PathCombineW(loginJsonPath, loginJsonPath, L"login.json");

    CoTaskMemFree(roamingAppData);

    char loginJsonPathMBS[MAX_PATH];
    wcstombs_s(nullptr, loginJsonPathMBS, loginJsonPath, _TRUNCATE);

    return loginJsonPathMBS;
}

static void dump_login_details(const LoginDetails& details)
{
    FILE* fp = fopen(build_login_json_path().c_str(), "w");

    if(fp == nullptr)
    {
        throw runtime_error("Failed to open login.json");
    }

    json_t* obj = json_object();
    json_object_set_new(obj, "serverIp", json_integer(details.serverIp));
    json_object_set_new(obj, "serverPort", json_integer(details.serverPort));
    json_object_set_new(obj, "accountName", json_string(details.accountName.c_str()));
    json_object_set_new(obj, "accountTicket", json_string(details.accountTicket.c_str()));
    json_dumpf(obj, fp, JSON_INDENT(2));
    json_decref(obj);

    fclose(fp);
}

int main(int argc, char* argv[])
{
    try
    {
        LoginDetails details;
        gather_login_details(details);
        dump_login_details(details);
    }
    catch(const runtime_error& e)
    {
        fprintf(stderr, "%s\n", e.what());
        getchar();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}