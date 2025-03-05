#include <windows.h>

#include "definition.h"
#include "beacon.h"

void PrintPrivileges(IN TOKEN_PRIVILEGES* pTokenPrivileges)
{
    BeaconPrintf(CALLBACK_OUTPUT,  "|\t    Privilege\t\t|\t\tAttributes\t\t|\n");
    BeaconPrintf(CALLBACK_OUTPUT,  "-------------------------------------------------------------------------\n\n");

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
    {
        LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
        CHAR privilegeName[256];
        DWORD privilegeNameSize = sizeof(privilegeName);

        if (ADVAPI32$LookupPrivilegeNameA(NULL, &laa.Luid, privilegeName, &privilegeNameSize))
        {
            (MSVCRT$strlen(privilegeName) > 28) ? BeaconPrintf(CALLBACK_OUTPUT,  "%s\t\t", privilegeName) : BeaconPrintf(CALLBACK_OUTPUT,  "%s\t\t\t", privilegeName);

            if (laa.Attributes & SE_PRIVILEGE_ENABLED)
            {
                BeaconPrintf(CALLBACK_OUTPUT,  "Enabled ");
            }
            if (laa.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
            {
                BeaconPrintf(CALLBACK_OUTPUT,  "'Enabled by default' ");
            }
            if (laa.Attributes & SE_PRIVILEGE_REMOVED)
            {
                BeaconPrintf(CALLBACK_OUTPUT,  "Removed ");
            }
            if (laa.Attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
            {
                BeaconPrintf(CALLBACK_OUTPUT,  "'Used for access' ");
            }

            BeaconPrintf(CALLBACK_OUTPUT,  "\n");
        }

        else
        {
            BeaconPrintf(CALLBACK_OUTPUT,  "LookupPrivilegeName failed (%d)\n", KERNEL32$GetLastError());
        }
    }
}

BOOL EnumerateTokenPrivs(IN PHANDLE phProcess, OUT PTOKEN_PRIVILEGES* ppTokenPrivs)
{
    BOOL bResult = TRUE;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;

    DWORD dwLength = 0;
    DWORD dwErr = 0;

    if (!ADVAPI32$OpenProcessToken(*phProcess, TOKEN_QUERY, &hToken))
    {
        bResult = FALSE;
        BeaconPrintf(CALLBACK_ERROR, "[-] Error:Opening the token #%d\n\n", KERNEL32$GetLastError());
        goto _EndFunc;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        bResult = FALSE;
        BeaconPrintf(CALLBACK_ERROR, "[-] Error:Somethings went wrong #%d\n\n", KERNEL32$GetLastError());
        goto _EndFunc;
    }

    *ppTokenPrivs = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, *ppTokenPrivs, dwLength, &dwLength))
    {
        bResult = FALSE;
        BeaconPrintf(CALLBACK_ERROR, "[-] Error:Getting token info #%d\n\n", KERNEL32$GetLastError());
        goto _EndFunc;
    }

_EndFunc:

    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
    }

    return bResult;
}

BOOL AdjustTokenPrivs(IN PHANDLE phProcess, IN TOKEN_PRIVILEGES* pTokenPrivileges, IN CHAR* chPrivName, IN BOOL bAdd)
{
    BOOL bResult = TRUE;
    HANDLE hToken = NULL;

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
    {
        LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
        CHAR privilegeName[256];
        DWORD privilegeNameSize = sizeof(privilegeName);

        if (!ADVAPI32$LookupPrivilegeNameA(NULL, &laa.Luid, privilegeName, &privilegeNameSize))
        {
            continue;
        }

        if (MSVCRT$strcmp(chPrivName, privilegeName) == 0)
        {
            pTokenPrivileges->Privileges[i].Attributes = bAdd ? SE_PRIVILEGE_ENABLED : 0;
            break;
        }
        else if (MSVCRT$strcmp("ALL", chPrivName) == 0)
        {
            pTokenPrivileges->Privileges[i].Attributes = bAdd ? SE_PRIVILEGE_ENABLED : 0;
        }
    }

    if (!ADVAPI32$OpenProcessToken(*phProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error:Opening the token\n\n");
        goto _EndFunc;
    }

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, pTokenPrivileges, 0, NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error:Adjusting privs\n\n");
        goto _EndFunc;
    }

_EndFunc:
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
    }

    return bResult;
}

DWORD _getOperation(IN PSTR pCommand)
{
    BOOL bResult = TRUE;

    if (MSVCRT$strcmp(pCommand, "SHOW_PRIVS") == 0)
    {
        return  1;
    }
    else if (MSVCRT$strcmp(pCommand, "ENABLE_PRIV") == 0)
    {
        return 2;
    }
    else if (MSVCRT$strcmp(pCommand, "DISABLE_PRIV") == 0)
    {
        return 3;
    }
    else
    {
        return 0;
    }
}

BOOL ParseParams(IN datap *pParser, IN DWORD argc, IN CHAR* args, PPARAMS pParams)
{
    BOOL bResult = TRUE;
    PSTR sCommand = { 0 };
    PSTR sArg = { 0 };

    BeaconDataParse(pParser, args, argc);

    sCommand = BeaconDataExtract(pParser, NULL);
    sArg = BeaconDataExtract(pParser, NULL);

    if (argc < 2)
    {
        BeaconPrintf(CALLBACK_ERROR, "[i] USAGE: bof <!OPERATION>\nSHOW_PRIVS; ENABLE_PRIV; DISABLE_PRIV\n");
        bResult = FALSE;

        goto _EndFunc;
    }

    pParams->dwOperation = _getOperation(sCommand);

    switch (pParams->dwOperation)
    {
    case 1:

        break;

    case 2:
        if (argc < 3)
        {
            BeaconPrintf(CALLBACK_ERROR, "[i] USAGE: bof ENABLE_PRIV <!PRIVILEGE>\n\n");
            bResult = FALSE;

            goto _EndFunc;
        }

        pParams->chPrivs = sArg;
        break;

    case 3:
        if (argc < 3)
        {
            BeaconPrintf(CALLBACK_ERROR, "[i] USAGE: bof DISABLE_PRIV <!PRIVILEGE>\n\n");
            bResult = FALSE;

            goto _EndFunc;
        }

        pParams->chPrivs = sArg;
        break;

    default:
        bResult = FALSE;
        break;
    }

_EndFunc:
    return bResult;
}

void go(char* args, int argc)
{
    datap Parser = { 0 };
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    PARAMS params = { 0 };
    HANDLE hProcess = NULL;
    DWORD dwPid = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Started.\n");

    if (!ParseParams(&Parser, argc, args, &params))
    {
        goto _EndFunc;
    }

    dwPid = KERNEL32$GetCurrentProcessId();

    if ((hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Opening the process %d - %d\n\n", dwPid, KERNEL32$GetLastError());
        goto _EndFunc;
    }

    if (!EnumerateTokenPrivs(&hProcess, &pTokenPrivs))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: Enumerating privs\n\n");
        goto _EndFunc;
    }

    switch (params.dwOperation)
    {
        case 1:
            PrintPrivileges(pTokenPrivs);

            break;
        case 2:
        
            BeaconPrintf(CALLBACK_OUTPUT, "[i] Enabling %s...\n", params.chPrivs);
            AdjustTokenPrivs(&hProcess, pTokenPrivs, params.chPrivs, TRUE);

            break;
        case 3:

            BeaconPrintf(CALLBACK_OUTPUT, "[i] Disabling %s...\n", params.chPrivs);
            AdjustTokenPrivs(&hProcess, pTokenPrivs, params.chPrivs, FALSE);

            break;
        default:
            goto _EndFunc;
    }

_EndFunc:
    if (pTokenPrivs != NULL)
    {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTokenPrivs);
    }

    if (hProcess != NULL)
    {
        KERNEL32$CloseHandle(hProcess);
    }
}