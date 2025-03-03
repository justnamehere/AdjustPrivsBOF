# AdjustPrivsBOF

## Overview  
AdjustPrivsBOF is a Beacon Object File (BOF) designed to adjust privileges in the access token. This tool is particularly useful for red teamers and penetration testers who need to modify privileges during post-exploitation activities. The BOF can be executed directly within Beacon, allowing for seamless integration into your existing workflow.

## Functions
- Show privileges caller access token;
- Enable disabled privilege (or ALL)
- Disable enabled privilege (or ALL)

## Compile
```bash
x86_64-w64-mingw32-gcc -c main.c -o bof.o
```

## Installation in Sliver
```bash
sliver (TEST) > extensions install <PATH_TO_REPO>

sliver (TEST) > extensions load <PATH_TO_REPO>
```

## Usage
To get help:
```
sliver (TEST) > adjust_privs -h

Usage:
======
  adjust_privs [flags] <COMMAND> [<ARGUMENT>]

Args:
=====
  <COMMAND>   string    A command for execution: SHOW_PRIVS, ENABLE_PRIV, DISABLE_PRIV.
  <ARGUMENT>  string    A privilege for adjustment: e.g. SeShutdownPrivilege; ALL to disable/enable all privs present in token.
```
Show privileges in token:
```
sliver (TEST) > adjust_privs SHOW_PRIVS

[*] Successfully executed adjust_privs (coff-loader)
[*] Got output:
[+] Started.
|           Privilege           |               Attributes              |
-------------------------------------------------------------------------

SeChangeNotifyPrivilege                 Enabled 'Enabled by default' 
SeIncreaseWorkingSetPrivilege            

```
Enable privilege:
```
sliver (TEST) > adjust_privs ENABLE_PRIV SeIncreaseWorkingSetPrivilege

[*] Successfully executed adjust_privs (coff-loader)
[*] Got output:
[+] Started.
[i] Enabling SeIncreaseWorkingSetPrivilege...

```
---