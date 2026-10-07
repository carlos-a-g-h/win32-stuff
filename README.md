# My Win32 stuff

This repo is a collection of modules and scripts for dealing with Windows stuff, wether it's through the Win32 API using ctypes, or by subprocessing commandline programs that come by default on Windows

WARNING: Many of the modules and scripts here will require Admin privileges in order to work or privileges higher than that

## WPrivilege

A small python module with high level functions that can be used for managing the rights and privileges of a currently running process. It works by using pywin32

Source code [here](https://github.com/carlos-a-g-h/win32-stuff/blob/main/WPrivilege.py)

### What can you do with this?

- You can find out within a currently running process wether the process is elevated, the elevation type and wether it is running as Administrator or not

- You can gain access to higher privilege beyond Administrator (read the source code for more details)

## WUEFI

Lets you modify the EFI/UEFI firmware boot options. It works by using the Windows API through ctypes and Windows's BCDEDIT commandline utility as a subprocess

### What works on a lower level?

- You can determine wether the system is EFI/UEFI booted or Legacy booted

- You can do raw reading and writing of EFI variables

### What works on a higher level or for specific EFI/UEFI variables?

- You can read the "BootCurrent" EFI variable

- You can read/write the "BootNext" EFI variable

- You can read/write the "BootOrder" EFI variable

- You can read and write a specific boot entry ("Boot####" EFI variable)

### Relevant files

[WUEFI.py](https://github.com/carlos-a-g-h/win32-stuff/blob/main/WUEFI.py) is the main module with ready-to-use top level functions

[WUEFI_evars.py](https://github.com/carlos-a-g-h/win32-stuff/blob/main/WUEFI_evars.py), is the module that holds all of the functionality specific to EFI variables. It can be used as a command line utility for quick querying and (very) minimal editing of EFI variables by their BootNNNN naming scheme

[WUEFI_bcdedit.py](https://github.com/carlos-a-g-h/win32-stuff/blob/main/WUEFI_bcdedit.py) has functions that run BCDEDIT commands that are specific for firmware boot entries
