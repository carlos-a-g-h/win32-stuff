# My Win32 stuff

This repo is a collection of modules and scripts for dealing with Windows stuff, wether it's through Win32 API, ctypes, or by subprocessing stuff

## win32_UEFI.py

Source file [here](https://github.com/carlos-a-g-h/win32-stuff/blob/main/win32_UEFI.py)

A python module that lets you modify the EFI/UEFI firmware boot options. It works using ctypes

What works on a lower level?

- You can determine wether the system was booted using UEFI or Legacy
- You can do raw reading and writing of EFI variables

What works on a higher level or for specific EFI/UEFI variables and functionalities?

- You can read the "BootCurrent" EFI variable
- You can read and write the "BootNext" EFI variable
- You can list all the firmware boot entries ("BootOrder" variable)
- You can read Boot entres ("Boot####" variables). At the moment I am focusing on type 4 subtype 4

What is still not finished?

- Creating custom boot entries for custom EFI applications and bootloaders
