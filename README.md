# My Win32 stuff

This repo is a collection of modules and scripts for dealing with Windows stuff, wether it's through the Win32 API using ctypes, or by subprocessing commandline programs that come OOTB on Windows

WANING: Many of the modules and scripts that will be uploaded here will require Admin privileges in order to work

## win32_UEFI.py

A python module that lets you modify the EFI/UEFI firmware boot options. It works by using the Wndows API through ctypes

Source code [here](https://github.com/carlos-a-g-h/win32-stuff/blob/main/win32_UEFI.py)

Example/tests script about boot entries [here](https://github.com/carlos-a-g-h/win32-stuff/blob/main/_win32_UEFI_tests_BootEntry.py) 

Example/tests script about boot order [here](https://github.com/carlos-a-g-h/win32-stuff/blob/main/_win32_UEFI_tests_BootOrder.py)

What works on a lower level?

- You can determine wether the system was booted using UEFI or Legacy

- You can do raw reading and writing of EFI variables

What works on a higher level or for specific EFI/UEFI variables and functionalities?

- You can read the "BootCurrent" EFI variable

- You can read/write the "BootNext" EFI variable

- You can read/write the "BootOrder" EFI variable

- You can read and write a specific boot entry ("Boot####" EFI variable)
