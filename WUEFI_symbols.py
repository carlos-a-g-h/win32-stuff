#!/usr/bin/python3

# Stuff inside Windows

_Win32_GetFwType="GetFirmwareType"
_Win32_GetFwEnVarW="GetFirmwareEnvironmentVariableW"
_Win32_SetFwEnvVarExW="SetFirmwareEnvironmentVariableExW"

# Misc

_ENC_UTF16LE="utf-16-le"
_KERNEL32="kernel32"
_NULLTERM=b"\x00\x00"

_UINT64_MAX=18_446_744_073_709_551_615
_UINT32_MAX=4_294_967_296
_UINT16_MAX=65_536
_UINT8_MAX=256

# Data types

_ERR_UINT64="Outside of UINT64"
_ERR_UINT32="Outside of UINT32"
_ERR_UINT16="Outside of UINT16"
_ERR_UINT8="Outside of UINT8"

# ELO = EFI_LOAD_OPTION

_EFI_GLOBALVAR="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
_EFI_VAR_NON_VOLATILE=0x00000001
_EFI_VAR_BOOTSERVICE_ACCESS=0x00000002
_EFI_VAR_RUNTIME_ACCESS=0x00000004

# EFI_LOAD_OPTION FilePathList Node headers

# NOTE:
# Most headers have a fixed value, the only header with a lengh that depends
# on the content is the one for the Media+FilePath node

_ELO_NODE_ACPI_HID=b"\x02\x01\x0c\x00"
_ELO_NODE_HARDWARE_PCI=b"\x01\x01\x06\x00"
_ELO_NODE_MESSAGING_NVMENAMESPACE=b"\x03\x17\x10\x00"
_ELO_NODE_MEDIA_HARDDRIVE=b"\x04\x01\x2a\x00"
_ELO_NODE_END=b"\x7f\xff\x04\x00"
_ELO_NODE_MEDIA_FILEPATH=b"\x04\x04"

# EFI_LOAD_OPTION Attributes

_ELO_ATTR_ACTIVE=0x00000001
_ELO_ATTR_FORCE_RECONNECT=0x00000002
_ELO_ATTR_OPTION_HIDDEN=0x00000008
_ELO_ATTR_CATEGORY=0x00001f00
_ELO_ATTR_CATEGORY_BOOT=0x00000000
_ELO_ATTR_CATEGORY_APP=0x00000100
