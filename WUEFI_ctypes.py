#!/usr/bin/python3

import ctypes

from ctypes import (
	# Array,
	WinDLL,
	# WinError,
	# get_last_error,
	wintypes
)

from typing import Callable

from WUEFI_symbols import (
	_KERNEL32,
	_Win32_GetFwEnVarW,
	_Win32_GetFwType,
	_Win32_SetFwEnvVarExW,

	# _EFI_GLOBALVAR,
	# _EFI_VAR_NON_VOLATILE,
	# _EFI_VAR_BOOTSERVICE_ACCESS,
	# _EFI_VAR_RUNTIME_ACCESS
)

###############################################################################

# Import stuff using ctypes

def import_GetFwType()->Callable:

	k32:WinDLL=WinDLL(
		_KERNEL32,
		use_last_error=True
	)

	fun:Callable=getattr(
		k32,
		_Win32_GetFwType
	)
	fun.argtypes=[ctypes.POINTER(wintypes.DWORD)]
	fun.restype=wintypes.BOOL

	return fun

def import_GetFwEnVarW()->Callable:

	k32:WinDLL=WinDLL(
		_KERNEL32,
		use_last_error=True
	)

	fun:Callable=getattr(
		k32,_Win32_GetFwEnVarW
	)

	fun.argtypes=[
		# lpName
			wintypes.LPCWSTR,
		# lpGuid
			wintypes.LPCWSTR,
		# pBuffer
			ctypes.c_void_p,
		# nSize
			wintypes.DWORD
	]

	return fun

def import_SetFwEnvVarExW()->Callable:

	k32:WinDLL=WinDLL(
		_KERNEL32,
		use_last_error=True
	)

	fun:Callable=getattr(
		k32,_Win32_SetFwEnvVarExW
	)

	fun.argtypes=[
		# lpName
			wintypes.LPCWSTR,
		# lpGuid
			wintypes.LPCWSTR,
		# pValue
			ctypes.c_void_p,
		# nSize
			wintypes.DWORD,
		# dwAttributes
			wintypes.DWORD
	]

	return fun
