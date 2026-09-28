#!/usr/bin/python3

# OK

import ctypes
from ctypes import (
	Array,WinError,
	get_last_error,wintypes,
)

from typing import Callable,Optional

from WUEFI_symbols import (

	_EFI_GLOBALVAR,
	_EFI_VAR_NON_VOLATILE,
	_EFI_VAR_BOOTSERVICE_ACCESS,
	_EFI_VAR_RUNTIME_ACCESS
)

###############################################################################

# Lower level functions

def get_fwtype(
		fun_GetFirmwareType:Callable,
		assertion:bool=True
	)->Optional[int]:

	# Returns the firmware type as an int

	res_dword=wintypes.DWORD()
	if not fun_GetFirmwareType(
			ctypes.byref(res_dword)
		):

		err=get_last_error()
		err_msg="Failed to determine the type of firmware"
		if assertion:
			raise WinError(err,err_msg)

		print(err_msg)
		return None

	return res_dword.value

def read_efi_variable(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		varname:str,
		efiguid:str=_EFI_GLOBALVAR,
		assertion:bool=True
	)->Optional[bytes]:

	# Reads an EFI variable

	size_base=256
	size=size_base

	data:Optional[bytes]=None

	err_msg:Optional[str]=None
	err=-1

	while True:

		buff=ctypes.create_string_buffer(size)
		howmuch=fun_GetFirmwareEnvironmentVariableW(
			varname,
			efiguid,
			buff,
			size
		)
		if howmuch>0:
			data=buff.raw[:howmuch]
			break

		err=get_last_error()

		if err==122:
			size=size+size_base
			continue

		if err==203:
			err_msg=f"EFI var not found: {varname}"
			break

		err_msg=f"Failed to find EFI var: {varname}"
		break

	if err_msg is not None:

		if assertion:
			raise WinError(err,err_msg)

		print(err,err_msg)
		return None

	return data

def write_efi_variable(
		fun_SetFirmwareEnvironmentVariableExW:Callable,
		varname:str,
		varvalue:Optional[bytes],
		efiguid:str=_EFI_GLOBALVAR,
		efiattrs:int=(
			_EFI_VAR_NON_VOLATILE
				| _EFI_VAR_BOOTSERVICE_ACCESS
				| _EFI_VAR_RUNTIME_ACCESS
		),
		assertion:bool=False,
	)->bool:

	# Sets a new value for an EFI variable
	# If the value is None, the variable gets erased

	valbuff:Optional[Array]=None
	valpoint:Optional[Array]=None
	valsize=0

	if varvalue is not None:
		valbuff=ctypes.create_string_buffer(varvalue)
		valpoint=valbuff
		valsize=len(varvalue)

	done=fun_SetFirmwareEnvironmentVariableExW(
		varname,efiguid,
		valpoint,valsize,
		efiattrs
	)

	if not done==1:

		err=get_last_error()
		err_msg=(
			"Failed to set new value"
			" for the selected EFI var"
		)

		if assertion:
			raise WinError(err,err_msg)

		print(err,err_msg)

	return done==1
