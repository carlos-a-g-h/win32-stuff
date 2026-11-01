#!/usr/bin/python3

from typing import Callable,Optional
from WUEFI_utils import subproc

import ctypes
from ctypes import wintypes,WinError,get_last_error

###############################################################################

def wsubproc(command:list,verbose:bool,test:bool=False):

	return subproc(
		command,
		verbose=verbose,
		test=test,
		encoding="oem"
	)

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

###############################################################################

# Misc functions

def is_fwtype_uefi(
		fun_GetFirmwareType:Callable,
		assertion:bool=False
	)->bool:

	# Returns wether the system is UEFI booted

	result=get_fwtype(
		fun_GetFirmwareType,
		assertion=assertion
	)

	if assertion:
		if result==0:
			raise Exception("Unknown firmware type")

	return (result==2)

def is_fwtype_legacy(
		fun_GetFirmwareType:Callable,
		assertion:bool=False
	)->bool:

	# Returns wether the system is Legacy booted

	result=get_fwtype(
		fun_GetFirmwareType,
		assertion=assertion
	)

	if assertion:
		if result==0:
			raise Exception("Unknown firmware type")

	return (result==1)
