#!/usr/bin/python3

from typing import Callable,Union,Optional

import ctypes
from ctypes import wintypes,WinError,get_last_error

from WUtils import subproc,is_guid
from WUEFI_symbols import _ID_BOOTMGR,_ID_FWBOOTMGR

###############################################################################

# Utilities for Identifiers and GUID/UUIDs

def util_filter_identifier(
		identifier:Optional[str],
		whitelist:Union[list,tuple]=(
			_ID_BOOTMGR,
			_ID_FWBOOTMGR
		),
		return_data:bool=False
	)->Union[bool,Optional[str]]:

	# Filters out a given string to determine wether is a valid identifier for
	# BCDEDIT or not

	if identifier is None:
		if return_data:
			return None
		return False

	if not len(whitelist)==0:
		if identifier in whitelist:
			if return_data:
				return identifier
			return True

	result:Union[bool,Optional[str]]=is_guid(
		identifier,
		return_data=return_data
	)

	if isinstance(result,str):

		# str only

		if len(result)==36:
			return "{"+result+"}"

	# None or bool

	return result

def util_filter_identifier_list(
		id_group:Union[list,tuple],
		whitelist:Union[list,tuple]=(
			_ID_BOOTMGR,
			_ID_FWBOOTMGR
		),
		return_data=False,
		debug:bool=False
	)->Union[bool,list]:

	# Filters out a group of identifiers

	if len(id_group)==0:
		if return_data:
			return []
		return False

	targets=[]
	maxlen=len(id_group)

	for item in id_group:

		tgt=util_filter_identifier(
			item,whitelist=whitelist,
			return_data=True
		)
		if tgt is None:
			if debug:
				print(item,"Is not valid")
			break
		if tgt in targets:
			if debug:
				print(
					item,
					"already exist among the"
					" targets. Max length reduced"
				)
			maxlen=maxlen-1
			continue
		if debug:
			print(
				"Adding the GUID",item,
				"to the targets"
			)
		targets.append(tgt)

	if not len(targets)==maxlen:
		if debug:
			print("One or more given GUIDs are not valid")
		if return_data:
			return []
		return False

	if debug:
		print(
			"Valid identifiers:",
			targets
		)

	if return_data:
		return targets

	return True

def from_text_extract_identifier(text:str)->Optional[str]:

	guid_start=text.find("{")
	if guid_start==-1:
		return None

	guid_end=text[guid_start+1:].find("}")
	if not guid_end==36:
		return None

	return util_filter_identifier(
		text[guid_start+1:guid_start+1+guid_end],
		whitelist=[],
		return_data=True
	)

###############################################################################

# Subprocess specific for Windows (OEM encoding)

def wsubproc(
		command:list,
		verbose:bool,
		test:bool=False
	)->Union[bool,tuple]:

	return subproc(
		command,
		verbose=verbose,
		test=test,
		encoding="oem"
	)

###############################################################################

# Functions related to boot

def set_nt60_bootcode(drive:str,debug:bool=False)->bool:

	# Using BOOTSECT, overwrites the MBR of a given device so that BOOTMGR can
	# load safely

	result=subproc(
		["bootsect","/nt60",drive,"/mbr"],
		verboese=debug,
		encoding="oem"
	)
	if not result[0]==0:
		msg="Failed to overwrite the MBR"
		if debug:
			raise Exception(msg)
		return False

	return True

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
