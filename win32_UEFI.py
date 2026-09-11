#!/usr/bin/python3

# NOTE:
# THIS IS A WORK IN PROGRESS

# WARNING:
# IF YOU BRICK YOUR FIRMWARE, OR SOMEONE ELSE'S FIRMWARE THAT'S ON YOU, NOT ME

import ctypes
from ctypes import (
	Array,
	WinDLL,
	WinError,
	get_last_error,
	wintypes,
)

import struct
from typing import (
	Callable,
	Optional
)
import win32api
import win32con
import win32security

_k32="kernel32"

_EFI_GLOBALVAR="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
_EFI_VAR_NON_VOLATILE=0x00000001
_EFI_VAR_BOOTSERVICE_ACCESS=0x00000002
_EFI_VAR_RUNTIME_ACCESS=0x00000004

###############################################################################

# Extract "things" from the depths of Windows using ctypes

_Win32_GetFwType="GetFirmwareType"
_Win32_GetFwEnVarW="GetFirmwareEnvironmentVariableW"
_Win32_SetFwEnvVarExW="SetFirmwareEnvironmentVariableExW"

def import_GetFwType()->Callable:

	kernel32:WinDLL=WinDLL(
		_k32,use_last_error=True
	)

	fun:Callable=getattr(
		kernel32,
		_Win32_GetFwType
	)
	fun.argtypes=[ctypes.POINTER(wintypes.DWORD)]
	fun.restype=wintypes.BOOL

	return fun

def import_GetFwEnVarW()->Callable:

	kernel32:WinDLL=WinDLL(
		_k32,use_last_error=True
	)

	fun:Callable=getattr(
		kernel32,
		_Win32_GetFwEnVarW
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

	kernel32:WinDLL=WinDLL(
		_k32,use_last_error=True
	)

	fun:Callable=getattr(
		kernel32,
		_Win32_SetFwEnvVarExW
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

###############################################################################

# Lower level functions
 
def init_gain_aditional_privileges(assertion:bool=True)->bool:

	# Enables aditional privileges that are necessary to work with stuff such as
	# interacting with EFI/UEFI firmware variables for example

	token=win32security.OpenProcessToken(
		win32api.GetCurrentProcess(),
		win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES
	)

	priv_id=win32security.LookupPrivilegeValue(
		None,"SeSystemENvironmentPrivilege"
	)

	win32security.AdjustTokenPrivileges(
		token,False,[(
			priv_id,
			win32con.SE_PRIVILEGE_ENABLED
		)]
	)
	err_code=win32api.GetLastError()
	if not err_code==0:
		err_msg=(
			"Unable to set the custom privilege;"
			f" error: {err_code}"
		)
		if not assertion:
			print(err_msg)
			return False

		raise Exception(err_msg)

	return True

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
		msg_err=(
			"Failed to determine firmware type;"
			f" error: {err}"
		)
		if assertion:
			raise WinError(msg_err)

		print(msg_err)
		return None

	res_ok=res_dword.value
	# print("fwtype:",res_ok)
	return res_ok

def get_efivariable(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		varname:str,efiguid:str=_EFI_GLOBALVAR,
		assertion:bool=True
	)->Optional[bytes]:

	size_base=256
	size=size_base

	data:Optional[bytes]=None

	msg_err:Optional[str]=None

	while True:

		buff=ctypes.create_string_buffer(size)
		howmuch=fun_GetFirmwareEnvironmentVariableW(
			varname,
			efiguid,
			buff,
			size
		)
		# print("howmuch?",howmuch)
		if howmuch>0:
			data=buff.raw[:howmuch]
			break

		err=get_last_error()

		if err==122:
			size=size+size_base
			continue

		if err==203:
			print(
				"UEFI var not found:",
				varname
			)
			break

		msg_err=(
			"Failed to find EFI variable;"
			f" error: {err}; varname: {varname}"
		)
		break

	if msg_err is not None:

		if not assertion:
			print(msg_err)
			return None

		raise WinError(msg_err)

	return data

def set_efi_variable(
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

	if not done:

		err=get_last_error()
		msg_err=(
			"Failed to set new value for the targetted EFI variable;"
			f" error: {err}; varname: {varname}"
		)

		if not assertion:

			print(msg_err)
			return False

		raise WinError(msg_err)

	return done

###############################################################################

# Some parsers

def parse_efi_filepath_list_0x04_0x04(data: bytes) -> dict:

	# Parses type 0x04 and subtype 0x04
	# Type 0x04 is Media Device Path
	# Subtype 0x04 is File Path

	fpath_lst=bytes(data)

	print("DATA:",fpath_lst)

	results = []
	offset = 0
	total_size = len(fpath_lst)

	while offset < total_size:

		print("loop",offset)

		if total_size - offset < 4:
			raise ValueError("Incomplete device-path node header")

		node_type = fpath_lst[offset]
		node_subtype = fpath_lst[offset + 1]
		node_length = struct.unpack_from(
			"<H",
			fpath_lst,
			offset + 2,
		)[0]

		if node_length < 4:
			raise ValueError(
				f"Invalid node length {node_length} at offset {offset}"
			)

		node_end = offset + node_length

		if node_end > total_size:
			raise ValueError(
				f"Node at offset {offset} exceeds the device-path list"
			)

		# End of the complete device path
		if node_type == 0x7F and node_subtype == 0xFF:
			break

		# Media Device Path / File Path node
		if node_type == 0x04 and node_subtype == 0x04:
			path_data = fpath_lst[offset + 4:node_end]

			path = path_data.decode(
				"utf-16-le",
				errors="replace",
			).split("\x00", 1)[0]

			results.append({
				"offset": offset,
				"type": node_type,
				"subtype": node_subtype,
				"node_length": node_length,
				"path": path,
			})

		offset = node_end

	return results




###############################################################################

# Hi level functions

def hl_is_fwtype_uefi(
		fun_GetFirmwareType:Callable,
		assertion:bool=True
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

def hl_is_fwtype_legacy(
		fun_GetFirmwareType:Callable,
		assertion:bool=True
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

def hl_get_efi_BootOrder(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=True
	)->Optional[tuple]:

	# Get the value inside the "BootOrder" EFI Variable

	data:Optional[bytes]=get_efivariable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootOrder",
		assertion=assertion
	)
	if data is None:
		return None

	data_unpkg=struct.unpack(
		f"<{len(data) // 2}H",
		data,
	)

	boot_order=[]
	for x in data_unpkg:
		boot_order.append(f"Boot{x:04X}")

	return tuple(boot_order)

def hl_get_efi_BootNext(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=True
	)->Optional[str]:

	# Get the value inside the "BootNext" EFI variable

	data:Optional[bytes]=get_efivariable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootNext",
		assertion=assertion
	)
	if data is None:
		return None

	data_size=len(data)

	if not data_size==2:
		msg_err=(
			"The value for BootNext must"
			" contain exactly 2 bytes,"
			f" but recieved {data_size}"
		)
		if not assertion:
			print(msg_err)
			return None

		raise Exception(msg_err)

	data_unpkg=struct.unpack(
		"<H",data
	)
	print(data_unpkg)

	boot_entry=data_unpkg[0]

	return f"Boot{boot_entry:04X}"

def hl_set_efi_BootNext(
		fun_SetFirmwareEnvironmentVariableExW:Callable,
		boot_entry:str,
		assertion:bool=True,
	)->bool:

	# Set the new value for the "BootNext" EFI variable

	if not len(boot_entry)==8:
		return False

	if not boot_entry.startswith("Boot"):
		return False

	boot_num=int(boot_entry[4:],16)

	boot_next_val=struct.pack(
		"<H",boot_num
	)

	done=set_efi_variable(
		fun_SetFirmwareEnvironmentVariableExW,
		"BootNext",boot_next_val,
		assertion=assertion
	)

	return done

def hl_get_efi_BootEntry(
		fun_GetFirmwareEnvironmentVariableW,
		boot_entry:str,
		assertion:bool=True,
		debug:bool=True,
	)->dict:

	# Gets the contents of a specific boot entry

	if not len(boot_entry)==8:
		return {}

	if not boot_entry.startswith("Boot"):
		return {}

	data_bytes=get_efivariable(
		fun_GetFirmwareEnvironmentVariableW,
		boot_entry,assertion=assertion
	)
	if data_bytes is None:
		return {}

	if debug:
		print("RAW DATA:",data_bytes)

	std_headersize=6
	std_encoding="utf-16-le"
	std_nullterm=b"\x00\x00"

	data_size=len(data_bytes)

	if data_size<std_headersize:
		msg_err="The data is smaller than the stantarized header"
		if not assertion:
			return {"error":msg_err}

		raise Exception(msg_err)

	data_attrs,data_fpath_len=struct.unpack_from(
		"<IH",data_bytes,0
	)

	# DESCRIPTION

	desc_start=std_headersize
	desc_end=data_bytes.find(std_nullterm,desc_start)
	if desc_end==-1:
		msg_err="The description is not NULL-terminated"
		if not assertion:
			return {"error":msg_err}

		raise Exception(msg_err)


	desc_bytes=data_bytes[desc_start:desc_end+1]

	if debug:
		print("DESCRIPTION AS BYTES",desc_bytes)

	desc=desc_bytes.decode(std_encoding,errors="replace")

	if debug:
		print("\tDESCRIPTION",desc)

	# DETECTING FILEPATH LIST

	fpath_start=desc_end+len(std_nullterm)

	# Check wether it's off by one byte
	if data_bytes[fpath_start:fpath_start+2]==b"\x00\x04":
		print("IT'S OFF")
		fpath_start=fpath_start+1

	fpath_end=fpath_start+data_fpath_len
	if fpath_end>data_size:

		msg_err="Filepath list is out of bounds"
		if not assertion:
			return {"error":msg_err}

		raise Exception(msg_err)

	fpath_lst=data_bytes[fpath_start:fpath_end]

	try:

		# NOTE:
		# I am only interested in 04 04 types, which are the EFI files
		# I'm not interested in hardware devices

		return parse_efi_filepath_list_0x04_0x04(fpath_lst)

	except Exception as exc:

		print(exc)

		return {}

###############################################################################

# Main function (tests only)
 
if __name__=="__main__":

	# Some tests

	from sys import exit as sys_exit

	init_gain_aditional_privileges()

	GetFwType=import_GetFwType()

	firmware_type=get_fwtype(GetFwType)
	if not firmware_type==2:
		print("Not running in a UEFI booted system")
		sys_exit(0)

	GetFwEnVarW=import_GetFwEnVarW()
	SetFwEnvVarExW=import_SetFwEnvVarExW()

	boot_order=hl_get_efi_BootOrder(GetFwEnVarW)
	print("Boot order:",boot_order)

	# done=hl_set_efi_BootNext(SetFwEnvVarExW,boot_order[0])
	# print("BootNext set?",done)

	# boot_next=hl_get_efi_BootNext(GetFwEnVarW)
	# print("Next system to boot:",boot_next)

	print("BOOT ENTRIES:")
	for boot_entry in boot_order:

		print(boot_entry)
		result=hl_get_efi_BootEntry(
			GetFwEnVarW,
			boot_entry
		)
		print("DETAILS:",result)
