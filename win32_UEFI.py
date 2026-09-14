#!/usr/bin/python3

# NOTE:
# THIS IS A WORK IN PROGRESS

# WARNING:
# IF YOU BRICK YOUR FIRMWARE, OR SOMEONE ELSE'S, THAT'S ON YOU, NOT ME
# IF TRAMONTINA MAKES KNIVES, THEY CAN'T BE HELD ACCOUNTABLE FOR ALL
# THE MURDERS THAT INVOLVE A TRAMONTINA KITCHEN KNIFE

import ctypes
from ctypes import (
	Array,WinDLL,WinError,
	get_last_error,wintypes,
)

import struct
from typing import Callable,Optional
from uuid import UUID
import win32api
import win32con
import win32security

_KERNEL32="kernel32"

_ENC_UTF16LE="utf-16-le"

_CONST_NULLTERM=b"\x00\x00"

_EFI_GLOBALVAR="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"

_EFI_VAR_NON_VOLATILE=0x00000001
_EFI_VAR_BOOTSERVICE_ACCESS=0x00000002
_EFI_VAR_RUNTIME_ACCESS=0x00000004

# Bytes
_EFI_NODE_HARD_DRIVE=b"\x04\x01"
_EFI_NODE_FILEPATH=b"\x04\x04"
_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH=b"\x7f\xff\x04\x00"

###############################################################################

# Extract "things" from the depths of Windows using ctypes

_Win32_GetFwType="GetFirmwareType"
_Win32_GetFwEnVarW="GetFirmwareEnvironmentVariableW"
_Win32_SetFwEnvVarExW="SetFirmwareEnvironmentVariableExW"

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

###############################################################################

# Lower level functions
 
def init_gain_aditional_privileges(assertion:bool=True)->bool:

	# Gain aditional privileges that are necessary to work with stuff that
	# Windows might be consider very sensitive, such as, interacting with
	# EFI/UEFI firmware variables for example

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

# Simple and lower level functions
 
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
			raise WinError(err)

		print(msg_err)
		return None

	res_ok=res_dword.value
	# print("fwtype:",res_ok)
	return res_ok

def get_efi_variable(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		varname:str,efiguid:str=_EFI_GLOBALVAR,
		assertion:bool=True
	)->Optional[bytes]:

	size_base=256
	size=size_base

	data:Optional[bytes]=None

	msg_err:Optional[str]=None
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

		raise WinError(err)

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

		raise WinError(err)

	return done

###############################################################################

# Parsing functions

def parse_efi_filepathlist_node_header(
		data:bytes,
		data_offset:int=0,
		debug:bool=False
	)->tuple:

	# Returns: ( Type , SubType, Node Size )

	offset=data_offset

	# TYPE      SUBTYPE   END OF HEADER
	# UINT8     UINT8     UINT16 LE
	# Offset 0  Offset 1  Offset 2
	# Size 1    Size 1    Size 2

	# Type

	readmax=1

	x_type=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	offset=offset+readmax

	# Subtype

	readmax=1

	x_subtype=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	offset=offset+readmax

	# Node size

	readmax=2

	x_nodesize=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	if debug:
		print("type",x_type)
		print("subtype",x_subtype)
		print("node size",x_nodesize)

	return (x_type,x_subtype,x_nodesize)

def parse_efi_filepathlist_node_harddrive(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		debug:bool=False
	)->dict:

	# NOTE:

	# TYPE               SUBTYPE             END OF HEADER
	# Media Device Path  Hard drive subtype  Node Length
	# UINT8              UINT8               UINT16 LE
	# Offset 0           Offset 1            Offset 2
	# Size 1             Size 1              Size 2
	# Bytes 04           Bytes 01

	if not unsafe:
		x_type,x_subtype,x_nodesize=parse_efi_filepathlist_node_header(
			data,data_offset=data_offset,
			debug=debug
		)
		if not (
			x_type==4 and
			x_subtype==1 and
			x_nodesize==42
		):
			return {}

	offset=data_offset+4

	# Partition Number
	# UINT32 LE
	# Offset 0
	# Size 4

	readmax=4

	d_partnum=data[offset:offset+readmax]
	d_partnum_ok=int.from_bytes(d_partnum,"little")
	if debug:
		print("PARTNUM:",d_partnum)
		print("PARTNUM (OK):",d_partnum_ok)

	offset=offset+readmax

	# Partition start LBA
	# UINT64
	# Size 8

	readmax=8

	d_pstartlba=data[offset:offset+readmax]
	d_partstartlba_ok=int.from_bytes(d_pstartlba,"little")
	if debug:
		print("PART START LBA:",d_pstartlba)
		print("PART START LBA (OK):",d_partstartlba_ok)

	offset=offset+readmax

	# Partition size
	# UINT64
	# Size 8

	readmax=8

	d_partsize=data[offset:offset+readmax]
	d_partsize_ok=int.from_bytes(d_partsize,"little")
	if debug:
		print("PART SIZE:",d_partsize)
		print("PART SIZE (OK):",d_partsize_ok)

	offset=offset+readmax

	# GPT Partition GUID
	# raw 16-byte sig
	# Size 16

	readmax=16

	d_partguid=data[offset:offset+readmax]
	d_partguid_ok=str(UUID(bytes_le=d_partguid))
	if debug:
		print("PART GUID:",d_partguid)
		print("PART GUID (OK):",d_partguid_ok)

	offset=offset+readmax

	# MBR Type
	# UINT8
	# Size 1

	readmax=1

	d_mbrtype=data[offset:offset+readmax]
	d_mbrtype_ok=int.from_bytes(d_mbrtype,"little")
	if debug:
		print("MBRTYPE:",d_mbrtype)
		print("MBRTYPE (OK):",d_mbrtype_ok)

	offset=offset+readmax

	# Signature Type
	# UINT8
	# Size 1

	readmax=1

	d_signtype=data[offset:offset+readmax]
	d_signtype_ok=int.from_bytes(d_signtype,"little")
	if debug:
		print("SIGNTYPE:",d_signtype)
		print("SIGNTYPE (OK):",d_signtype_ok)

	offset=offset+readmax

	progress=offset-data_offset

	return {
		"node":_EFI_NODE_HARD_DRIVE,
		"partition_number":d_partnum_ok,
		"partition_start_lba:":d_partstartlba_ok,
		"partition_size":d_partsize_ok,
		"partition_guid":d_partguid_ok,
		"mbrtype":d_mbrtype_ok,
		"signtype":d_signtype_ok,
		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_filepathlist_node_filepath(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		debug:bool=False
	)->dict:

	# NOTE:

	# TYPE               SUBTYPE           END OF HEADER
	# Media Device Path  Filepath subtype  Node Length
	# UINT8              UINT8             UINT16 LE
	# Offset 0           Offset 1          Offset 2
	# Size 1             Size 1            Size 2
	# Bytes 04           Bytes 04

	x_nodesize=-1
	if not unsafe:
		x_type,x_subtype,x_nodesize=parse_efi_filepathlist_node_header(
			data,data_offset=data_offset,
			debug=debug
		)
		if not (x_type==4 and x_subtype==4):
			return {}

	offset=data_offset+4

	# Filepath
	# UINT32 LE NT
	# Offset 0
	# Size ?

	d_filepath_end=-1

	has_nodesize=(not x_nodesize==-1)

	if has_nodesize:
		d_filepath_end=x_nodesize-4

	if not has_nodesize:
		d_filepath_end=data[offset:].find(_CONST_NULLTERM)
		if d_filepath_end==-1:
			return {}

		if not d_filepath_end%2==0:
			d_filepath_end=d_filepath_end+1

	# Minus two so that the null terminator gets excluded
	# print("FILEPATH (raw)",data[offset:offset+d_filepath_end-2])

	d_filepath_ok=data[offset:offset+d_filepath_end-2].decode(_ENC_UTF16LE)

	offset=offset+d_filepath_end

	progress=offset-data_offset

	return {
		"node":_EFI_NODE_FILEPATH,
		"filepath":d_filepath_ok,
		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_filepathlist_type_0x04(
		data:bytes,
		data_offset:int=0,
		debug:bool=False
	)->list:

	offset=data_offset
	maxlen=len(data)

	nodes=[]

	while True:

		if debug:
			print("PROGRESS:",offset,"/",maxlen)
			print("REMAINING:",data[offset:])
	
		if offset==maxlen:
			break
		if offset>maxlen:
			break

		if data[offset:offset+2]==_EFI_NODE_HARD_DRIVE:

			if debug:
				print("Detected: Node 04 01")

			node_hdd=parse_efi_filepathlist_node_harddrive(
				data,data_offset=offset,
				debug=debug
			)
			# print(node_hdd)
			payload_size=node_hdd["payload_size"]

			offset=offset+payload_size
	
			nodes.append(node_hdd)

			continue

		if data[offset:offset+2]==_EFI_NODE_FILEPATH:

			if debug:
				print("Detected: Node 04 04")

			node_fpath=parse_efi_filepathlist_node_filepath(
				data,data_offset=offset,
				debug=debug
			)
			payload_size=node_fpath["payload_size"]

			offset=offset+payload_size
	
			nodes.append(node_fpath)

			continue

		if data[offset:offset+4]==_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH:

			if debug:
				print("Detected: End of Device Path Node")

			nodes.append({"node":_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH})

			break

		nodes.append({"nodes":data[offset:]})

		break

	return nodes

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

	data:Optional[bytes]=get_efi_variable(
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

def hl_get_efi_BootCurrent(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=True
	)->Optional[str]:

	# Get the value inside the "BootCUrrent" EFI variable

	data:Optional[bytes]=get_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootCurrent",
		assertion=assertion
	)
	if not isinstance(data,(bytes,bytearray)):
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

def hl_get_efi_BootNext(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=True
	)->Optional[str]:

	# Get the value inside the "BootNext" EFI variable

	data:Optional[bytes]=get_efi_variable(
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
		debug:bool=False,
	)->dict:

	# Gets the contents of a specific boot entry

	if not len(boot_entry)==8:
		return {}

	if not boot_entry.startswith("Boot"):
		return {}

	data_bytes=get_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		boot_entry,assertion=assertion
	)
	if data_bytes is None:
		return {}

	data_bytes_size=len(data_bytes)

	if debug:
		print(
			"LEN; RAW DATA:",
			data_bytes_size,
			data_bytes
		)

	# Parsing according to the EFI_LOAD_OPTION specification

	offset=0

	# Field 1
	# Attributes
	# UINT32
	# Offset 0x00
	# Size 4

	readmax=4
	data_attributes=data_bytes[offset:offset+readmax]
	if debug:
		print(
			"ATTRIBUTES:",
			data_attributes
		)
		print(
			"ATTRIBUTES (DECODED):",
			int.from_bytes(
				data_attributes,
				byteorder="little"
			)
		)

	offset=offset+readmax

	# Field 2
	# FilePathListLength
	# UINT16
	# Offset 0x04
	# Size 2

	readmax=2
	data_fpathlen=data_bytes[offset:offset+readmax]
	data_fpathlen_ok=int.from_bytes(
		data_fpathlen,
		byteorder="little"
	)
	if debug:
		print("FILEPATH LENGTH:",data_fpathlen)
		print("FILEPATH LENGTH (OK):",data_fpathlen_ok)

	offset=offset+readmax

	# Field 3
	# Description
	# UTF-16 string, Null term.
	# Offset 0x06
	# Size any

	readmax=data_bytes[offset:].find(_CONST_NULLTERM)
	if readmax==-1:
		return {}

	if not readmax%2==0:
		readmax=readmax+1

	data_description=data_bytes[offset:offset+readmax]
	data_description_ok=data_description.decode("utf-16-le")

	if debug:
		print("DESCRIPTION:",data_description)
		print("DESCRIPTION (OK):",data_description_ok)

	offset=offset+readmax+len(_CONST_NULLTERM)

	# Field 4
	# FilePathList
	# Complicated shit
	# Offset depends on where does Desccription ends
	# Size is given by FilePathListLength

	data_fpathlist=data_bytes[offset:offset+data_fpathlen_ok]

	data_fpathlist_ok=parse_efi_filepathlist_type_0x04(
		data_fpathlist,
		debug=debug
	)

	offset=offset+data_fpathlen_ok

	data_ok={
		"raw_attributes":data_attributes,
		"description":data_description_ok,
		"filepath_list":data_fpathlist_ok,
	}

	if not offset<data_bytes_size:

		if debug:
			print("OptionalData not found")

		return data_ok

	# Field 5
	# OptionalData
	# This is the tail of the Boot#### entry

	data_optional=data_bytes[offset:]

	data_ok.update({"raw_optdata":data_optional})

	return data_ok

###############################################################################

# Main function (tests only)
 
if __name__=="__main__":

	# Some tests

	from sys import exit as sys_exit

	# NOTE:
	# If you get a 1314 error is because you need to run this script as
	# Administrator or use the module as Administrator
	# If you get 1300 error, is because you also need to run the function
	# called "init_gain_aditional_privileges()" so that the entire process
	# is authorized to do modifications on parts of the system that require
	# privileges beyond what the regular Administrator user already gives

	init_gain_aditional_privileges()

	GetFwType=import_GetFwType()

	firmware_type=get_fwtype(GetFwType)
	if not firmware_type==2:
		print("Not running in a UEFI booted system")
		sys_exit(0)

	GetFwEnVarW=import_GetFwEnVarW()
	SetFwEnvVarExW=import_SetFwEnvVarExW()

	# Get current system

	boot_current=hl_get_efi_BootCurrent(GetFwEnVarW)
	print("\nBootCurrent",boot_current)

	# List Boot order

	boot_order=hl_get_efi_BootOrder(GetFwEnVarW)
	print("\nBoot order:",boot_order)

	# List boot entries

	print("\nBOOT ENTRIES:")

	more_verbose=False

	for boot_entry in boot_order:

		print("\nBOOT ENTRY:",boot_entry)
		result=hl_get_efi_BootEntry(
			GetFwEnVarW,
			boot_entry,
			debug=more_verbose
		)
		print("DETAILS:",result)
