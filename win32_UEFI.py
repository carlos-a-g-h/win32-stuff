#!/usr/bin/python3

# NOTE:
# THIS IS A WORK IN PROGRESS

# WARNING:
# IF YOU BRICK YOUR FIRMWARE, OR SOMEONE ELSE'S FIRMWARE, THAT'S ON YOU, NOT ME

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

_k32="kernel32"

_EFI_GLOBALVAR="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
_EFI_VAR_NON_VOLATILE=0x00000001
_EFI_VAR_BOOTSERVICE_ACCESS=0x00000002
_EFI_VAR_RUNTIME_ACCESS=0x00000004

_CONST_NULLTERM=b"\x00\x00"
_CONST_END_OF_ENTIRE_DEVICE_PATH=b"\x7f\xff\x04\x00"

_ENC_UTF16LE="utf-16-le"

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

# Parers

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
		if not (x_type==4 and x_subtype==1 and x_nodesize==42):
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

	return {
		"node":1,
		"partition_number":d_partnum_ok,
		"partition_start_lba:":d_partstartlba_ok,
		"partition_size":d_partsize_ok,
		"partition_guid":d_partguid_ok,
		"mbrtype":d_mbrtype_ok,
		"signtype":d_signtype_ok,
		"payload_size":offset-data_offset,
		"payload_end":data_offset+offset
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
	if not x_nodesize==-1:
		d_filepath_end=x_nodesize-4

	if x_nodesize==-1:
		d_filepath_end=data[offset:].find(_CONST_NULLTERM)
		if d_filepath_end==-1:
			return {}

		if not d_filepath_end%2==0:
			d_filepath_end=d_filepath_end+1

	d_filepath_ok=data[offset:offset+d_filepath_end].decode(_ENC_UTF16LE)

	offset=offset+d_filepath_end

	return {
		"node":4,
		"filepath":d_filepath_ok,
		"payload_size":offset-data_offset,
		"payload_end":data_offset+offset
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

		if data[offset:offset+2]==b"\x04\x01":

			print("Node 04 01")

			node_hdd=parse_efi_filepathlist_node_harddrive(
				data,data_offset=offset,
				debug=True
			)
			# print(node_hdd)
			payload_size=node_hdd["payload_size"]

			offset=offset+payload_size
	
			nodes.append(node_hdd)

			continue

		if data[offset:offset+2]==b"\x04\x04":

			print("Node 04 04")

			node_fpath=parse_efi_filepathlist_node_filepath(
				data,data_offset=offset,
				debug=True
			)
			payload_size=node_fpath["payload_size"]

			offset=offset+payload_size
	
			nodes.append(node_fpath)

			continue

		if data[offset:offset+4]==_CONST_END_OF_ENTIRE_DEVICE_PATH:

			nodes.append({"node":-1})

			break

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
		debug:bool=False,
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

	return {
		"raw_attributes":data_attributes,
		"description":data_description_ok,
		"filepath_list":data_fpathlist_ok,
	}

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

	# List Boot order

	boot_order=hl_get_efi_BootOrder(GetFwEnVarW)
	print("Boot order:",boot_order)

	result=hl_get_efi_BootEntry(
		GetFwEnVarW,
		boot_order[0],
		debug=True
	)
	print("DETAILS:",result)

	sys_exit(0)

	# boot_entry_with_grub:Optional[str]=None

	# # List boot entries

	# print("BOOT ENTRIES:")
	# for boot_entry in boot_order:

	# 	print("\nBOOT ENTRY:",boot_entry)
	# 	result=hl_get_efi_BootEntry(
	# 		GetFwEnVarW,
	# 		boot_entry,
	# 		debug=True
	# 	)
	# 	print("DETAILS:",result)

	# 	# Grab a specific boot entry

	# 	if not isinstance(result,list):
	# 		continue

	# 	if not len(result)==1:
	# 		continue

	# 	x=result[0].get("path")
	# 	if not isinstance(x,str):
	# 		continue

	# 	if ("grub2" in x) and ("efi" in x):
	# 		print("FOUND GRUB2 EFI in:",boot_entry)
	# 		boot_entry_with_grub=boot_entry
	# 		break


	# done=hl_set_efi_BootNext(SetFwEnvVarExW,boot_entry_with_grub)
	# print("BootNext set?",done)

	# # boot_next=hl_get_efi_BootNext(GetFwEnVarW)
	# # print("Next system to boot:",boot_next)

