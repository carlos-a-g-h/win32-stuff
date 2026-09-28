#!/usr/bin/python3

# from random import randint

# import ctypes
# from ctypes import (
# 	Array,WinDLL,WinError,
# 	get_last_error,wintypes,
# )
import struct
from typing import Callable,Optional,Union

from WPrivilege import (
	env_gain_extra_priv,
	query_proc_priv_info
)

from WUEFI_lowlevel import (
	get_fwtype,
	read_efi_variable,
	write_efi_variable
)

from WUEFI_ctypes import (
	import_GetFwType,
	import_GetFwEnVarW,
	import_SetFwEnvVarExW
)
from WUEFI_serde import (

	# Deserializers
	parse_efi_BootOrder,
	parse_efi_filepathlist,

	# Serializers
	build_efi_BootOrder,
)
from WUEFI_symbols import (
	_NULLTERM,
	_ENC_UTF16LE,
	_ELO_ATTR_ACTIVE,
	_ELO_ATTR_CATEGORY_BOOT,
	_ELO_NODE_END
)


# Stuff inside Windows

# _Win32_GetFwType="GetFirmwareType"
# _Win32_GetFwEnVarW="GetFirmwareEnvironmentVariableW"
# _Win32_SetFwEnvVarExW="SetFirmwareEnvironmentVariableExW"

# # Misc

# _ENC_UTF16LE="utf-16-le"
# _KERNEL32="kernel32"
# _NULLTERM=b"\x00\x00"

# _UINT64_MAX=18_446_744_073_709_551_615
# _UINT32_MAX=4_294_967_296
# _UINT16_MAX=65_536
# _UINT8_MAX=256

# _ERR_UINT64="Outside of UINT64"
# _ERR_UINT32="Outside of UINT32"
# _ERR_UINT16="Outside of UINT16"
# _ERR_UINT8="Outside of UINT8"

# # ELO = EFI_LOAD_OPTION

# _EFI_GLOBALVAR="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
# _EFI_VAR_NON_VOLATILE=0x00000001
# _EFI_VAR_BOOTSERVICE_ACCESS=0x00000002
# _EFI_VAR_RUNTIME_ACCESS=0x00000004

# # EFI_LOAD_OPTION FilePathList Node headers

# _ELO_NODE_ACPI_HID=b"\x02\x01"
# _ELO_NODE_HARDWARE_PCI=b"\x01\x01"
# _ELO_NODE_MESSAGING_NVMENAMESPACE=b"\x03\x17"
# _ELO_NODE_MEDIA_HARDDRIVE=b"\x04\x01\x2a\x00"
# _ELO_NODE_MEDIA_FILEPATH=b"\x04\x04"
# _ELO_NODE_END=b"\x7f\xff\x04\x00"

# # EFI_LOAD_OPTION Attributes

# _ELO_ATTR_ACTIVE=0x00000001
# _ELO_ATTR_FORCE_RECONNECT=0x00000002
# _ELO_ATTR_OPTION_HIDDEN=0x00000008
# _ELO_ATTR_CATEGORY=0x00001f00
# _ELO_ATTR_CATEGORY_BOOT=0x00000000
# _ELO_ATTR_CATEGORY_APP=0x00000100

###############################################################################

# Extract "things" from the depths of Windows using ctypes

# def import_GetFwType()->Callable:

# 	k32:WinDLL=WinDLL(
# 		_KERNEL32,
# 		use_last_error=True
# 	)

# 	fun:Callable=getattr(
# 		k32,
# 		_Win32_GetFwType
# 	)
# 	fun.argtypes=[ctypes.POINTER(wintypes.DWORD)]
# 	fun.restype=wintypes.BOOL

# 	return fun

# def import_GetFwEnVarW()->Callable:

# 	k32:WinDLL=WinDLL(
# 		_KERNEL32,
# 		use_last_error=True
# 	)

# 	fun:Callable=getattr(
# 		k32,_Win32_GetFwEnVarW
# 	)

# 	fun.argtypes=[
# 		# lpName
# 			wintypes.LPCWSTR,
# 		# lpGuid
# 			wintypes.LPCWSTR,
# 		# pBuffer
# 			ctypes.c_void_p,
# 		# nSize
# 			wintypes.DWORD
# 	]

# 	return fun

# def import_SetFwEnvVarExW()->Callable:

# 	k32:WinDLL=WinDLL(
# 		_KERNEL32,
# 		use_last_error=True
# 	)

# 	fun:Callable=getattr(
# 		k32,_Win32_SetFwEnvVarExW
# 	)

# 	fun.argtypes=[
# 		# lpName
# 			wintypes.LPCWSTR,
# 		# lpGuid
# 			wintypes.LPCWSTR,
# 		# pValue
# 			ctypes.c_void_p,
# 		# nSize
# 			wintypes.DWORD,
# 		# dwAttributes
# 			wintypes.DWORD
# 	]

# 	return fun

###############################################################################

# Utilities, simple functions, and lower level fw access functions

# def is_uint8(data:int)->bool:
# 	if not data>-1:
# 		return False
# 	if not data<_UINT8_MAX:
# 		return False
# 	return True

# def is_uint16(data:int)->bool:
# 	if not data>-1:
# 		return False
# 	if not data<_UINT16_MAX:
# 		return False
# 	return True

# def is_uint32(data:int)->bool:
# 	if not data>-1:
# 		return False
# 	if not data<_UINT32_MAX:
# 		return False
# 	return True

# def is_uint64(data:int)->bool:
# 	if not data>-1:
# 		return False
# 	if not data<_UINT64_MAX:
# 		return False
# 	return True

# def gen_str_BootNNNN(
# 		already_exist:Union[tuple,list]=[],
# 		debug:bool=False
# 	)->Optional[str]:

# 	# Generates a random Boot#### string

# 	# Very useful for creating a new name for a boot entry
# 	# You can feed this function a list or a tuple of names to
# 	# avoid a collision

# 	qtty=len(already_exist)
# 	if qtty==_UINT16_MAX:
# 		if debug:
# 			print("what the f***")

# 		return None

# 	must_check=(not qtty==0)

# 	while True:

# 		new="Boot"+hex(randint(0,_UINT16_MAX-1))[2:]
# 		if not must_check:
# 			break

# 		if new not in already_exist:
# 			if debug:
# 				print(new,"is unique!")

# 			break

# 		if debug:
# 			print(new,"already exists, trying a new one")

# 	return new

# def get_fwtype(
# 		fun_GetFirmwareType:Callable,
# 		assertion:bool=True
# 	)->Optional[int]:

# 	# Returns the firmware type as an int

# 	res_dword=wintypes.DWORD()
# 	if not fun_GetFirmwareType(
# 			ctypes.byref(res_dword)
# 		):

# 		err=get_last_error()
# 		err_msg="Failed to determine the type of firmware"
# 		if assertion:
# 			raise WinError(err,err_msg)

# 		print(err_msg)
# 		return None

# 	return res_dword.value

# def read_efi_variable(
# 		fun_GetFirmwareEnvironmentVariableW:Callable,
# 		varname:str,
# 		efiguid:str=_EFI_GLOBALVAR,
# 		assertion:bool=True
# 	)->Optional[bytes]:

# 	# Reads an EFI variable

# 	size_base=256
# 	size=size_base

# 	data:Optional[bytes]=None

# 	err_msg:Optional[str]=None
# 	err=-1

# 	while True:

# 		buff=ctypes.create_string_buffer(size)
# 		howmuch=fun_GetFirmwareEnvironmentVariableW(
# 			varname,
# 			efiguid,
# 			buff,
# 			size
# 		)
# 		if howmuch>0:
# 			data=buff.raw[:howmuch]
# 			break

# 		err=get_last_error()

# 		if err==122:
# 			size=size+size_base
# 			continue

# 		if err==203:
# 			err_msg=f"EFI var not found: {varname}"
# 			break

# 		err_msg=f"Failed to find EFI var: {varname}"
# 		break

# 	if err_msg is not None:

# 		if assertion:
# 			raise WinError(err,err_msg)

# 		print(err,err_msg)
# 		return None

# 	return data

# def write_efi_variable(
# 		fun_SetFirmwareEnvironmentVariableExW:Callable,
# 		varname:str,
# 		varvalue:Optional[bytes],
# 		efiguid:str=_EFI_GLOBALVAR,
# 		efiattrs:int=(
# 			_EFI_VAR_NON_VOLATILE
# 				| _EFI_VAR_BOOTSERVICE_ACCESS
# 				| _EFI_VAR_RUNTIME_ACCESS
# 		),
# 		assertion:bool=False,
# 	)->bool:

# 	# Sets a new value for an EFI variable
# 	# If the value is None, the variable gets erased

# 	valbuff:Optional[Array]=None
# 	valpoint:Optional[Array]=None
# 	valsize=0

# 	if varvalue is not None:
# 		valbuff=ctypes.create_string_buffer(varvalue)
# 		valpoint=valbuff
# 		valsize=len(varvalue)

# 	done=fun_SetFirmwareEnvironmentVariableExW(
# 		varname,efiguid,
# 		valpoint,valsize,
# 		efiattrs
# 	)

# 	if not done==1:

# 		err=get_last_error()
# 		err_msg=(
# 			"Failed to set new value"
# 			" for the selected EFI var"
# 		)

# 		if assertion:
# 			raise WinError(err,err_msg)

# 		print(err,err_msg)

# 	return done==1

###############################################################################

# Hi level and specific functions

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

def get_evar_BootCurrent(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=False,
		raw_only:bool=False,
	)->Union[bytes,Optional[str]]:

	# Get the value inside the "BootCUrrent" EFI variable

	data:Optional[bytes]=read_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootCurrent",
		assertion=assertion
	)
	if raw_only:
		return data

	if not isinstance(data,(bytes,bytearray)):
		return None

	data_size=len(data)

	if not data_size==2:
		err_msg=(
			"The value for BootNext must"
			" contain exactly 2 bytes,"
			f" but recieved {data_size}"
		)
		if not assertion:
			print(err_msg)
			return None

		raise Exception(err_msg)

	data_unpkg=struct.unpack(
		"<H",data
	)

	boot_entry=data_unpkg[0]

	return f"Boot{boot_entry:04X}"

def get_evar_BootNext(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		assertion:bool=False,
		raw_only:bool=False
	)->Optional[str]:

	# Get the value inside the "BootNext" EFI variable

	data:Optional[bytes]=read_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootNext",
		assertion=assertion
	)

	if data is None:
		return None
	if raw_only:
		return data

	data_size=len(data)

	if not data_size==2:
		err_msg=(
			"The value for BootNext must"
			" contain exactly 2 bytes,"
			f" but recieved {data_size}"
		)
		if not assertion:
			print(err_msg)
			return None

		raise Exception(err_msg)

	data_unpkg=struct.unpack(
		"<H",data
	)
	print(data_unpkg)

	boot_entry=data_unpkg[0]

	return f"Boot{boot_entry:04X}"

def set_evar_BootNext(
		fun_SetFirmwareEnvironmentVariableExW:Callable,
		boot_entry:str,
		assertion:bool=False,
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

	done=write_efi_variable(
		fun_SetFirmwareEnvironmentVariableExW,
		"BootNext",boot_next_val,
		assertion=assertion
	)

	return done

def get_evar_BootOrder(
		fun_GetFirmwareEnvironmentVariableW:Callable,
		as_list:bool=False,
		assertion:bool=False,
		raw_only:bool=False
	)->Optional[Union[tuple,list]]:

	# Get the value inside the "BootOrder" EFI Variable

	data:Optional[bytes]=read_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		"BootOrder",
		assertion=assertion
	)
	if data is None:
		return None

	if raw_only:
		return data

	boot_order=parse_efi_BootOrder(data,as_list=as_list)

	return boot_order

def set_evar_BootOrder(
		fun_SetFirmwareEnvironmentVariableExW:Callable,
		boot_order:Union[tuple,list],
		assertion:bool=False,
		debug:bool=False
	)->Union[bytes,bool]:

	data_bytes=build_efi_BootOrder(boot_order)

	if debug:
		return data_bytes

	ok=write_efi_variable(
		fun_SetFirmwareEnvironmentVariableExW,
		"BootOrder",data_bytes,
		assertion=assertion
	)

	return ok

def get_evar_BootNNNN(
		fun_GetFirmwareEnvironmentVariableW,
		boot_entry:str,
		assertion:bool=False,
		debug:bool=False,
		raw_only:bool=False,
	)->dict:

	# Gets the contents of a specific boot entry

	if not len(boot_entry)==8:
		return {}

	if not boot_entry.startswith("Boot"):
		return {}

	data_bytes=read_efi_variable(
		fun_GetFirmwareEnvironmentVariableW,
		boot_entry,
		assertion=assertion
	)

	if raw_only:
		return data_bytes

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

	readmax=data_bytes[offset:].find(_NULLTERM)
	if readmax==-1:
		return {}

	if not readmax%2==0:
		readmax=readmax+1

	data_description=data_bytes[offset:offset+readmax]
	data_description_ok=data_description.decode("utf-16-le")

	if debug:
		print("DESCRIPTION:",data_description)
		print("DESCRIPTION (OK):",data_description_ok)

	offset=offset+readmax+len(_NULLTERM)

	# Field 4
	# FilePathList
	# Complicated shit
	# Offset depends on where does Desccription ends
	# Size is given by FilePathListLength

	data_fpathlist=data_bytes[offset:offset+data_fpathlen_ok]

	data_fpathlist_ok=parse_efi_filepathlist(
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

def set_evar_BootNNNN(
		fun_SetFirmwareEnvironmentVariableExW:Optional[Callable],
		# Boot####
			boot_entry:str,
		# The name of a Bootloader or an OS for example
			description:str,
		# List of nodes WITHOUT including the end of filepath node
			nodes:list,
		# Attributes (don't touch this unless you know what you're doing)
			attributes:int=(
				_ELO_ATTR_ACTIVE | _ELO_ATTR_CATEGORY_BOOT
			),
		# the OptionalData field
			opdata:Optional[bytes]=None,

		assertion:bool=False,
		debug:bool=False
	)->Union[bool,Optional[bytes]]:

	# Creates a bootable EFI Boot#### variable
	# The FilePathList coming out of this thing is composed of a HardDrive node
	# and a FilePath node

	# NOTE:
	# The FilePathList must be constructed first using the hard drive
	# and filepath nodes

	bytes_fpathlst=b""
	for nnn in nodes:
		bytes_fpathlst=bytes_fpathlst+nnn

	bytes_fpathlst=bytes_fpathlst+_ELO_NODE_END

	fpathlst_len=len(bytes_fpathlst)

	# PAYLOAD CONSTRUCTION

	payload=b""

	# Field 1
	# Attributes
	# UINT32
	# Size 4

	bytes_attributes=struct.pack("<I",attributes)

	if assertion and debug:
		assert len(bytes_attributes)==4

	payload=payload+bytes_attributes

	# Field 2
	# FilePathListLength
	# UINT16
	# Offset 0x04
	# Size 2

	bytes_fpathlst_len=fpathlst_len.to_bytes(2,byteorder="little")

	if assertion and debug:
		assert len(bytes_fpathlst_len)==2

	payload=payload+bytes_fpathlst_len

	# Field 3
	# Description
	# UTF-16 string, Null term.
	# Offset 0x06
	# Size any

	bytes_description=description.encode(_ENC_UTF16LE)+_NULLTERM

	payload=payload+bytes_description

	# Field 4
	# FilePathList
	# Complicated shit
	# Offset depends on where does Desccription ends
	# Size is given by FilePathListLength

	payload=payload+bytes_fpathlst

	# Field 5
	# OptionalData

	if isinstance(opdata,bytes):

		payload=payload+opdata

	if debug:

		# NOTE:
		# Since this function is highly dangerous, the debug argument will return
		# the constructed payload that has been formed and it will NOT perform a
		# write operation

		return payload

	if not isinstance(fun_SetFirmwareEnvironmentVariableExW,Callable):

		return payload

	ok=write_efi_variable(
		fun_SetFirmwareEnvironmentVariableExW,
		boot_entry,payload,
		assertion=assertion
	)

	return ok

###############################################################################

# Main function (tests only)
 
if __name__=="__main__":

	# Some tests

	from sys import exit as sys_exit
	from sys import argv as sys_argv

	arg_main=sys_argv[1].strip().lower()

	_BOOT_ORDER_ADD_FIRST="BootOrder.add_first"
	_BOOT_ORDER_ADD_LAST="BootOrder.add_last"
	_BOOT_ORDER_REMOVE="BootOrder.remove"

	if arg_main=="help":

		epoint=sys_argv[0]
		is_exe=epoint.endswith(".exe")

		if is_exe:
			epoint=f"> {epoint}"
		if not is_exe:
			epoint=f"> python {epoint}"

		print(
			f"\nGet boot entries, BootOrder, BootNext, and BootOrder):\n{epoint}",
			"get|read","$EFI_VARIABLE"
		)

		print(
			f"\nSet BootNext variable:\n{epoint}",
			"set|write","BootNext","$BootNNNN"
		)

		print(
			f"\nAppend a boot entry at the end of the boot order:\n{epoint}",
			"set|write",_BOOT_ORDER_ADD_LAST,"$BootNNNN"
		)

		print(
			f"\nAdd the boot entry to the fist place of the boot order:\n{epoint}",
			"set|write",_BOOT_ORDER_ADD_FIRST,"$BootNNNN"
		)

		print(
			f"\nRemove a boot entry from the boot order:\n{epoint}",
			"set|write",_BOOT_ORDER_REMOVE,"$BootNNNN"
		)

		sys_exit(0)

	if not query_proc_priv_info(
			get_is_elevated=False,
			get_is_admin=True
		):
		print("You must run this program as administrator")
		sys_exit(0)

	env_gain_extra_priv()

	GetFwType=import_GetFwType()

	if not is_fwtype_uefi(GetFwType):
		print("CANNNOT UNDER A NON UEFI/EFI BOOTED SYSTEM")
		sys_exit(0)

	GetFwEnVarW=import_GetFwEnVarW()

	if arg_main in ("get","read"):

		evar=sys_argv[2].strip()

		if evar=="BootCurrent":
			print(
				"BootCurrent:",
				get_evar_BootCurrent(GetFwEnVarW)
			)
			sys_exit(0)

		if evar=="BootNext":
			print(
				"BootNext:",
				get_evar_BootNext(GetFwEnVarW)
			)
			sys_exit(0)

		if evar=="BootOrder":
			print(
				"BootOrder:",
				get_evar_BootOrder(GetFwEnVarW,as_list=True)
			)
			sys_exit(0)

		if evar.startswith("Boot"):
			print(
				f"{evar}:",
				get_evar_BootNNNN(GetFwEnVarW,evar)
			)

		sys_exit(0)

	if arg_main in ("set","write"):

		SetFwEnvVarExW=import_SetFwEnvVarExW()

		arg_action=sys_argv[2].strip()

		if arg_action=="BootNext":

			evar=sys_argv[3].strip()

			if set_evar_BootNext(SetFwEnvVarExW,evar):
				print(f"new BootNext: {evar}")
				sys_exit(0)

			print("FAILED")
			sys_exit(1)


		if arg_action in (
				_BOOT_ORDER_ADD_FIRST,
				_BOOT_ORDER_ADD_LAST,
				_BOOT_ORDER_REMOVE
			):

			evar=sys_argv[3].strip()

			boot_order=get_evar_BootOrder(GetFwEnVarW,as_list=True)

			if arg_action==_BOOT_ORDER_REMOVE:

				if evar in boot_order:

					boot_order.remove(evar)

					if set_evar_BootOrder(SetFwEnvVarExW,boot_order):
						print("NEW BootOrder:",boot_order)
						sys_exit(0)

					print("FAILED")
					sys_exit(1)

			if arg_action==_BOOT_ORDER_ADD_LAST:

				if evar in boot_order:
					boot_order.remove(evar)

				boot_order.append(evar)

				if set_evar_BootOrder(SetFwEnvVarExW,boot_order,debut=True):
					print("NEW BootOrder:",boot_order)
					sys_exit(0)

				print("FAILED")
				sys_exit(1)

			if arg_action==_BOOT_ORDER_ADD_FIRST:
	
				if evar in boot_order:
					boot_order.remove(evar)
					print("AFTER REMOVAL",boot_order)

				boot_order_new=[evar]

				boot_order_new.extend(boot_order)
	
				if set_evar_BootOrder(SetFwEnvVarExW,boot_order_new):
					print("NEW BootOrder:",boot_order_new)
					sys_exit(0)

				print("FAILED")
				sys_exit(1)
