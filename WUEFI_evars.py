#!/usr/bin/python3

# OK

import ctypes
from ctypes import (
	Array,WinError,
	get_last_error,wintypes,
)

import struct

from typing import Callable,Optional,Union

from WUEFI_serde import (
	parse_efi_BootOrder,
	parse_efi_filepathlist,

	build_efi_BootOrder,
)

from WUEFI_symbols import (

	_ENC_UTF16LE,
	_NULLTERM,

	_ELO_ATTR_ACTIVE,
	_ELO_ATTR_CATEGORY_BOOT,
	_ELO_NODE_END,

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

###############################################################################

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

	data_ok={
		"raw_attributes":data_attributes,
		"description":data_description_ok,
		"filepath_list":data_fpathlist_ok,
		"filepath_list_start":offset,
		"filepath_list_end":offset+data_fpathlen_ok
	}

	offset=offset+data_fpathlen_ok

	if not offset<data_bytes_size:

		if debug:
			print("OptionalData not found")

		return data_ok

	# Field 5
	# OptionalData
	# This is the tail of the Boot#### entry

	data_optional=data_bytes[offset:]

	data_ok.update({"optdata":data_optional})

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


if __name__=="__main__":

	# Some tests

	from sys import exit as sys_exit
	from sys import argv as sys_argv

	from WUEFI_ctypes import (
		import_GetFwType,
		import_GetFwEnVarW,
		import_SetFwEnvVarExW
	)

	from WUEFI_utils import is_fwtype_uefi

	from WPrivilege import (
		query_proc_priv_info,
		env_gain_extra_priv
	)

	# from WUEFI_evars import (
	# 	get_evar_BootCurrent,
	# 	get_evar_BootNext,
	# 	get_evar_BootNNNN,
	# 	get_evar_BootOrder,

	# 	set_evar_BootNext,
	# 	set_evar_BootOrder
	# )

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
