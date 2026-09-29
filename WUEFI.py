#!/usr/bin/python3

from typing import Callable,Optional

from WUEFI_bcdedit import (

	cmd_entry_copy as bcdedit_copy,
	cmd_entry_modify as bcdedit_set,

	cmd_fw_do_modify_addfirst as bcdedit_fwdo_add1st,
	cmd_fw_bs_modify as bcdedit_fwbs_new
)

from WUEFI_evars import (

	read_efi_variable,
	write_efi_variable,

	get_evar_BootOrder,
	get_evar_BootNNNN
)

def main_Create_boot_entry_using_BCDEDIT_and_WinAPI_functions(

		# GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,
		# SetFirmwareEnvironmentVariableExW
			fun_SetFwEnvVarExW:Callable,

		path_efi:str,
		description:str,
		metadata:Optional[bytes]=None,

		opt_BootNext:bool=False,
		opt_BootOrder_addfirst:bool=False

		debug:bool=False

	)->Optional[tuple]:

	# (1) Get the current BootOrder

	boot_order_before=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order_before is None:
		print("error_1")
		return None

	# (2) Copy the Windows firmware boot entry

	entry_guid=bcdedit_copy(
		description=description,
		debug=debug
	)
	if entry_guid is None:
		print("error_2")
		return None

	print("ENTRY GUID:",entry_guid)

	# (3) Modify the new firmware boot entry

	if not bcdedit_set(
			entry_guid,
			"path",path_efi,
			debug=debug
		):
		print("error_3")
		return None

	# (4) Get the new current BootOrder

	boot_order_after=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order_after is None:
		print("error_4")
		return None

	# (5) Extract the new entry name as Boot####

	entry_name:Optional[str]=None
	for name in boot_order_after:
		if name in boot_order_before:
			continue
		entry_name=name
	if entry_name is None:
		print("error_5")
		return None

	print("ENTRY NAME:",entry_name)

	# (6, 7, 8) From the entry details, get the OptionalData offset

	entry_details=get_evar_BootNNNN(
		fun_GetFwEnVarW,
		entry_name,
		debug=debug
	)
	if len(entry_details)==0:
		print("error_6")
		return None
	optdata_offset:Optional[int]=entry_details.get("filepath_list_end")
	if optdata_offset is None:
		print("error_7")
		return None
	if not optdata_offset>0:
		print("error_8")
		return None

	# (9, 10) Read the boot entry as raw data, cut off the OptionalData and, if
	# requested, add the new metadata

	entry_raw:Optional[bytes]=read_efi_variable(
		fun_GetFwEnVarW,
		entry_name
	)
	if entry_raw is None:
		print("error_9")
		return None

	entry_raw_ok=entry_raw[0:optdata_offset]
	if isinstance(metadata,bytes):
		entry_raw_ok=entry_raw_ok+metadata

	if not write_efi_variable(
			fun_SetFwEnvVarExW,
			entry_name,
			entry_raw_ok
		):
		print("error_10")
		return None

	# (11, 12) Set bootsequence

	if opt_BootNext:
		if not bcdedit_fwbs_new(
				entry_guid,
				debug=True
			):
			print("error_11")
			return None

	if opt_BootOrder_addfirst:
		if not bcdedit_fwdo_add1st(
				[entry_guid],
				debug=True
			):
			print("error_12")
			return None

	return (entry_name,entry_guid)

###############################################################################

# Main function (tests only)
 
if __name__=="__main__":

	from WPrivilege import (
		query_proc_priv_info,
		env_gain_extra_priv
	)
	from WUEFI_ctypes import (
		import_GetFwEnVarW,
		import_SetFwEnvVarExW
	)

	if not query_proc_priv_info():
		print("Must run as admin")
		exit(1)

	env_gain_extra_priv()

	fun_EFIVarGetter=import_GetFwEnVarW()
	fun_EFIVarSetter=import_SetFwEnvVarExW()

	the_path="\\EFI\\Boot\\grub2.bootx64.efi"
	the_desc="GRUB2 EFI (WUEFI)"

	entry_id=main_Create_boot_entry_using_BCDEDIT_and_WinAPI_functions(

		fun_EFIVarGetter,
		fun_EFIVarSetter,

		the_path,
		the_desc,

		opt_BootNext=False,
		opt_BootOrder_addfirst=False

		debug=True
	)
	if entry_id is None:
		exit(1)

	print("NEW ENTRY:",entry_id)

