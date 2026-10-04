#!/usr/bin/python3

from typing import Callable,Mapping,Optional,Union

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

from WUEFI_symbols import _ELO_NODE_MEDIA_FILEPATH

def main_CreateFwBootEntry(

		# Creates a firmware boot entry using a combination of BCDEDIT commands and
		# Windows API functions related to EFI variables

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,
		# (Windows API) SetFirmwareEnvironmentVariableExW
			fun_SetFwEnvVarExW:Callable,

		filepath:str,
		description:str,
		metadata:Optional[bytes]=None,

		opt_BootNext:bool=False,
		opt_BootOrder_addfirst:bool=False,

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
			"path",filepath,
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

	# (11, 12) Set BootOrder and BootNext thorugh BCDEDIT

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

def main_LocateFwBootEntry(

		# Locates a firmware boot entry using hints such as description, filepath,
		# and metadata (EFI_LOAD_OPTION's OptionalData)

		# NOTE:
		# You must provide at least ONE hint and the result must match all provided
		# hints
		# It can only return one result using the Boot#### naming scheme

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,

		hint_description:Optional[str]=None,
		hint_filepath:Optional[str]=None,
		hint_metadata:Optional[bytes]=None,

		return_detailed:bool=False,

	)->Union[Optional[str],Mapping]:

	ph_description=(isinstance(hint_description,str))
	ph_filepath=(isinstance(hint_filepath,str))
	ph_metadata=(isinstance(hint_metadata,bytes))

	if not (
			ph_description or
			ph_filepath or
			ph_metadata
		):
		if return_detailed:
			return {}
		return None

	matches_found=0
	matches_req=0
	if ph_description:
		matches_req=matches_req
	if ph_filepath:
		matches_req=matches_req
	if ph_metadata:
		matches_req=matches_req

	boot_order=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order is None:
		if return_detailed:
			return {}
		return None

	# Provided ONLY metadata as hint

	found=[]
	if (
			ph_metadata and
			(not ph_description) and
			(not ph_filepath)
		):
		pass

	for name in boot_order:
		matches_found=0
		if return_detailed:
			found.append(
				get_evar_BootNNNN(
					fun_GetFwEnVarW,
					name
				)
			)
			if len(found[-1])==0:
				found.pop(-1)
				continue
			if ph_description:
				if found[-1].get("description")==ph_description:
					matches_found=matches_found+1
			if ph_metadata:
				if found[-1].get("optdata")==ph_metadata:
					matches_found=matches_found+1
			if ph_filepath:
				if not isinstance(
						found[-1].get("filepath_list"),
						list
					):
					found.pop(-1)
					continue
				for node in found[-1]["filepath_list"]:
					if not node.get("header")==_ELO_NODE_MEDIA_FILEPATH:
						continue
					if node.get("filepath")==ph_filepath:
						matches_found=matches_found+1
	
			if not matches_found==matches_req:
				found.pop(-1)
				continue

			if matches_found==matches_req:
				break

		# return_detailed == False



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

	entry_id=main_CreateFwBootEntry(

		fun_EFIVarGetter,
		fun_EFIVarSetter,

		the_path,
		the_desc,

		opt_BootNext=False,
		opt_BootOrder_addfirst=False,

		debug=True
	)
	if entry_id is None:
		exit(1)

	print("NEW ENTRY:",entry_id)

