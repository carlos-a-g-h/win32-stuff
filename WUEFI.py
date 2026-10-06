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

from WUEFI_serde import (

	parse_efi_EFI_LOAD_OPTION,
	build_efi_elo_Description,
	build_efi_elo_fpl_node_Media_FilePath
)

from WUEFI_utils import rich_err_hand

def main_CreateFwBootEntry(

		# Creates a firmware boot entry using a combination of BCDEDIT commands and
		# Windows API functions related to EFI variables

		# NOTE:
		# This function makes serveral assumptions, the most important one being
		# that you are creating an EFI Boot entry placing an EFI file of a bootloader
		# inside the same ESP where you have Windows's main EFI file

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,
		# (Windows API) SetFirmwareEnvironmentVariableExW
			fun_SetFwEnvVarExW:Callable,

		filepath:str,
		description:str,
		metadata:Optional[bytes]=None,

		opt_BootNext:bool=False,
		opt_BootOrder_addfirst:bool=False,

		debug:bool=False,
		detailed_output:bool=False,

	)->Optional[tuple]:

	fn="main_CreateFwBootEntry()"

	# (1) Get the current BootOrder

	boot_order_before=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order_before is None:
		c=1
		m="BootOrder not found?"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug)
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	# (2) Copy the Windows firmware boot entry

	entry_guid=bcdedit_copy(
		description=description,
		debug=debug
	)
	if entry_guid is None:
		c=2
		m="Failed to copy Windows's firmware boot entry into a new one"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug)
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	print(fn,"02 ENTRY GUID:",entry_guid)

	# (3) Modify the new firmware boot entry

	if not bcdedit_set(
			entry_guid,
			"path",filepath,
			debug=debug
		):
		c=3
		m="Failed to set custom path to "+entry_guid
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	# (4,5) Get the new current BootOrder

	boot_order_after=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order_after is None:
		c=4
		m="Failed to get the new BootOrder"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	sizediff=len(boot_order_after)-len(boot_order_before)

	if not sizediff==1:
		c=5
		m=(
			"The new BootOrder is supposed to have one more item compared to the"
			" previous BootOrder"
		)
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	# (6) Extract the new entry name as Boot####

	entry_name:Optional[str]=None
	for name in boot_order_after:
		if name in boot_order_before:
			continue
		entry_name=name
	if entry_name is None:
		c=6
		m="Failed to get the name of the new boot entry"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	print(fn,"06 ENTRY NAME:",entry_name)

	# (7, 8, 9) From the entry details, get the OptionalData offset

	entry_details=get_evar_BootNNNN(
		fun_GetFwEnVarW,
		entry_name,
		debug=debug
	)
	if len(entry_details)==0:
		c=7
		m="Failed to parse "+entry_name
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	optdata_offset:Optional[int]=entry_details.get("filepath_list_end")
	if optdata_offset is None:
		c=8
		m=f"Unable to determine where does {entry_name}'s OptionalData starts"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	if not optdata_offset>0:
		c=9
		m=f"Expected the given OptionalData offset from {entry_name} to be larger than zero"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	# (10, 11) Read the boot entry as raw data, cut off the OptionalData and, if
	# provided, add the metadata as the new OptionalData for the boot entry

	entry_raw:Optional[bytes]=read_efi_variable(
		fun_GetFwEnVarW,
		entry_name
	)
	if entry_raw is None:
		c=10
		m=f"Failed to read {entry_name} as a raw EFI variable"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	entry_raw_ok=entry_raw[0:optdata_offset]
	if isinstance(metadata,bytes):
		entry_raw_ok=entry_raw_ok+metadata

	if not write_efi_variable(
			fun_SetFwEnvVarExW,
			entry_name,
			entry_raw_ok
		):
		c=11
		m=f"Failed to write the new data to {entry_name}"
		if detailed_output:
			return rich_err_hand(m,prefix=fn,code=c,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			rich_err_hand(m,code=c,prefix=fn,print_only=True)
		return None

	# (12, 13) Set BootOrder and BootNext thorugh BCDEDIT

	notes=[]

	if opt_BootNext:
		if not bcdedit_fwbs_new(
				entry_guid,
				debug=True
			):
			m="Failed to set"+entry_guid+"as the NEXT entry to boot"
			notes.append(m)

	if opt_BootOrder_addfirst:
		if not bcdedit_fwdo_add1st(
				[entry_guid],
				debug=True
			):
			m="Failed to set"+entry_guid+"as the FIRST entry to boot"
			notes.append(m)

	if debug:
		print(
			fn,"Returns:",
			(entry_name,entry_guid)
		)
		if not len(notes)==0:
			print(fn,"Warnings:",notes)

	if detailed_output:

		# Returns ( CODE, ENTRY_NAME , ENTRY_GUID , NOTE1, NOTE2 )

		result=[0,entry_name,entry_guid]
		if not len(notes)==0:
			result.extend(notes)
		return tuple(result)

	return (entry_name,entry_guid)

def main_LocateFwBootEntry(

		# Locates a firmware boot entry using specific data

		# NOTE:
		# You must provide at least ONE hint and the result must match all the
		# provided hints
		# It can only return one result using the Boot#### naming scheme

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,

		# Description
			hint_description:Optional[str]=None,
		# FPL Media Filepath Node
			hint_filepath:Optional[str]=None,
		# OptionalData
			hint_metadata:Optional[bytes]=None,

		# Return the content of the boot entry instead of the name
		return_content:bool=False,

		debug=False

	)->Union[Optional[str],Mapping]:

	fn="main_LocateFwBootEntry()"

	ph_description=(isinstance(hint_description,str))
	ph_filepath=(isinstance(hint_filepath,str))
	ph_metadata=(isinstance(hint_metadata,bytes))

	# Check 1

	if not (
			ph_description or
			ph_filepath or
			ph_metadata
		):
		if debug:
			rich_err_hand("Nothing to do?",code=1,prefix=fn,print_only=True)
		if return_content:
			return {}
		return None

	matches_found=0
	matches_req=0
	if ph_description:
		matches_req=matches_req+1
	if ph_filepath:
		matches_req=matches_req+1
	if ph_metadata:
		matches_req=matches_req+1

	# Check 2

	boot_order=get_evar_BootOrder(fun_GetFwEnVarW)
	if boot_order is None:
		if debug:
			rich_err_hand("Boot order not found...?",code=2,prefix=fn,print_only=True)
		if return_content:
			return {}
		return None

	# Provided ONLY metadata as hint

	found=[]
	if (
			ph_metadata and
			(not ph_description) and
			(not ph_filepath)
		):

		if debug:
			print(fn,"NOTE: (after check 2) provided metadata only")

		metadata_len=len(hint_metadata)

		for name in boot_order:

			found.append(
				(
					name,
					get_evar_BootNNNN(
						fun_GetFwEnVarW,
						name,
						raw_only=True
					)
				)
			)

			if debug:
				print(fn,"Loop:",name,found[-1])

			tmp_elosize=len(found[-1][1])
			optdata_offset=tmp_elosize-metadata_len

			if found[-1][1][optdata_offset:-1]==hint_metadata:
				if debug:
					print(fn,f"The OptionalData found in {name} matches the given metadata")
				break

			found.pop(-1)
			continue

		# Check 3

		if not len(found)==1:
			if debug:
				rich_err_hand(
					f"Found {len(found)} instead of ONE",
					code=3,prefix=fn,
					print_only=True
				)
			if return_content:
				return {}
			return None

		if return_content:

			name=found[-1][0]

			return parse_efi_EFI_LOAD_OPTION(
				found[-1][1],
				name=name
			)

		return found[-1][0]

	# One or more hints provided

	desc_as_bytes=b""
	if ph_description:
		desc_as_bytes=build_efi_elo_Description(hint_description)

	node_media_fpath=b""
	if ph_filepath:
		node_media_fpath=build_efi_elo_fpl_node_Media_FilePath(hint_filepath)

	for name in boot_order:

		matches_found=0
		found.append(
			(
				name,
				get_evar_BootNNNN(
					fun_GetFwEnVarW,
					name,raw_only=True
				)
			)
		)

		print(name,found[-1])

		if found[-1][1] is None:
			found.pop(-1)
			continue

		if ph_description:
			if found[-1][1].find(desc_as_bytes)==-1:
				if debug:
					print(fn,f"Description not found in {name}")
				found.pop(-1)
				continue
			matches_found=matches_found+1

		if ph_filepath:
			if found[-1][1].find(node_media_fpath)==-1:
				if debug:
					print(fn,f"Media FilePath node not found in {name}")
				found.pop(-1)
				continue
			matches_found=matches_found+1

		if ph_metadata:
			if found[-1][1].find(hint_metadata)==-1:
				if debug:
					print(fn,f"Metadata (OptionalData) not found in {name}")
				found.pop(-1)
				continue
			matches_found=matches_found+1

		if not matches_found==matches_req:
			if debug:
				print(fn,f"Not enough matches in {name}")
			found.pop(-1)
			continue

		if debug:
			print(fn,f"Hints match {name}")

	# Check 4

	if not len(found)==1:
		if debug:
			rich_err_hand(
				f"Found {len(found)} instead of ONE",
				code=4,prefix=fn,
				print_only=True
			)
		return None

	entry_name=found[-1][0]

	if return_content:

		entry_data=found[-1][1]

		return parse_efi_EFI_LOAD_OPTION(
			entry_data,
			entry_name,
			debug=debug
		)

	if debug:
		print(fn,"Returns:",entry_name)

	return entry_name

def main_FwBootEntry_EditMetadata(
		# Edits the OptionalData of an existing EFI_LOAD_OPTION

		# NOTE:
		# Some EFI bootloaders could malfunction if they have an OptionalData
		# field or if it is removed/altered

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,
		# (Windows API) SetFirmwareEnvironmentVariableExW
			fun_SetFwEnvVarExW:Callable,

		# Target boot entry
		boot_entry:str,

		# New metadata (OptionalData)
		metadata:Optional[bytes]

	)->bool:

	fn="main_FwBootEntry_EditMetadata()"

	# (1, 2) Check wether the given boot entry exists

	boot_order=get_evar_BootOrder(fun_GetFwEnVarW,as_list=True)
	if len(boot_order)==0:
		return False

	if boot_entry not in boot_order:
		return False

	# (3) read the boot entry as a raw EFI variable

	data_curr:Optional[bytes]=read_efi_variable(
		fun_GetFwEnVarW,
		boot_entry
	)
	if data_curr is None:
		return False

	# (4, 5) Parse the raw data and get the offset of the OptionalData

	data_parsed=parse_efi_EFI_LOAD_OPTION(data_curr)
	if len(data_parsed):
		return False

	opdata_offset:Optional[int]=data_parsed.get("filepath_list_end")
	if not isinstance(opdata_offset):
		return False

	if opdata_offset<1:
		return False

	data_new=data_curr[0:opdata_offset]

	if metadata is not None:

		ok=isinstance(metadata,bytes)
		if not ok:
			return False

		if len(metadata)==0:
			return False

		data_new=data_new+metadata

	return write_efi_variable(
		fun_SetFwEnvVarExW,
		boot_entry,
		data_new
	)

###############################################################################

if __name__=="__main__":

	# The following test creates a boot entry and tracks

	from WPrivilege import (
		query_proc_priv_info,
		env_gain_extra_priv
	)
	from WUEFI_ctypes import (
		import_GetFwEnVarW,
		import_SetFwEnvVarExW
	)

	# Make sure the script is being ran as admin

	if not query_proc_priv_info():
		print("Must run as admin")
		exit(1)

	# Gain aditional privileges

	env_gain_extra_priv()

	# Parameters

	the_path="\\EFI\\Boot\\grub2.bootx64.efi"
	the_desc="MY GRUB 2 EFI"
	set_bootnext=False
	set_bootfirst=False

	# Import some functions from WinDLL

	fun_EFIVarGetter=import_GetFwEnVarW()
	fun_EFIVarSetter=import_SetFwEnvVarExW()

	# Create a boot entry for Grub2 EFI

	entry_id=main_CreateFwBootEntry(
		fun_EFIVarGetter,
		fun_EFIVarSetter,
		the_path,
		the_desc,
		opt_BootNext=set_bootnext,
		opt_BootOrder_addfirst=set_bootfirst,
		debug=True
	)
	if entry_id is None:
		exit(1)

	# Locate the new boot entry by its description and show its details if found

	print(
		"LOCATED:",
		main_LocateFwBootEntry(
			fun_EFIVarGetter,
			hint_description=the_desc,
			return_content=True,
			debug=True
		)
	)
