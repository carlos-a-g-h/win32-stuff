#!/usr/bin/python3

from secrets import token_hex
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
	get_evar_BootNNNN,
	set_evar_BootNext,
	set_evar_BootOrder
)

from WUEFI_serde import (

	parse_efi_EFI_LOAD_OPTION,
	build_efi_elo_Description,
	build_efi_elo_fpl_node_Media_FilePath
)

from WUEFI_symbols import _ELO_NODE_MEDIA_FILEPATH,_ELO_NODE_END

from WUEFI_utils import return_result,fix_str,is_uint32

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

		set_BootNext:bool=False,
		set_BootOrder_addfirst:bool=False,

		cfg_set_BootNext_and_BootOrder_using_bcdedit:bool=False,
		cfg_set_path_and_desc_using_bcdedit:bool=False,

		debug:bool=False,
		detailed_output:bool=False,

	)->Optional[tuple]:

	fn="main_CreateFwBootEntry()"

	# (1) Copy the Windows firmware boot entry with a temporary description

	tmp_desc=f"BootEntry {token_hex(16)}"

	step=1
	entry_guid=bcdedit_copy(
		description=tmp_desc,
		debug=debug
	)
	if entry_guid is None:
		msg="Failed to copy Windows's firmware boot entry into a new one"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug)
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	print(
		fn,
		"01 ENTRY GUID:",entry_guid,
		"; tmp_desc:",tmp_desc
	)

	# (2, 3) Get the name of the new boot entry as Boot####

	step=step+1
	boot_order=get_evar_BootOrder(fun_GetFwEnVarW,as_list=True)
	if len(boot_order)==0:
		msg="Failed to get the BootOrder"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	found=[]
	tmp_desc_bytes=build_efi_elo_Description(tmp_desc)
	for name in boot_order:
		found.append(
			(
				name,
				read_efi_variable(
					fun_GetFwEnVarW,
					name
				)
			)
		)
		if not isinstance(found[-1][1],bytes):
			found.pop(-1)

		if not found[-1][1].find(tmp_desc_bytes)>0:
			found.pop(-1)

	step=step+1
	if not len(found)==1:
		msg="Multiple descriptions match the temporary description"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,tmp_desc])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	entry_name=found[0][0]

	found.pop()

	print(fn,"03 ENTRY NAME FOUND:",entry_name)

	# (4, 5) Set real filepath and description using BCDEDIT

	if not cfg_set_path_and_desc_using_bcdedit:

		step=step+2

	if cfg_set_path_and_desc_using_bcdedit:

		if debug:
			print(fn,step,"Using BCDEDIT to set the path and description of the new entry")

		step=step+1
		if not bcdedit_set(
				entry_guid,
				"path",
				filepath,
				debug=debug
			):
			msg="Failed to set custom path to "+entry_guid
			if detailed_output:
				return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid])
			if debug:
				return_result(msg,code=step,prefix=fn,print_only=True)
			return None

		step=step+1
		if not bcdedit_set(
				entry_guid,
				"description",
				description,
				debug=debug
			):
			msg="Failed to change the temporary description for the real description"
			if detailed_output:
				return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
			if debug:
				return_result(msg,code=step,prefix=fn,print_only=True)
			return None

	# (6) Read the boot entry as raw data

	step=step+1
	data_curr:Optional[bytes]=read_efi_variable(
		fun_GetFwEnVarW,
		entry_name
	)
	if data_curr is None:
		msg=f"Failed to read {entry_name} as a raw EFI variable"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	# (7) Parse the current data of the new entry

	step=step+1
	data_curr_parsed=parse_efi_EFI_LOAD_OPTION(
		data_curr,
		debug=debug
	)
	if len(data_curr_parsed)==0:
		msg=f"Failed to parse {entry_name}"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	# (8, 9, 10, 11) Grab data from the deserialized boot entry

	step=step+1
	data_curr_fpl_start=data_curr_parsed.get("filepath_list_start")
	data_curr_fpl_end=data_curr_parsed.get("filepath_list_end")
	ok=isinstance(
		data_curr_parsed.get("filepath_list"),
		list
	)
	if not (
			is_uint32(data_curr_fpl_start) and
			is_uint32(data_curr_fpl_end) and
			ok
		):
		if debug:
			print(
				"is filepath_list a list?",ok,
				"; filepath_list_start =",data_curr_fpl_start,
				"; filepath_list_end =",data_curr_fpl_end
			)
		msg=f"Failed to grab parsed data from {entry_name}"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	step=step+1
	if not len(data_curr_parsed["filepath_list"])>1:
		msg=f"The FilePathList from {entry_name} has less than two nodes"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	step=step+1
	if not (
			isinstance(
				data_curr_parsed["filepath_list"][-1],
				dict
			) and
			isinstance(
				data_curr_parsed["filepath_list"][-2],
				dict
			)
		):
		msg=f"The last two nodes in {entry_name}'s FilePathList are not nodes"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	step=step+1
	if not (
			data_curr_parsed["filepath_list"][-1].get("node_header")==_ELO_NODE_END and
			data_curr_parsed["filepath_list"][-2].get("node_header")==_ELO_NODE_MEDIA_FILEPATH
		):
		msg=f"The last two nodes in {entry_name}'s FilePathList do not contain the required headers"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	# (12) Build the new EFI_LOAD_OPTION payload

	# Field 1 (Attributes)

	data_new=data_curr[:4]

	step=step+1

	if cfg_set_path_and_desc_using_bcdedit:

		data_new=data_new+data_curr[:data_curr_fpl_end]

	if not cfg_set_path_and_desc_using_bcdedit:

		if debug:
			print(fn,step,"Using WinAPI to set the path and description of the new entry")

		n1_size=data_curr_parsed["filepath_list"][-1].get("payload_size")
		n2_size=data_curr_parsed["filepath_list"][-2].get("payload_size")
		if not (
				is_uint32(n1_size) and
				is_uint32(n2_size)
			):
			msg=f"The last two nodes in {entry_name}'s FilePathList have an unknown size"
			if detailed_output:
				return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
			if debug:
				return_result(msg,code=step,prefix=fn,print_only=True)
			return None

		cutoff=n1_size+n2_size
		newelo_fpl_node_media_fpath=build_efi_elo_fpl_node_Media_FilePath(filepath)
		newelo_fpl=data_curr[data_curr_fpl_start:data_curr_fpl_end-cutoff]+newelo_fpl_node_media_fpath+_ELO_NODE_END

		# Field 2 (FilePathListLength)

		newelo_fpl_len=len(newelo_fpl)
		newelo_fpl_len_bytes=newelo_fpl_len.to_bytes(length=2,byteorder="little")
		data_new=data_new+newelo_fpl_len_bytes

		# Field 3 (Description)

		data_new=data_new+build_efi_elo_Description(description)

		# Field 4 (FilePathList)

		data_new=data_new+newelo_fpl

	# Field 5 (OptionalData)

	if isinstance(metadata,bytes):
		data_new=data_new+metadata

	if debug:
		print(
			"\nNEW DATA:",
			parse_efi_EFI_LOAD_OPTION(data_new,debug)
		)

	# (13) Write the new

	step=step+1
	if not write_efi_variable(
			fun_SetFwEnvVarExW,
			entry_name,
			data_new
		):
		msg=f"Failed to write the new data to {entry_name}"
		if detailed_output:
			return return_result(msg,prefix=fn,code=step,as_exc=debug,payload=[entry_guid,entry_name])
		if debug:
			return_result(msg,code=step,prefix=fn,print_only=True)
		return None

	# (14, 15) At The End. Set BootOrder and BootNext
	# This is entirely optional

	notes=[]

	step=step+1

	if set_BootNext:

		if cfg_set_BootNext_and_BootOrder_using_bcdedit:

			if debug:
				print(fn,step,"Using BCDEDIT to set BootNext")

			if not bcdedit_fwbs_new(
					entry_guid,
					debug=True
				):
				msg="Failed to set"+entry_guid+"as the NEXT entry to boot"
				notes.append(msg)

		if not cfg_set_BootNext_and_BootOrder_using_bcdedit:

			if debug:
				print(fn,step,"Using WinAPI to set BootNext")

			if not set_evar_BootNext(
					fun_SetFwEnvVarExW,
					entry_name,
					debug=debug
				):
				msg=f"Failed to set {entry_name} as the NEXT entry to boot"
				notes.append(msg)

	step=step+1

	if set_BootOrder_addfirst:

		if cfg_set_BootNext_and_BootOrder_using_bcdedit:

			if debug:
				print(fn,step,"Using BCDEDIT to set BootOrder")

			if not bcdedit_fwdo_add1st(
					[entry_guid],
					debug=True
				):
				msg="Failed to set"+entry_guid+"as the FIRST entry to boot"
				notes.append(msg)

		if not cfg_set_BootNext_and_BootOrder_using_bcdedit:

			boot_order.remove(entry_name)
			boot_order_new=[entry_name]
			boot_order_new.extend(boot_order)

			if debug:
				print(fn,step,"Using WinAPI to set BootOrder")

			if not set_evar_BootOrder(
					fun_SetFwEnvVarExW,
					boot_order_new,
					debug=debug
				):
				msg=f"Failed to set {entry_name} as the FIRST entry to boot"
				notes.append(msg)

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
			return_result("Nothing to do?",code=1,prefix=fn,print_only=True)
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
			return_result("Boot order not found...?",code=2,prefix=fn,print_only=True)
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
				return_result(
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
			return_result(
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
			name=entry_name,
			debug=debug
		)

	if debug:
		print(fn,"Returns:",entry_name)

	return entry_name

def main_EditFwBootEntry(

		# Edits the filepath, description and/or metadata of an existing boot entry,
		# but instead of using BCDEDIT, it uses the Windows API

		# (Windows API) GetFirmwareEnvironmentVariableW
			fun_GetFwEnVarW:Callable,
		# (Windows API) SetFirmwareEnvironmentVariableExW
			fun_SetFwEnvVarExW:Optional[Callable],

		# Target boot entry (as  Boot####)
		boot_entry:str,

		# New description
		description:Optional[str]=None,

		# New filepath
		filepath:Optional[str]=None,

		# New metadata (OptionalData)
		metadata:Optional[bytes]=None,

		detailed_output:bool=False

	)->Union[bool,Mapping]:

	fn="main_FwBootEntry_EditMetadata()"

	ch_description=isinstance(description,str)
	if ch_description:
		ch_description=(len(description.strip())>0)

	ch_filepath=isinstance(filepath,str)
	if ch_filepath:
		ch_filepath=(len(filepath.strip())>0)

	ch_metadata=isinstance(metadata,bytes)

	step=1
	if not (
			ch_description or
			ch_filepath or
			ch_metadata
		):
		if detailed_output:
			return return_result(
				"Nothing to do...?",
				prefix=fn,
				code=step
			)
		return False

	# Check wether the given boot entry exists

	step=step+1
	boot_order=get_evar_BootOrder(fun_GetFwEnVarW,as_list=True)
	if len(boot_order)==0:
		if detailed_output:
			return return_result(
				"Nothing to do...?",
				prefix=fn,
				code=step
			)
		return False

	if boot_entry not in boot_order:
		return False

	# Read the boot entry as a raw EFI variable

	data_original:Optional[bytes]=read_efi_variable(
		fun_GetFwEnVarW,
		boot_entry
	)
	if data_original is None:
		return False

	# Parse the raw data

	data_parsed=parse_efi_EFI_LOAD_OPTION(data_original)
	if len(data_parsed)==0:
		return False

	curr_description=fix_str(data_parsed.get("description"))
	if curr_description is None:
		return False

	# Make sure the FilePathList key is holding the list of nodes
	if not isinstance(data_parsed.get("filepath_list"),list):
		return False

	# Make sure that there is more than one node
	if not len(data_parsed.get("filepath_list"))>1:
		return False

	# Make sure the last node is A NODE
	if not isinstance(data_parsed["filepath_list"][-1],Mapping):
		return False

	# Make sure the last nodes are not raw
	if isinstance(data_parsed["filepath_list"][-1].get("raw"),bytes):
		return False

	# Detect Final Node
	if not data_parsed["filepath_list"][-1].get("header")==_ELO_NODE_END:
		return False

	# Make sure the node before the last node is A NODE
	if not isinstance(data_parsed["filepath_list"][-2],Mapping):
		return False

	# Detect Media Filepath Node
	if not data_parsed["filepath_list"][-2].get("header")==_ELO_NODE_MEDIA_FILEPATH:
		return False

	# Get FilePathList start
	filepathlist_start=data_parsed.get("filepath_list_start")
	if not is_uint32(filepathlist_start):
		return False

	# Get FilePathList end
	filepathlist_end=data_parsed.get("filepath_list_end")
	if not is_uint32(filepathlist_end):
		return False

	# Get the size of the Media Filepath Node
	size_node_media_fpath=data_parsed["filepath_list"][-2].get("payload_size")
	if not is_uint32(size_node_media_fpath):
		return False

	# Get the size of the Final Node
	size_node_final=data_parsed["filepath_list"][-1].get("payload_size")
	if not is_uint32(size_node_final):
		return False

	# Get original OptionalData
	curr_opdata=data_original[filepathlist_end:]

	# Build the new FilePathList and get its length

	newdata_filepathlist=b""
	if not ch_filepath:
		newdata_filepathlist=data_original[filepathlist_start:filepathlist_end]
	if ch_filepath:
		tmp=size_node_media_fpath+size_node_final
		newdata_filepathlist=data_original[filepathlist_start:filepathlist_end-tmp]
		newdata_filepathlist=newdata_filepathlist+build_efi_elo_fpl_node_Media_FilePath(filepath)
		newdata_filepathlist=newdata_filepathlist+_ELO_NODE_END
	newdata_fpl_len=len(newdata_filepathlist)

	# Start constructing the new payload

	# 1 - Header

	newdata=data_original[0:4]

	# 2 - FilePathListLength

	if ch_filepath:
		newdata=newdata+newdata_fpl_len.to_bytes(length=2,byteorder="little")

	# 3 - Description

	if not ch_description:
		newdata=newdata+build_efi_elo_Description(curr_description)
	if ch_description:
		newdata=newdata+build_efi_elo_Description(description)

	# 4 - FilePathList

	newdata+newdata+newdata_filepathlist

	# 5 - OptionalData

	if not ch_metadata:
		newdata=newdata+curr_opdata
	if ch_metadata:
		newdata=newdata+metadata

	if not isinstance(fun_SetFwEnvVarExW,Callable):

		print(
			"NEW DATA:",
			parse_efi_EFI_LOAD_OPTION(
				newdata,
				name=boot_entry
			)
		)

		return False

	if not write_efi_variable(
			fun_SetFwEnvVarExW,
			boot_entry,
			newdata
		):

		return False

	if detailed_output:
		return return_result(
			"Success",
			prefix=fn
		)

	return True

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

	the_path="\\EFI\\Boot\\systemd-boot-x64.efi"
	the_desc="SystemD Boot (pure bcdedit with Metadata)"
	set_bootnext=True
	set_bootfirst=True

	# Import some functions from WinDLL

	fun_EFIVarGetter=import_GetFwEnVarW()
	fun_EFIVarSetter=import_SetFwEnvVarExW()

	# Create a boot entry for a bootloader, set it as the next one to boot and as
	# the first one to boot in the new boot order

	result=main_CreateFwBootEntry(
		fun_EFIVarGetter,
		fun_EFIVarSetter,
		the_path,
		the_desc,
		set_BootNext=set_bootnext,
		set_BootOrder_addfirst=set_bootfirst,
		debug=True,
		detailed_output=True,
		metadata=b"Installed using WUEFI"
	)
	print("\nRESULT:",result)

	# Locate the new boot entry by its description and show its details if found

	# entry_name=main_LocateFwBootEntry(
	# 	fun_EFIVarGetter,
	# 	hint_description=the_desc,
	# 	debug=True
	# )

	# main_EditFwBootEntry(fun_EFIVarGetter,None,entry_name,description="SYSTEMDBOOT")
