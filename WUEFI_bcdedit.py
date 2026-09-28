#!/usr/bin/python3

from typing import Mapping,Optional,Union

from WUEFI_utils import (
	fix_str as util_fix_str,
	is_guid as util_is_guid,
	subproc as util_subproc,
	split_line_into_kv as util_split_line_into_kv,
)

# IMPORTANT NOTE:
# BCDEDIT's usage throughout this specific module will focus only on working
# with the EFI/UEFI firmware, not with Windows's BCD store. Therefore, this
# module is NOT RECOMMENDED for working with Windows's BCD store even though
# it contains some basic functionality

# Common identifiers

_ID_BOOTMGR="{bootgmr}"
_ID_FWBOOTMGR="{fwbootmgr}"

# Arguments related to lists

_ARG_ADDFIRST="/addfirst"
_ARG_ADDLAST="/addlast"
_ARG_REMOVE="/remove"

###############################################################################

# Utilities specific for this module

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

	result:Union[bool,Optional[str]]=util_is_guid(
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

###############################################################################

# Parsing functions

def parse_bcdedit_entry_listfield(
		lines_list:list,
		offset:int,
		opt_items_as_list:bool=False,
		opt_wrap_in_a_hashmap:bool=False
	)->Union[str,list,Mapping]:

	# NOTE:
	# parses list items such as displayorder

	first_item=util_split_line_into_kv(
		lines_list[offset],
		get_tup=True
	)
	if first_item is None:
		if opt_wrap_in_a_hashmap:
			return {}
		return []

	name,fvalue=first_item

	maxlen=len(lines_list)

	sp=" "
	space=""
	for x in name:
		space=space+sp

	items:str=""

	pos=offset
	while True:

		pos=pos+1
		if pos>maxlen-1:
			break
		line=lines_list[pos]
		if len(line.strip())==0:
			break
		if not line.startswith(space):
			break
		if line[-1]==sp:
			break

		item_str=line.strip()

		print(
			"\tFOUND ITEM:",
			item_str
		)

		items=items+sp+item_str

	items_ok=items.strip()

	print("ITEMS FOUND:",items_ok)

	if opt_wrap_in_a_hashmap:
		if opt_items_as_list:
			return {name:items_ok.split()}

		return {name:items_ok}

	if opt_items_as_list:
		return items_ok.split() 

	return items_ok

def parse_bcdedit_entry(
		raw_lines:list,offset:int,
		kli:Union[tuple,list]=(
			"displayorder",
			"toolsdisplayorder"
		)
	)->Mapping:

	pos=offset

	# Parses a specific entry, taking as a starting position, the underline of
	# the heading

	# NOTE:
	# The offset is at the underline, so above we have the "title" and below the
	# identifier field

	# NOTE:
	# KLI stands for Known List Items. Field names that are known to hold items
	# as lists can be declared here as tuple or lists

	heading_loc=util_fix_str(
		raw_lines[pos-1]
	)
	if heading_loc is None:
		return {}

	pair_identifier=util_split_line_into_kv(
		raw_lines[pos+1],
		get_tup=True
	)
	if pair_identifier is None:
		return {}

	pos=pos+1

	maxlen=len(raw_lines)

	# NOTE: Heading is localized and it depends on the Windows Installation

	fields={
		"identifier":pair_identifier[1],
		"_Heading":heading_loc
	}

	has_kli=isinstance(kli,(list,tuple))
	if has_kli:
		has_kli=(not len(kli)==0)

	while True:
		pos=pos+1
		if pos>maxlen-1:
			break
		currline=raw_lines[pos]

		if currline.startswith(" "):
			continue

		if len(currline.strip())==0:
			break

		pair=util_split_line_into_kv(currline,get_tup=True)
		if pair is None:
			continue

		if has_kli:

			# Detects Known List Items

			if pair[0] in kli:
				fields.update(
					parse_bcdedit_entry_listfield(
						raw_lines,pos,
						opt_wrap_in_a_hashmap=True
					)
				)
				continue

		if pair is None:
			continue

		fields.update({pair[0]:pair[1]})

	fields.update({"progress":pos-offset})

	return fields

def parse_bcdedit_enum(
		raw_str:str,
		kli:Union[tuple,list]=(
			"displayorder",
			"toolsdisplayorder"
		)
	)->list:

	# Main parsing function for BCDEDIT's output

	lines_as_list=raw_str.splitlines()

	entries=[]
	content={}

	count=-1
	maxlen=len(lines_as_list)

	while True:

		count=count+1
		if count>maxlen-1:
			break

		if not len(content)==0:
			content.clear()

		line=lines_as_list[count]

		if line.startswith("-"):

			content.update(
				parse_bcdedit_entry(
					lines_as_list,
					count,
					kli=kli
				)
			)

		if not len(content)==0:
			progress=content.pop("progress")
			count=count+progress-1
			if not len(content)==0:
				entries.append(
					content.copy()
				)

	return entries

###############################################################################

# Basic and low level BCDEDIT funtions 

def cmd_bcdedit_enum_firmware(
		identifier:Optional[str]=None,
		debug:bool=False
	)->list:

	# Enumerate all entries from the firmware group or a specific entry
	# (preferrably from the firmware group)

	target:Optional[str]=None

	specific=(isinstance(identifier,str))
	if not specific:
		target="firmware"

	if specific:

		target=util_filter_identifier(
			identifier,
			# whitelist=[],
			return_data=True
		)

		if target is None:
			return []

	result_subproc=util_subproc(
		[
			"bcdedit",
			"/enum",
			target,
			"/v"
		],
		verbose=debug
	)

	if not result_subproc[0]==0:
		return []

	return parse_bcdedit_enum(result_subproc[1])

def cmd_bcdedit_copy(
		identifier:str=_ID_BOOTMGR,
		description:Optional[str]=None,
		debug:bool=False
	)->Optional[str]:

	# Copies an entry and returns the GUID of the new entry
	# By default, it copies the {bootmgr} entry

	target=util_filter_identifier(
		identifier,
		whitelist=[_ID_BOOTMGR],
		return_data=True
	)
	if target is None:
		if debug:
			print(
				"Identifier not valid:",
				identifier
			)
		return None

	command=[
		"bcdedit",
		"/copy",
		target
	]

	desc=util_fix_str(description)
	if desc is not None:
		command.extend(["/d",desc])

	result_subproc=util_subproc(
		command,
		verbose=debug
	)

	if not result_subproc[0]==0:
		return None

	# Parse the standard output to grab the GUID

	stdout=result_subproc[1]

	guid_start=stdout.find("{")
	if guid_start==-1:
		return None
	guid_end=stdout[guid_start+1:].find("}")
	if not guid_end==36:
		return None

	return util_filter_identifier(
		stdout[guid_start+1:guid_start+1+guid_end],
		whitelist=[],
		return_data=True
	)

def cmd_bcdedit_modify(
		identifier:str,
		name:str,
		value:Optional[str],
		debug:bool=False,
	)->bool:

	# Modifies the value of a property in an entry

	# NOTE:
	# This function does not cover values stored in lists

	target=util_filter_identifier(
		identifier,
		return_data=True
	)
	if target is None:
		if debug:
			print(
				"Identifier not valid:",
				identifier
			)
		return False

	command=[]

	new_value=isinstance(value,str)
	if new_value:
		command.extend([
			"bcdedit",
				"/set",
				target,
				name,value
		])
	if not new_value:
		command.extend([
			"bcdedit",
				"/deletevalue",
				target,
				name
		])

	result_subproc=util_subproc(
		command,
		verbose=debug
	)

	return (result_subproc[0]==0)

def cmd_bcdedit_delete(
		identifier:str,
		debug:bool=False
	)->bool:

	# Deletes a specific entry

	# NOTE:
	# Due to how dangerous this function can be, you have to explicitly give it
	# an identifier in the form of a GUID, which means that you SHOULD NOT try
	# and target identifiers such as {bootmgr} or {fwbootmgr}

	target=util_is_guid(
		identifier,verbose=debug,
		return_data=True
	)
	if target is None:
		return False

	if len(target)==36:
		target="{"+target+"}"

	result_subproc=util_subproc(
		[
			"bcdedit",
				"/delete",
				target
		],
		verbose=debug
	)
	return (result_subproc[0]==0)

###############################################################################

# Specific BCDEDIT functions for the firmware displayorder ({fwbootmgr})
# The name "fwdo" stands for "Firmware Display Order"

# NOTE:
# the *fwdo_modify* functions have not been tested yet

def cmd_bcdedit_fwdo_list(
		detailed:bool=False,
		debug:bool=False
	)->list:

	# Returns the firmware display order
	# It's almost the same as the "cmd_bcdedit_enum_firmware" function, but way
	# more specific

	result_subproc=util_subproc(
		[
			"bcdedit",
				"/enum",
				_ID_FWBOOTMGR,
				"/v"
		]
	)
	if not result_subproc[0]==0:
		return []

	result_parsed=parse_bcdedit_enum(
		result_subproc[1],
		kli=["displayorder"]
	)
	if not len(result_parsed)==1:
		return []

	fwdo:Optional[str]=result_parsed[0].get("displayorder")

	if fwdo is None:
		return []

	fwdo_list=fwdo.split(sep=" ")

	if detailed:

		entries=[]

		for identifier in fwdo_list:

			entries.extend(
				cmd_bcdedit_enum_firmware(
					identifier,
					debug=debug
				)
			)

		return entries

	return fwdo_list

def cmd_bcdedit_fwdo_modify_replace(
		id_list:Union[list,tuple],
		debug:bool=False,
		test:bool=False
	)->bool:

	# Modifies the firmware displayorder by
	# replacing the current order with a new order

	# NOTE:
	# this is dangerous as f***

	tgtlist=util_filter_identifier_list(
		id_list,
		whitelist=[_ID_BOOTMGR],
		return_data=True,
		debug=debug
	)
	if len(tgtlist)==0:
		return False

	command=[
		"bcdedit","/set",
			_ID_FWBOOTMGR,
			"displayorder"
	]

	command.extend(tgtlist)

	result_subproc=util_subproc(
		command,
		verbose=debug,
		test=test
	)

	return (result_subproc[0]==0)

def cmd_bcdedit_fwdo_modify_addfirst(
		id_list:Union[list,tuple],
		debug:bool=False,
		test:bool=False
	)->bool:

	# Modifies the firmware displayorder
	# Adds one or more GUIDs in first place (uses /addfirst)

	tgtlist=util_filter_identifier_list(
		id_list,
		whitelist=[_ID_BOOTMGR],
		return_data=True,
		debug=debug
	)
	if len(tgtlist)==0:
		return False

	command=[
		"bcdedit","/set",
			_ID_FWBOOTMGR,
			"displayorder"
	]

	command.extend(tgtlist)

	command.append("/addfirst")

	result_subproc=util_subproc(
		command,
		verbose=debug,
		test=test
	)

	return (result_subproc[0]==0)

def cmd_bcdedit_fwdo_modify_addlast(
		id_list:Union[list,tuple],
		debug:bool=False,
		test:bool=False
	)->bool:

	# Modifies the firmware displayorder
	# Adds one or more GUIDs in at the end (uses /addlast)

	tgtlist=util_filter_identifier_list(
		id_list,
		whitelist=[_ID_BOOTMGR],
		return_data=True,
		debug=debug
	)
	if len(tgtlist)==0:
		return False

	command=[
		"bcdedit","/set",
			_ID_FWBOOTMGR,
			"displayorder"
	]

	command.extend(tgtlist)

	command.append("/addlast")

	result_subproc=util_subproc(
		command,
		verbose=debug,
		test=test
	)

	return (result_subproc[0]==0)

def cmd_bcdedit_fwdo_modify_remove(
		identifier:str,
		debug:bool=False,
		test:bool=False
	)->bool:

	# Modifies the firmware displayorder by
	# removing one GUID

	target=util_filter_identifier(
		identifier,
		whitelist=[_ID_BOOTMGR],
		return_data=True
	)
	if target is None:
		return False

	result_subproc=util_subproc(
		[
			"bcdedit",
				"/set",
				_ID_FWBOOTMGR,
				"displayorder",
				target,
				"/remove"
		],
		verbose=debug,
		test=test
	)

	return (result_subproc[0]==0)

###############################################################################

# Small test

if __name__=="__main__":

	from sys import exit as sys_exit

	from WPrivilege import query_proc_priv_info

	if  not query_proc_priv_info():
		print("You need admin privileges")
		sys_exit(1)

	this_one=None

	entries=cmd_bcdedit_enum_firmware(
		identifier=this_one,
		debug=True
	)
	c=0
	print("\nENTRIES FOUND {")
	for e in entries:
		c=c+1
		print(f"\nEntry {c}:",e)

	print("} ENTRIES FOUND\n")

	displayorder=cmd_bcdedit_fwdo_list(detailed=True,debug=True)

	print("\nDISPLAYORDER:",displayorder)
