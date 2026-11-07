#!/usr/bin/python3

# Windows Boot Configuration Data (BCD) stuff

# IMPORTANT NOTE:
# This module performs very minimal interactions with the UEFI/EFI firmware,
# most of the stuff it does is only Windows BCD stores, that reside either
# on the host system or on a sepparate device

# Dependencies (python3.9.5):
# pywin32==306

# Dependencies (python3.14):
# pywin32==312

# This module interacts with Windows BCD Stores using the WMI interface and
# subprocessing BCDBOOT and BCDEDIT

###############################################################################

from pathlib import Path,WindowsPath
from typing import Mapping,Optional,Union
from uuid import uuid4,UUID

from win32com.client import (
	CDispatch as wmi_CDispatch,
	GetObject as wmi_GetObject
)

from WUtils import (
	fix_str as util_fix_str,
	split_line_into_kv as util_split_line_into_kv
)

from WUtils_windows import (
	wsubproc,
	util_filter_identifier,
	from_text_extract_identifier
)

from WUEFI_symbols import _C_WINDOWS

###############################################################################

# Constants and symbols

_BCD_ID_BOOTMGR="{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
_BCD_ID_FWBOOTMGR="{A5A30FA2-3D06-4E9F-B5F4-A01DF9D1FCBA}"

_BCD_ELEMENTS_DATATYPES=[

	# 0
		"Boolean",
	# 1
		"Integer",
	# 2
		"String",
	# 3
		"Id",
	# 4
		"Integers",
	# 5
		"Ids",
	# 6
		"Device",
]

_BCD_OBJECTS_APPLICATIONS={
	# /create {fwbootmgr}
	"0x10100001":"fwbootmgr",
	# /create {bootmgr}
	"0x10100002":"bootmgr",
	# /create /application osloader
	"0x10200003":"osloader",
	# /create /application resume
	"0x10200004":"resume",
	# /create {memdiag}
	"0x10200005":"memdiag",
	# /create {ntldr}
	"0x10300006":"ntldr",
	# /create /application bootsector
	"0x10400008":"bootsector",
	# /create /application startup
	"0x10400009":"startup",
	# /create /application bootapp
	"0x1020000A":"bootapp"
}

_BCD_ELEMENTS_GLOBAL = {

	# Library Elements

	"0x11000001": "device",
	"0x12000002": "path",
	"0x12000004": "description",
	"0x12000005": "locale",
	"0x14000006": "inherit",
	"0x15000007": "truncatememory",
	"0x14000008": "recoverysequence",
	"0x16000009": "recoveryenabled",
	"0x1700000A": "badmemorylist",
	"0x1600000B": "badmemoryaccess",
	"0x1500000C": "firstmegabytepolicy",
	"0x1500000D": "relocatephysical",
	"0x1500000E": "avoidlowmemory",
	"0x1600000F": "traditionalkseg",
	"0x16000010": "bootdebug",
	"0x15000011": "debugtype",
	"0x15000012": "debugaddress",
	"0x15000013": "debugport",
	"0x15000014": "baudrate",
	"0x15000015": "channel",
	"0x12000016": "targetname",
	"0x16000017": "noumex",
	"0x15000018": "debugstart",
	"0x12000019": "busparams",
	"0x1500001A": "hostip",
	"0x1500001B": "port",
	"0x1600001C": "dhcp",
	"0x1200001D": "key",
	"0x1600001E": "vm",
	"0x1200001F": "hostipv6",
	"0x16000020": "bootems",
	"0x15000022": "emsport",
	"0x15000023": "emsbaudrate",
	"0x12000030": "loadoptions",
	"0x16000031": "attemptnonbcdstart",
	"0x16000040": "advancedoptions",
	"0x16000041": "optionsedit",
	"0x15000042": "keyringaddress",
	"0x11000043": "bootstatdevice",
	"0x12000044": "bootstatfilepath",
	"0x16000045": "preservebootstat",
	"0x16000046": "graphicsmodedisabled",
	"0x15000047": "configaccesspolicy",
	"0x16000048": "nointegritychecks",
	"0x16000049": "testsigning",
	"0x1200004A": "fontpath",
	"0x1500004B": "integrityservices",
	"0x1500004C": "volumebandid",
	"0x16000050": "extendedinput",
	"0x15000051": "initialconsoleinput",
	"0x15000052": "graphicsresolution",
	"0x16000053": "restartonfailure",
	"0x16000054": "highestmode",
	"0x16000060": "isolatedcontext",
	"0x15000065": "displaymessage",
	"0x15000066": "displaymessageoverride",
	"0x16000067": "nobootuxlogo",
	"0x16000068": "nobootuxtext",
	"0x16000069": "nobootuxprogress",
	"0x1600006A": "nobootuxfade",
	"0x1600006B": "bootuxreservepooldebug",
	"0x1600006C": "bootuxdisabled",
	"0x1500006D": "0x1500006D",# bootuxfadeframes ?
	"0x1600006E": "bootuxdumpstats",
	"0x1600006F": "bootuxshowstats",
	"0x16000071": "multibootsystem",
	"0x16000072": "nokeyboard",
	"0x15000073": "0x15000073",# aliaswindowskey?
	"0x16000074": "bootshutdowndisabled",
	"0x15000075": "0x15000075",# performancefrequency?
	"0x15000076": "securebootrawpolicy",
	"0x17000077": "allowedinmemorysettings",
	"0x16000078": "unknown_16000078",
	"0x15000079": "bootuxtransitiontime",
	"0x1600007A": "mobilegraphics",
	"0x1600007B": "forcefipscrypto",
	"0x1500007D": "booterrorux",
	"0x1600007E": "flightsigning",
	"0x1500007F": "measuredbootlogformat",
	"0x15000080": "displayrotation",
	"0x15000081": "logcontrol",
	"0x16000082": "nofirmwaresync",
	"0x11000083": "0x11000083",
	"0x11000084": "windowssyspart",
	"0x16000085": "0x16000085",
	"0x15000086": "0x15000086",
	"0x16000087": "numlock",
	"0x12000088": "additionalcipolicy",
	"0x15000088": "linearaddress57",

	# "Modern?" application elements

	"0x26000202": "skipffumode",
	"0x26000203": "forceffumode",
	"0x25000510": "chargethreshold",
	"0x26000512": "offmodecharging",
	"0x25000AAA": "bootflow"
}

# FWBOOTMGR elements belong to the Firmware Boot Manager object, {fwbootmgr}
# (type 0x10100001). BOOTMGR elements belong to the Windows Boot Manager object,
# {bootmgr} (type 0x10100002). These are separate BCD objects, though both are
# application objects

_BCD_ELEMENTS_FWBOOTMGR_BOOTMGR = {
	"0x24000001": "displayorder",
	"0x24000002": "bootsequence",
	"0x23000003": "default",
	"0x25000004": "timeout",
	"0x26000005": "resume",
	"0x23000006": "resumeobject",
	"0x24000007": "startupsequence",
	"0x24000010": "toolsdisplayorder",
	"0x26000020": "displaybootmenu",
	"0x26000021": "noerrordisplay",
	"0x21000022": "bcddevice",
	"0x22000023": "bcdfilepath",
	"0x26000024": "0x26000024",
	"0x26000025": "hiberboot",
	"0x22000026": "0x22000026",
	"0x22000027": "0x22000027",
	"0x26000028": "processcustomactionsfirst",
	"0x2600002A": "0x2600002A",
	"0x27000030": "customactions",
	"0x26000031": "persistbootsequence",
	"0x26000032": "skipstartupsequence",
	"0x22000040": "fverecoveryurl",
	"0x22000041": "fverecoverymessage",
	"0x26000042": "flightedbootmgr",
	"0x25000043": "0x25000043",
	"0x25000044": "0x25000044",
	"0x22000045": "0x22000045",
	"0x22000046": "0x22000046",
	"0x22000047": "0x22000047",
	"0x22000048": "0x22000048",
	"0x22000049": "0x22000049",
	"0x2200004A": "0x2200004A",
	"0x2200004B": "0x2200004B",
	"0x2200004C": "0x2200004C",
	"0x2500004D": "0x2500004D",
	"0x2500004E": "0x2500004E",
	"0x2500004F": "0x2500004F",
	"0x25000050": "0x25000050",
	"0x25000051": "0x25000051",
}

# OSLOADER elements belong to OS loader application objects, whose object type
# is 0x10200003 (/application osloader in BCDEdit). 

_BCD_ELEMENTS_OSLOADER = {
	"0x21000001": "osdevice",
	"0x22000002": "systemroot",
	"0x23000003": "resumeobject",
	"0x26000004": "stampdisks",
	"0x21000005": "0x21000005",
	"0x25000008": "0x25000008",
	"0x26000010": "detecthal",
	"0x22000011": "kernel",
	"0x22000012": "hal",
	"0x22000013": "dbgtransport",
	"0x25000020": "nx",
	"0x25000021": "pae",
	"0x26000022": "winpe",
	"0x26000024": "nocrashautoreboot",
	"0x26000025": "uselastgoodsettings",
	"0x26000027": "0x26000027",
	"0x26000030": "nolowmemory",
	"0x25000031": "removememory",
	"0x25000032": "increaseuserva",
	"0x26000040": "usevga",
	"0x26000041": "novesa",
	"0x26000042": "novga",
	"0x26000043": "0x26000043",
	"0x25000050": "cluster_mode_addressing",
	"0x26000051": "usephysicaldestination",
	"0x25000052": "restrictapiccluster",
	"0x26000054": "uselegacyapicmode",
	"0x25000055": "x2apicpolicy",
	"0x26000060": "onecpu",
	"0x25000061": "numproc",
	"0x26000062": "maxproc",
	"0x25000063": "processorconfigurationflags",
	"0x26000064": "maximizegroups",
	"0x26000065": "forcegroupawareness",
	"0x25000066": "groupsize",
	"0x26000070": "usefirmwarepcisettings",
	"0x25000071": "msipolicy",
	"0x25000080": "safeboot",
	"0x26000081": "safebootalternateshell",
	"0x26000090": "bootlog",
	"0x26000091": "sos",
	"0x260000A0": "debug",
	"0x260000A1": "halbreakpoint",
	"0x260000A2": "useplatformclock",
	"0x260000A3": "forcelegacyplatform",
	"0x250000A6": "tscsyncpolicy",
	"0x260000B0": "ems",
	"0x250000C1": "driverloadfailurepolicy",
	"0x250000C2": "bootmenupolicy",
	"0x260000C3": "advancedoptions",
	"0x250000E0": "bootstatuspolicy",
	"0x260000E1": "disableelamdrivers",
	"0x250000F0": "hypervisorlaunchtype",
	"0x260000F2": "hypervisordebug",
	"0x250000F3": "hypervisordebugtype",
	"0x250000F4": "hypervisordebugport",
	"0x250000F5": "hypervisorbaudrate",
	"0x250000F6": "hypervisor1394channel",
	"0x250000F7": "bootux",
	"0x220000F9": "hypervisorbuparams",
	"0x250000FA": "hypervisornumproc",
	"0x250000FB": "hypervisorrootprocpernode",
	"0x260000FC": "hypervisoruselargevtlb",
	"0x250000FD": "hypervisornethostip",
	"0x250000FE": "hypervisornethostport",
	"0x25000100": "tpmbootentropy",
	"0x22000110": "hypervisornetkey",
	"0x26000114": "hypervisornetdhcp",
	"0x25000115": "hypervisoriommupolicy",
	"0x2500012B": "xsavedisable"
}

###############################################################################

# Parsing functions

def parse_enum_entry_listfield(
		lines_list:list,
		offset:int,
		opt_items_as_list:bool=False,
		opt_wrap_in_a_hashmap:bool=False
	)->Union[str,list,Mapping]:

	# Handles values stored as lists. A good example of this is the
	# "displayorder" property

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

def parse_enum_entry(
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
					parse_enum_entry_listfield(
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

def parse_enum(
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
				parse_enum_entry(
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

def cmd_new_bcdstore(
		target_drive:str,
		origin:str=_C_WINDOWS,
		for_bios:bool=False,
		for_uefi:bool=False,
		confirm_only:bool=False,
		debug:bool=False
	)->Union[bool,Optional[WindowsPath]]:

	# Creates a new BCD store on a new device based on the host's BCD store

	store_type:Optional[None]=None
	if for_bios and for_uefi:
		store_type="ALL"
	if store_type is None:
		if for_bios and (not for_uefi):
			store_type="BIOS"
	if store_type is None:
		if (not for_bios) and for_uefi:
			store_type="UEFI"
	if store_type is None:
		msg="Unknown store type"
		if debug:
			raise Exception(msg)
		print(msg)
		if confirm_only:
			return False
		return None

	result=wsubproc([
		"bcdboot",
			str(WindowsPath(origin)),
			"/s",target_drive,
			"/f",store_type
		],
		verbose=debug
	)
	if not result[0]==0:
		msg="Failed to create the a new BCD store"
		if debug:
			raise Exception(msg)
		print(msg)
		if confirm_only:
			return False
		return None

	if confirm_only:
		return True

	return WindowsPath(f"{target_drive}/Boot/BCD")

def cmd_new_bootsector_application(
		identifier:Optional[Union[str,UUID]]=None,
		bcd_store:Optional[WindowsPath]=None,
		param_description:Optional[str]=None,
		debug:bool=False
	):

	# Creates a bootsector Application entry in a currently existing BCD store

	return_id=False
	identifier_ok:Optional[str]=None

	command=["bcdedit"]

	if isinstance(bcd_store,Path):

		if bcd_store.is_file():
			if debug:
				print("PROVIDED STORE:",bcd_store)

			command.extend(["/store",str(bcd_store)])

	return_id=True
	if identifier is not None:

		if debug:
			print("PROVIDED GUID (?):",identifier)

		if isinstance(identifier,UUID):
			identifier_ok="{"+str(identifier)+"}"
		if isinstance(identifier,str):
			identifier_ok=util_filter_identifier(
				identifier,
				return_data=True
			)

			if identifier_ok is None:
				msg="Malformed GUID"
				if debug:
					raise Exception(msg)
				print(msg)

		if identifier_ok is not None:
			command.extend(["/create",identifier_ok])
			return_id=False

	if isinstance(param_description,str):

		command.extend(["/d",param_description])

	command.extend([
		"/application","BOOTSECTOR"
	])

	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		msg="Failed to create the entry"
		if debug:
			raise Exception(msg)
		print(msg)
		if not return_id:
			return False
		return None

	if identifier_ok is None:
		identifier_ok=from_text_extract_identifier(result[1])
		if identifier_ok is None:
			msg="Failed to obtain the identifier"
		if debug:
			raise Exception(msg)
		print(msg)
		if not return_id:
			return False
		return None

	if debug:
		print("RESULT:",identifier_ok)

	if return_id:
		return True
	return identifier_ok

def cmd_entry_set_description(
		identifier:Union[str,UUID],
		param_description:str,
		bcd_store:Optional[WindowsPath]=None,
		debug:bool=False
	)->bool:

	# Sets the description of an entry

	identifier_ok:Optional[str]=None
	if isinstance(identifier,UUID):
		identifier_ok="{"+str(identifier)+"}"

	if isinstance(identifier,str):
		identifier_ok=util_filter_identifier(
			identifier,
			return_data=True
		)

	if identifier_ok is None:
		msg="Identifier not valid"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	command=["bcdedit"]

	if isinstance(bcd_store,Path):

		command.extend(["/store",str(bcd_store)])

	command.extend([
		"/set",identifier_ok,
		"description",param_description
	])

	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		msg="Failed to set the description"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	return True

def cmd_entry_set_device(
		identifier:Union[str,UUID],
		param_device:str,
		bcd_store:Optional[WindowsPath]=None,
		debug:bool=False
	)->bool:

	# Sets the device of an entry

	identifier_ok:Optional[str]=None
	if isinstance(identifier,UUID):
		identifier_ok="{"+str(identifier)+"}"

	if isinstance(identifier,str):
		identifier_ok=util_filter_identifier(
			identifier,
			return_data=True
		)

	if identifier_ok is None:
		msg="Identifier not valid"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	command=["bcdedit"]

	if isinstance(bcd_store,Path):

		command.extend(["/store",str(bcd_store)])

	command.extend([
		"/set",identifier_ok,
		"device",param_device
	])

	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		msg="Failed to set the device"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	return True

def cmd_entry_set_path(
		identifier:Union[str,UUID],
		param_path:str,
		bcd_store:Optional[WindowsPath]=None,
		debug:bool=False
	)->bool:

	# Sets the path of an entry

	identifier_ok:Optional[str]=None
	if isinstance(identifier,UUID):
		identifier_ok="{"+str(identifier)+"}"

	if isinstance(identifier,str):
		identifier_ok=util_filter_identifier(
			identifier,
			return_data=True
		)

	if identifier_ok is None:
		msg="Identifier not valid"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	command=["bcdedit"]

	if isinstance(bcd_store,Path):

		command.extend(["/store",str(bcd_store)])

	command.extend([
		"/set",identifier_ok,
		"path",param_path
	])

	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		msg="Failed to set the path"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	return True

###############################################################################

# WMI Approach

def wmi_init()->wmi_CDispatch:

	# Returns the dispatch wrapper to access the WMI services

	wmi_moniker=r"winmgmts:{impersonationLevel=impersonate}!\\.\root\WMI"

	wmi_services_interface:wmi_CDispatch=wmi_GetObject(wmi_moniker)

	return wmi_services_interface

# Basic read operations

def bcdstore_open(
		wsw:wmi_CDispatch,
		fpath_bcdstore:str="",
		debug:bool=False
	)->Optional[wmi_CDispatch]:

	# Returns the BCD Store as a WMI Object that we can use

	bcd_class=wsw.Get("BcdStore")
	params=bcd_class.Methods_("OpenStore").InParameters.SpawnInstance_()
	params.Properties_.Item("File").Value=fpath_bcdstore
	result=bcd_class.ExecMethod_("OpenStore",params)
	rval=result.Properties_.Item("ReturnValue").Value
	if debug:
		print("OpenStore.ReturnValue:",rval)
	if not rval:
		msg="OpenStore failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return None

	store:wmi_CDispatch=result.Properties_.Item("Store").Value
	# if debug:
	# 	print("typeOf store:",type(store))

	return store

def read_elem_device(
		device:wmi_CDispatch,
		as_alist:bool=False,
		debug:bool=False,
	)->Union[list,Mapping]:

	# Reads a device object (Windows COM Object)

	if as_alist:

		# Return as [(K,V)] list

		itemslist=[]

		for p in device.Properties_:
			itemslist.append(
				(p.Name,p.Value)
			)

		if debug:
			print(
				"Device Data:",
				itemslist
			)
		return itemslist

	# Return as a normal mapping

	itemsmap={}

	for p in device.Properties_:

		itemsmap.update({p.Name:p.Value})

	if debug:
		print(
			"Device Data:",
			itemsmap
		)

	return itemsmap

def read_obj_element(
		bcdobj:wmi_CDispatch,
		bcdobj_elem:wmi_CDispatch,
		raw:bool=False,
		debug:bool=False,
	)->Mapping:

	# Given an Element and its parent Object, extract information form the Element

	elem_type=bcdobj_elem.Properties_.Item("Type").Value
	elem_type_hex=f"0x{elem_type:08X}"

	params=bcdobj.Methods_("GetElement").InParameters.SpawnInstance_()
	params.Properties_.Item("Type").Value=elem_type

	got=bcdobj.ExecMethod_("GetElement",params)
	if not got.Properties_.Item("ReturnValue").Value:
		return {"Element.Type_hex":elem_type_hex}

	elem=got.Properties_.Item("Element").Value

	parent_id=f"{bcdobj.Properties_.Item("Id").Value}"
	parent_type=bcdobj.Properties_.Item("Type").Value
	parent_type_hex=hex(parent_type)

	data_type:Optional[str]=None

	# Gather all properties first and collect the value

	elem_props={
		"Parent.Type_hex":parent_type_hex,
		"Element.Type_hex":elem_type_hex,
	}

	for p in elem.Properties_:

		name=p.Name

		if not debug:
			if name=="StoreFilePath":
				continue

			if name=="ObjectId":
				if p.Value==parent_id:
					continue

		if name in _BCD_ELEMENTS_DATATYPES:

			if data_type is not None:

				elem_props.update({"error":"Aditional type detected"})
				break

			data_type=name

			elem_props.update({"Element.DataType":data_type})

			if data_type in (

					# Boolean
						_BCD_ELEMENTS_DATATYPES[0],
					# String
						_BCD_ELEMENTS_DATATYPES[2],
					# Id
						_BCD_ELEMENTS_DATATYPES[3],
					# Integers
						_BCD_ELEMENTS_DATATYPES[4],
					# Ids
						_BCD_ELEMENTS_DATATYPES[5],
				):
				elem_props.update({data_type:p.Value})

			# Integer
			if data_type==_BCD_ELEMENTS_DATATYPES[1]:

				elem_props.update({data_type:int(p.Value)})

			# Device
			if data_type==_BCD_ELEMENTS_DATATYPES[6]:

				elem_props.update({data_type:read_elem_device(p.Value,debug=debug)})

			continue

		elem_props.update({name:p.Value})

	elem_value=elem_props[data_type]

	# Collect the specific name of the element

	elem_name:Optional[str]=_BCD_ELEMENTS_GLOBAL.get(elem_type_hex)

	if elem_name is None:

		if _BCD_OBJECTS_APPLICATIONS.get(parent_type_hex)=="osloader":

			elem_name=_BCD_ELEMENTS_OSLOADER.get(elem_type_hex)

		if _BCD_OBJECTS_APPLICATIONS.get(parent_type_hex) in ("fwbootmgr","bootmgr"):

			elem_name=_BCD_ELEMENTS_FWBOOTMGR_BOOTMGR.get(elem_type_hex)

	if debug:
		print("_obj.element:",elem_props)

	if elem_name is None:
		return {elem_type_hex:elem_props}

	if raw:
		elem_props.update({"Element.Name":elem_name})
		return {"obj.element":elem_props}

	return {elem_name:elem_value}

def read_obj(
		bcdobj:wmi_CDispatch,
		debug:bool=False
	)->Mapping:

	# General function to enumerate the items (and elements) inside a BCD Object

	obj_identifier=f"{bcdobj.Properties_.Item("Id").Value}"
	obj_type=int(bcdobj.Properties_.Item("Type").Value)
	obj_type_hex=hex(obj_type)

	fields={
		"obj.identifier":obj_identifier,
		"obj.type_int":obj_type,
		"obj.type_hex":obj_type_hex,
	}
	if obj_type_hex in _BCD_OBJECTS_APPLICATIONS:
		fields.update({"obj.type_name":_BCD_OBJECTS_APPLICATIONS[obj_type_hex]})

	result=bcdobj.ExecMethod_("EnumerateElements")
	if not result.Properties_.Item("ReturnValue").Value:
		msg="EnumerateElements failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return fields

	for elem in result.Properties_.Item("Elements").Value:

		fields.update(
			read_obj_element(
				bcdobj,elem,
				debug=debug,
			)
		)

	return fields

def read_objects(
		wsw:wmi_CDispatch,
		bcdstore_obj:Optional[wmi_CDispatch]=None,
		bcdstore_path:str="",
		filter_ids:list=[],
		filter_types:list=[],
		debug:bool=False,
	)->list:

	# Enumerate all objects

	# NOTE:
	# The default BCD store of the system will include objects such as the UEFI
	# firmware objects

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_obj,wmi_CDispatch):
		store=bcdstore_obj
	if store is None:
		if bcdstore_path is not None:
			store=bcdstore_open(
				wsw,fpath_bcdstore=bcdstore_path,
				debug=debug
			)

	params=store.Methods_("EnumerateObjects").InParameters.SpawnInstance_()
	params.Properties_.Item("Type").Value=0

	result=store.ExecMethod_("EnumerateObjects",params)
	rval=result.Properties_.Item("ReturnValue").Value
	if debug:
		print("EnumerateObjects.ReturnValue:",rval)
	if not rval:
		msg="EnumerateObjects failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return []

	items=[]

	filter_out=len(filter_ids)>0

	for obj in result.Properties_.Item("Objects").Value:

		if filter_out:
			obj_id=obj.Properties_.Item("Id").Value
			if obj_id not in filter_ids:
				continue

		items.append(
			read_obj(obj,debug=debug)
		)
		if debug:
			print("\nBCD_Object:",items[-1])

	return items

# Specific read operations

def read_bootmgr_displayorder(
		wsw:wmi_CDispatch,
		bcdstore_obj:Optional[wmi_CDispatch]=None,
		bcdstore_path:str="",
		as_list:bool=False,
		debug:bool=False
	)->Union[Optional[tuple],list]:

	# Reads the displayorder variable from a BOOTMGR object from a BCD Store

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_obj,wmi_CDispatch):
		store=bcdstore_obj
	if store is None:
		if bcdstore_path is not None:
			store=bcdstore_open(
				wsw,fpath_bcdstore=bcdstore_path,
				debug=debug
			)
	if store is None:
		if as_list:
			return []
		return None

	# Pull out the Windows Boot Manager Object

	p=store.Methods_("OpenObject").InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=_BCD_ID_BOOTMGR
	result=store.ExecMethod_("OpenObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="OpenObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if as_list:
			return []
		return None

	bootmgr=result.Properties_.Item("Object").Value

	# Get the current displayorder element from the object

	p=bootmgr.Methods_("GetElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	result=bootmgr.ExecMethod_("GetElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="GetElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if as_list:
			return []
		return None

	element=result.Properties_.Item("Element").Value

	displayorder=element.Properties_.Item("Ids").Value

	if as_list:

		displayorder_list=[]
		for item in displayorder:
			displayorder_list.append(item)

		return displayorder_list

	return displayorder

def read_fwbootmgr_displayorder(
		wsw:wmi_CDispatch,
		bcdstore_sys:Optional[wmi_CDispatch]=None,
		as_list:bool=False,
		debug:bool=False
	)->Union[Optional[tuple],list]:

	# Reads the displayorder variable from a FWBOOTMGR object

	# NOTE:
	# This only works for UEFI systems, and the "bcdstore_obj" CANNOT be a custom
	# BCD store object, it has to be the system's BCD store

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_sys,wmi_CDispatch):
		store=bcdstore_sys
	if store is None:
		store=bcdstore_open(
			wsw,
			debug=debug
		)
	if store is None:
		if as_list:
			return []
		return None

	# Pull out the Firmware Boot Manager Object

	p=store.Methods_("OpenObject").InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=_BCD_ID_FWBOOTMGR
	result=store.ExecMethod_("OpenObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="OpenObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if as_list:
			return []
		return None

	bootmgr=result.Properties_.Item("Object").Value

	# Get the current displayorder element from the object

	p=bootmgr.Methods_("GetElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	result=bootmgr.ExecMethod_("GetElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="GetElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if as_list:
			return []
		return None

	element=result.Properties_.Item("Element").Value

	displayorder=element.Properties_.Item("Ids").Value

	if as_list:

		displayorder_list=[]
		for item in displayorder:
			displayorder_list.append(item)

		return displayorder_list

	return displayorder

# Specific Write Operations

# NOTE, WARNING

def write_bootmgr_default(
		wsw:wmi_CDispatch,
		bcdstore_obj:Optional[wmi_CDispatch]=None,
		bcdstore_path:str="",
		identifier:Optional[str]=None,
		debug:bool=False
	)->bool:

	# Write the BOOTMGR's object "default" variable by adding new data

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_obj,wmi_CDispatch):
		store=bcdstore_obj
	if store is None:
		if bcdstore_path is not None:
			store=bcdstore_open(
				wsw,fpath_bcdstore=bcdstore_path,
				debug=debug
			)
	if store is None:
		return False

	# Pull out the Windows Boot Manager Object

	p=store.Methods_("OpenObject").InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=_BCD_ID_BOOTMGR
	result=store.ExecMethod_("OpenObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="OpenObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	bootmgr=result.Properties_.Item("Object").Value

	if not isinstance(identifier,str):

		# Removal of the "default"

		p=bootmgr.Methods_("DeleteElement").InParameters.SpawnInstance_()
		p.Properties_.Item("Type").Value=0x23000003
		result=bootmgr.ExecMethod_("DeleteElement",p)
		if not result.Properties_.Item("ReturnValue").Value:
			msg="DeleteElement method failed"
			if debug:
				raise Exception(msg)
			print(msg)
			return False

		if debug:
			print("The default in the BOOTMGR has been removed")

		return True

	# Set the specified identifier as the new "default"

	p=bootmgr.Methods_("SetObjectElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x23000003
	p.Properties_.Item("Id").Value=identifier
	result=bootmgr.ExecMethod_("SetObjectElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="SetObjectElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	if debug:
		print(identifier,"is the default in the BOOTMGR")

	return True

def write_bootmgr_displayorder(
		wsw:wmi_CDispatch,
		ids:Union[tuple,list],
		bcdstore_obj:Optional[wmi_CDispatch]=None,
		bcdstore_path:str="",
		addfirst:bool=False,
		remove:bool=False,
		debug:bool=False
	)->bool:

	# Write the BOOTMGR's "displayorder" variable by adding new data

	# NOTE:
	# The identifiers are added as last items by default
	# "remove" will remove the selected elements instead of adding them

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_obj,wmi_CDispatch):
		store=bcdstore_obj
	if store is None:
		if bcdstore_path is not None:
			store=bcdstore_open(
				wsw,fpath_bcdstore=bcdstore_path,
				debug=debug
			)
	if store is None:
		return False

	# Pull out the Windows Boot Manager Object

	p=store.Methods_("OpenObject").InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=_BCD_ID_BOOTMGR
	result=store.ExecMethod_("OpenObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="OpenObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	bootmgr=result.Properties_.Item("Object").Value

	# Get the current displayorder element from the object

	p=bootmgr.Methods_("GetElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	result=bootmgr.ExecMethod_("GetElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="GetElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	# Modify the displayorder

	element=result.Properties_.Item("Element").Value

	displayorder_list=[]
	if (not remove) and addfirst:
		# if debug:
		# 	print("Adding first...")
		for item in ids:
			# if debug:
			# 	print("ADD:",item)
			displayorder_list.append(item)

	# if debug:
	# 	print("Adding from orig list")
	for item in element.Properties_.Item("Ids").Value:

		if item in ids:
			# if debug:
			# 	print("REM:",item)
			continue

		displayorder_list.append(item)

	if (not remove) and (not addfirst):
		# if debug:
		# 	print("Adding last...")
		for item in ids:
			# if debug:
			# 	print("ADD:",item)
			displayorder_list.append(item)

	if debug:
		print("NEW ORDER:",displayorder_list)

	p=bootmgr.Methods_("SetObjectListElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	p.Properties_.Item("Ids").Value=displayorder_list
	result=bootmgr.ExecMethod_("SetObjectListElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="SetObjectListElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	return True

def write_fwbootmgr_displayorder(
		wsw:wmi_CDispatch,
		ids:Union[tuple,list],
		bcdstore_sys:Optional[wmi_CDispatch]=None,
		addfirst:bool=False,
		remove:bool=False,
		debug:bool=False
	)->bool:

	# Write the FWBOOTMGR's displayorder variable by adding new data

	# NOTE:
	# This only works for UEFI systems, and the "bcdstore_obj" CANNOT be a custom
	# BCD store object, it has to be the system's BCD store
	# The identifiers are added as last items by default

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_sys,wmi_CDispatch):
		store=bcdstore_sys
	if store is None:
		store=bcdstore_open(
			wsw,
			debug=debug
		)
	if store is None:
		return False

	# Pull out the Firmware Boot Manager Object

	p=store.Methods_("OpenObject").InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=_BCD_ID_FWBOOTMGR
	result=store.ExecMethod_("OpenObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="OpenObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	bootmgr=result.Properties_.Item("Object").Value

	# Get the current displayorder element from the object

	p=bootmgr.Methods_("GetElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	result=bootmgr.ExecMethod_("GetElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="GetElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	# Modify the displayorder

	element=result.Properties_.Item("Element").Value

	displayorder_list=[]
	if addfirst:
		for item in ids:
			displayorder_list.append(item)

	for item in element.Properties_.Item("Ids").Value:

		if item in ids:
			continue

		displayorder_list.append(item)

	if not addfirst:
		for item in ids:
			displayorder_list.append(item)

	if debug:
		print("NEW ORDER:",displayorder_list)

	p=bootmgr.Methods_("SetObjectListElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x24000001
	p.Properties_.Item("Ids").Value=displayorder_list
	result=bootmgr.ExecMethod_("SetObjectListElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="SetObjectListElement method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		return False

	return True

def write_bootmgr_bootsector_application(
		wsw:wmi_CDispatch,
		app_filepath:str,
		app_description:str,
		app_device:Mapping={},
		bcdstore_obj:Optional[wmi_CDispatch]=None,
		bcdstore_path:str="",
		identifier:Optional[Union[str,UUID]]=None,
		set_as_first:bool=True,
		set_as_default:bool=True,
		debug:bool=False,
	)->Union[bool,Optional[str]]:

	# Creates a bootsector application (Legacy Boot) inside a given BCD store

	# NOTE:
	# The default settings for the device are the equivalent of setting the
	# device field as "boot" in BCDEDIT

	# Get an UUID

	obj_id:Optional[str]=None
	random_id=(identifier is None)
	if random_id:
		obj_id="{"+str(uuid4())+"}"
	if not random_id:
		if isinstance(identifier,UUID):
			obj_id="{"+str(identifier)+"}"
		if isinstance(identifier,str):
			obj_id=util_filter_identifier(identifier,return_data=True)

	if obj_id is None:
		msg="Identifier or UUID not valid"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	# Get the store

	store:Optional[wmi_CDispatch]=None
	if isinstance(bcdstore_obj,wmi_CDispatch):
		store=bcdstore_obj
	if store is None:
		if bcdstore_path is not None:
			store=bcdstore_open(
				wsw,fpath_bcdstore=bcdstore_path,
				debug=debug
			)

	# Create the Object

	m=store.Methods_("CreateObject")
	p=m.InParameters.SpawnInstance_()
	p.Properties_.Item("Id").Value=obj_id
	p.Properties_.Item("Type").Value=0x10400008
	result=store.ExecMethod_("CreateObject",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="CreateObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	bcdobj=result.Properties_.Item("Object").Value

	# Add the Description to the Object

	p=bcdobj.Methods_("SetStringElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x12000004
	p.Properties_.Item("String").Value=app_description
	result=bcdobj.ExecMethod_("SetStringElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="CreateObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	# Add the Path to the Object

	p=bcdobj.Methods_("SetStringElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x12000002
	p.Properties_.Item("String").Value=app_filepath
	result=bcdobj.ExecMethod_("SetStringElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="CreateObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	# Add the Device to the Object

	device_DeviceType=app_device.get("DeviceType",1)

	if not isinstance(device_DeviceType,int):
		msg="DeviceType is not valid"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	p=bcdobj.Methods_("SetDeviceElement").InParameters.SpawnInstance_()
	p.Properties_.Item("Type").Value=0x11000001

	if device_DeviceType==1:

		p.Properties_.Item("DeviceType").Value=1
		p.Properties_.Item("AdditionalOptions").Value=""

	if device_DeviceType==2:

		p.Properties_.Item("DeviceType").Value=2
		p.Properties_.Item("AdditionalOptions").Value=""

		# Path = \Device\HarddiskVolumeX
		p.Properties_.Item("Path").Value=app_device.get("Path")

	result=bcdobj.ExecMethod_("SetDeviceElement",p)
	if not result.Properties_.Item("ReturnValue").Value:
		msg="CreateObject method failed"
		if debug:
			raise Exception(msg)
		print(msg)
		if random_id:
			return None
		return False

	if not write_bootmgr_displayorder(
			wsw,[obj_id],
			bcdstore_obj=store,
			addfirst=set_as_first,
			debug=debug
		):
		if random_id:
			return None
		return False

	if set_as_default:

		if not write_bootmgr_default(
				wsw,
				bcdstore_obj=store,
				identifier=obj_id,
				debug=debug
			):
			if random_id:
				return None
			return False

	# All good...?

	if random_id:
		return obj_id

	return True

# def write_fwbootmgr

if __name__=="__main__":

	pass
