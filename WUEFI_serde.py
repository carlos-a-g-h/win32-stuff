#!/usr/bin/python3

# OK

from WUEFI_symbols import (

	_NULLTERM,
	_ENC_UTF16LE,

	_ERR_UINT8,
	_ERR_UINT16,
	_ERR_UINT32,
	_ERR_UINT64,

	_ELO_NODE_ACPI_HID,
	_ELO_NODE_HARDWARE_PCI,
	_ELO_NODE_MESSAGING_NVMENAMESPACE,
	_ELO_NODE_MEDIA_HARDDRIVE,
	_ELO_NODE_MEDIA_FILEPATH,
	_ELO_NODE_END
)

from WUEFI_utils import (
	is_uint8,
	is_uint16,
	is_uint32,
	is_uint64,
	is_guid
)

from uuid import UUID

from typing import Optional,Union

###############################################################################

# Parsing functions

def parse_efi_BootOrder(
		data_enc:bytes,
		as_list:bool=False,
	)->Union[tuple,list]:

	maxlen=len(data_enc)

	if not maxlen%2==0:
		if as_list:
			return []
		return None

	progress=0

	boot_order=[]

	while True:

		if progress==maxlen:
			break

		p_int=int.from_bytes(
			data_enc[progress:progress+2],
			byteorder="little"
		)
		boot_order.append(f"Boot{p_int:04X}")

		progress=progress+2

	if not progress==maxlen:
		if as_list:
			return []
		return None

	if as_list:
		return boot_order

	return tuple(boot_order)

def parse_efi_elo_fpl_node_head(
		data:bytes,
		data_offset:int=0,
		req_type=-1,
		req_subtype=-1,
		req_nodesize=-1,
	)->Optional[tuple]:

	# EFI LOAD OPTION FilePathList Node Header

	# Returns: ( Type , SubType, Node Size )

	offset=data_offset

	# TYPE      SUBTYPE   END OF HEADER
	# UINT8     UINT8     UINT16
	# Offset 0  Offset 1  Offset 2
	# Size 1    Size 1    Size 2

	# Type

	readmax=1

	x_type=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint8(x_type):
		err_msg=(f"err in TYPE: {_ERR_UINT8}")
		# if assertion:
		# 	raise ValueError(err_msg)
		print(err_msg)
		return None

	if req_type>-1:
		if not x_type==req_type:
			err_msg=(
				"err in TYPE:"
				f" expected {req_type},"
				f" but got {x_type}"
			)
			# if assertion:
			# 	raise ValueError(err_msg)
			print(err_msg)
			return None

	offset=offset+readmax

	# Subtype

	readmax=1

	x_subtype=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint8(x_subtype):
		err_msg=f"err in SUBTYPE: {_ERR_UINT8}"
		# if assertion:
		# 	raise ValueError(err_msg)
		print(err_msg)
		return None

	if req_subtype>-1:
		if not x_subtype==req_subtype:
			err_msg=(
				"err in SUBTYPE:"
				f" expected {req_subtype},"
				f" but got {x_subtype}"
			)
			# if assertion:
			# 	raise ValueError(err_msg)
			print(err_msg)
			return None

	offset=offset+readmax

	# NodeSize

	readmax=2

	x_nodesize=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint16(x_nodesize):
		err_msg=f"err in NODESIZE: {_ERR_UINT16}"
		# if assertion:
		# 	raise ValueError(err_msg)
		print(err_msg)
		return None

	if req_nodesize>-1:
		if not x_nodesize==req_nodesize:
			err_msg=(
				"err in SUBTYPE:"
				f" expected {req_nodesize},"
				f" but got {x_nodesize}"
			)
			# if assertion:
			# 	raise ValueError(err_msg)
			print(err_msg)
			return None

	return (
		x_type,
		x_subtype,
		x_nodesize
	)

def parse_efi_elo_fpl_node_Messaging_NVMeNamespace(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		verify_build:bool=False
	)->Union[bool,dict]:

	# EFI LOAD OPTION FilePathList (Messageing NVMe Namespace Node)

	# NOTE:

	# TYPE       SUBTYPE         END OF HEADER
	# Messaging  NVME Namespace  Node Length
	# UINT8      UINT8           UINT16 LE
	# Offset 0   Offset 1        Offset 2
	# Size 1     Size 1          Size 2
	# Value 3    Value 17        Value 16

	x_nodesize=-1
	offset=data_offset

	if unsafe:
		x_nodesize=16

	if not unsafe:

		header_info=parse_efi_elo_fpl_node_head(
			data,data_offset=offset,
			req_type=3,
			req_subtype=17,
			req_nodesize=16,
			# debug=debug,
		)
		if header_info is None:
			err_msg=(
				"Type and subtype"
				" mismatch on the header"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		x_nodesize=header_info[2]

	offset=offset+4

	# NAMESPACE ID
	# UINT32
	# Offset 4
	# Size 4

	readmax=4

	d_namespace_id=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	offset=offset+readmax

	# NAMESPACE UUID
	# EUI-64
	# Offset 8
	# Size 8

	readmax=8

	d_namespace_uuid=data[offset:offset+readmax].hex(sep="-")

	offset=offset+readmax

	# END OF DATA

	progress=offset-data_offset

	ok=True
	if x_nodesize>-1:
		ok=(progress==x_nodesize)
	if verify_build:
		return ok
	if not ok:
		return {}
	return {
		"node_header":_ELO_NODE_MESSAGING_NVMENAMESPACE,

		"namespace_id":d_namespace_id,
		"namespace_uuid":d_namespace_uuid,

		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_elo_fpl_node_ACPI_HID(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		verify_build:bool=False
	)->Union[bool,dict]:

	# EFI LOAD OPTION FilePathList (ACPI HID Node)

	# NOTE:

	# TYPE              SUBTYPE             END OF HEADER
	# ACPI Device Path  Hard drive subtype  Node Length
	# UINT8             UINT8               UINT16 LE
	# Offset 0          Offset 1            Offset 2
	# Size 1            Size 1              Size 2
	# Bytes 02          Bytes 01            Bytes 0x000c ?

	x_nodesize=-1
	offset=data_offset

	if unsafe:
		x_nodesize=12

	if not unsafe:

		header_info=parse_efi_elo_fpl_node_head(
			data,data_offset=offset,
			req_type=2,
			req_subtype=1,
			req_nodesize=12
		)
		if header_info is None:
			err_msg=(
				"The header does not match with the"
				" standardized header for an ACPI HID node"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		x_nodesize=header_info[2]

	offset=offset+4

	# HID
	# UINT32 LE
	# Offset 4
	# Size 4

	# NOTE:
	# the HID is an EISA Encoded hardware ID

	readmax=4

	d_hid_decimal=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	d_hid_hex=f"{d_hid_decimal:08X}"

	letters=""
	for shift in (10,5,0):
		n=(d_hid_decimal>>shift)&0x1F
		letters=letters+chr(ord("A")+n-1)
	hid=letters+f"{(d_hid_decimal>>16)&0xFFFF:04X}"


	offset=offset+readmax

	# UID
	# UINT32 LE
	# Offset 4
	# Size 4

	readmax=4

	d_uid=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)

	offset=offset+readmax

	progress=offset-data_offset

	ok=True
	if x_nodesize>-1:
		ok=(progress==x_nodesize)
	if verify_build:
		return ok
	if not ok:
		return {}
	return {
		"node_header":_ELO_NODE_ACPI_HID,

		"hid":hid,
		"hid_decimal":d_hid_decimal,
		"hid_hex":d_hid_hex,

		"uid":d_uid,

		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_elo_fpl_node_Hardware_PCI(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		verify_build:bool=False
	)->Union[bool,dict]:

	# EFI LOAD OPTION FilePathList (Hardware PCI Node)

	# NOTE:
	# Fixed size of 6


	x_nodesize=-1
	offset=data_offset

	# TYPE                  SUBTYPE          END OF HEADER
	# Hardware Device Path  PCI Device Path  Node Length
	# UINT8                 UINT8            UINT16 LE
	# Offset 0              Offset 1         Offset 2
	# Size 1                Size 1           Size 2
	# Bytes 01              Bytes 01         Bytes 0x0006

	if unsafe:
		x_nodesize=6

	if not unsafe:

		header_info=parse_efi_elo_fpl_node_head(
			data,
			data_offset=offset,
			req_type=1,
			req_subtype=1,
			req_nodesize=6,
		)
		if header_info is None:
			err_msg=(
				"The given header does not match the"
				" standards for a PCI header"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		x_nodesize=header_info[2]

	offset=offset+4

	# Function
	# UINT8
	# Offset 4
	# Size 1

	readmax=1

	d_function=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	print("d_function:",d_function)
	if not is_uint8(d_function):
		err_msg=f"err in Function: {_ERR_UINT8}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax

	# Device
	# UINT8
	# Offset 5
	# Size 1

	readmax=1

	d_device=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint8(d_device):
		err_msg=f"err in Device: {_ERR_UINT8}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax
	progress=offset-data_offset

	ok=True
	if x_nodesize>-1:
		ok=(progress==x_nodesize)
	if verify_build:
		return ok
	if not ok:
		return {}
	return {
		"node_header":_ELO_NODE_HARDWARE_PCI,

		"function":d_function,
		"device":d_device,

		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_elo_fpl_node_Media_HardDrive(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		verify_build:bool=False
	)->Union[bool,dict]:

	# EFI LOAD OPTION File Path List (Media Hard Drive Node)

	# NOTE:
	# Fixed size of 42

	# TYPE               SUBTYPE             END OF HEADER
	# Media Device Path  Hard drive subtype  Node Length
	# UINT8              UINT8               UINT16 LE
	# Offset 0           Offset 1            Offset 2
	# Size 1             Size 1              Size 2
	# Bytes 04           Bytes 01            Bytes 2A 00

	x_nodesize=-1
	offset=data_offset

	if unsafe:
		x_nodesize=42

	if not unsafe:

		header_info=parse_efi_elo_fpl_node_head(
			data,
			data_offset=offset,
			req_type=4,
			req_subtype=1,
			req_nodesize=42,
		)
		if header_info is None:
			err_msg=(
				"The given header does not match the"
				" standardized Media Hardrive node header"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		x_nodesize=header_info[2]

	offset=data_offset+4

	# Partition Number
	# UINT32 LE
	# Offset 0
	# Size 4

	readmax=4

	d_partnum_ok=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint32(d_partnum_ok):
		err_msg=f"err in PART NUMBER: {_ERR_UINT32}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax

	# Partition start LBA
	# UINT64
	# Size 8

	readmax=8

	d_partstartlba_ok=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint64(d_partstartlba_ok):
		err_msg=f"err in PART START LBA: {_ERR_UINT64}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax

	# Partition size (Logical Blocks btw)
	# UINT64
	# Size 8

	readmax=8

	d_partsize_ok=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint64(d_partsize_ok):
		err_msg=f"err in PART SIZE: {_ERR_UINT64}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax

	# GPT Partition GUID
	# raw 16-byte sig
	# Size 16

	readmax=16

	tmp:Optional[UUID]=None
	try:
		tmp=UUID(
			bytes_le=data[
				offset:offset+readmax
			]
		)
	except Exception as exc:
		err_msg=f"err in PART GUID: {exc}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	d_partguid_ok=str(tmp)

	offset=offset+readmax

	# MBR Type
	# UINT8
	# Size 1

	readmax=1

	d_mbrtype_ok=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint8(d_mbrtype_ok):
		err_msg=f"err in MBR TYPE: {_ERR_UINT8}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax

	# Signature Type
	# UINT8
	# Size 1

	readmax=1

	d_sigtype_ok=int.from_bytes(
		data[offset:offset+readmax],
		byteorder="little"
	)
	if not is_uint8(d_sigtype_ok):
		err_msg=f"err in SIGN TYPE: {_ERR_UINT8}"
		print(err_msg)
		if verify_build:
			return False
		return {}

	offset=offset+readmax
	progress=offset-data_offset

	ok=True
	if x_nodesize>-1:
		ok=(progress==x_nodesize)
	if verify_build:
		return ok
	if not ok:
		return {}
	return {
		"node_header":_ELO_NODE_MEDIA_HARDDRIVE,

		"partition_number":d_partnum_ok,
		"partition_startlba":d_partstartlba_ok,
		"partition_size":d_partsize_ok,
		"partition_guid":d_partguid_ok,

		"mbrtype":d_mbrtype_ok,
		"sigtype":d_sigtype_ok,

		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_elo_fpl_node_Media_FilePath(
		data:bytes,
		data_offset:int=0,
		unsafe:bool=False,
		verify_build:bool=False,
	)->Union[bool,dict]:

	# EFI LOAD OPTION File Path List (Media Filepath Node)

	# NOTE:
	# TYPE               SUBTYPE           END OF HEADER
	# Media Device Path  Filepath subtype  Node Length
	# UINT8              UINT8             UINT16 LE
	# Offset 0           Offset 1          Offset 2
	# Size 1             Size 1            Size 2
	# Bytes 04           Bytes 04          Bytes ???

	offset=data_offset

	x_nodesize=-1
	if not unsafe:

		header_info=parse_efi_elo_fpl_node_head(
			data,
			data_offset=offset,
			req_type=4,
			req_subtype=4,
		)
		if header_info is None:

			err_msg=(
				"The header does not match"
				" with the corresponding header"
				" for a Media Filepath Node"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		x_nodesize=header_info[2]

	offset=offset+4

	# Filepath
	# UINT32 LE NT
	# Offset 4
	# Size ?

	d_filepath_end=-1

	has_nodesize=(not x_nodesize==-1)

	if has_nodesize:
		d_filepath_end=x_nodesize-4

	if not has_nodesize:
		d_filepath_end=data[offset:].find(_NULLTERM)
		if d_filepath_end==-1:
			err_msg=(
				"err in filepath field:"
				" not null terminated"
			)
			print(err_msg)
			if verify_build:
				return False
			return {}

		if not d_filepath_end%2==0:
			d_filepath_end=d_filepath_end+1

	d_filepath=data[offset:offset+d_filepath_end-2]

	d_filepath_ok=d_filepath.decode(_ENC_UTF16LE)

	offset=offset+d_filepath_end

	progress=offset-data_offset

	ok=True
	if x_nodesize>-1:
		ok=(progress==x_nodesize)
	if verify_build:
		return ok
	if not ok:
		return {}
	return {
		"node_header":_ELO_NODE_MEDIA_FILEPATH,

		"filepath":d_filepath_ok,

		"payload_size":progress,
		"payload_end":data_offset+progress
	}

def parse_efi_elo_filepathlist(
		data:bytes,
		data_offset:int=0,
		debug:bool=False,
		skip_fixed_size_nodes:bool=False,
	)->list:

	offset=data_offset
	maxlen=len(data)

	nodes=[]

	cnode={}
	cnode_headertype=-1
	cnode_head:Optional[bytes]=None
	# -1 = unknown header
	# 0 = fixed header
	# 1 = variable header
	# 2 = end node

	node_index=-1
	corrupted=False

	# known node sizes

	known_nsizes={
		_ELO_NODE_ACPI_HID:12,
		_ELO_NODE_HARDWARE_PCI:6,
		_ELO_NODE_MESSAGING_NVMENAMESPACE:16,
		_ELO_NODE_MEDIA_HARDDRIVE:42,
	}

	# Known parsers for fixed size nodes

	known_parsers_fsn={
		_ELO_NODE_ACPI_HID:parse_efi_elo_fpl_node_ACPI_HID,
		_ELO_NODE_HARDWARE_PCI:parse_efi_elo_fpl_node_Hardware_PCI,
		_ELO_NODE_MESSAGING_NVMENAMESPACE:parse_efi_elo_fpl_node_Messaging_NVMeNamespace,
		_ELO_NODE_MEDIA_HARDDRIVE:parse_efi_elo_fpl_node_Media_HardDrive,
	}

	# Known parsers for variable size nodes

	known_parsers_vsn={
		_ELO_NODE_MEDIA_FILEPATH:parse_efi_elo_fpl_node_Media_FilePath
	}

	while True:

		if isinstance(cnode_head,bytes):
			cnode_head=None
		if not cnode_headertype==-1:
			cnode_headertype=-1
		if not len(cnode)==0:
			cnode.clear()

		if corrupted:
			print("This FilepathList is corrupted")
			break

		if debug:
			print(
				"\nPROGRESS:",
					offset,"/",maxlen
			)

		if offset==maxlen:
			break

		if offset>maxlen:
			break

		if debug:
			print("REMAINING:",data[offset:])

		if data[offset:offset+4] in (
				_ELO_NODE_ACPI_HID,
				_ELO_NODE_HARDWARE_PCI,
				_ELO_NODE_MESSAGING_NVMENAMESPACE,
				_ELO_NODE_MEDIA_HARDDRIVE
			):
			cnode_head=data[offset:offset+4]
			cnode_headertype=0

		if cnode_headertype==-1:

			if data[offset:offset+2] in (
					_ELO_NODE_MEDIA_FILEPATH
				):
				cnode_headertype=1
				cnode_head=data[offset:offset+2]

		if cnode_headertype==-1:
			if data[offset:offset+4] == _ELO_NODE_END:
				cnode_headertype=2


		if not cnode_headertype==-1:

			if cnode_headertype==0:

				# Fixed size node

				print(
					"SELECTED PARSER",
					known_parsers_fsn[cnode_head]
				)

				if not skip_fixed_size_nodes:
					cnode.update(
						known_parsers_fsn[cnode_head](
							data,data_offset=offset,
							unsafe=True,
							verify_build=False
						)
					)

				ok=False
				if skip_fixed_size_nodes:
					ok=known_parsers_fsn[cnode_head](
						data,data_offset=offset,
						unsafe=True,
						verify_build=True
					)

				payload_size=0

				if skip_fixed_size_nodes:
					if not ok:
						corrupted=True
						continue

					payload_size=known_nsizes[cnode_head]
					node_index=node_index+1

				if not skip_fixed_size_nodes:
					if len(cnode)==0:
						corrupted=True
						continue

					payload_size=cnode["payload_size"]
					node_index=node_index+1
					cnode.update({"node_index":node_index})
					nodes.append(cnode.copy())

				offset=offset+payload_size
				continue

			if cnode_headertype==1:

				# Variable size node

				print(
					"SELECTED PARSER",
					known_parsers_vsn[cnode_head]
				)

				cnode.update(
					known_parsers_vsn[cnode_head](
						data,data_offset=offset,
						unsafe=False
					)
				)
				if len(cnode)==0:
					corrupted=True
					break

				payload_size=cnode["payload_size"]
				offset=offset+payload_size
				node_index=node_index+1
				cnode.update({"node_index":node_index})
				nodes.append(cnode.copy())
				continue

			if cnode_headertype==2:

				# ENd of filepathlist node

				print("REACHED END OF FILE_PATH_LIST")

				node_index=node_index+1
				nodes.append({
					"header":_ELO_NODE_END,
					"node_index":node_index,
					"payload_size":4,
					"payload_end":offset+4
				})

				break

			if debug:
				print(
					"The next node and beyond"
					" cannot be parsed by this program"
				)

		payload_size=len(data[offset:])

		nodes.append({
			"raw":data[offset:],
			"payload_size":payload_size,
			"payload_end":payload_size+offset
		})

		break

	return nodes

###############################################################################

# Serializers

def build_efi_BootOrder(
		boot_order:list,
		verify_build:bool=False
	)->Optional[bytes]:

	boot_order_ok=b""

	data_int:Optional[int]=None
	err_msg:Optional[str]=None

	for entry in boot_order:

		data_int=None

		if isinstance(entry,str):

			if not entry.startswith("Boot"):
				err_msg=f"Entry not valid: {entry}"
				break

			entry_len=len(entry)
			if not entry_len>4:
				err_msg=f"Entry has invalid length: {entry_len}"
				break

			data_str:str=entry[4:]

			if not data_str.isdigit():
				err_msg=True
				break

			data_int=int(f"0x{data_str}",16)

		if isinstance(entry,int):

			data_int=entry

		if data_int is None:
			err_msg=True
			break

		if not is_uint16(data_int):
			err_msg=True
			break

		boot_order_ok=boot_order_ok+data_int.to_bytes(
			length=2,
			byteorder="little"
		)

	if err_msg is not None:
		print(err_msg)
		if verify_build:
			return False
		return None

	if verify_build:
		return True

	return boot_order_ok

def build_spec_EISAID_to_HID(
		eisa_id:str,
		get_hid_int:bool=False,
		get_hid_hex:bool=False
	)->Optional[Union[bytes,tuple]]:

	# Turns an EISA ID to an HID

	if not len(eisa_id)==7:
		print("EISA ID must be of length 7")
		return None

	vendor=eisa_id[0:3].upper()

	if not vendor.isalpha():
		print("Vendor is not alphanumeric")
		return None

	product=int(eisa_id[3:],16)

	lanumbs=[]

	for letter in vendor:
		lanumbs.append(
			ord(letter)-ord("A")+1
		)

	print(lanumbs)

	vendor_code=(
		(lanumbs[0]<<10)
		| (lanumbs[1]<<5)
		| (lanumbs[2])
	)

	hid_int=(
		(product<<16)
		| vendor_code
	)

	hid_bytes=hid_int.to_bytes(
		length=4,
		byteorder="little"
	)
	result=[hid_bytes]
	if get_hid_int:
		result.append(hid_int)
	if get_hid_hex:
		result.append(hex(hid_int))

	if not len(result)==1:
		return tuple(result)

	return result[0]

def build_efi_elo_Description(data:str):

	# Builds the description blob for the EFI LOAD OPTION

	# NOTE:
	# The Description field is located after FilePathListLength and before
	# FilePathList

	return data.encode(_ENC_UTF16LE)+_NULLTERM

def build_efi_elo_fpl_node_ACPI_HID(
		eisa_id:str,uid:int,
		verify_build:bool=False
	)->Union[Optional[bytes],bool]:

	# Builds an ACPI HID node for a FilePathList (EFI_LOAD_OPTION)

	# NOTE:
	# Usually the most common EISA value is just PNP0A03, but I can't put that
	# in here as a default value, I'm not an expert on UEFI (yet)

	# TYPE              SUBTYPE   END OF HEADER
	# ACPI Device Path  Hardware  Node Length
	# UINT8             UINT8     UINT16 LE
	# Offset 0          Offset 1  Offset 2
	# Size 1            Size 1    Size 2
	# Value 2           Value 1   Value 12

	payload=_ELO_NODE_ACPI_HID

	# HID (encoded EISA ID)
	# UINT32
	# Offset 4
	# Size 4

	hid_bin=build_spec_EISAID_to_HID(eisa_id)
	if hid_bin is None:
		print("Failed to turn EISA ID into HID")
		if verify_build:
			return False
		return None

	payload=payload+hid_bin

	# UID
	# UINT32
	# Offset 8
	# Size 4

	if not is_uint32(uid):
		if verify_build:
			return False
		return None

	payload=payload+uid.to_bytes(
		length=4,
		byteorder="little"
	)

	if not len(payload)==12:
		if verify_build:
			return False
		return None

	if verify_build:
		return True
	return payload

def build_efi_elo_fpl_node_Hardware_PCI(
		function:int,device:int,
		verify_build:bool=False
	)->Union[Optional[bytes],bool]:

	# Builds a Hardware PCI node for a FilePathList (EFI_LOAD_OPTION)

	# TYPE      SUBTYPE   END OF HEADER
	# Hardware  PCI       Node Length
	# UINT8     UINT8     UINT16 LE
	# Offset 0  Offset 1  Offset 2
	# Size 1    Size 1    Size 2
	# Value 1   Value 1   Value 6

	payload=_ELO_NODE_HARDWARE_PCI

	# Function
	# UINT 8
	# Offset 4
	# Size 1

	if not is_uint8(function):
		if verify_build:
			return False
		return None

	payload=payload+function.to_bytes(
		length=1,
		byteorder="little"
	)

	# Device
	# UINT 8
	# Offset 5
	# Size 1

	if not is_uint8(device):
		if verify_build:
			return False
		return None

	payload=payload+device.to_bytes(
		length=1,
		byteorder="little"
	)

	if not len(payload)==6:
		if verify_build:
			return False
		return None

	if verify_build:
		return True

	return payload

def build_efi_elo_fpl_node_Media_HardDrive(
		part_num:int,
		part_startlba:int,
		part_size:int,
		part_guid:Union[str,UUID],
		mbrtype:int=2,
		sigtype:int=2,
		verify_build:bool=False
	)->Optional[bytes]:

	# Builds a FilePathList Media Hard Drive node (EFI_LOAD_OPTION)

	# NOTE:

	# The default values for MBRType and Signature Type are for GUID Partition
	# table disks, which is what SHOULD be expected for any hardrive hosting an
	# ESP with the EFI file

	# The easiest way to get the necessary arguments for this function is to get
	# them from an existing Hard drive node of an existing Bootentry, like, for
	# example, the current boot entry

	# TYPE               SUBTYPE             END OF HEADER
	# Media Device Path  Hard drive subtype  Node Length
	# UINT8              UINT8               UINT16 LE
	# Offset 0           Offset 1            Offset 2
	# Size 1             Size 1              Size 2
	# Value 4            Value 1             Value 42

	payload=_ELO_NODE_MEDIA_HARDDRIVE

	# Partition Number
	# UINT32 LE
	# Offset 0
	# Size 4

	if not is_uint32(part_num):
		if verify_build:
			return False
		return None

	payload=payload+part_num.to_bytes(
		length=4,
		byteorder="little"
	)

	# Partition start LBA
	# UINT64
	# Size 8

	if not is_uint64(part_startlba):
		if verify_build:
			return False
		return None

	payload=payload+part_startlba.to_bytes(
		length=8,
		byteorder="little"
	)

	# Partition size (Logical Blocks btw)
	# UINT64
	# Size 8

	if not is_uint64(part_size):
		if verify_build:
			return False
		return None

	payload=payload+part_size.to_bytes(
		length=8,
		byteorder="little"
	)

	# GPT Partition GUID
	# raw 16-byte sig
	# Size 16

	part_guid_ok=b""

	if isinstance(part_guid,UUID):
		part_guid_ok=part_guid.bytes_le

	if isinstance(part_guid,str):
		if not is_guid(part_guid):
			if verify_build:
				return False
			return None

		part_guid_ok=UUID(part_guid).bytes_le

	if len(part_guid_ok)==0:
		if verify_build:
			return False
		return None

	payload=payload+part_guid_ok

	# MBR Type  Signature Type
	# UINT8     UINT8
	# Size 1    Size 1

	if not is_uint8(mbrtype):
		if verify_build:
			return False
		return None

	payload=payload+mbrtype.to_bytes(
		length=1,
		byteorder="little"
	)

	if not is_uint8(sigtype):
		if verify_build:
			return False
		return None

	payload=payload+sigtype.to_bytes(
		length=1,
		byteorder="little"
	)

	if not len(payload)==42:
		if verify_build:
			return False
		return None

	if verify_build:
		return True

	return payload

def build_efi_elo_fpl_node_Media_FilePath(
		filepath:str,
		verify_build:bool=False
	)->Optional[bytes]:

	# Builds Filepath node for a FilePathList(EFI LOAD OPTION)

	filepath_ok=filepath.encode(_ENC_UTF16LE)+_NULLTERM

	nodelen=4+len(filepath_ok)

	# TYPE               SUBTYPE           END OF HEADER
	# Media Device Path  Filepath subtype  Node Length
	# UINT8              UINT8             UINT16 LE
	# Offset 0           Offset 1          Offset 2
	# Size 1             Size 1            Size 2
	# Bytes 04           Bytes 04

	payload=_ELO_NODE_MEDIA_FILEPATH+nodelen.to_bytes(
		length=2,
		byteorder="little"
	)

	print("HEADERSIZE:",len(payload))
	print("HEADER:",payload)

	# Filepath
	# UINT32 LE NT
	# Offset 0
	# Size ?

	payload=payload+filepath_ok

	if not len(payload)==nodelen:
		if verify_build:
			return False
		return None

	if verify_build:
		return True

	return payload
