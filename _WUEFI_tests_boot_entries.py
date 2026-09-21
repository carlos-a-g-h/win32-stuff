#!/usr/bin/python3

# DONE

from typing import Optional

from WPrivilege import env_gain_extra_priv

from WUEFI import (

	_EFI_NODE_HARD_DRIVE,
	_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH,

	import_GetFwEnVarW,

	build_efi_filepathlist_node_harddrive,
	parse_efi_filepathlist_node_harddrive,

	build_efi_filepathlist_node_filepath,
	parse_efi_filepathlist_node_filepath,

	parse_efi_filepathlist_t0x04,

	get_evar_BootCurrent,
	get_evar_BootNNNN
)

# Gain elevated privileges

env_gain_extra_priv()

# Import the necessary function (for read access only)

GetFwEnVarW=import_GetFwEnVarW()

# Get the boot entry that corresponds to the current running system

boot_entry_curr=get_evar_BootCurrent(GetFwEnVarW)

print("\nYour system is",boot_entry_curr)

# Get the full contents of the selected boot entry

boot_entry_details=get_evar_BootNNNN(GetFwEnVarW,boot_entry_curr)

print(
	"\nDetails of",
	boot_entry_curr,
	boot_entry_details
)

# Get hard drive node from the filepathlist and grab all the necessary data

partition_number=0
partition_startlba=-1
partition_size=-1
partition_guid:Optional[str]=None

for node in boot_entry_details["filepath_list"]:

	if not node.get("node")==_EFI_NODE_HARD_DRIVE:
		continue

	print("\nSelected node:",node)

	partition_number=node.get("partition_number")
	partition_startlba=node.get("partition_startlba")
	partition_size=node.get("partition_size")
	partition_guid=node.get("partition_guid")

print("partition_number",partition_number)
print("partition_startlba",partition_startlba)
print("partition_size",partition_size)
print("partition_guid",partition_guid)

# Create a HardDrive node

new_node_hdd=build_efi_filepathlist_node_harddrive(
	partition_number,partition_startlba,
	partition_size,partition_guid
)
print(
	"\nNew hard drive node:",
	new_node_hdd
)

# Deserialize the new hard drive node

print(
	"\nThe new hard drive node, but deserialized:",
	parse_efi_filepathlist_node_harddrive(
		new_node_hdd
	)
)

# Create a new filepath node

filepath_str="\\EFI\\Boot\\SomeRandomBootLoader.EFI"

new_filepath_node=build_efi_filepathlist_node_filepath(filepath_str)

print("\nNew filepath node:",new_filepath_node)

# deserialize the new filepath node

print(
	"\nThe new filepath node, but deseralized:",
	parse_efi_filepathlist_node_filepath(
		new_filepath_node
	)
)

# Combine the new hard drive node and the new filepath node to create a new

filepathlist=new_node_hdd+new_filepath_node+_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH

print("New filepathlist:",filepathlist)

# deserialize the new filepathlist

print(
	"\nThe new filepathlist (deserialized):",
	parse_efi_filepathlist_t0x04(filepathlist)
)
