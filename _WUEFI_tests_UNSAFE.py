#!/usr/bin/python3

# NOT DONE

from typing import Optional

from uuid import UUID

from WPrivilege import env_gain_extra_priv

from WUEFI import (

	_EFI_NODE_HARD_DRIVE,

	env_gain_aditional_privileges,

	import_GetFwEnVarW,

	import_SetFwEnvVarExW,

	get_evar_BootCurrent,

	get_evar_BootNNNN,

	get_evar_BootOrder,

	set_evar_BootNext,

	set_evar_BootOrder,

	set_evar_BootNNNN,

	build_efi_filepathlist_node_harddrive,

	build_efi_filepathlist_node_filepath
)

# Boot entry name and EFI filepath

const_name="BootF000"

const_description="Grub2 EFI (BootF000)"

const_filepath="\\EFI\\Boot\\grub2.bootx64.efi"

# Get aditional privileges

env_gain_aditional_privileges()

# Import functionality

GetFwEnVarW=import_GetFwEnVarW()

SetFwEnvVarExW=import_SetFwEnvVarExW()

# Get the boot entry of the current system

boot_current_name=get_evar_BootCurrent(GetFwEnVarW)

print(
	"\nBootCurrent (name):",
	boot_current_name
)

boot_current_ok=get_evar_BootNNNN(
	GetFwEnVarW,
	boot_current_name
)

print(
	f"\nContents of {boot_current_name}",
	boot_current_ok
)

# Grab specific data from the hard drive node from the current system

part_numb=0
part_slba=-1
part_size=-1
part_guid:Optional[str]=None

for n in boot_current_ok["filepath_list"]:

	if not n.get("node")==_EFI_NODE_HARD_DRIVE:
		continue

	print("\nNODE:",n)

	part_numb=n.get("partition_number")
	part_slba=n.get("partition_startlba")
	part_size=n.get("partition_size")
	part_guid=n.get("partition_guid")

print("partition number",part_numb)
print("partition start lba",part_slba)
print("partition size",part_size)
print("partition guid",part_guid)

assert part_numb>0
assert part_slba>-1
assert part_size>-1
assert UUID(part_guid)

# Create a new filepathlist

node_filepath=build_efi_filepathlist_node_filepath(
	const_filepath,
	verify_build=True
)
if node_filepath is None:
	print("\nINVALID FILEPATH NODE")
	exit(1)

node_harddive=build_efi_filepathlist_node_harddrive(
	part_numb,part_slba,
	part_size,part_guid,
	verify_build=True
)
if node_harddive is None:
	print("\nINVALID HARD DRIVE NODE")
	exit(1)

if not set_evar_BootNNNN(
	SetFwEnvVarExW,
	const_name,
	const_description,
	nodes=[node_harddive,node_filepath]
):
	print("\nFAILED TO CREATE BOOT ENTRY")
	exit(1)

# Place the new boot entry as the first option

boot_order_lst=get_evar_BootOrder(GetFwEnVarW,as_list=True)

boot_order_new=[const_name]

boot_order_new.extend(boot_order_lst)

print("\nNew boot order:",boot_order_new)

if not set_evar_BootOrder(SetFwEnvVarExW,boot_order_new):
	print("\nFAILED TO SET NEW BOOT ORDER")
	exit(1)

# Set the new boot order as the next system to boot

if not set_evar_BootNext(SetFwEnvVarExW,const_name):
	print("\nFAILED TO SET BOOTNEXT VAR")
	exit(1)

print("DONE! Reboot the PC")
