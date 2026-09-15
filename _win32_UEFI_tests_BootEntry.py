#!/usr/bin/python3

from win32_UEFI import (

	_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH,

	build_efi_filepathlist_node_harddrive,
	parse_efi_filepathlist_node_harddrive,

	build_efi_filepathlist_node_filepath,
	parse_efi_filepathlist_node_filepath,

	parse_efi_filepathlist_t0x04,

	init_gain_aditional_privileges,
	import_SetFwEnvVarExW,
	hl_set_efi_BootEntry,
	hl_set_efi_BootNext,
)

# test 1
# Hard Drive node

part_num=1
part_startlba=2048
part_size=204800
part_guid='18adb7fa-6cd4-4440-b3f6-5bcf2fe56256'

enc_hdd_node=build_efi_filepathlist_node_harddrive(part_num,part_startlba,part_size,part_guid)

print("\nenc_hdd_node:",enc_hdd_node)

parsed_hdd_node=parse_efi_filepathlist_node_harddrive(enc_hdd_node)

print("\nparsed_hdd_node:",parsed_hdd_node)

# test 2
# Filepath node

filepath="\\EFI\\Boot\\grub2.bootx64.efi"

enc_fpath_node=build_efi_filepathlist_node_filepath(filepath)

print("\nenc_fpath_node:",enc_fpath_node)

parsed_fpath_node=parse_efi_filepathlist_node_filepath(enc_fpath_node,debug=True)

print("\nparsed_fpath_node:",parsed_fpath_node)

# test 3
# FilePathList using Hard Drive node + Filepath node + End of Device path

nodes=parse_efi_filepathlist_t0x04(
	enc_hdd_node+enc_fpath_node+_EFI_NODE_END_OF_ENTIRE_DEVICE_PATH,
	debug=True
)
print("\nNodes:",nodes)

# Test 4 is highly dangerous and it should not be reached unless you know what you're doing
exit(0)

# Test 4
# Uses the previously made nodes to make a real boot entry

init_gain_aditional_privileges()
SetFwEnvVarExW=import_SetFwEnvVarExW()

ok=hl_set_efi_BootEntry(
	SetFwEnvVarExW,"BootFFFF",
	"[NEW] Grub2 EFI",
	[
		enc_hdd_node,
		enc_fpath_node
	],
	assertion=True
)

print("OK?",ok)

# Set BootNext!
ok=hl_set_efi_BootNext(SetFwEnvVarExW,"BootFFFF")
print("OK?",ok)
