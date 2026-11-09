#!/usr/bin/python3

from pathlib import WindowsPath
from secrets import token_hex

from WBCD import (
	cmd_new_bcdstore,
	wmi_init,
	wmi_read_objects,
	wmi_write_bootmgr_new_bootsector_application,
)

from WUtils_windows import set_nt60_bootcode

###########################################################################

# The following test requires real hardware

# I grabbed a USB flash drive and changed its partition table to MBR/DOS,
# marked the partition as primary and copied the essential files for booting
# BOOTMGR and Grub4DOS

# This is basically what's going on when the BIOS (or the UEFI firmware
# through CSM/Legacy support) pick the flash drive:

# BIOS -> USB -> BOOTMGR -> Grub4DOS

# This test creates a BCD bootsector application inside the selected
# flash drive I tested it on a QEMU virtual machine

if __name__=="__main__":

	###########################################################################

	dbg_mode=True

	drive="y:"

	descr="Grub4DOS entry (using WMI)"

	path_bcd=r"Y:\Boot\BCD"

	path_bin=r"\grldr.mbr"

	###########################################################################

	# Overwrite the MBR in the flash drive

	set_nt60_bootcode(drive,debug=dbg_mode)

	# Rename any existing Boot folder in the flash drive

	pl=WindowsPath(path_bcd)
	if pl.is_file():
		pl_parent_new=WindowsPath(drive,f"{pl.parent.name}.{token_hex(8)}")
		pl.parent.rename(pl_parent_new)
		if pl_parent_new.is_dir():
			print(pl.parent,":RENAMED_TO:",pl_parent_new)

	# Create new BCD store

	ok=cmd_new_bcdstore(
		drive,
		for_bios=True,
		confirm_only=True,
		debug=dbg_mode
	)
	assert ok

	# Initialize the WMI service wrapper

	svc=wmi_init()

	# Create the bootsector menu entry in teh BCD store

	identifier=wmi_write_bootmgr_new_bootsector_application(
		svc,path_bin,descr,
		bcdstore_path=path_bcd,
		debug=dbg_mode
	)
	assert (identifier is not None)

	# Show the details about the new entry

	wmi_read_objects(
		svc,
		bcdstore_path=path_bcd,
		filter_ids=[identifier],
		debug=dbg_mode,
	)
