#!/usr/bin/python3

from WBCD import (
	wmi_init,
	read_objects,
	cmd_new_bcdstore,
	write_bootmgr_bootsector_application,
)

###########################################################################

# The following test was done using real hardware
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

	descr="Grub4DOS entry created using the WBCD python module"

	path_bcd=r"Y:\Boot\BCD"

	path_bin=r"\grldr.mbr"

	###########################################################################

	ok=cmd_new_bcdstore(
		drive,
		for_bios=True,
		confirm_only=True,
		debug=dbg_mode
	)
	assert ok

	svc=wmi_init()

	identifier=write_bootmgr_bootsector_application(
		svc,path_bin,descr,
		bcdstore_path=path_bcd,
		debug=dbg_mode
	)
	assert (identifier is not None)

	read_objects(
		svc,
		bcdstore_path=path_bcd,
		filter_ids=[identifier],
		debug=dbg_mode,
	)
