#!/usr/bin/python3

from pathlib import WindowsPath
from secrets import token_hex

from WBCD import (
	cmd_new_bcdstore,
	cmd_write_bootmgr_new_bootsector_application,
)

from WUtils_windows import set_nt60_bootcode

###########################################################################

# Similar to test 1, the difference is that instead of WMI, we are using
# BCDEDIT to create the bootsector application for Grub4DOS

if __name__=="__main__":

	###########################################################################

	dbg_mode=True

	drive="y:"

	descr="Grub4DOS entry (using BCDEDIT commands)"

	path_bcd=r"Y:\Boot\BCD"

	path_bin=r"\grldr.mbr"

	###########################################################################

	set_nt60_bootcode(drive,debug=dbg_mode)

	pl=WindowsPath(path_bcd)
	if pl.is_file():
		pl_parent_new=WindowsPath(drive,f"{pl.parent.name}.{token_hex(8)}")
		pl.parent.rename(pl_parent_new)
		if pl_parent_new.is_dir():
			print(pl.parent,":RENAMED_TO:",pl_parent_new)

	ok=cmd_new_bcdstore(
		drive,
		for_bios=True,
		confirm_only=True,
		debug=dbg_mode
	)
	assert ok

	result=cmd_write_bootmgr_new_bootsector_application(
		descr,path_bin,
		bcdstore_path=WindowsPath(path_bcd),
		debug=dbg_mode
	)
	print("TestResult:",result)
