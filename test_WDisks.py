#!/usr/bin/python3

from WDisks import (
	init_kernel32,
	enum_disks,enum_volumes,
	# from_mountpoint_get_volume,
	enum_drive_roots,
	get_free_mountpoint,
	from_mountpoint_get_volume,
	from_mountpoint_get_volume_ex
)

from WPrivilege import env_gain_extra_priv,query_proc_priv_info

if __name__=="__main__":

	if not query_proc_priv_info():
		print("Must run as admin")
		exit(1)

	env_gain_extra_priv()

	k=init_kernel32()

	print("\n[ DRIVE LETTERS ]")
	enum_drive_roots(k,debug=True)

	nfl=get_free_mountpoint(k,ret_as_path=True)
	print("\nNEXT FREE DRIVE LETTER:",nfl)

	print("\n[ DISKS] ")
	enum_disks(k,debug=True,detail_lvl=2)

	print("\n[ VOLUMES ] ")
	vols=enum_volumes(k,get_spm=True,debug=True)

	print("\n[ VOLUMES (SPM) ]")
	for v in vols:
		print("\nVOLUME:",v)


	target_letter=r"Y:\\"

	volname=from_mountpoint_get_volume(target_letter,debug=True)
	print("\nSPECIFIC VOLUME IN",target_letter,volname)

	voldata=from_mountpoint_get_volume_ex(target_letter,get_spm=True,debug=True)
	print("\nVOLUME DATA FROM",target_letter,voldata)
