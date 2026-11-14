#!/usr/bin/python3

from WDisks import init_kernel32,enum_disks,enum_volumes

from WPrivilege import env_gain_extra_priv,query_proc_priv_info

if __name__=="__main__":

	if not query_proc_priv_info():
		print("Must run as admin")
		exit(1)

	env_gain_extra_priv()

	k=init_kernel32()

	print("\n[ DISKS] ")

	enum_disks(k,debug=True,detail_lvl=2)

	print("\n[ VOLUMES ] ")

	vols=enum_volumes(k,get_spm=True,debug=True)

	print("\n[ VOLUMES (SPM) ]")

	for v in vols:

		print("\nVOLUME:",v)
