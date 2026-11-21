#!/usr/bin/python3

# Query disk information using ctypes and mount volumes

import ctypes
from ctypes import wintypes,WinDLL,WinError

# from pathlib import WindowsPath

from typing import Mapping,Optional,Union
from uuid import UUID

from WUtils_windows import (
	wsubproc,
	from_text_extract_identifier as from_str_extract_uuid
)

_DRIVELETTERS="ABCDEFGHIJKLMNOPQRSTUVWXYZ"

_IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
OPEN_EXISTING = 3

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
GENERIC_READ = 0x80000000

VOLUME_NAME_GUID = 0x1

ERROR_ACCESS_DENIED=5
ERROR_FILE_NOT_FOUND=2
ERROR_NO_MORE_FILES=18
ERROR_MORE_DATA=234
ERROR_INSUFFICIENT_BUFFER=122
ERROR_UNRECOGNIZED_VOLUME=1005

PART_STYLES=(
	"MBR", # 0
	"GPT", # 1
	"RAW" # 2
)

PART_GUID_TYPES={
	"c12a7328-f81f-11d2-ba4b-00a0c93ec93b":"EFI System Partition",
	"e3c9e316-0b5c-4db8-817d-f92df00215ae":"Microsoft Reserverd",
	"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7":"Microsoft Basic Data",
	"de94bba4-06d1-4d40-a16a-bfd50179d6ac":"Windows Recovery",
}

class DISK_EXTENT(ctypes.Structure):
	_fields_ = [
		("DiskNumber", wintypes.DWORD),
		("StartingOffset", ctypes.c_longlong),
		("ExtentLength", ctypes.c_longlong),
	]

class DRIVE_LAYOUT_INFORMATION_MBR(ctypes.Structure):
	_fields_ = [
		("Signature", wintypes.DWORD),
		("CheckSum", wintypes.DWORD),
	]


class DRIVE_LAYOUT_INFORMATION_GPT(ctypes.Structure):
	_fields_ = [
		("DiskId", ctypes.c_ubyte * 16),  # GUID bytes
		("StartingUsableOffset", ctypes.c_longlong),
		("UsableLength", ctypes.c_longlong),
		("MaxPartitionCount", wintypes.DWORD),
	]


class DRIVE_LAYOUT_UNION(ctypes.Union):
	_fields_ = [
		("Mbr", DRIVE_LAYOUT_INFORMATION_MBR),
		("Gpt", DRIVE_LAYOUT_INFORMATION_GPT),
	]


class DRIVE_LAYOUT_INFORMATION_EX_HEADER(ctypes.Structure):
	_fields_ = [
		("PartitionStyle", wintypes.DWORD),
		("PartitionCount", wintypes.DWORD),
		("Layout", DRIVE_LAYOUT_UNION),
	]

def init_kernel32()->WinDLL:

	# initialize the WIn32 API client for all the functions that this module has
	# to deal with

	k32=WinDLL("kernel32",use_last_error=True)

	# CloseHandle

	k32.CloseHandle.argtypes=[wintypes.HANDLE]
	k32.CloseHandle.restype=wintypes.BOOL

	# CreateFileW

	k32.CreateFileW.argtypes=[
		wintypes.LPCWSTR,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.DWORD,
		wintypes.DWORD,
		wintypes.HANDLE
	]
	k32.CreateFileW.restype=wintypes.HANDLE

	# DeviceIoControl

	k32.DeviceIoControl.argtypes=[
		wintypes.HANDLE,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.DWORD,
		wintypes.LPVOID,
		wintypes.DWORD,
		ctypes.POINTER(wintypes.DWORD),
		wintypes.LPVOID
	]
	k32.DeviceIoControl.restype=wintypes.BOOL

	# FindFirstVolumeW

	k32.FindFirstVolumeW.argtypes = [
		wintypes.LPWSTR,
		wintypes.DWORD
	]
	k32.FindFirstVolumeW.restype = wintypes.HANDLE

	# FirstNextVolumeW

	k32.FindNextVolumeW.argtypes = [
		wintypes.HANDLE,
		wintypes.LPWSTR,
		wintypes.DWORD
	]
	k32.FindNextVolumeW.restype = wintypes.BOOL

	# FindVolumeClose

	k32.FindVolumeClose.argtypes = [wintypes.HANDLE]
	k32.FindVolumeClose.restype = wintypes.BOOL

	# GetFinalPathNameByHandleW

	k32.GetFinalPathNameByHandleW.argtypes = [
		wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD
	]
	k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

	# GetLogicalDriveStrings

	k32.GetLogicalDriveStringsW.argtypes=[
		wintypes.DWORD,
		wintypes.LPWSTR
	]
	k32.GetLogicalDriveStringsW.restype = wintypes.DWORD

	# GetDiskFreeSpaceExW

	k32.GetDiskFreeSpaceExW.argtypes=[
		wintypes.LPCWSTR,
		ctypes.POINTER(ctypes.c_ulonglong),
		ctypes.POINTER(ctypes.c_ulonglong),
		ctypes.POINTER(ctypes.c_ulonglong),
	]
	k32.GetDiskFreeSpaceExW.restype=wintypes.BOOL

	# GetVolumeInformationW

	k32.GetVolumeInformationW.argtypes = [
		wintypes.LPCWSTR,             # root path
		wintypes.LPWSTR,              # volume label buffer
		wintypes.DWORD,               # label buffer size
		ctypes.POINTER(wintypes.DWORD),  # serial number
		ctypes.POINTER(wintypes.DWORD),  # max component length
		ctypes.POINTER(wintypes.DWORD),  # filesystem flags
		wintypes.LPWSTR,              # filesystem name buffer
		wintypes.DWORD,               # filesystem buffer size
	]
	k32.GetVolumeInformationW.restype = wintypes.BOOL

	# GetVolumeNameForVolumeMountPointW

	k32.GetVolumeNameForVolumeMountPointW.argtypes = [
		wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD
	]
	k32.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL

	# GetVolumePathNamesForVolumeNameW

	k32.GetVolumePathNamesForVolumeNameW.argtypes=[
		wintypes.LPCWSTR,
		wintypes.LPWSTR,
		wintypes.DWORD,
		ctypes.POINTER(wintypes.DWORD)
	]
	k32.GetVolumePathNamesForVolumeNameW.restype=wintypes.BOOL

	# GetVolumePathNameW

	k32.GetVolumePathNameW.argtypes = [
		wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD
	]
	k32.GetVolumePathNameW.restype = wintypes.BOOL

	# GetWindowsDirectoryW

	k32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
	k32.GetWindowsDirectoryW.restype = wintypes.UINT

	return k32

def util_parse_MULTI_SZ(buf:str,nv:int)->list:

	text=buf[:nv]
	parts=text.split("\0")
	if len(parts)==1:
		if parts[0]==text:
			return parts

	items=[]
	for p in parts:
		if len(p)==0:
			continue
		items.append(p)

	return items

def util_winerror(
		return_code:bool=False,
		debug:bool=False
	)->Optional[int]:

	error=ctypes.get_last_error()
	if debug:
		raise WinError(error)

	print("ERROR:",error)

	if return_code:
		return error

	return None

###############################################################################

# Disks and partitions

def get_disk_partitions(
		kernel32:Optional[WinDLL],
		disk_index:int,
		debug:bool=False
	)->Optional[list]:

	# From a disk index, get the partitions

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.CloseHandle.argtypes=[wintypes.HANDLE]
		k32.CloseHandle.restype=wintypes.BOOL

		k32.CreateFileW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE
		]
		k32.CreateFileW.restype=wintypes.HANDLE

		k32.DeviceIoControl.argtypes=[
			wintypes.HANDLE,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPVOID
		]
		k32.DeviceIoControl.restype=wintypes.BOOL

	path=rf"\\.\PhysicalDrive{disk_index}"

	handle=k32.CreateFileW(
		path,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		0,
		None
	)
	if handle==INVALID_HANDLE_VALUE:
		util_winerror(debug=debug)
		return None

	bsize_inc=4096
	bsize_max=1024*1024
	bsize=bsize_inc

	werror=0
	oversized=False

	buffer_ok=None
	partition_count=-1

	while True:

		buffer=ctypes.create_string_buffer(bsize)
		rbytes=wintypes.DWORD()

		ok=k32.DeviceIoControl(
			handle,
			_IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			None,
			0,
			buffer,
			bsize,
			ctypes.byref(rbytes),
			None
		)
		if ok:

			buffer_ok=buffer

			partition_count=int.from_bytes(
				buffer.raw[4:8],
				byteorder="little"
			)

			break

		werror=ctypes.get_last_error()
		# ERROR 122 = Insufficient buffer
		# ERROR 234 = More data required
		if werror not in (ERROR_INSUFFICIENT_BUFFER,ERROR_MORE_DATA):
			break

		if debug:
			print("INCREASING BUFFER SIZE...")

		bsize=bsize+bsize_inc
		oversized=(bsize>bsize_max)
		if oversized:
			break

	# Loop end

	if oversized or (not werror==0):

		k32.CloseHandle(handle)

		if oversized:
			m="The next buffer will be too oversized"
			if debug:
				raise Exception(m)

			print(m)
			return None

		if debug:
			raise WinError(werror)

		print("WinError:",werror)
		return None

	entry_offset=48

	# PARTITION_INFORMATION_EX on 64-bit Windows
	entry_size=144

	partitions=[]

	for idx in range(partition_count):

		offset=entry_offset+idx*entry_size

		part_style=int.from_bytes(
			# buffer_ok.raw[offset:offset+8],
			buffer_ok.raw[offset:offset+4],
			byteorder="little",
		)
		part_active=False
		if part_style==0:
			part_active=bool(buffer_ok.raw[offset+33])
	
		part_start=int.from_bytes(
			buffer_ok.raw[offset+8:offset+16],
			byteorder="little",
			signed=True
		)
		part_len=int.from_bytes(
			buffer_ok.raw[offset+16:offset+24],
			byteorder="little",
			signed=True
		)
		part_num=int.from_bytes(
			buffer_ok.raw[offset+24:offset+28],
			byteorder="little",
		)

		if not (part_num>0 and part_len>0):
			continue

		part_style_name=None
		if part_style in range(-1,len(PART_STYLES)):
			part_style_name=PART_STYLES[part_style]

		part_guid=None
		part_guid_name=None
		if part_style==1:
			part_guid=str(UUID(bytes_le=buffer_ok.raw[offset+32:offset+48]))
			part_guid_name=PART_GUID_TYPES.get(part_guid)

		partitions.append({
			"part_num":part_num,
			"part_start":part_start,
			"part_len":part_len,
			"part_active":part_active,
			"part_style":part_style,
			"part_style_name":part_style_name,
			"part_guid":part_guid,
			"part_guid_name":part_guid_name,
		})

		if debug:
			print("FOUND PART:",partitions[-1])

	k32.CloseHandle(handle)

	return partitions

def get_disk(
		kernel32:Optional[WinDLL],
		disk_index:int,
		return_as_path:bool=False,
		return_partitions:bool=False,
		debug:bool=False
	)->Optional[Union[int,str,tuple]]:

	# Get a disk from an int
	# Returns None if the disk doesn't exist

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.CloseHandle.argtypes=[wintypes.HANDLE]
		k32.CloseHandle.restype=wintypes.BOOL

		k32.CreateFileW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE
		]
		k32.CreateFileW.restype=wintypes.HANDLE

		k32.DeviceIoControl.argtypes=[
			wintypes.HANDLE,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPVOID
		]
		k32.DeviceIoControl.restype=wintypes.BOOL

	path=rf"\\.\PhysicalDrive{disk_index}"

	handle=k32.CreateFileW(
		path,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		0,
		None
	)
	if handle==INVALID_HANDLE_VALUE:
		if debug:
			util_winerror(debug=True)
		return None

	k32.CloseHandle(handle)

	if return_as_path:
		return path

	if return_partitions:
		parts=get_disk_partitions(k32,disk_index,debug=debug)
		return (path,parts)

	return disk_index

def enum_disks(
		kernel32:Optional[WinDLL],
		detail_lvl:int=1,
		max_disks:int=256,
		debug:bool=False
	)->list:

	# Enumerate all disks

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.CreateFileW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE
		]
		k32.CreateFileW.restype=wintypes.HANDLE

		k32.CloseHandle.argtypes=[wintypes.HANDLE]
		k32.CloseHandle.restype=wintypes.BOOL

	disks=[]

	return_as_path=(detail_lvl==1)
	return_partitions=(detail_lvl==2)

	for disk_number in range(max_disks):

		result=get_disk(
			k32,disk_number,
			return_as_path=return_as_path,
			return_partitions=return_partitions
		)

		if result is None:
			continue

		disks.append(result)

		if debug:
			print(disks[-1])

	return disks

###############################################################################

# Volumes

def get_single_partition_from_extents(
		kernel32:Optional[WinDLL],
		ext_disk:int,
		ext_start:int,
		ext_len:int,
		partitions:list=[],
		return_int:bool=False,
		debug:bool=False
	)->Union[int,Mapping]:

	# Given a disk extent (disk index, extent start and extent length), get the
	# partition that matches that exact extent

	# NOTE:
	# by providing the partitions list, it is assumed that they belong to the
	# specific disk

	plist:Optional[list]=None

	if len(partitions)==0:

		plist=get_disk_partitions(kernel32,ext_disk,debug=debug)
		if plist is None:
			if return_int:
				return -1
			return {}

		if len(plist)==0:
			if return_int:
				return -1
			return {}

	pp={}
	part_num_ok=-1

	for p in plist:

		part_num=p.get("part_num")
		if not isinstance(part_num,int):
			continue
		if not part_num>0:
			continue

		part_start=p.get("part_start")
		if not isinstance(part_start,int):
			continue
		if not part_start>0:
			continue

		part_len=p.get("part_len")
		if not isinstance(part_len,int):
			continue
		if not part_len>0:
			continue

		if not part_start==ext_start:
			continue

		if not part_len==ext_len:
			continue

		print("EXTENTS MATCH:",p)

		if return_int:
			part_num_ok=part_num
			break

		pp.update(p)
		break

	if return_int:
		return part_num_ok

	return pp

def get_volume_extents(
		kernel32:Optional[WinDLL],
		volume_name:str,
		debug:bool=False,
	)->list:

	# Get the disk extents from a volume

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.CloseHandle.argtypes=[wintypes.HANDLE]
		k32.CloseHandle.restype=wintypes.BOOL

		k32.CreateFileW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE
		]
		k32.CreateFileW.restype=wintypes.HANDLE

		k32.DeviceIoControl.argtypes=[
			wintypes.HANDLE,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPVOID
		]
		k32.DeviceIoControl.restype=wintypes.BOOL


	device_path = volume_name.rstrip("\\")

	handle = kernel32.CreateFileW(
		device_path,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		0,
		None,
	)

	if handle==INVALID_HANDLE_VALUE:
		util_winerror(debug=debug)
		return []

	size = 8 + ctypes.sizeof(DISK_EXTENT)

	buffer_ok=None

	werror=0
	fatal=False

	while True:

		werror=0

		buffer=ctypes.create_string_buffer(size)
		rbytes=wintypes.DWORD()

		ok=k32.DeviceIoControl(
			handle,
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
			None,
			0,
			buffer,
			size,
			ctypes.byref(rbytes),
			None
		)

		if ok:

			buffer_ok=buffer

			break

		count=int.from_bytes(
			buffer.raw[:4],
			byteorder="little"
		)

		werror=util_winerror(return_code=True,debug=False)
		if werror not in (ERROR_MORE_DATA,ERROR_INSUFFICIENT_BUFFER):
			fatal=True
			break

		size = max(size * 2, 8 + count * ctypes.sizeof(DISK_EXTENT))

	# End of Loop

	if fatal:
		k32.CloseHandle(handle)
		if debug:
			raise WinError(werror)

		print("WinError:",werror)
		return []

	count=int.from_bytes(
		buffer_ok.raw[:4],
		byteorder="little"
	)

	extents=ctypes.cast(
		ctypes.addressof(buffer_ok)+8,
		ctypes.POINTER(DISK_EXTENT*count)
	).contents

	results=[]
	for ext in extents:

		ext_start=int(ext.StartingOffset)
		ext_len=int(ext.ExtentLength)
		ext_dn=int(ext.DiskNumber)

		results.append({
			"DiskNumber":ext_dn,
			"StartingOffset":ext_start,
			"ExtentLength":ext_len,
		})

	k32.CloseHandle(handle)

	return results

def get_volume_paths(
		kernel32:Optional[WinDLL],
		volume_name:str,
		debug:bool=False,
	)->list:

	k32=kernel32

	size=256
	error=0
	fatal=False

	paths=[]

	while True:

		error=0

		buffer = ctypes.create_unicode_buffer(size)
		chars_needed = wintypes.DWORD()

		ok = k32.GetVolumePathNamesForVolumeNameW(
			volume_name,
			buffer,
			size,
			ctypes.byref(chars_needed)
		)
		if ok:
			paths.extend(
				util_parse_MULTI_SZ(buffer,chars_needed.value)
			)
			break

		error=util_winerror(return_code=True,debug=False)
		if error==ERROR_MORE_DATA:
			size = max(size * 2, chars_needed.value)
			continue

		if error==ERROR_FILE_NOT_FOUND:
			break

		fatal=True
		break

	if fatal:
		if debug:
			raise WinError(error)

		print("WinError:",error)
		return []

	return paths

def get_volume_filesystem(
		kernel32:WinDLL,
		vol_name_or_path:str,
		debug:bool=True,
	)->Optional[str]:

	# Get filesystem using volume name or volume path

	root:Optional[str]=None
	ok=vol_name_or_path.endswith("\\")
	if ok:
		root=vol_name_or_path
	if not ok:
		root=vol_name_or_path+"\\"

	buffer=ctypes.create_unicode_buffer(64)
	ok=kernel32.GetVolumeInformationW(
		root,
		None,0,
		None,None,None,
		buffer,
		len(buffer)
	)
	if not ok:
		werror=util_winerror(return_code=True,debug=False)
		if not werror==ERROR_UNRECOGNIZED_VOLUME:
			raise WinError(werror)

		return None

	return buffer.value

def get_volume_space(
		kernel32:Optional[WinDLL],
		vol_name_or_path:str,
		as_tuple:bool=False,
		debug:bool=False
	)->Mapping:

	# Returns Total, Free and Used space in a volume

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32.GetDiskFreeSpaceExW.argtypes=[
			wintypes.LPCWSTR,
			ctypes.POINTER(ctypes.c_ulonglong),
			ctypes.POINTER(ctypes.c_ulonglong),
			ctypes.POINTER(ctypes.c_ulonglong),
		]
		k32.GetDiskFreeSpaceExW.restype=wintypes.BOOL

	root:Optional[str]=None
	ok=vol_name_or_path.endswith("\\")
	if ok:
		root=vol_name_or_path
	if not ok:
		root=vol_name_or_path+"\\"

	_atc=ctypes.c_ulonglong()
	_total=ctypes.c_ulonglong()
	_free=ctypes.c_ulonglong()

	ok=k32.GetDiskFreeSpaceExW(
		root,
		ctypes.byref(_atc),
		ctypes.byref(_total),
		ctypes.byref(_free)
	)
	if not ok:
		util_winerror(debug=debug)
		if as_tuple:
			return None
		return {}

	total=_total.value
	free=_free.value
	used=total-free

	if as_tuple:

		# TOTAL, USED, FREE

		return (total,used,free)

	return {
		"total":total,
		"used":used,
		"free":free
	}

def get_volume(
		kernel32:WinDLL,
		volume_name:str,
		debug:bool=True,
	)->Mapping:

	# Get volume data

	vol={
		"volume_name":volume_name,
		"volume_guid":from_str_extract_uuid(volume_name)
	}

	volume_tfu=get_volume_space(kernel32,volume_name,as_tuple=True)
	if volume_tfu is not None:
		vol.update({"volume_space":volume_tfu})

	volume_fs=get_volume_filesystem(kernel32,volume_name)
	if volume_fs is not None:
		vol.update({"volume_fs":volume_fs})

	volume_paths=get_volume_paths(kernel32,volume_name,debug=debug)
	if not len(volume_paths)==0:
		vol.update({"volume_paths":volume_paths})

	volume_extents=get_volume_extents(
		kernel32,volume_name,
		# get_sp=get_partitions,
		debug=debug
	)
	if not len(volume_extents)==0:
		vol.update({"volume_extents":volume_extents})

	return vol

def get_volume_ex(
		k32:WinDLL,
		volume_name:str,
		get_spm:bool=False,
		debug:bool=True
	)->Mapping:

	volume=get_volume(k32,volume_name,debug=debug)

	if get_spm:

		disks_involved=[]

		if not len(volume.get("volume_extents",[]))==1:
			return volume

		disk_number=volume["volume_extents"][0].get("DiskNumber")
		if disk_number<0:
			return volume

		disks_involved.append(disk_number)

		parts_involved={}

		for disk in disks_involved:

			if disk in parts_involved.keys():
				continue

			parts_involved.update({
				disk:get_disk_partitions(k32,disk,debug=debug)
			})


		if not len(volume.get("volume_extents",[]))==1:
			return volume

		disk_number=volume["volume_extents"][0].get("DiskNumber")
		if disk_number<0:
			return volume

		if disk_number not in parts_involved.keys():
			return volume

		extent_start=volume["volume_extents"][0].get("StartingOffset",-1)
		if not extent_start>0:
			return volume

		extent_length=volume["volume_extents"][0].get("ExtentLength",-1)
		if not extent_length>0:
			return volume

		spm=get_single_partition_from_extents(
			k32,
			disk_number,
			extent_start,
			extent_length,
		)
		if len(spm)==0:
			return volume

		volume["volume_extents"].append(spm)

	return volume

def enum_volumes(
		kernel32:Optional[WinDLL],
		get_spm:bool=False,
		debug:bool=True
	)->list:

	# Enumerate volumes

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.FindFirstVolumeW.argtypes=[
			wintypes.LPWSTR,
			wintypes.DWORD
		]
		k32.FindFirstVolumeW.restype=wintypes.HANDLE

		k32.FindNextVolumeW.argtypes=[
			wintypes.HANDLE,
			wintypes.LPWSTR,
			wintypes.DWORD
		]
		k32.FindNextVolumeW.restype=wintypes.BOOL

		k32.FindVolumeClose.argtypes = [wintypes.HANDLE]
		k32.FindVolumeClose.restype = wintypes.BOOL

		k32.GetVolumeInformationW.argtypes = [
			wintypes.LPCWSTR,
			wintypes.LPWSTR,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			ctypes.POINTER(wintypes.DWORD),
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPWSTR,
			wintypes.DWORD,
		]
		k32.GetVolumeInformationW.restype = wintypes.BOOL


		k32.GetVolumePathNamesForVolumeNameW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.LPWSTR,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD)
		]
		k32.GetVolumePathNamesForVolumeNameW.restype=wintypes.BOOL

	buffer=ctypes.create_unicode_buffer(1024)

	handle = k32.FindFirstVolumeW(buffer, len(buffer))

	if handle == INVALID_HANDLE_VALUE:
		util_winerror(debug=debug)
		return []

	volumes=[]

	error=0
	fatal=False
	while True:

		volume_name = buffer.value

		volumes.append(
			get_volume(
				k32,volume_name,
				# get_partitions=get_partitions,
				debug=debug
			)
		)
		if debug:
			print("VOL:",volumes[-1])

		if not k32.FindNextVolumeW(handle,buffer,len(buffer)):
			error=util_winerror(return_code=True,debug=False)
			if error==ERROR_NO_MORE_FILES:
				break

			fatal=True
			break

	if fatal:
		k32.FindVolumeClose(handle)
		if debug:
			raise WinError(error)

	k32.FindVolumeClose(handle)

	if get_spm:

		# Get Single Partition Match of each volume

		disks_involved=[]

		for vol in volumes:

			if not len(vol.get("volume_extents",[]))==1:
				continue

			disk_number=vol["volume_extents"][0].get("DiskNumber")
			if disk_number<0:
				continue

			disks_involved.append(disk_number)

		parts_involved={}

		k32_extra=init_kernel32()

		for disk in disks_involved:

			if disk in parts_involved.keys():
				continue

			parts_involved.update({
				disk:get_disk_partitions(k32_extra,disk,debug=debug)
			})

		for vvv in volumes:

			if not len(vvv.get("volume_extents",[]))==1:
				continue

			disk_number=vvv["volume_extents"][0].get("DiskNumber")
			if disk_number<0:
				continue

			if disk_number not in parts_involved.keys():
				continue

			extent_start=vvv["volume_extents"][0].get("StartingOffset",-1)
			if not extent_start>0:
				continue

			extent_length=vvv["volume_extents"][0].get("ExtentLength",-1)
			if not extent_length>0:
				continue

			vvv["volume_extents"].append(
				get_single_partition_from_extents(
					None,
					disk_number,
					extent_start,
					extent_length,
				)
			)

			print("Vol with part",vvv)

	return volumes

def enum_drive_roots(
		kernel32:Optional[WinDLL],
		ljtl:bool=False,
		debug:bool=False
	)->list:

	# Get drive letters that are already being used

	# LJTL = Literally, Just The Letters

	k32:Optional[WinDLL]=kernel32

	if k32 is None:

		k32=WinDLL("kernel32",use_last_error=True)

		k32.GetLogicalDriveStringsW.argtypes=[
			wintypes.DWORD,
			wintypes.LPWSTR
		]
		k32.GetLogicalDriveStringsW.restype = wintypes.DWORD

	size=256

	werror=0
	buffer_ok=None
	fatal=False

	while True:

		werror=0

		buffer=ctypes.create_unicode_buffer(size)

		chars_written=k32.GetLogicalDriveStringsW(size,buffer)

		if chars_written==0:

			werror=util_winerror(return_code=True,debug=False)
			fatal=True

			break

		if chars_written<size:

			buffer_ok=buffer

			break

		size=chars_written+1

	if fatal:
		if debug:
			raise WinError(werror)

		print("WinError:",werror)
		return []

	drives=util_parse_MULTI_SZ(buffer_ok,chars_written)

	# print("DRIVES:",drives)

	if ljtl:
		letters=[]
		for d in drives:
			letters.append(d[0])

		return letters

	return drives

###############################################################################

# Specific Windows Volumes

def get_winvol_system(
		kernel32:Optional[WinDLL]=None,
		get_spm:bool=False,
		get_voldata:bool=False,
		debug:bool=False
	)->Union[Optional[str],Mapping]:

	# Gets the volume where the system files reside, Usually the C:\ drive

	k32:Optional[WinDLL]=kernel32

	if k32 is None:
	
		k32 = ctypes.WinDLL("kernel32", use_last_error=True)

		k32.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
		k32.GetWindowsDirectoryW.restype = wintypes.UINT

		k32.GetVolumePathNameW.argtypes = [
			wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD
		]
		k32.GetVolumePathNameW.restype = wintypes.BOOL

		k32.GetVolumeNameForVolumeMountPointW.argtypes = [
			wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD
		]
		k32.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL

	BUF_SIZE = 32768

	buf = ctypes.create_unicode_buffer(BUF_SIZE)
	n = k32.GetWindowsDirectoryW(buf, BUF_SIZE)
	if (not n) or (not n<BUF_SIZE):
		util_winerror(debug=debug)
		if get_voldata:
			return {}
		return None

	mount = ctypes.create_unicode_buffer(BUF_SIZE)
	if not k32.GetVolumePathNameW(buf.value, mount, BUF_SIZE):
		util_winerror(debug=debug)
		if get_voldata:
			return {}
		return None

	guid = ctypes.create_unicode_buffer(BUF_SIZE)
	if not k32.GetVolumeNameForVolumeMountPointW(
			mount.value,
			guid,
			BUF_SIZE
		):
		util_winerror(debug=debug)

	volume_name=guid.value

	if get_voldata:

		return get_volume_ex(
			k32,volume_name,
			get_spm=get_spm,
			debug=debug
		)

	return volume_name

def get_winvol_boot(
		kernel32:Optional[WinDLL]=None,
		get_spm:bool=False,
		get_voldata:bool=False,
		debug:bool=False
	)->Union[Optional[str],Mapping]:

	# Gets the volume that corresponds with the boot partition. In UEFI systems
	# this is known as the ESP

	k32:Optional[WinDLL]=kernel32

	if k32 is None:
	
		k32 = ctypes.WinDLL("kernel32", use_last_error=True)

		k32.CloseHandle.argtypes=[wintypes.HANDLE]
		k32.CloseHandle.restype=wintypes.BOOL

		k32.CreateFileW.argtypes=[
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE
		]
		k32.CreateFileW.restype=wintypes.HANDLE

		k32.GetFinalPathNameByHandleW.argtypes = [
			wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD
		]
		k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD


	path="\\\\?\\Global\\SystemPartition\\"
	handle=k32.CreateFileW(
		path,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		None,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		None,
	)
	if handle==INVALID_HANDLE_VALUE:
		util_winerror(debug=debug)
		if get_voldata:
			return {}
		return None

	BUF_SIZE = 32768

	buf=ctypes.create_unicode_buffer(BUF_SIZE)

	n = k32.GetFinalPathNameByHandleW(
		handle,
		buf,
		BUF_SIZE,
		VOLUME_NAME_GUID
	)

	if (not n) or (not n<BUF_SIZE):
		werror=util_winerror(return_code=True,debug=debug)
		k32.CloseHandle(handle)
		if debug:
			raise WinError(werror)
		print("WinError",werror)
		if get_voldata:
			return {}
		return None

	volume_name=buf.value

	k32.CloseHandle(handle)

	if get_voldata:

		k32_ex=init_kernel32()

		return get_volume_ex(
			k32_ex,
			volume_name,
			get_spm=get_spm,
			debug=debug
		)

	return volume_name

###############################################################################

# Mount functions

def get_free_mountpoint(
		kernel32:WinDLL,
		ret_as_drive:bool=False,
		ret_as_path:bool=False,
		debug:bool=False
	)->Optional[str]:

	letters_busy=enum_drive_roots(
		kernel32,
		ljtl=True,
		debug=debug
	)
	if len(letters_busy)==0:
		return None

	letter_free=None

	for char in _DRIVELETTERS:

		print(char)

		if char in ("A","B","C"):
			continue

		if char in letters_busy:
			continue

		print("taking...")

		if ret_as_drive:
			letter_free=char+":"
			break

		if ret_as_path:
			letter_free=rf"{char}:\\"
			break

		letter_free=char

		break

	return letter_free

def mount_volume(
		vol_name:str,letter:str,
		debug=False
	)->bool:

	command=[
		"mountvol",
			letter,
			vol_name
	]

	result=wsubproc(command,verbose=debug)
	if not result==0:
		return False

	return True

def mount_esp_partition(letter:str,debug=False):

	command=[
		"mountvol",
			letter,
			"/S"
	]

	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		return False

	return True

def from_mountpoint_get_volume(
		letter_or_path:str,
		return_uuid:bool=False,
		debug:bool=False
	)->Optional[str]:

	# Given a mountpoint or a dirpath, get wether a volume is mounted or not

	command=[
		"mountvol",
			letter_or_path,
			"/L"
	]
	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		return None

	trimmed=result[1].strip()

	vol_id=from_str_extract_uuid(trimmed)
	if vol_id is None:
		msg="Volume not found in STDOUT...?"
		if debug:
			raise ValueError(msg)
		print("Error:",msg)
		return None

	if return_uuid:
		return vol_id

	if debug:
		print(trimmed)

	return trimmed

def from_mountpoint_get_volume_ex(
		letter_or_path:str,
		get_spm:bool=False,
		debug:bool=False,
	)->Mapping:

	# Given a mountpoint or a dirpath, get all the data about a volume if found
	# NOTE:
	# get_SPM (Single Partition Match) returns the single matching partition
	# that corresponds to the volume

	command=[
		"mountvol",
			letter_or_path,
			"/L"
	]
	result=wsubproc(command,verbose=debug)
	if not result[0]==0:
		return {}

	volume_name=result[1].strip()

	if not from_str_extract_uuid(
			volume_name,
			just_check=True
		):
		msg="Volume not found in STDOUT...?"
		if debug:
			raise ValueError(msg)
		print("Error:",msg)
		return {}

	k32=init_kernel32()

	return get_volume_ex(
		k32,volume_name,
		get_spm=get_spm,
		debug=debug
	)

# if __name__=="__main__":

# 	x=get_winvol_boot(get_voldata=True,get_spm=True)

# 	print(x)
