#!/usr/bin/python3

# OK

from pathlib import Path,WindowsPath
from random import randint
from subprocess import run as sub_run,CompletedProcess
from typing import Any,Callable,Mapping,Optional,Union

import ctypes
from ctypes import wintypes,WinError,get_last_error

from WUEFI_symbols import (

	# _ENC_UTF16LE,

	_UINT8_MAX,
	_UINT16_MAX,
	_UINT32_MAX,
	_UINT64_MAX,
)

###############################################################################

# Misc. Utilities

def return_result(
		msg:str,
		code:int=0,
		prefix:Optional[str]=None,
		as_exc:bool=False,
		payload:list=[],
		print_only:bool=False,
	)->Optional[tuple]:

	# Rich error handling and result function. No exceptions are thrown y default

	# NOTE:

	# Returns tuple(CODE,MESSAGE), where CODE is an integer that represents a step
	# or an exit code and MESSAGE is a string with the detailed error, and the
	# payload is any aditional data that can be delivered with the error, growing
	# the tuple with the aditional data

	has_prefix=(isinstance(prefix,str))
	success=(code==0)
	if has_prefix:
		if success:
			print(prefix,msg)
		if not success:
			print(prefix,f"Error {code};",msg)
	if not has_prefix:
		if success:
			print(msg)
		if not success:
			print(f"Error {code};",msg)

	if print_only:
		return None

	if as_exc and (not success):

		txt=f"Error {code}; "+msg
		if has_prefix:
			txt=prefix+" "+txt

		raise Exception(txt)

	result=[code,msg]
	if not len(payload)==0:
		result.extend(payload)

	return tuple(payload)

def is_uint8(data:Optional[Any])->bool:
	if not isinstance(data,int):
		return False
	if not data>-1:
		return False
	if not data<_UINT8_MAX:
		return False
	return True

def is_uint16(data:Optional[Any])->bool:
	if not isinstance(data,int):
		return False
	if not data>-1:
		return False
	if not data<_UINT16_MAX:
		return False
	return True

def is_uint32(data:Optional[Any])->bool:
	if not isinstance(data,int):
		return False
	if not data>-1:
		return False
	if not data<_UINT32_MAX:
		return False
	return True

def is_uint64(data:Optional[Any])->bool:
	if not isinstance(data,int):
		return False
	if not data>-1:
		return False
	if not data<_UINT64_MAX:
		return False
	return True

def is_hex(
		data:str,
		# White list aditional characters
		opt_whitelist:Union[list,Optional[tuple]]=None,
		# Skip specific positions
		opt_skiplist:Union[list,Optional[tuple]]=None,

		verbose:bool=False
	)->bool:

	# Checks wether every character in a sctring is within hexadecimal range

	book="1234567890abcdef"

	data_lower:str=data.lower()


	flag_wlist=False
	if isinstance(opt_whitelist,(list,tuple)):
		flag_wlist=(not len(opt_whitelist)==0)

	flag_canskip=False
	if isinstance(opt_skiplist,(list,tuple)):
		flag_canskip=(not len(opt_skiplist)==0)

	count=-1
	maxlen=len(data)
	for ch in data_lower:
		count=count+1
		if flag_canskip:
			if count in opt_skiplist:
				if verbose:
					print("SKIPPED:",ch)
				continue

		if ch in book:
			if verbose:
				print("MATCH:",ch)
			continue

		if flag_wlist:
			if ch in opt_whitelist:
				if verbose:
					print("MATCH (WL):",ch)
				continue

		count=-1
		if verbose:
			print("ERROR:",ch)

		break

	if verbose:
		print(count,"/",maxlen-1)

	return (count==maxlen-1)

def is_guid(
		data:str,
		verbose:bool=False,
		return_data:bool=False
	)->Union[bool,Optional[str]]:

	# Checks wether a string is a GUID

	if len(data) not in (36,38):
		if return_data:
			return None
		return False

	data_ok=data
	if (
			len(data)==38
			and data[0]=="{"
			and data[-1]=="}"
		):
		data_ok=data[1:-1]

	hyphen="-"
	if not data_ok[8]==hyphen:
		if verbose:
			print("ERROR",data_ok[8])
		if return_data:
			return None
		return False
	if not data_ok[13]==hyphen:
		if verbose:
			print("ERROR",data_ok[13])
		if return_data:
			return None
		return False
	if not data_ok[18]==hyphen:
		if verbose:
			print("ERROR",data_ok[18])
		if return_data:
			return None
		return False
	if not data_ok[23]==hyphen:
		if verbose:
			print("ERROR",data_ok[23])
		if return_data:
			return None
		return False

	if not is_hex(
			data_ok,
			opt_whitelist=["-"],
			opt_skiplist=[8,13,18,23],
			verbose=verbose
		):

		if return_data:
			return None

		return False

	if return_data:
		return data_ok

	return True

def fix_str(
		data_raw:Union[Optional[str],bytes],
		encoding:str="utf-8"
	)->Optional[str]:

	if data_raw is None:
		return None

	data:Optional[str]=None
	is_bytes=isinstance(data_raw,bytes)
	if is_bytes:
		data=data_raw.decode(
			encoding,
			errors="surrogateescape"
		)
	if not is_bytes:
		data=data_raw.strip()

	if len(data)==0:
		return None

	return data

def fix_path(
		path_bdir:Union[Path,WindowsPath],
		path_given:Union[Path,WindowsPath],
		must_exist:bool=False,
		must_assert:bool=False
	)->Optional[Union[Path,WindowsPath]]:

	if path_given.is_absolute():
		return path_given

	path_new=path_bdir.joinpath(path_given)

	if must_exist:

		if must_assert:
			return path_new.resolve()

		if not must_assert:
			if path_new.exists():
				return path_new.resolve()

			return None

	return path_new.absolute()

def get_next_hex_char(ch:str)->str:

	hex_chars="0123456789abcdef"

	if not len(ch)==1:
		raise Exception("ch must be of length 1")
	if ch not in hex_chars:
		raise Exception("the character is not a hex character")

	pos=-1
	for c in hex_chars:
		pos=pos+1
		if c==ch:
			break

	next=pos+1
	if next==len(hex_chars):
		next=0

	return hex_chars[next]

def from_str_extract_str(
		bound1:str,bound2:str,
		data_raw:str,
		inc_bounds:bool=False
	)->Optional[str]:

	str1_len=len(bound1)
	pos_start=data_raw.find(bound1)
	if pos_start==-1:
		return None

	cut1=data_raw[pos_start+str1_len:]
	pos_end=cut1.find(bound2)
	if pos_end==-1:
		return None

	result=cut1[:pos_end]

	if inc_bounds:
		result=f"{bound1}{result}{bound2}"

	return result

def get_value_from_alist(
		akey:str,alist:list,
		string_only:bool=True
	)->Union[Optional[str],Optional[tuple]]:

	# Pulls value from an associative list
	# The result can be returned as a string only or the entire tuple

	result:Union[Optional[str],Optional[tuple]]=None

	for pair in alist:

		if not pair[0]==akey:
			continue

		if not string_only:
			result=(pair[0],pair[1])
			break

		result=pair[1]

	return result

def split_line_into_kv(
		line:str,
		get_tup:bool=False
	)->Union[Mapping,Optional[tuple]]:

	# Splits a line into a key value pair
	# The result can be returned as a tuple or as a hashmap

	line_ok=line.strip()
	if len(line_ok)==0:
		if not get_tup:
			return {}
		return None

	parts=line_ok.split(maxsplit=1)
	if not len(parts)==2:
		if not get_tup:
			return {}
		return None

	line_key=fix_str(parts[0])
	if line_key is None:
		if not get_tup:
			return {}
		return None

	line_value=fix_str(parts[1])
	if line_value is None:
		if not get_tup:
			return {}
		return None

	if not get_tup:
		return {line_key:line_value}
	return (line_key,line_value)

def subproc(
		command:list,
		verbose:bool=False,
		test:bool=False
	):

	print("RUN:",command)

	if test:
		print(
			"NOT RUNNING THE COMMAND,"
			" JUST PRINTING IT"
		)
		return False

	proc:CompletedProcess=sub_run(
		command,
		capture_output=True,encoding="oem"
	)
	result_code=proc.returncode
	result_stdout:Optional[str]=fix_str(
		proc.stdout
	)
	result_stderr:Optional[str]=fix_str(
		proc.stderr
	)

	ok=(result_code==0)

	if ok and verbose:
		if result_stdout is not None:
			print("STDOUT {")
			print(result_stdout)
			print("} STDOUT")

	if not ok:
		if result_stdout is not None:
			print("STDOUT {")
			print(result_stdout)
			print("} STDOUT")
		if result_stderr is not None:
			print("STDERR {")
			print(result_stderr)
			print("} STDERR")

	return (
		result_code,
		result_stdout,
		result_stderr
	)
def get_fwtype(
		fun_GetFirmwareType:Callable,
		assertion:bool=True
	)->Optional[int]:

	# Returns the firmware type as an int

	res_dword=wintypes.DWORD()
	if not fun_GetFirmwareType(
			ctypes.byref(res_dword)
		):

		err=get_last_error()
		err_msg="Failed to determine the type of firmware"
		if assertion:
			raise WinError(err,err_msg)

		print(err_msg)
		return None

	return res_dword.value

###############################################################################

# Misc functions

def is_fwtype_uefi(
		fun_GetFirmwareType:Callable,
		assertion:bool=False
	)->bool:

	# Returns wether the system is UEFI booted

	result=get_fwtype(
		fun_GetFirmwareType,
		assertion=assertion
	)

	if assertion:
		if result==0:
			raise Exception("Unknown firmware type")

	return (result==2)

def is_fwtype_legacy(
		fun_GetFirmwareType:Callable,
		assertion:bool=False
	)->bool:

	# Returns wether the system is Legacy booted

	result=get_fwtype(
		fun_GetFirmwareType,
		assertion=assertion
	)

	if assertion:
		if result==0:
			raise Exception("Unknown firmware type")

	return (result==1)

def gen_str_BootNNNN(
		already_exist:Union[tuple,list]=[],
		debug:bool=False
	)->Optional[str]:

	# Generates a random Boot#### string

	# Very useful for creating a new name for a boot entry
	# You can feed this function a list or a tuple of names to
	# avoid a collision

	qtty=len(already_exist)
	if qtty==_UINT16_MAX:
		if debug:
			print("what the f***")

		return None

	must_check=(not qtty==0)

	while True:

		new="Boot"+hex(randint(0,_UINT16_MAX-1))[2:]
		if not must_check:
			break

		if new not in already_exist:
			if debug:
				print(new,"is unique!")

			break

		if debug:
			print(new,"already exists, trying a new one")

	return new

