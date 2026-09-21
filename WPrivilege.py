#!/usr/bin/python3

# Requires: pywin32
# {
from win32api import (
	GetCurrentProcess,
	GetLastError
)
from win32con import (
	TOKEN_QUERY,
	TOKEN_ADJUST_PRIVILEGES,
	SE_PRIVILEGE_ENABLED
)
from win32security import (
	AdjustTokenPrivileges,
	CheckTokenMembership,
	CreateWellKnownSid,
	GetTokenInformation,
	LookupPrivilegeValue,
	OpenProcessToken,
	TokenElevation,
	TokenElevationType,
		TokenElevationTypeDefault,
		TokenElevationTypeFull,
		TokenElevationTypeLimited,
	WinBuiltinAdministratorsSid
)
# }

from ctypes import WinError
from typing import Optional,Union

def query_proc_priv_info(

		# returns Bool
			get_is_elevated:bool=True,

		# returns Tuple
			get_elevation_type:bool=False,

		# returns Bool
			get_is_admin:bool=False,

		# Options
			return_value_directly_if_result_has_single_key:bool=True

	)->Union[bool,tuple,dict]:

	# Extracts privilege information about the current process

	proc=GetCurrentProcess()

	token=OpenProcessToken(proc,TOKEN_QUERY)

	results={}

	if get_is_elevated:

		is_elevated=GetTokenInformation(
			token,
			TokenElevation
		)
		results.update({"is_elevated":(is_elevated==1)})

	if get_elevation_type:

		elevation_type=GetTokenInformation(
			token,
			TokenElevationType
		)

		elevation_type_name={
			TokenElevationTypeDefault:"Default",
			TokenElevationTypeFull:"Full",
			TokenElevationTypeLimited:"Limited"
		}[elevation_type]

		results.update({
			"elevation_type":(
				elevation_type,
				elevation_type_name
			)
		})

	admins_sid:Optional[str]=None

	if get_is_admin:

		admins_sid=CreateWellKnownSid(
			WinBuiltinAdministratorsSid,
			None
		)
		is_admin=CheckTokenMembership(
			None,
			admins_sid
		)
		results.update({"is_admin":is_admin})

	if return_value_directly_if_result_has_single_key:
		if len(results)==1:
			the_key=list(results.keys())[0]
			return results.pop(the_key)

	return results

def env_gain_extra_priv():

	# If you ever get an error like 1300 while attempting to do something
	# that requires privileges above Administrator, run this function

	# NOTE:
	# If you get a 1314 error is because you need to run this code
	# as Administrator

	token=OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
	)

	priv_id=LookupPrivilegeValue(
		None,
		"SeSystemEnvironmentPrivilege"
	)

	AdjustTokenPrivileges(
		token,
		False,
		[(
			priv_id,
			SE_PRIVILEGE_ENABLED
		)]
	)

	err=GetLastError()
	if not err==0:
		raise WinError(err)

if __name__=="__main__":

	# Small test

	print(
		"\nIs this process running elevated?\n-->",
		query_proc_priv_info()
	)

	print(
		"\nShow all metrics\n-->",
		query_proc_priv_info(
			get_elevation_type=True,
			get_is_admin=True,
		)
	)
