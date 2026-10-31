#!/usr/bin/python3

from pathlib import Path
from sys import platform as sys_platform


from WUEFI_crypto import (

	openssl_request_rsa_keypair_with_x509_csr,
	openssl_x509_read_certder,
	from_x509_keypair_make_certder,
	sign_image,
	_RTYPE_PATH
)

if sys_platform in ("linux","linux2"):
	from WUEFI_utils import subproc as util_subproc
if sys_platform=="win32":
	from WUEFI_utils_windows import wsubproc as util_subproc

###############################################################################

debug=True

running_on_windows=(sys_platform=="win32")

test_dir=Path("test_results")

test_efi_file=Path("/media/root/02FE-9983/EFI/Boot/grub2.bootx64.efi")

test_stem="mytest"

###############################################################################

test_dir.mkdir(exist_ok=True,parents=True)

result=openssl_request_rsa_keypair_with_x509_csr(
	test_dir,
	"/CN=WUEFI crypto tests/",
	test_stem,
	debug=debug
)
assert result[0]==0

test_pvtkey=result[1]
test_pubkey=result[2]

test_certder=from_x509_keypair_make_certder(
	test_pvtkey,
	test_pubkey,
	fpath_out=test_dir.joinpath(f"{test_stem}.der"),
	debug=debug,
	return_type=_RTYPE_PATH
)

result=openssl_x509_read_certder(
	test_certder,
	debug=debug
)
assert result[0]==0

test_efi_file_signed=sign_image(
	test_pvtkey,
	test_certder,
	test_efi_file,
	test_dir.joinpath(f"{test_efi_file.stem}.SIGNED"),
	debug=debug
)

if running_on_windows:
	print("Cannot continue test on Windows, run on Linux")
	exit(0)

# apt install -yy sbsigntool

result=util_subproc([
	"sbverify",
		"--cert",str(test_certder),
		str(test_efi_file_signed)
])
assert result[0]==0

print("PASSED!")
