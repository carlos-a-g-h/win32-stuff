#!/usr/bin/python3

# This test consists in creating part of the necessary credentials using pure
# python, verify each of them using OpenSSL, use the credentials to sign an
# EFI file, and verify the signature of the signed file using SBVERIFY

from pathlib import Path
from sys import platform as sys_platform
from sys import argv as sys_argv

from WUEFI_crypto import (

	openssl_request_rsa_keypair_with_x509_csr,
	openssl_x509_read_certder,
	openssl_x509_convert_certder_to_pem,
	from_x509_keypair_make_certder,
	from_x509_certder_get_pem,
	sign_image,
	_RTYPE_PATH
)

if sys_platform in ("linux","linux2"):
	from WUEFI_utils import subproc as util_subproc
if sys_platform=="win32":
	from WUEFI_utils_windows import wsubproc as util_subproc

###############################################################################

running_on_windows=(sys_platform=="win32")
test_stem=Path(sys_argv[0]).stem
test_fname=Path(sys_argv[0]).name
test_dir=Path(f"{test_stem}.results")
test_dir.mkdir(exist_ok=True,parents=True)

###############################################################################

# Test parameters

debug_mode=True
test_stem="Test"
test_efi_file=Path("/media/root/02FE-9983/EFI/Boot/grub2.bootx64.efi")

###############################################################################

# Create RSA x509 key pair

result=openssl_request_rsa_keypair_with_x509_csr(
	test_dir,
	"/CN=WUEFI crypto tests/",
	test_stem,
	debug=debug_mode
)
assert result[0]==0

# Make DER certificate from scratch using the generated keypair

test_pvtkey=result[1]
test_pubkey=result[2]

test_certder=from_x509_keypair_make_certder(
	test_pvtkey,
	test_pubkey,
	fpath_out=test_dir.joinpath(f"{test_stem}.der"),
	debug=debug_mode,
	return_type=_RTYPE_PATH
)
assert isinstance(test_certder,Path)

# Make sure that the public key inside the generated certificate matches the
# public key from the keypair

assert from_x509_certder_get_pem(test_certder,test_pubkey)

# Read (parse) the generated certificate using OpenSSL

result=openssl_x509_read_certder(
	test_certder,
	debug=debug_mode
)
assert result[0]==0

test_efi_file_signed=sign_image(
	test_pvtkey,
	test_certder,
	test_efi_file,
	test_dir.joinpath(f"{test_efi_file.stem}.SIGNED"),
	debug=debug_mode
)

if running_on_windows:
	print("Cannot continue test on Windows, run on Linux")
	exit(0)

# NOTE:
# sbsigntool and efitools must be installed
# apt install -yy sbsigntool efitools

# - Verify the signature within the signed EFI file

test_pubkey_recovered=openssl_x509_convert_certder_to_pem(test_certder,debug=debug_mode)

assert isinstance(test_pubkey_recovered,Path)

result=util_subproc([
	"sbverify",
		"--cert",str(test_pubkey_recovered),
		str(test_efi_file_signed)
	],
	verbose=debug_mode
)
assert result[0]==0

print(f"\n{test_fname}: PASSED")
