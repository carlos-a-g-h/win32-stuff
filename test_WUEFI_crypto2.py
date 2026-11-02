#!/usr/bin/python3

# Similar to the first test, but instead of creating the DER certificate using
# OpenSSL, it is created using pure python and verified using OpenSSL

from pathlib import Path
from sys import platform as sys_platform
from sys import argv as sys_argv

from WUEFI_crypto import (

	openssl_request_rsa_keypair_with_x509_csr,
	openssl_x509_read_certder,
	# openssl_x509_convert_certder_to_pem,
	from_x509_certder_make_esl,
	# from_x509_keypair_make_certder,
	from_x509_pem_make_certder,
	from_x509_certder_get_pubkey,
	sign_image,
	# _RTYPE_PATH
)
from WUEFI_symbols import _GUID_MIN


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
	"/CN=WUEFI crypto test1/",
	test_stem,
	debug=debug_mode
)
assert result[0]==0

# Make DER certificate from scratch using the generated keypair

test_pvtkey=result[1]
test_pemcert=result[2]

test_certder=from_x509_pem_make_certder(test_pemcert,debug=debug_mode)

# test_certder=from_x509_keypair_make_certder(
# 	test_pvtkey,
# 	test_pubkey,
# 	fpath_out=test_dir.joinpath(f"{test_stem}.der"),
# 	debug=debug_mode,
# 	return_type=_RTYPE_PATH
# )
assert isinstance(test_certder,Path)

# Make sure that the public key inside the generated certificate matches the
# public key from the PEM cert

assert from_x509_certder_get_pubkey(test_certder,test_pemcert)

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

# - Make the ESL file

test_esl=from_x509_certder_make_esl(test_certder,_GUID_MIN,debug=debug_mode)
assert isinstance(test_esl,Path)

if running_on_windows:
	print("Cannot continue test on Windows, run on Linux")
	exit(1)

# NOTE:
# sbsigntool and efitools must be installed
# apt install -yy sbsigntool efitools

# - Verify the signature within the signed EFI file
# The success of this command confirms that the image signing function works
# propperly

result=util_subproc([
	"sbverify",
		"--cert",str(test_pemcert),
		str(test_efi_file_signed)
	],
	verbose=debug_mode
)
assert result[0]==0

# - Extract the DER certificate inside the generated ESL file

stem_rcert=f"{test_stem}_from_esl"

result=util_subproc([
	"sig-list-to-certs",
		str(test_esl),
		str(test_dir.joinpath(stem_rcert))
		# f"{test_dir}/{stem_rcert}",
	],
	verbose=debug_mode
)
assert result[0]==0

# - Get the real name of the DER certificate extracted from the ESL file

result=util_subproc([
	"find",
		str(test_dir),
		"-name",stem_rcert+"*"
	],
	verbose=debug_mode
)
assert result[0]==0

test_certder_from_esl=Path(result[1].strip())

assert test_certder_from_esl.is_file()

# - Get the SHA26 hash of the DER certificate

result=util_subproc(
	["sha256sum",str(test_certder)],
	verbose=debug_mode
)
assert result[0]==0

print(result[1].strip())
sha256sum_original=result[1].strip()[:64]

# - Get the SHA26 hash of the DER certificate obtained from the ESL file

result=util_subproc(
	["sha256sum",str(test_certder_from_esl)],
	verbose=debug_mode
)
assert result[0]==0

print(result[1].strip())
sha256sum_recovered=result[1].strip()[:64]

# - Check if the two checksums from the two DER certificates are the same
# Both checksums being equal confirms that the function that creates the ESL
# using a DER certificate works propperly

assert sha256sum_original==sha256sum_recovered

print(f"\n{test_fname}: PASSED")
