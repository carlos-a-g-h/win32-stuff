#!/usr/bin/python3

# This test consists in creating all credentials using OpenSSL (except for the
# ESL, the code for that one is pure python), sign an EFI file using the
# credentials and finally verify the signature using SBVERIFY

from pathlib import Path
from sys import platform as sys_platform
from sys import argv as sys_argv

from WUEFI_crypto import (

	openssl_request_rsa_keypair_with_x509_csr,
	openssl_x509_convert_pem_to_der,
	from_x509_certder_make_esl,
	sign_image,
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

# - Create an RSA x509 keypair

result=openssl_request_rsa_keypair_with_x509_csr(
	test_dir,
	"/CN=WUEFI crypto tests/",
	test_stem,
	debug=debug_mode
)
assert result[0]==0

test_pvtkey=result[1]
test_pubkey=result[2]

# - Convert PEM public key to DER format

test_certder=openssl_x509_convert_pem_to_der(test_pubkey,debug=debug_mode)
assert (isinstance(test_certder,Path))

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

# - Make sure we are NOT running on Windows

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
		"--cert",str(test_pubkey),
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
