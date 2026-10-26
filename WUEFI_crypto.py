#!/usr/bin/python3

from sys import platform as sys_platform

from pathlib import Path
from typing import Optional,Union
from uuid import UUID

from WUEFI_symbols import _EFI_CERT_X509_GUID
from WUEFI_utils import is_guid as util_guid

# NOTE:
# I am only doing this because I am not always working from Windows, also btw,
# the SBSIGN tools are natively Linux only

if sys_platform in ("linux","linux2"):
	from WUEFI_utils import subproc as util_subproc
if sys_platform=="win32":
	from WUEFI_utils_windows import wsubproc as util_subproc

# OpenSSL Commands

def openssl_request_rsa_keypair_with_x509_csr(
		outdir:Path,
		subj_name:str="/CN=Credentials Made Using WUEFI/",
		key_stem:str="myrsa",
		expir_years:int=10,
		debug:bool=False,
		confirm_only:bool=False
	)->Union[bool,tuple]:

	# Requests OpenSSL to generate an RSA key pair with the public key being self
	# signed under x.509 standard

	# NOTE:
	# The resulting files are stored inside the given output directory and named
	# according to teh given stem

	fpath_rsa_key:Path=outdir.joinpath(f"{key_stem}.key")
	fpath_rsa_pem:Path=outdir.joinpath(f"{key_stem}.pem")

	command=[
		"openssl",
			"req",
			"-new",
			"-x509",
			"-newkey","rsa:2048",
			"-sha256",
			"-days",str(expir_years),
			"-subj",subj_name,
			"-keyout",str(fpath_rsa_key.absolute()),
			"-out",str(fpath_rsa_pem.absolute()),
			"-nodes"
		]

	result=util_subproc(
		command,
		verbose=debug,
		encoding=None
	)
	ok=(result[0]==0)
	if confirm_only:
		return ok

	if not ok:
		return result

	# Tuple: (
	#   Status code,
	#   Absolute Path to the Private RSA key,
	#   Absolute Path to the Public RSA key
	# )
# NOTE:
# I am only doing this because I am not always on Windows

	return (
		0,
		fpath_rsa_key.absolute(),
		fpath_rsa_pem.absolute()
	)

def openssl_x509_convert_pem_to_der(
		fpath_pem:Path,
		confirm_only:bool=False,
		debug:bool=False
	)->Union[bool,Optional[Path]]:

	# Uses OpenSSL's x509 command to convert a PEM key file into DER format

	# NOTE:
	# The resulting file will be stored in the same directory as the given
	# PEM file

	fpath_pem_ok:Optional[Path]=None
	is_abs=fpath_pem.is_absolute()
	if is_abs:
		fpath_pem_ok=fpath_pem
	if not is_abs:
		fpath_pem_ok=fpath_pem.absolute()

	stem=fpath_pem_ok.stem
	outdir=fpath_pem_ok.parent
	fpath_der_ok=outdir.joinpath(f"{stem}.der")

	command=[
		"openssl",
			"x509",
			"-in",str(fpath_pem_ok),
			"-outform","DER",
			"-out",str(fpath_der_ok)
		]

	result=util_subproc(
		command,
		verbose=debug,
		encoding=None
	)
	ok=(result[0]==0)
	if confirm_only:
		return ok

	if not ok:
		return None

	return fpath_der_ok

def build_esl_from_a_x509_der(
		fpath_der:Path,
		owner_guid:Union[str,UUID],
		confirm_only:bool=False,
		debug:bool=False
	)->Union[bool,Optional[Path]]:

	# Given a DER x509 certificate, generate an ESL (EFI_SIGNATURE_LIST)

	# NOTE:
	# Some vendors/firmwares require the ESL)

	owner_guid_ok:Optional[UUID]=None
	if isinstance(owner_guid,UUID):
		owner_guid_ok=owner_guid
	if isinstance(owner_guid,str):
		if not util_guid(owner_guid,verbose=debug):
			if confirm_only:
				return False
			return None
		owner_guid_ok=UUID(owner_guid)
	if owner_guid_ok is None:
		if confirm_only:
			return False
		return None

	cert_type=UUID(_EFI_CERT_X509_GUID)

	content_der=fpath_der.read_bytes()

	owner_guid_as_bytes=owner_guid_ok.bytes_le

	size_sign=len(content_der)+len(owner_guid_as_bytes)

	size_list=28+size_sign
	# SignatureType + SignatureListSize + SignatureHeaderSize + SignatureSize
	# 16 + 4 + 4 + 4

	size_sign_header=0

	esl_content=(
		cert_type.bytes_le
		+ size_list.to_bytes(length=4,byteorder="little")
		+ size_sign_header.to_bytes(length=4,byteorder="little")
		+ size_sign.to_bytes(length=4,byteorder="little")
		+ owner_guid_as_bytes
		+ content_der
	)

	stem=fpath_der.stem

	fpath_esl=fpath_der.parent.joinpath(f"{stem}.esl")

	fpath_esl.write_bytes(esl_content)

	if confirm_only:
		return True

	return fpath_esl

if __name__=="__main__":

	# NOTE:
	# This test has two main parts
	# THe first part consists in creating all fo the necessary credentials related
	# to UEFI certificates: the private key, the PEM public key, the DER cert,
	# and the ESL file, which is required by some vendors
	# The second part can only run on Linux, check below for more details

	from sys import argv

	from WUEFI_symbols import _GUID_MIN
	from WUEFI_crypto_sbsign import sign_image as sbsign

	epoint=Path(argv[0])
	outdir_tests=epoint.parent.joinpath("tests")
	outdir_tests.mkdir(exist_ok=True,parents=True)

	debugging=True

	res1=openssl_request_rsa_keypair_with_x509_csr(outdir_tests,key_stem="testdb",debug=debugging)
	if res1[0]==-1:
		print("ERROR:",res1)
		exit(1)

	_,fpath_private_key,fpath_public_key=res1

	fpath_cert_der=openssl_x509_convert_pem_to_der(fpath_public_key,debug=debugging)

	print("PRIV KEY:",fpath_private_key)
	print("PUBL KEY:",fpath_public_key)
	print("DER CERT:",fpath_cert_der)

	res3=build_esl_from_a_x509_der(fpath_cert_der,UUID(_GUID_MIN),debug=debugging)
	if res3 is None:
		print("ERROR: failed to create ESL file")
		exit(1)

	print("ESL FILE:",res3)

	if sys_platform not in ("linux","linux2"):
		print("Stopping this test right here (if you don't know why, read the source code)")
		exit(0)

	# NOTE:

	# This part of the test can only be ran on Linux, because SBVERIFY (which is
	# part of the SBSIGN project) is natively available natively only on Linux
	# systems

	# We basically take the previously created private key and its corresponding
	# DER certificate and we use a (preferrably unsigned) EFI file to sign it
	# using the signer in WUEFI_crypto_sbsign. Then we use an actual copy of
	# SBVERIFY to check if the resulting signed file is correct

	# In order for this part of the test to work, ya need to install sbsign-tools
	# on whatever distro you're using

	efi_file_str="/media/root/02FE-9983/EFI/Boot/grub2.bootx64.efi"

	efi_file=Path(efi_file_str)

	efi_file_signed=sbsign(fpath_private_key,fpath_cert_der,efi_file)

	r=util_subproc([
		"sbverify",
			"--cert",str(fpath_public_key),
			str(efi_file_signed)
	])
	if not r[0]==0:
		print("TEST FAILED!")
		exit(1)

	print(r[1])

	print("SIGNED FILE:",r)
