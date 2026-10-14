#!/usr/bin/python3

from pathlib import Path
from typing import Optional,Union
from uuid import UUID

from WUEFI_symbols import _EFI_CERT_X509_GUID
from WUEFI_utils import subproc as util_suproc,is_guid as util_guid
# from WUEFI_utils_windows import subproc as util_suproc

def openssl_request_rsa_keypai_with_x509_csr(
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

	result=util_suproc(
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

	result=util_suproc(
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

	from sys import argv

	from WUEFI_symbols import _GUID_MIN

	epoint=Path(argv[0])
	outdir_tests=epoint.parent.joinpath("tests")
	outdir_tests.mkdir(exist_ok=True,parents=True)

	debugging=True

	res1=openssl_request_rsa_keypai_with_x509_csr(outdir_tests,key_stem="testdb",debug=debugging)
	if res1[0]==-1:
		print("ERROR:",res1)
		exit()

	res2=openssl_x509_convert_pem_to_der(res1[2],debug=debugging)

	print("PRIV KEY:",res1[1])
	print("PUBL KEY:",res1[2])
	print("DER CERT:",res2)

	res3=build_esl_from_a_x509_der(res2,UUID(_GUID_MIN),debug=debugging)
	if res3 is None:
		print("ERROR: failed to create ESL file")
		exit()

	print("ESL FILE:",res3)
