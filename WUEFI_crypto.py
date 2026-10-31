#!/usr/bin/python3

# Cryptographic functionalities

# Dependencies (python 3.9):
# pycryptodome==3.2.3

# Dependencies (python 3.14):
# pycryptodome==4.2.0

# NOTE:
# All cryptographic functionality is centered around x509 RSA key pairs, DER
# certificates and EFI file signing

from datetime import datetime,timedelta,timezone
from pathlib import Path
import secrets
from sys import platform as sys_platform
from typing import Optional,Union
from uuid import UUID

# from Crypto.IO import PEM
# from asn1crypto import keys, pem, x509
from asn1crypto import core as asn1c_core
from asn1crypto import keys as asn1c_keys
# from asn1crypto import pem as a1snc_pem
from asn1crypto import x509 as asn1c_x509
from asn1crypto.x509 import Certificate as x509_Certificate
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15
# from Crypto.Util.asn1 import DerSequence

from WUEFI_crypto_sbsign import main as sbsign
from WUEFI_symbols import _EFI_CERT_X509_GUID
from WUEFI_utils import is_guid as util_guid
from WUEFI_utils import fix_path_out

if sys_platform in ("linux","linux2"):
	from WUEFI_utils import subproc as util_subproc
if sys_platform=="win32":
	from WUEFI_utils_windows import wsubproc as util_subproc

# Return Types

_RTYPE_RAW="ReturnType_Raw"
_RTYPE_PATH="ReturnType_Path"
_RTYPE_ASN1="ReturnType_Asn1Crypto"
_RTYPE_PYCD="ReturnType_PyCryptodome"

###############################################################################

# Utils

def read_tlv(
		data:bytes,
		off:int,
		debug:bool=False
	)->Optional[tuple]:

	tag=data[off]
	offset=off+1
	size=data[offset]
	offset=offset+1

	if size & 0x80:
		count=size & 0x7F
		if count==0:
			m="Indefinite length is not valid DER"
			if debug:
				raise Exception(m)
			print(m)
			return None

		if offset+count>len(data):
			m="Truncated DER length"
			if debug:
				raise Exception(m)
			print(m)
			return None

		size=int.from_bytes(
			data[offset:offset+count],
			byteorder="big"
		)
		offset=offset+count

	end=offset+size
	if end>len(data):
		msg="Truncated DER data"
		if debug:
			raise ValueError(msg)
		return None

	result=(tag,data[offset:end],end)

	# if debug:
	# 	print("read_tlv():",result)

	return result

def is_rsa_match(
		fpath_pvtkey:Path,
		fpath_pubkey:Path,
		debug:bool=False
	)->bool:

	obj_pvtkey:Optional[RsaKey]=None
	obj_pvtkey:Optional[RsaKey]=None
	try:
		obj_pvtkey=RSA.import_key(fpath_pvtkey.read_bytes())
		obj_pubkey=RSA.import_key(fpath_pubkey.read_bytes())

	except Exception as exc:
		if debug:
			raise exc

		print(exc)
		return False

	print(type(obj_pubkey),type(obj_pvtkey))

	result=(
		obj_pvtkey.n==obj_pubkey.n
		and obj_pvtkey.e==obj_pubkey.e
	)

	if debug:
		print(
			fpath_pvtkey.name,":",
			fpath_pubkey.name,":",
			result
		)

	return result

###############################################################################

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

	fpath_pvtkey:Path=outdir.joinpath(f"{key_stem}.key")
	fpath_pubkey:Path=outdir.joinpath(f"{key_stem}.pem")

	command=[
		"openssl",
			"req",
			"-new",
			"-x509",
			"-newkey","rsa:2048",
			"-sha256",
			"-days",str(expir_years),
			"-subj",subj_name,
			"-keyout",str(fpath_pvtkey.absolute()),
			"-out",str(fpath_pubkey.absolute()),
			"-nodes"
		]

	result=util_subproc(
		command,
		verbose=debug,
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
		fpath_pvtkey.absolute(),
		fpath_pubkey.absolute()
	)

def openssl_pkey_extract_public_key(
		fpath_pvtkey:Path,
		fpath_out:Optional[Path],
		confirm_only:bool=False,
		debug:bool=False,
	)->Union[bool,Optional[Path]]:

	# Uses OpenSSL's PKEY command to extract the public key from the private key

	fpath_pubkey:Optional[Path]=fix_path_out(
		fpath_out,
		f"{fpath_pvtkey.stem}.pem",
		debug=debug
	)
	if fpath_pubkey is None:
		if confirm_only:
			return False
		return None

	command=[
		"openssl",
			"pkey"
			"-in",str(fpath_pvtkey),
			"-pubout",
			"-out",str(fpath_pubkey)
	]

	result=util_subproc(
		command,
		verbose=debug,
	)
	ok=(result[0]==0)
	if confirm_only:
		return ok

	if not ok:
		return None

	return fpath_pubkey

def openssl_x509_convert_pem_to_der(
		fpath_pubkey:Path,
		fpath_out:Optional[Path]=None,
		confirm_only:bool=False,
		debug:bool=False,
	)->Union[bool,Optional[Path]]:

	# Uses OpenSSL's x509 command to convert a PEM key file into DER format

	# NOTE:
	# The resulting file will be stored in the same directory as the given
	# PEM file

	fpath_certder:Optional[Path]=fix_path_out(
		fpath_out,
		f"{fpath_pubkey.stem}.der",
		debug=debug
	)
	if fpath_certder is None:
		if confirm_only:
			return False
		return None

	command=[
		"openssl",
			"x509",
			"-in",str(fpath_pubkey.absolute()),
			"-outform","DER",
			"-out",str(fpath_certder)
		]

	result=util_subproc(
		command,
		verbose=debug,
	)
	ok=(result[0]==0)
	if confirm_only:
		return ok

	if not ok:
		return None

	return fpath_certder

def openssl_x509_read_certder(
		fpath_certder:Path,
		confirm_only:bool=False,
		debug:bool=False
	)->Union[bool,tuple]:

	# Uses OpenSSL's x509 command to parse a DER Certificate
	# This can be used to confirm the validity of a DER Certificate

	# openssl x509 -inform DER -in "certificate.der" -noout -text

	command=[
		"openssl",
			"x509",
			"-inform","DER",
			"-in",str(fpath_certder.absolute()),
			"-noout",
			"-text"
	]

	result=util_subproc(
		command,
		verbose=debug,
	)
	ok=(result[0]==0)
	if confirm_only:
		return ok

	return result

###############################################################################

# Pure python

def from_x509_keypair_make_certder(
		fpath_pvtkey:Path,
		fpath_pubkey:Optional[Path]=None,
		fpath_out:Optional[Path]=None,
		time_date_start:Optional[datetime]=None,
		time_duration_days:int=365,
		issuer:str="WUEFI",
		duration:int=365,
		debug:bool=False,
		return_type:Optional[str]=_RTYPE_ASN1
	)->Optional[Union[bool,bytes,Path,x509_Certificate]]:

	# Creates a self-signed x509 self signed certificate

	obj_pvtkey:RsaKey=RSA.import_key(
		fpath_pvtkey.read_bytes()
	)

	obj_pubkey:Optional[RsaKey]=None
	has_pubkey=isinstance(fpath_pubkey,Path)
	if has_pubkey:
		obj_pubkey=RSA.import_key(fpath_pubkey.read_bytes())
		if not (
				obj_pvtkey.n==obj_pubkey.n and
				obj_pvtkey.e==obj_pubkey.e
			):
			m="The provided private key does not match with the provided public key"
			if debug:
				raise Exception(m)
			print(m)
			return None

	if not has_pubkey:
		obj_pubkey=obj_pvtkey.public_key()

	fpath_certder:Optional[Path]=None

	return_type_ok:Optional[str]=None

	if return_type==_RTYPE_PATH or isinstance(fpath_out,Path):
		return_type_ok=return_type
		fname=".der"
		if has_pubkey:
			fname=f"{fpath_pubkey.stem}{fname}"
		if not has_pubkey:
			fname=f"{fpath_pvtkey.stem}{fname}"
		fpath_certder=fix_path_out(
			fpath_out,
			f"{fpath_pubkey.stem}.der",
			debug=False
		)
		if fpath_certder is None:
			return None

	spki_der = obj_pubkey.public_key().export_key(format="DER")
	spki = asn1c_keys.PublicKeyInfo.load(spki_der)

	# name = asn1c_x509.Name.build({"common_name": "example.com"})
	name = asn1c_x509.Name.build({"common_name": issuer})

	date_start:Optional[datetime]=None
	ok=isinstance(time_date_start,datetime)
	if ok:
		date_start=time_date_start
	if not ok:
		date_start=datetime.now(timezone.utc).replace(microsecond=0)

	extensions=[
		asn1c_x509.Extension({
			"extn_id": "basic_constraints",
			"critical": True,
			"extn_value": asn1c_x509.BasicConstraints({"ca": False}),
		}),
		asn1c_x509.Extension({
			"extn_id": "key_usage",
			"critical": True,
			"extn_value": asn1c_x509.KeyUsage({"digital_signature", "key_encipherment"}),
		}),
		asn1c_x509.Extension({
			"extn_id": "extended_key_usage",
			"extn_value": asn1c_x509.ExtKeyUsageSyntax(["server_auth"]),
		}),
		# asn1c_x509.Extension({
		# 	"extn_id": "subject_alt_name",
		# 	"extn_value": asn1c_x509.GeneralNames([
		# 		asn1c_x509.GeneralName(
		# 			name="dns_name",
		# 			value="example.com"
		# 		),
		# 	]),
		# })
	]

	signature_algorithm = {
		"algorithm": "sha256_rsa",
		"parameters":asn1c_core.Null()
	}

	tbs = asn1c_x509.TbsCertificate({
		"version": "v3",
		"serial_number": secrets.randbits(159) or 1,
		"signature": signature_algorithm,
		"issuer": name,
		"validity": {
			"not_before": {"utc_time": date_start},
			"not_after": {"utc_time": date_start + timedelta(days=365)},
			# "not_before": {"utc_time": now},
			# "not_after": {"utc_time": now + datetime.timedelta(days=365)},
		},
		"subject": name,
		"subject_public_key_info": spki,
		"extensions": extensions,
	})

	signature = pkcs1_15.new(obj_pvtkey).sign(SHA256.new(tbs.dump()))

	cert:x509_Certificate = x509_Certificate({
		"tbs_certificate": tbs,
		"signature_algorithm": signature_algorithm,
		"signature_value": signature,
	})

	if return_type_ok is None:
		return_type_ok=return_type

	if return_type_ok==_RTYPE_ASN1:
		return cert

	if return_type_ok==_RTYPE_RAW:
		return cert.dump()

	if return_type_ok==_RTYPE_PATH:
		fpath_certder.write_bytes(cert.dump())
		return fpath_certder

	return True

def from_x509_certder_make_esl(
		fpath_certder:Path,
		owner_guid:Union[str,UUID],
		fpath_out:Optional[Path]=None,
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

	content_der=fpath_certder.read_bytes()

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

	stem=fpath_certder.stem

	fpath_esl=fpath_certder.parent.joinpath(f"{stem}.esl")

	fpath_esl.write_bytes(esl_content)

	if confirm_only:
		return True

	return fpath_esl

def from_x509_certder_get_pem(
		fpath_certder:Path,
		fpath_pubkey:Optional[Path]=None,
		debug=False
	)->Union[bool,Optional[RsaKey]]:

	# Given an x509 DER encoded certificate, it extracts the public key (PEM)
	# from it, returning an pycryptodome RsaKey object holding the PEM key

	# NOTE:
	# If you provide a public key as an argument, this function will compare that
	# public key with the piblic key that was extracted from the provided DER
	# certificate, in this case, it will return a boolean

	compare=isinstance(fpath_pubkey,Path)
	if compare:
		compare=fpath_pubkey.is_file()

	readres=read_tlv(fpath_certder.read_bytes(),0,debug=debug)
	if readres is None:
		return None
	tag=readres[0]
	cert_content=readres[1]
	if not tag==0x30:
		m="Not a DER X.509 Certificate"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	readres=read_tlv(cert_content,0,debug=debug)
	if readres is None:
		return None
	tag,tbs,_=readres
	if not tag==0x30:
		m="Invalid TBSCertificate"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	offset=0
	readres=read_tlv(tbs,offset,debug=debug)
	if readres is None:
		return None
	tag,_,offset_next=readres
	if tag==0xA0:
		offset=offset_next

	err=False
	fields=[]
	while offset<len(tbs):
		readres=read_tlv(tbs,offset)
		if readres is None:
			err=True
			break

		tag,value,offset_next=readres
		fields.append((tag,value))
		offset=offset_next

	if err:
		m="Loop fail"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	spki_index=-0
	if fields[0][0]==0xA0:
		spki_index=6
	if fields[0][0]==0x02:
		spki_index=5
	if spki_index==0:
		m="Unexpected first TBSCertificate field"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	spki_tag,spki=fields[spki_index]

	if not spki_tag==0x30:
		m="Invalid SubjectPublicKeyInfo"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	readres=read_tlv(spki,0)
	if readres is None:
		return None
	bit_str_tlv_end=readres[2]

	readres=read_tlv(spki,bit_str_tlv_end)
	if readres is None:
		return None
	bit_tag=readres[0]
	bit_str=readres[1]
	if bit_tag!=0x03 or not bit_str or bit_str[0]!=0:
		m="Invalid public-key BIT STRING"
		if debug:
			raise Exception(m)
		print(m)
		if compare:
			return False
		return None

	pubkey1=RSA.import_key(bit_str[1:])

	if compare:

		pubkey2=RSA.import_key(fpath_pubkey.read_bytes())

		result=(
			pubkey1.n==pubkey2.n
			and pubkey1.e==pubkey2.e
		)

		if debug:
			print(
				fpath_certder.name,":CAME FROM:",
				fpath_pubkey.name,":?",
				result
			)

		return result

	return pubkey1

def sign_image(
		fpath_pvtkey:Path,
		fpath_certder:Path,
		fpath_input:Path,
		fpath_output:Optional[Path],
		debug:bool=False,
	)->Optional[Path]:

	fpath_out_ok=fix_path_out(
		fpath_output,
		f"{fpath_input.stem}.signed",
		debug=debug
	)
	if fpath_out_ok is None:
		return None

	obj_pvtkey:Optional[RsaKey]=RSA.import_key(
		fpath_pvtkey.read_bytes()
	)
	obj_pubkey=obj_pvtkey.public_key()

	obj_pubkey_from_certder:Optional[RsaKey]=from_x509_certder_get_pem(
		fpath_certder,
		debug=debug
	)
	if not (
			obj_pubkey.n==obj_pubkey_from_certder.n and
			obj_pubkey.e==obj_pubkey_from_certder.e
		):
		msg="The provided certificate does not match the provided key"
		if debug:
			raise Exception(msg)

		print(msg)
		return None

	if not sbsign(
			fpath_pvtkey,
			fpath_certder,
			fpath_input,
			fpath_out_ok
		):
		msg="Failed to sign the file"
		if debug:
			raise Exception(msg)

		print(msg)
		return None

	return fpath_out_ok
