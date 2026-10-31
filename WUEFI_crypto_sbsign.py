#!/usr/bin/python3

# Minimal PURE Python implementation of SBSIGN

# Based on https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git

# Dependencies (python 3.9):
# asn1crypto==1.5.1
# pycryptodome==3.2.3

# Dependencies (python 3.14):
# asn1crypto==1.5.1
# pycryptodome==4.2.0

import hashlib
import struct

from pathlib import Path
from typing import Optional,Union

from asn1crypto import x509 as asn1_x509
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Authenticode / PKCS#7 object identifiers
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"

def tlv(tag:int,content:bytes)->bytes:
	lencon=len(content)
	lencon_bytes=b""
	smaller=(lencon<128)
	if smaller:
		lencon_bytes=bytes([lencon])
	if not smaller:
		raw = lencon.to_bytes(
			length=(lencon.bit_length() + 7)//8,
			byteorder="big"
		)
		lencon_bytes=bytes([0x80 | len(raw)]) + raw

	return bytes([tag]) + lencon_bytes + content

def seq(*items: bytes) -> bytes:
	return tlv(0x30, b"".join(items))

def der_set(*items: bytes) -> bytes:
	return tlv(0x31, b"".join(sorted(items)))

def der_integer(n:int)->Optional[bytes]:
	if n<0:
		return None
	raw=n.to_bytes(
		length=max(1,(n.bit_length()+ 7)//8),
		byteorder="big"
	)
	if raw[0] & 0x80:
		raw = b"\x00" + raw
	return tlv(0x02,raw)

def der_oid_base128(n:int)->bytes:
	parts = [n & 0x7F]
	n>>=7
	while n:
		parts.append(0x80 | (n & 0x7F))
		n>>=7
	return bytes(reversed(parts))

def der_oid(value:str)->Optional[bytes]:
	arcs = [int(x) for x in value.split(".")]
	if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
		return None

	# def base128(n: int) -> bytes:
	# 	parts = [n & 0x7F]
	# 	n>>=7
	# 	while n:
	# 		parts.append(0x80 | (n & 0x7F))
	# 		n>>=7
	# 	return bytes(reversed(parts))
	# body = base128(arcs[0] * 40 + arcs[1])
	body=der_oid_base128(arcs[0] * 40 + arcs[1])

	for arc in arcs[2:]:
		body=body+der_oid_base128(arc)
	return tlv(0x06,body)

def algorithm_identifier(oid: str) -> bytes:
	# NULL parameters
	return seq(
		der_oid(oid),
		tlv(0x05, b"")
	)

def pe_layout(data:bytes,detailed:bool=False)->Optional[tuple]:

	# Return PE header offsets and section raw-data ranges

	step=1
	if len(data) < 0x40 or data[:2] != b"MZ":
		msg="Input is not a DOS/PE image"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	peoff = struct.unpack_from("<I", data, 0x3C)[0]
	if peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\0\0":
		msg="Invalid PE signature or truncated file"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	nsections = struct.unpack_from("<H", data, peoff + 6)[0]
	opt_size = struct.unpack_from("<H", data, peoff + 20)[0]
	opt = peoff + 24
	if opt + opt_size > len(data) or opt_size < 68:
		msg="Truncated PE optional header"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	num_dirs_off=0
	dirs_off=0
	ok=False

	step=step+1
	magic = struct.unpack_from("<H", data, opt)[0]
	if magic==0x10B:
		# PE32
		# num_dirs_off, dirs_off = opt + 92, opt + 96
		num_dirs_off=opt+92
		dirs_off=opt+96
		ok=True
	if magic==0x20B:
		# PE32+
		# num_dirs_off, dirs_off = opt + 108, opt + 112
		num_dirs_off=opt+108
		dirs_off= opt+112
		ok=True
	if not ok:
		msg=f"Unsupported PE optional-header magic: {magic:#x}"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	num_dirs = struct.unpack_from("<I", data, num_dirs_off)[0]
	if num_dirs < 5 or dirs_off + 5 * 8 > opt + opt_size:
		msg="PE image has no security-directory entry"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	checksum_off = opt + 64
	security_entry_off = dirs_off + 4 * 8
	cert_off, cert_size = struct.unpack_from("<II", data, security_entry_off)
	if cert_off or cert_size:
		msg="This minimal script accepts unsigned input images only"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
	if size_of_headers > len(data):
		msg="Invalid SizeOfHeaders"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	step=step+1
	section_table = opt + opt_size
	if section_table + nsections * 40 > len(data):
		msg="Truncated PE section table"
		if detailed:
			return (step,msg)
		print(msg)
		return None

	msg:Optional[str]=None
	step=step+1
	sections = []
	for i in range(nsections):
		sh=section_table+i*40
		raw_size,raw_ptr=struct.unpack_from("<II",data,sh+16)
		if not raw_size>-1:
			continue
		if raw_ptr + raw_size > len(data):
			msg="Section extends beyond end of file"
			break
		sections.append((raw_ptr, raw_size))
	if msg is not None:
		if detailed:
			return (step,msg)
		print(msg)
		return None

	if detailed:
		return (
			0,
			checksum_off,
			security_entry_off,
			size_of_headers,
			sections
		)

	return (
		checksum_off,
		security_entry_off,
		size_of_headers,
		sections
	)

def authenticode_sha256(data:bytes) -> Optional[bytes]:

	# Compute the PE Authenticode digest for a conventional unsigned PE image:
	# Omit CheckSum and the security-directory entry, hash headers, then sections
	# in file-offset order, followed by any trailing bytes.

	result=pe_layout(data)
	if result is None:
		return None

	checksum_off,security_off,headers_size,sections=result

	if checksum_off + 4 > headers_size or security_off + 8 > headers_size:
		print("PE checksum/security directory is outside headers")
		return None

	h = hashlib.sha256()
	h.update(data[:checksum_off])
	h.update(data[checksum_off + 4:security_off])
	h.update(data[security_off + 8:headers_size])

	sections.sort(key=lambda item: item[0])
	for raw_ptr, raw_size in sections:
		h.update(data[raw_ptr:raw_ptr + raw_size])

	# Conventional Authenticode handling for data after the section contents
	bytes_hashed = headers_size + sum(size for _, size in sections)
	if bytes_hashed < len(data):
		h.update(data[bytes_hashed:])

	return h.digest()

def make_indirect_data(image_digest:bytes)->tuple[bytes,bytes]:

	# Return (full DER SpcIndirectDataContent, its sequence body)
	# The body is the content sbsigntools hashes for PKCS#7 signed attributes

	# SpcPeImageData: empty flags + file link containing "<<<Obsolete>>>"
	# as a BMPString with the [0] implicit tag used by sbsigntools.

	obsolete = "<<<Obsolete>>>".encode("utf-16-be")
	bmp_string = tlv(0x80, obsolete)

	# [2] EXPLICIT
	file_link = tlv(0xA2, bmp_string)

	# [0] EXPLICIT
	pe_file = tlv(0xA0, file_link)

	# empty BIT STRING
	pe_image_data = seq(tlv(0x03, b"\x00"), pe_file)  

	data_field = seq(der_oid(OID_SPC_PE_IMAGE_DATA), pe_image_data)
	digest_info = seq(
		algorithm_identifier(OID_SHA256),
		tlv(0x04, image_digest),
	)
	body = data_field + digest_info
	return seq(body), body

def make_pkcs7(
		indirect_der:bytes,
		indirect_body:bytes,
		cert_der:bytes,
		cert_asn1,
		private_key
	) -> bytes:

	#  Build the embedded PKCS#7 SignedData used by this minimal signer

	content_type_attr = seq(
		der_oid(OID_CONTENT_TYPE),
		der_set(der_oid(OID_SPC_INDIRECT_DATA)),
	)
	message_digest = hashlib.sha256(indirect_body).digest()
	message_digest_attr = seq(
		der_oid(OID_MESSAGE_DIGEST),
		der_set(tlv(0x04, message_digest)),
	)

	signed_attrs = der_set(content_type_attr,message_digest_attr)

	# Sign the DER SET encoding; SignerInfo stores the same bytes with [0] tag.
	signature=pkcs1_15.new(private_key).sign(SHA256.new(signed_attrs))
	signed_attrs_implicit = tlv(0xA0, signed_attrs[2:])
	digest_alg = algorithm_identifier(OID_SHA256)
	signature_alg = algorithm_identifier(OID_RSA_ENCRYPTION)
	issuer_and_serial = seq(
		cert_asn1.issuer.dump(),
		der_integer(cert_asn1.serial_number),
	)
	signer_info = seq(
		der_integer(1),
		issuer_and_serial,
		digest_alg,
		signed_attrs_implicit,
		signature_alg,
		tlv(0x04, signature),
	)

	# PKCS#7 ContentInfo for SPC_INDIRECT_DATA; the content is the ASN.1
	# sequence itself, not an ordinary file-data OCTET STRING.
	content_info = seq(
		der_oid(OID_SPC_INDIRECT_DATA),
		tlv(0xA0, indirect_der),
	)
	signed_data = seq(
		der_integer(1),
		der_set(digest_alg),
		content_info,
		# [0] IMPLICIT certificate set (one certificate)
		tlv(0xA0, cert_der),
		der_set(signer_info),
	)
	return seq(
			der_oid(OID_SIGNED_DATA),
			tlv(0xA0,
			signed_data
		)
	)

def main(
		fpath_pvtkey:Path,
		fpath_certder:Path,
		fpath_input:Path,
		fpath_output:Path,
	)->bool:

	data=bytearray(fpath_input.read_bytes())

	# Align the start of the certificate table to 8 bytes.
	data += b"\0" * ((-len(data)) % 8)

	checksum_off,security_off,_,_=pe_layout(data)
	image_digest = authenticode_sha256(data)

	certder=fpath_certder.read_bytes()

	indirect_der, indirect_body = make_indirect_data(image_digest)
	pkcs7=make_pkcs7(
		indirect_der,
		indirect_body,
		certder,
		asn1_x509.Certificate.load(certder),
		RSA.importKey(fpath_pvtkey.read_bytes())
	)

	dw_length = 8 + len(pkcs7)
	entry = struct.pack("<IHH", dw_length, 0x0200, 0x0002) + pkcs7
	entry += b"\0" * ((-len(entry)) % 8)

	cert_offset = len(data)
	struct.pack_into("<II", data, security_off, cert_offset, len(entry))

	# output_path=fpath_input.parent.joinpath(f"{fpath_input}.signed")
	fpath_output.write_bytes(data + entry)
	# return fpath_output

	return True
