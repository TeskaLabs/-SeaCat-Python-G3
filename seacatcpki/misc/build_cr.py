import datetime
import platform

import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.hashes

from .miniasn1 import DER


def build_certificate_request(private_key, appname, attributes: dict = None):
	public_key = private_key.public_key()
	public_key_bytes = public_key.public_bytes(
		encoding=cryptography.hazmat.primitives.serialization.Encoding.DER,
		format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
	)

	created_at = datetime.datetime.now()
	valid_to = created_at + datetime.timedelta(minutes=5)

	transformed_attributes = [
		DER.SEQUENCE([
			DER.IA5String("OS"),
			DER.IA5String(platform.system())
		]),
		DER.SEQUENCE([
			DER.IA5String("Client"),
			DER.IA5String("python")
		]),
	
	]

	if attributes is not None:
		for k, v in attributes:
			transformed_attributes.append(
				DER.SEQUENCE([
					DER.IA5String(k),
					DER.IA5String(v)
				])
			)

	tbs_request = DER.SEQUENCE([
		DER.INTEGER(0x1902),
		DER.UTF8String(appname),  # application
		DER.UTCTime(created_at),  # createdAt
		DER.UTCTime(valid_to),  # validTo
		DER.SEQUENCE([  # SubjectPublicKeyInfo
			DER.SEQUENCE([
				DER.OBJECT_IDENTIFIER("1.2.840.10045.2.1"),  # ecPublicKey (ANSI X9.62 public key type)
				DER.OBJECT_IDENTIFIER("1.2.840.10045.3.1.7")  # prime256v1 (ANSI X9.62 named elliptic curve)
			]),
			DER.BIT_STRING(public_key_bytes[-65:])  # Last 65 bytes
		]),
		DER.SEQUENCE_OF(transformed_attributes)
	])

	tbs_request[0] = 0xA0

	# Sign a request body
	signature = private_key.sign(tbs_request, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
		cryptography.hazmat.primitives.hashes.SHA256()
	))

	cr = DER.SEQUENCE([
		tbs_request,
		DER.SEQUENCE([
			DER.OBJECT_IDENTIFIER("1.2.840.10045.4.3.2")  # ecdsa-with-SHA256
		]),
		DER.OCTET_STRING(signature)
	])

	return cr
