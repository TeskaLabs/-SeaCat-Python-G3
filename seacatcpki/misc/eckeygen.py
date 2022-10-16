import cryptography.hazmat.primitives.asymmetric.ec


def generate_ec_keypair(name: str):
	curve = cryptography.hazmat.primitives.asymmetric.ec._CURVE_TYPES['prime256v1']
	private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
		curve(),
		cryptography.hazmat.backends.default_backend()
	)

	private_key_pem = private_key.private_bytes(
		encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
		format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
		encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
	)
	with open(name + '.pem', 'wb') as f:
		f.write(private_key_pem)

	return private_key
