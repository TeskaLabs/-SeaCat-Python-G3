import os
import datetime
import hashlib
import base64

import requests
import cryptography.x509

from .misc.eckeygen import generate_ec_keypair
from .misc.build_cr import build_certificate_request


class Identity(object):


	def __init__(self, seacat):
		self.KeyPair = None
		self.Certificate = None
		self.SeaCat = seacat


	def _post_init(self):
		if not self.load():
			self.renew()


	def identity(self):
		if self.KeyPair is None:
			return None
		return seacat_identity(self.KeyPair.public_key())


	def load(self):
		# Load a private/public key
		try:
			with open("seacat_key.pem", "rb") as fi:
				self.KeyPair = cryptography.hazmat.primitives.serialization.load_pem_private_key(
					fi.read(),
					None,
					cryptography.hazmat.backends.default_backend()
				)

		except FileNotFoundError:
			self.Certificate = None
			self.KeyPair = None
			return False

		# Load a certificate
		try:
			with open("seacat_cert.der", "rb") as fi:
				self.Certificate = cryptography.x509.load_der_x509_certificate(fi.read())
		except FileNotFoundError:
			self.Certificate = None
			self.KeyPair = None
			return False

		return self.verify()


	def renew(self):
		# TODO: seacat.controller.onAction(SeaCat.ACTION_IDENTITY_RENEW)
		if self.Certificate is None:
			self.SeaCat.Controller.on_initial_enrollment_requested(self.SeaCat)
		else:
			self.SeaCat.Controller.on_reenrollment_requested(self.SeaCat)


	def enroll(self, attributes=None):
		if attributes is None:
			attributes = {}

		if self.KeyPair is None:
			self.KeyPair = generate_ec_keypair("seacat_key")
			self.Certificate = None
			try:
				os.unlink("seacat_cert.der")
			except FileNotFoundError:
				pass

		self.enroll_certificate_request(
			build_certificate_request(self.KeyPair, self.SeaCat.ApplicationName, attributes)
		)

	def revoke(self):
		try:
			os.unlink("seacat_cert.der")
		except FileNotFoundError:
			pass

		try:
			os.unlink("seacat_key.pem")
		except FileNotFoundError:
			pass

		self.KeyPair = None
		self.Certificate = None


		# TODO: seacat.controller.onAction(SeaCat.ACTION_IDENTITY_REVOKED)


	def enroll_certificate_request(self, cr: bytes):
		url = self.SeaCat.ApiURL + '/enroll'
		print(">>>", url)
		# TODO: verify=False is a temporary fix
		r = requests.put(url, cr, headers={'Content-Type': 'application/octet-stream'}, verify=False)
		if r.status_code != 200:
			raise RuntimeError("SeaCat PKI returned '{}' when accessing '{}'".format(r.status_code, url))

		rawcert = r.content
		certificate = cryptography.x509.load_der_x509_certificate(rawcert)
		if certificate is not None:
			with open("seacat_cert.der", "wb") as fo:
				fo.write(rawcert)

		self.load()

		# TODO: seacat.controller.onAction(SeaCat.ACTION_IDENTITY_ENROLLED)


	def verify(self):
		if self.Certificate is None:
			return False

		if self.KeyPair is None:
			return False

		# Do a soft verification of the expiration, commence renewal if needed
		# If the identity certificate is after a half of its life
		# OR it is less than 30 days to expiration day
		# then start renew() process
		nvb = self.Certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
		nva = self.Certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)

		now = datetime.datetime.now(datetime.timezone.utc)
		half = nvb + ((nva - nvb) / 2)
		days30 = nva - datetime.timedelta(days=30)

		if (now > half) or (now >= days30):
			self.renew()

		if nvb > now:
			# Not valid yet
			return False

		if nva < now:
			# Not valid any longer
			return False

		return True


def seacat_identity(public_key):
	pn = public_key.public_numbers()

	# for an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y.
	x963 = bytes([0x04]) + pn.x.to_bytes(32, "big") + pn.y.to_bytes(32, "big")
	
	m = hashlib.sha384()
	m.update(x963)
	d = m.digest()

	d = base64.b32encode(d)
	return d[:16].decode('ascii')
