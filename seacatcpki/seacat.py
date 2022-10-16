import ssl

from .identity import Identity
from .controller import Controller


class SeaCat(object):

	def __init__(self, application_name, api_url, *, controller=None):
		self.ApplicationName = application_name
		self.Controller = controller if controller is not None else Controller()		

		while api_url[-1:] == '/':
			api_url = api_url[:-1]
		self.ApiURL = api_url
		self.Identity = Identity(self)

		self.Identity._post_init()


	def build_ssl_context(self):
		if self.Identity.identity() is None:
			raise RuntimeError("The identity is not ready yet.")

		ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
		ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
		ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
		
		ssl_context.load_cert_chain(certfile="./seacat_cert.pem", keyfile="./seacat_key.pem")

		# Till the SSL settings in Nginx is fixed
		ssl_context.load_verify_locations("./ca-bundle.pem", None, None)

		return ssl_context
