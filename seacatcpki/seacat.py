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
