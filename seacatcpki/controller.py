

class Controller(object):

	def on_initial_enrollment_requested(self, seacat):
		# You may decide to call seacat.identity.enroll() later
		seacat.Identity.enroll()

	def on_reenrollment_requested(self, seacat):
		# You may decide to call seacat.identity.enroll() later
		seacat.Identity.enroll()
