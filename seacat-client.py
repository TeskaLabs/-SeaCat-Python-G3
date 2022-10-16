#!/usr/bin/env python3
import time

import seacatcpki

import urllib3


def main():
	SeaCat = seacatcpki.SeaCat("SeaCat Demo Client", "https://localhost.seacat.io/seacat")
	print("Identity: {}".format(SeaCat.Identity.identity()))

	while True:
		time.sleep(0.5)

		http = urllib3.PoolManager(
			ssl_context=SeaCat.build_ssl_context()
		)

		# Make a request
		r = http.request(
			'GET',
			'https://masterdcpoc.seacat.io/xxx',
		)
		print(">>", r)


if __name__ == '__main__':
	main()
