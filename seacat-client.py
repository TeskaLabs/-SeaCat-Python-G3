#!/usr/bin/env python3
import time

import seacatcpki


def main():
	SeaCat = seacatcpki.SeaCat("SeaCat Demo Client", "https://localhost.seacat.io/seacat")
	print("Identity: {}".format(SeaCat.Identity.identity()))
	while True:
		time.sleep(500)


if __name__ == '__main__':
	main()
