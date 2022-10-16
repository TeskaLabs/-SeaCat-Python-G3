import datetime


def int_to_bytes(value):
	d = bytearray()
	x = value
	while (x > 0):
		d.insert(0, x & 0xff)  # d.add(0, x.and(0xff).toByte())
		x = x >> 8
	return d


def il(tag: int, length: int):
	if length < 128:
		return bytearray([tag, length])
	else:
		d = int_to_bytes(length)
		return bytearray([tag, len(d) | 0x80]) + d


class DER(object):

	@staticmethod
	def SEQUENCE(elements: list, implicit_tagging: bool = True, tag: int = 0x30):
		d = bytearray()

		n = 0
		for e in elements:
			if e is None:
				n += 1
				continue

			if implicit_tagging:
				e0 = e[0]
				if ((e0 & 0x1F) == 0x10) | ((e0 & 0x1F) == 0x11) | (e0 == 0xA0):
					# the element is constructed
					identifier = 0xA0
				else:
					identifier = 0X80
				identifier += n

			else:
				identifier = e[0]

			n += 1
			d.append(identifier)
			d.extend(e[1:])

		return il(tag, len(d)) + d


	@staticmethod
	def SEQUENCE_OF(elements: list):
		return DER.SEQUENCE(elements, False)


	@staticmethod
	def SET_OF(elements: list):
		return DER.SEQUENCE(elements, False, 0x31)


	@staticmethod
	def INTEGER(value: int):
		if value == 0:
			return il(0x02, 1) + bytearray([0x00])

		b = int_to_bytes(value)
		if (b[0] & 0x80 == 0x80):
			return il(0x02, len(b)) + bytearray([0x00]) + b
		else:
			return il(0x02, len(b)) + b


	@staticmethod
	def OCTET_STRING(value: bytes):
		return il(0x04, len(value)) + value


	@staticmethod
	def NULL():
		return il(0x05, 0)


	@staticmethod
	def IA5String(value: str):
		value = value.encode('ascii')
		return il(0x16, len(value)) + value


	@staticmethod
	def BIT_STRING(value: bytes):
		return il(0x03, len(value) + 1) + bytearray([0x00]) + value


	@staticmethod
	def UTF8String(value: str):
		value = value.encode('utf-8')
		return il(12, len(value)) + value


	@staticmethod
	def PrintableString(value: str):
		value = value.encode('ascii')
		return il(19, len(value)) + value


	@staticmethod
	def UTCTime(value: datetime.datetime):
		b = value.strftime(r"%y%m%d%H%M%SZ").encode('ascii')
		return il(23, len(b)) + b


	@staticmethod
	def OBJECT_IDENTIFIER(value: str):
		a = [int(x) for x in value.split(".")]
		
		# First two items are coded by a1*40+a2
		oid = bytearray([a[0] * 40 + a[1]]) 
		
		# A rest is Variable-length_quantity
		for n in a[2:]:
			oid = oid + variable_length_quantity(n)

		return il(0x06, len(oid)) + oid


def variable_length_quantity(value: int):
	v = value
	m = 0
	output = bytearray()

	while (v >= 0x80):
		output.insert(0, (v & 0x7f) | m) 
		v = v >> 7
		m = 0x80

	output.insert(0, v | m)
	return output
