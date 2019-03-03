#!/usr/bin/python

def versplit(v):
	res = []
	s = ""
	for c in v:
		if c != '.':
			res.append(ord(c))

	return res
"""
		if (len(s) == 0 or s[-1].isalpha() == c.isalpha()) and c != '.':
			s += c
		else:
			res.append(s)
			if c != '.':
				s = c
			else:
				s = ""
	if len(s) > 0:
		res.append(s)

	return res
"""
def vercmp(v0, v1):
	v0 = versplit(v0)
	v1 = versplit(v1)

	# Pad to normalize lengths
	if len(v0) < len(v1):
		v0 += [0] * (len(v1) - len(v0))
	else:
		v1 += [0] * (len(v0) - len(v1))

	for x, y in zip(v0, v1):

		if x > y:
			return False
		elif x < y:
			return True
	return True

print vercmp("1.4.1.2b", "1.3")
print vercmp("123", "100")
