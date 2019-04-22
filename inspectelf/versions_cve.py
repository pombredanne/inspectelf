#!/usr/bin/python

import argparse
import requests
from pprint import pprint

BASE_URL = "http://cve.circl.lu/api/search/"
def cves(libname, version):
	r = requests.get(BASE_URL + "%s/%s" % (libname, version))

	results = []
	for cve in r.json():
		record = {}
		if "id" in cve:
			record["cve"] = cve["id"]

		if "cvss" in cve:
			record["cvss"] = cve["cvss"]

		if "access" in cve:
			record["vector"] = cve["access"]["vector"]
			record["complexity"] = cve["access"]["complexity"]

		if "cvss-time" in cve:
			record["since"] = cve["cvss-time"]

		if "summary" in cve:
			record["summary"] = cve["summary"]

		if "vulnerable_configuration" in cve:
			record["versions"] = [ v[v.rfind(":") + 1:] for v in cve["vulnerable_configuration"]]

		results.append(record)

	return results

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description = "Report CVEs for requested library and version")
	parser.add_argument("libname", help = "Library name")
	parser.add_argument("version", help = "Version")

	args = parser.parse_args()
	pprint(cves(args.libname, args.version))
