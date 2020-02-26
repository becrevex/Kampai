# Programmer: Brent Chambers
# Date: March 16, 2018 (updated 5/16/2019)
# Filename: kampai.py
# Technique:
# Syntax: (TBD)
# Description:  Custom kenna connector for single for bulk imports

import csv, xlrd, xlwt, sys
import requests, json
import argparse
import datetime
import pprint
import re
import report_writer
from os import system

help_example = "EXAMPLE: kampai.py -id CVE-1999-5656 -ip 10.21.21.21 -p 8080 -s 5 -fix \"Upgrade to the latest version\""
parser = argparse.ArgumentParser(description='Kampai: Custom Kenna Connector for single or bulk import.'+'\n\n'+help_example, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-ip', '--ipaddress')
parser.add_argument('-url', '--url')
parser.add_argument('-host', '--hostname')
parser.add_argument('-p', '--port')
parser.add_argument('-id', '--vulnid', help='Vulnerability identifier.  e.g. CVE or CWE')
parser.add_argument('-fix', '--remediation', help='Enter context and remediation guidance.')
parser.add_argument('-s', '--severity', help='Integer value.  e.g. 6')
parser.add_argument('-iX', '--excel', help='Specify a filename for bulk import. e.g kampai_test.xlsx')
parser.add_argument('-iC', '--csv', help='Specify a CSV filename for bulk import.  e.g records.csv')
parser.add_argument('-createxls', action='store_true', help='Create a sample XLSX template for population.')

args = parser.parse_args()
importsig = " Imported with Kampai custom Kenna import tool."


def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def is_valid_ip(ip):
	test = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
	if test:
		return True
	else:
		return False



###
# Imports all records within an XLS into Kenna
##
def xls_batch_import(filename):
	try:
		book = xlrd.open_workbook(filename)
	except:
		print("Could not open source file.  Quitting.")
	print("Resource file loaded.")
	source = book.sheet_by_index(0)
	recordCount = len(source.col_values(0))-1
	print("Record count: ", recordCount)
	for i in range(1, recordCount+1):
		print("Record #"+str(i))
		print("********************")
		print("Vuln ID:    ", source.row_values(i)[0])
		print("IP Address: ", source.row_values(i)[1])
		try:
			print("Port:       ", int(source.row_values(i)[2]))
		except:
			print("Port:       ", source.row_values(i)[2])
		print("Details:    ", source.row_values(i)[3])
		print("Severity:   ", int(source.row_values(i)[4]))
		print("")
	answer = input("Import all records into Kenna? Y/n ")
	if answer == "Y" or answer == "y":
		record_array = []
		for i in range(1, recordCount+1):
			vuln_json = row_to_json(source.row_values(i))
			kid = import_vuln_json(vuln_json)
			rArray = [source.row_values(i)[0],
				  source.row_values(i)[1],
				  source.row_values(i)[2],
				  source.row_values(i)[3],
				  source.row_values(i)[4],
				  kid]
			record_array.append(rArray)
		xls_create_report(record_array)
	else:
		print("Okay, quitting.")
		sys.exit()
###
# Converts a list of finding records into JSON and returns the text
##
def row_to_json(row_list):
	vuln_json = {'vulnerability':{}}
	ident = row_list[0].split('-')[0]
	if ident == "CVE":
		vuln_json['vulnerability']['cve_id'] = row_list[0]
	elif ident == "CWE":
		vuln_json['vulnerability']['cwe_id'] = row_list[0]

	# Identify asset logic for bulk imports
	if is_valid_hostname(row_list[1]):
		vuln_json['vulnerability']['primary_locator'] = 'hostname'
		vuln_json['vulnerability']['hostname'] = row_list[1]
	elif is_valid_ip(row_list[1]):
		vuln_json['vulnerability']['primary_locator'] = 'ip_address'
		vuln_json['vulnerability']['ip_address'] = row_list[1]
	else:
		vuln_json['vulnerability']['primary_locator'] = 'url'
		vuln_json['vulnerability']['url'] = row_list[1]
	try:
		vuln_json['vulnerability']['port'] = int(row_list[2])
	except:
		vuln_json['vulnerability']['port'] = 0
	vuln_json['vulnerability']['notes'] = row_list[3]
	vuln_json['vulnerability']['severity'] = int(row_list[4])
	return vuln_json


###
# Takes JSON string of a record and imports it into Kenna printing the
#  the location upon successful import and returning the KennaID
##
def import_vuln_json(vuln_json):
	logger = report_writer.WriteFile("kampai_log.txt", report_writer.LogFormatter)
	url = "https://api.kennasecurity.com:443/vulnerabilities"
	token = "**************"
	headers = {'content-type': 'application/json', 'X-Risk-Token': token}
	api = requests.post(url, data=json.dumps(vuln_json), headers=headers)
	response = api.json()
	transaction = json.dumps(response, indent=4, sort_keys=True)
	logger.write(transaction)
	logger.close()
	print(response['location'])
	return response['vulnerability']['id']



###
# Generates an XLS file template that can be used to import XLS files
##
def xls_create_template():
	filename = "kampai_xls_template.xls"
	excel_file = xlwt.Workbook()
	sheet = excel_file.add_sheet('Records')
	sheet.write(0,0, "VulnID")
	sheet.write(0,1, "IP Address")
	sheet.write(0,2, "Port")
	sheet.write(0,3, "Remediation")
	sheet.write(0,4, "Severity")
	sheet.write(0,5, "Kenna ID")
	excel_file.save(filename)
	print("Kampai Template File", filename, "created.")



###
# Converts an array of vulnerability findings into an XLS report that includes KennaID's
##
def xls_create_report(record_array):
	stamp = '{0:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
	filename = stamp+"_kampai_report.xls"
	excel_file = xlwt.Workbook()
	sheet = excel_file.add_sheet('Records')
	sheet.write(0,0, "Identifier")
	sheet.write(0,1, "Asset")
	sheet.write(0,2, "Port")
	sheet.write(0,3, "Remediation")
	sheet.write(0,4, "Severity")
	sheet.write(0,5, "Kenna ID")
	rCount = len(record_array)
	print("Record count: ", rCount)
	for i in range(0, rCount):
		sheet.write(i+1,0, record_array[i][0])
		sheet.write(i+1,1, record_array[i][1])
		sheet.write(i+1,2, record_array[i][2])
		sheet.write(i+1,3, record_array[i][3])
		sheet.write(i+1,4, record_array[i][4])
		sheet.write(i+1,5, record_array[i][5])
	excel_file.save(filename)
	print("Generated Kampai Report File: ", filename, "created.")


###
# Takes vulnerability JSON string of one record and imports it into Kenna
##
def create_vuln(vuln_json):
	logger = report_writer.WriteFile("kampai_log.txt", report_writer.LogFormatter)
	url = "https://api.kennasecurity.com:443/vulnerabilities"
	token = "****************"
	headers = {'content-type': 'application/json', 'X-Risk-Token': token}
	pprint.pprint(vuln_json)
	answer = input("Import this record into Kenna? Y/n ")
	if answer == "Y" or "y":
		api = requests.post(url, data=json.dumps(vuln_json), headers=headers)
		response = api.json()
		transaction = json.dumps(response, indent=4, sort_keys=True)
		logger.write(transaction)
		logger.close()
		print(json.dumps(response, indent=4, sort_keys=True))
	else:
		print("Okay. Quitting.")
		sys.exit()


if __name__=='__main__':
	vuln_json = {'vulnerability':{}}
	if args.excel:
		xls_batch_import(args.excel)
	elif args.createxls:
		xls_create_template()
	elif args.vulnid:
		ident = args.vulnid.split('-')[0]
		if ident == "CVE":
			if args.ipaddress:
				vuln_json['vulnerability']['primary_locator'] = "ip_address"
				vuln_json['vulnerability']['ip_address'] = args.ipaddress
				if args.port:
					vuln_json['vulnerability']['port'] = args.port
				else:
					print("Port specification needed.")
					sys.exit()
			elif args.url:
				vuln_json['vulnerability']['primary_locator'] = 'url'
				vuln_json['vulnerability']['url'] = args.url
			elif args.hostname:
				vuln_json['vulnerability']['primary_locator'] = 'hostname'
				vuln_json['vulnerability']['hostname'] = args.hostname
				if args.port:
					vuln_json['vulnerability']['port'] = args.port
				else:
					vuln_json['vulnerability']['port'] = 0
			else:
				print("Asset/Target needed.  e.g. ipaddress|url|hostname")
				parser.print_help()
				sys.exit()
			vuln_json['vulnerability']['cve_id'] = args.vulnid
			vuln_json['vulnerability']['notes'] = args.remediation+importsig
			vuln_json['vulnerability']['severity'] = args.severity
			#print(vuln_json['vulnerability'])
			create_vuln(vuln_json)

		elif ident == "CWE":
			if args.ipaddress:
				vuln_json['vulnerability']['primary_locator'] = "ip_address"
				vuln_json['vulnerability']['ip_address'] = args.ipaddress
				if args.port:
					vuln_json['vulnerability']['port'] = args.port
				else:
					print("Port specification needed.")
					sys.exit()
			elif args.url:
				vuln_json['vulnerability']['primary_locator'] = 'url'
				vuln_json['vulnerability']['url'] = args.url
			elif args.hostname:
				vuln_json['vulnerability']['primary_locator'] = 'hostname'
				vuln_json['vulnerability']['hostname'] = args.hostname
				if args.port:
					vuln_json['vulnerability']['port'] = args.port
				else:
					vuln_json['vulnerability']['port'] = 0
			else:
				print("Asset/Target needed.  e.g. ipaddress|url|hostname")
				parser.print_help()
				sys.exit()
			vuln_json['vulnerability']['cwe_id'] = args.vulnid
			vuln_json['vulnerability']['notes'] = args.remediation+importsig
			vuln_json['vulnerability']['severity'] = args.severity
			#vuln_json['vulnerability'][0]
			create_vuln(vuln_json)
		else:
			print("New records require a vulnerability ID. e.g. CVE|CWE")
			sys.exit()
	else:
		parser.print_help()

