#!/usr/bin/env python3
##############################################################################
# domainlookup.py               FortiJon                      24 August 2019 #
#----------------------------------------------------------------------------#
# I wrote this script for a buddy. Although I work for Fortinet, this code   #
# is provided as is with no warranty or commitment to suitability. If you    #
# would like a script that is supported by Fortinet please contact our       #
# Professional Services team.                                                #
#----------------------------------------------------------------------------#
# Dependencies                                                               #
#   python3                                                                  #
#   requests                                                                 #
#   Registered access token with firewall                                    #
#----------------------------------------------------------------------------#
# This code connects to your local firewall to lookup the domain rating from #
# FortiGuard. It is recommended that the user use a lab firewall.            #
# I disabled InsecureRequestWarning because my firewall did not have a       #
# public cert and the output was pissing me off. :P                          #
##############################################################################
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

fw = input("Enter firewall domain or ip address: ")

domainfilename = input("Enter filename of domains: ")
domainfile = open(domainfilename,"r")
domains = domainfile.readlines()
domainfile.close()

responsefilename = input("Enter filename for response: ")
responsefile = open(responsefilename,"w+")
responsefile.write('"url","category","subcategory","status"\n')

fwtoken=input("Enter firewall access token: ")

for domain in domains:
	requeststr='https://'+fw+'/api/v2/monitor/utm/rating-lookup/select?access_token='
	requeststr=requeststr+fwtoken+'&url='+domain.rstrip('\n')
	response = requests.get(requeststr, verify=False)
	jsonresponse = response.json()
	responsefile.write('"')
	responsefile.write(jsonresponse["results"]["url"])
	responsefile.write('"')
	responsefile.write(",")
	responsefile.write('"')
	responsefile.write(jsonresponse["results"]["category"])
	responsefile.write('"')
	responsefile.write(",")
	responsefile.write('"')
	responsefile.write(jsonresponse["results"]["subcategory"])
	responsefile.write('"')
	responsefile.write(",")
	responsefile.write('"')
	responsefile.write(jsonresponse["status"])
	responsefile.write('"')
	responsefile.write("\n")

responsefile.close()
##############################################################################