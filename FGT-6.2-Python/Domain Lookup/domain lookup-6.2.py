#!/usr/bin/env python3
##############################################################################
# domainlookup6.2.py             FortiJon                      23 April 2020 #
#----------------------------------------------------------------------------#
# I wrote this script for a buddy. Although I work for Fortinet, this code   #
# is provided as is with no warranty or commitment to suitability. If you    #
# would like a script that is supported by Fortinet please contact our       #
# Professional Services team.                                                #
#----------------------------------------------------------------------------#
# Dependencies                                                               #
#   python3                                                                  #
#   requests                                                                 #
#   json                                                                     #
#   Registered access token with firewall                                    #
#----------------------------------------------------------------------------#
# This code connects to your local firewall to lookup the domain rating from #
# FortiGuard. It is recommended that the user use a lab firewall.            #
##############################################################################
import requests
import json

# This disables invalid cert warnings - comment out for higher security
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


headerss = {
    'Content-Type': 'application/json',
}



# Obtain user input and prep the output file
fw = input("Enter firewall domain or ip address: ")
domainfilename = input("Enter filename of domains: ")
domainfile = open(domainfilename,"r")
domains = domainfile.readlines()
domainfile.close()
responsefilename = input("Enter filename for response: ")
responsefile = open(responsefilename,"w+")
responsefile.write('"url","category","subcategory"\n')
fwtoken=input("Enter firewall access token: ")

# Create strings out of the input
paramset = (
    ('access_token', fwtoken),
)
requeststr='https://'+fw+'/api/v2/monitor/utm/rating-lookup/select'

# Iterate through each domain in the file
for domain in domains:
	dataset = {
		"url" : [domain.rstrip('\n')],
		'lang' : 'en'
	}
	datasetj = json.dumps(dataset)

	# retrieves the info from the FGT - remove verify for higher security
	response = requests.post(requeststr, headers=headerss, params=paramset, data=datasetj, verify=False)

	jsonresponse = response.json()
	responsefile.write('"')
	responsefile.write(jsonresponse['results'][0]['url'])
	responsefile.write('","')
	category = jsonresponse['results'][0].get('category','Undefined')
	responsefile.write(category)
	responsefile.write('","')
	responsefile.write(jsonresponse['results'][0]['subcategory'])
	responsefile.write('"')
	responsefile.write("\n")

responsefile.close()

##############################################################################
