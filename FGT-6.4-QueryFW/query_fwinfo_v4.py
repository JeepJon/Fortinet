#!/usr/bin/env python3
##############################################################################
# query_fwinfo_v4.py             FortiJon                   23 November 2021 #
#----------------------------------------------------------------------------#
# This script provides stats taken from API calls to FortiGate firewalls     #
# that are setup with API key access.                                        #
#                                                                            #
# The function calls used are:                                               #
#     /monitor/web-ui/state                                                  #
#     /monitor/license/status                                                #
#                                                                            #
# Although I work for Fortinet, this code is provided "as is" with no        #
# warranty or commitment to suitability.                                     #
#                                                                            #
# If you would like a script that is supported by Fortinet, please contact   #
# our Professional Services team.                                            #
#----------------------------------------------------------------------------#
# Usage:                                                                     #
#   python4_query_fwinfo.py                                                  #
#                                                                            #
# Input:                                                                     #
#   fwapi.txt                                                                #
#     "Firewall IP or FQDN","Access Token"                                   #
#     e.g. "192.168.1.1","7mj39rkjlQkkqG7Fm6NxsppGrk6jh9" - one per line     #
#                                                                            #
# Output:                                                                    #
#   fwstatus.csv                                                             #
#   Contains the retrieved info for each firewall, one per line              #
#----------------------------------------------------------------------------#
# Dependencies                                                               #
#   python3                                                                  #
#   requests                                                                 #
#   json                                                                     #
#   sys                                                                      #
#   Registered access token with firewall                                    #
#----------------------------------------------------------------------------#
# Created by FortiJon 02 October 2021                                        #
# Updated by Swag  02 November 2021                                          #
#  Added a ton of additional fields                                          #
#  Added an output file for failed FGT lookups                               #
# Updated by FortiJon 23 November 2021                                       #
#  Cleaned up the code, fixed a couple of errors                             #
##############################################################################

import requests
import json
import sys
import time
from datetime import datetime, date


# This disables invalid cert warnings - comment out for higher security
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# read fwapi.txt file
try:
	fwapifile = open("fwapi.txt","r")
	fws = fwapifile.readlines()
	fwapifile.close()
except IOError:
	print("Unable to open fwapi.txt file")
	sys.exit("Input file error")


# open fwstatus.csv file
try:
	fwstatusfile = open("fwstatus.csv","w+")
	fwstatusstr = "\"hostname\",\"FGT WAN IP\",\"OS version\",\"Model\",\"SN\",\"VDOMs Used\","+\
		"\"FortiGuard Schedule\",\"FortiGuard Status\",\"FortiGuard Account\",\"Expire Date\","+\
		"\"FortiGuard Next Update\",\"AV Version\",\"AV Last Update\",\"IPS ver\""+\
		"\"IPS Last Update\",\"App Version\",\"App Last Update\",\"ISDB Version\","+\
		"\"ISDB Last Update\",\"Botnet IP Version\",\"Botnet IP Last Update\","+\
		"\"Botnet Domain Version\",\"Botnet Domain Last Update\",\"Malicious URL Version\","+\
		"\"Malicious URL Last Update\",\"FAZ Server\",\"FAZ Status\",\"FMG Server\","+\
		"\"DNS Primary\",\"DNS Secondary\",\"HA Mode\",\"CPU\",\"Memory\",\"Session Count\"\n"
	fwstatusfile.write(fwstatusstr)
except IOError:
	print("Unable to open fwstatus.csv file")
	sys.exit("Output file error")

try:
	fwfailedfile = open("fwfailed.csv","w+")
	fwfailedfile.write('"failed-mgmtip"\n')
except IOError:
	print("Unable to open fwstatus.csv file")
	sys.exit("Output file error")


# iterate through lines in input file
for fw in fws:
	vm = 0
	fw2 = fw.rstrip('\n')
	if fw2=="":
		continue 
	fw3 = fw2.split(",")
	mgtip = fw3[0].rstrip('"').lstrip('"')
	acctok = fw3[1].rstrip('"').lstrip('"')

# The use of verify=False - overrides SSL cert issues
	# extract /monitor/license/status info
	lsresponse = requests.get("https://"+mgtip+"/api/v2/monitor/license/status?access_token="+acctok, verify=False)
	# extract /monitor/web-ui/state info
	wsresponse = requests.get("https://"+mgtip+"/api/v2/monitor/web-ui/state?access_token="+acctok, verify=False)
	# extract /fortiguard status info
	fgdschedule = requests.get("https://"+mgtip+"/api/v2/cmdb/system.autoupdate/schedule?access_token="+acctok, verify=False)
	# External Connector checks
	extconnector = requests.get("https://"+mgtip+"/api/v2/cmdb/system/external-resource?access_token="+acctok, verify=False)
	# Fortianalyzer check
	fazresponse = requests.get("https://"+mgtip+"/api/v2/cmdb/log.fortianalyzer/setting?access_token="+acctok, verify=False)
	# FortiManager check
	fmgresponse = requests.get("https://"+mgtip+"/api/v2/cmdb/system/central-management?access_token="+acctok, verify=False)
	# DNS Information
	dnsresponse = requests.get("https://"+mgtip+"/api/v2/cmdb/system/dns?access_token="+acctok, verify=False)
	# HA Status
	haresponse = requests.get("https://"+mgtip+"/api/v2/cmdb/system/ha?access_token="+acctok, verify=False)
	# CPU and Memory Status
	statsresponse = requests.get("https://"+mgtip+"/api/v2/monitor/system/vdom-resource/select?access_token="+acctok, verify=False)
	# CPU and Memory Status
	sessresponse = requests.get("https://"+mgtip+"/api/v2/monitor/system/resource/usage?access_token="+acctok, verify=False)
	# Retrieve VM information - necessary to discern between hardware and vm fields
	vminforesponse = requests.get("https://"+mgtip+"/api/v2/monitor/system/vm-information?access_token="+acctok, verify=False)
	

# If either API call fails then skip to next firewall and update failed file
	if lsresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall ="+mgtip+" License status API failed\n")
  		continue
	if wsresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall ="+mgtip+" Web-UI status API failed\n")
  		continue
	if fgdschedule.status_code != 200:
  		fwfailedfile.write("Failed to query firewall ="+mgtip+" FortiGuard status API failed\n")
  		continue
	if extconnector.status_code != 200:
		print("Failed to query firewall ="+mgtip+" License status API failed")
		continue
	if fazresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" FAZ Status API failed\n")
  		continue
	if fmgresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" FMG status API failed\n")
  		continue
	if dnsresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" DNS Response API failed\n")
  		continue
	if haresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" HA status API failed\n")
  		continue
	if statsresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" CPU & Memory Stats  API failed\n")
  		continue
	if sessresponse.status_code != 200:
  		fwfailedfile.write("Failed to query firewall "+mgtip+" Session stats API failed\n")
  		continue
	if not ((vminforesponse.status_code == 200) or (vminforesponse.status_code == 404)):
		# code of 200 means it's a VM. Code of 404 means it's an appliance
		fwfailedfile.write("Failed to query firewall "+mgtip+" VM information API failed\n")
		continue

	
# Parse the API responses
	licstat = lsresponse.json()
	webui = wsresponse.json()
	fgdsch = fgdschedule.json()
	exconnt = extconnector.json()
	fazchck = fazresponse.json()
	fmgchck = fmgresponse.json()
	dnschck = dnsresponse.json()
	hachck = haresponse.json()
	statchck = statsresponse.json()
	sesschck = sessresponse.json()
 
 
# Attach values to shorter vars for formatting in output
	hostname = webui["results"]["hostname"]
	model = webui["results"]["model"]
	fgtwanip = licstat["results"]["fortiguard"]["fortigate_wan_ip"]
	osver = licstat["version"]
	sn = licstat["serial"]
	vdomused = licstat["results"]["vdom"]["used"]
	#fgrdschedule = fgdsch["results"]["frequency"]
	fgrdstatus = licstat["results"]["forticare"]["status"]
	fgrdacct = licstat["results"]["forticare"]["account"]
	fgrdexpire = licstat["results"]["forticare"]["support"]["enhanced"]["expires"] #TESTING
	fgrdupdate = licstat["results"]["fortiguard"]["next_scheduled_update"]
	avver = licstat["results"]["antivirus"]["version"]
	avtime = licstat["results"]["antivirus"]["last_update"] #Output is INT use str() below to grab
	ipsver = licstat["results"]["ips"]["version"]
	ipstime = licstat["results"]["ips"]["last_update"] #Output is INT use str() below to grab
	appver = licstat["results"]["appctrl"]["version"]
	apptime = licstat["results"]["appctrl"]["last_update"] #Output is INT use str() below to grab
	isdbver = licstat["results"]["internet_service_db"]["version"]
	isdbtime = licstat["results"]["internet_service_db"]["last_update"] #Output is INT use str() below to grab
	botipver = licstat["results"]["botnet_ip"]["version"]
	botiptime = licstat["results"]["botnet_ip"]["last_update"] #Output is INT use str() below to grab
	botdmver = licstat["results"]["botnet_domain"]["version"]
	botdmtime = licstat["results"]["botnet_domain"]["last_update"] #Output is INT use str() below to grab
	malurlver = licstat["results"]["malicious_urls"]["version"]
	malurltime = licstat["results"]["malicious_urls"]["last_update"] #Output is INT use str() below to grab
	extconnect = exconnt["version"]
	print("Version="+extconnect+"\n")
	fazserver = fazchck["results"]["server"]
	fazstatus = fazchck["results"]["status"]
	fmgserver = fmgchck["results"]["fmg"]
	dnsprim = dnschck["results"]["primary"]
	dnssec = dnschck["results"]["secondary"]
	hamode = hachck["results"]["mode"]
	cpustats = statchck["results"]["cpu"]
	memstats = statchck["results"]["memory"]
	sesstats = sesschck["results"]["session"][0]["current"]
	fgrdschedule = fgdsch["results"]["frequency"]+" "+fgdsch["results"]["time"]


#change epoch time to human readable format
	humavtime = datetime.fromtimestamp(avtime)
	humfgrdupdate = datetime.fromtimestamp(fgrdupdate)
	humfgrdexpire = datetime.fromtimestamp(fgrdexpire)
	humipstime = datetime.fromtimestamp(ipstime)
	humapstime = datetime.fromtimestamp(apptime)
	humisdbtime = datetime.fromtimestamp(isdbtime)
	humbotiptime = datetime.fromtimestamp(botiptime)
	humbotdmtime = datetime.fromtimestamp(botdmtime)
	hummalurltime = datetime.fromtimestamp(malurltime)


	try:
		fwstatusstr = "\""+hostname+"\",\""+fgtwanip+"\",\""+osver+"\",\""+model+"\",\""+\
			sn+"\",\""+str(vdomused)+"\",\""+fgrdschedule+"\",\""+fgrdstatus+"\",\""+\
			fgrdacct+"\",\""+str(humfgrdexpire)+"\",\""+str(humfgrdupdate)+"\",\""+\
			avver+"\",\""+str(humavtime)+"\",\""+ipsver+"\",\""+str(humipstime)+"\",\""+\
			appver+"\",\""+str(humapstime)+"\",\""+isdbver+"\",\""+str(humisdbtime)+"\",\""+\
			botipver+"\",\""+str(humbotiptime)+"\",\""+botdmver+"\",\""+str(humbotdmtime)+\
			"\",\""+malurlver+"\",\""+str(hummalurltime)+"\",\""+fazserver+"\",\""+\
			fazstatus+"\",\""+fmgserver+"\",\""+dnsprim+"\",\""+dnssec+"\",\""+hamode+\
			"\",\""+str(cpustats)+"\",\""+str(memstats)+"\",\""+str(sesstats)+"\"\n"
		fwstatusfile.write(fwstatusstr)
		print("Done with device  "+mgtip+" ")
	except IOError:
		fwfailedfile.write("Unable to write to fwstatus.csv file! FW Hostname="+hostname+"\n")



# close file and exit
fwstatusfile.close()
fwfailedfile.close()

print("Execution Complete")


