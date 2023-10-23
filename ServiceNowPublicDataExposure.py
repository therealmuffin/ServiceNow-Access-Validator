import urllib.request
import urllib.parse
from urllib.parse import urlencode
import json
import re
import sys

environmentPrefix = 'dev86386'
validateTable = ''
sessionToken = ''
sessionCookie = ''

######## START FUNCTIONS ########

def getSessionData(environmentPrefix):
	sessionDataRequest = urllib.request.Request('https://'+environmentPrefix+'.service-now.com/login.do')
	sessionDataResponse = urllib.request.urlopen(sessionDataRequest)
	
	sessionDataResponseBody = sessionDataResponse.read().decode("utf-8")
	sessionDataResponseHeaders = sessionDataResponse.info().items()
	
	global sessionToken, sessionCookie
	try:
		sessionToken = re.search(r"var g_ck = '(.*?)'", sessionDataResponseBody).group(1)
	except AttributeError as e:
		return 1
	
	responseHeaderList = []
	for key, value in sessionDataResponseHeaders:
		if(key == 'Set-Cookie'):
			responseHeaderList.append(value)
	
	sessionCookie = ','.join(responseHeaderList)
	
	return 0


def getExposedRecordCount(environmentPrefix, validateTable):
	headers = {'Content-Type': 'application/json', 'X-UserToken': sessionToken, 'Cookie': sessionCookie}
	req = urllib.request.Request('https://'+environmentPrefix+'.service-now.com/api/now/sp/widget/widget-simple-list?t='+validateTable, urlencode({}).encode("utf-8"), headers)
	
	response = urllib.request.urlopen(req)
	try:
		responseBody = json.loads(response.read().decode("utf-8"))
	except json.decoder.JSONDecodeError as e:
		return 0
	
	
	# If ti fails, list is not available and table is not vulnerable
	try:
		responseLength = len(responseBody['result']['data']['list'])
	except KeyError as e:
		responseLength = 0
	
	if (validateTable == 'sys_user') and (responseLength == 1):
		responseLength = 0
		
	return responseLength

def getTableList():
	with open('tablelist.txt') as f:
		tableList = f.read().splitlines()
	return tableList

def getEnvironmentDomainPrefix():
	try:
		with open('environment.txt') as f:
			environmentPrefix = f.readline()
	except FileNotFoundError as e:
		return ''
	
	return environmentPrefix

######## END FUNCTIONS ########

environmentPrefix = getEnvironmentDomainPrefix()

if environmentPrefix == '':
	print('Failed to get ServiceNow domain prefix')
	sys.exit()

tableList = getTableList()

if getSessionData(environmentPrefix) != 0:
	print('Failed to get session data')
	sys.exit()

fileExposedTables = open('exposedTables-'+environmentPrefix+'.txt', 'a')

tableListLength = len(tableList)

for currentIndex in range(tableListLength):
	currentTable = tableList[currentIndex]
	
	# We'll clear this line later in terminal to keep it clean
	print("Current table: (%i / %i) %s" % (currentIndex, tableListLength, currentTable))
	
	exposedRecordCount = getExposedRecordCount(environmentPrefix, currentTable)
	if exposedRecordCount != 0:
		fileExposedTables.write(currentTable+':'+str(exposedRecordCount)+"\n")
	
	# Clear previous line
	sys.stdout.write("\033[F")
	
		

