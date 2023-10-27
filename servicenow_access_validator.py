import json,re, sys, argparse, sys, signal, urllib.request, urllib.parse
from urllib.parse import urlencode

if sys.version_info[0] < 3:
    print("This application has only been tested in Python 3. You're using " + sys.version_info[0])

# Variables / ESC (1b) - VT100 codes
CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'
# "\033[F"
# https://stackoverflow.com/questions/36520120/overwriting-clearing-previous-console-line

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


validateTable = ''
sessionToken = ''
sessionCookie = ''


settings =  {   'daemonize': False,
                'environment': False,
                'username': False,
                'password': False,
                'filename': False,
                'tables': False,
                'debug': False
            }
            
session =   {
                'token':False,
                'cookie':False
            }

######## START FUNCTIONS ########


def help():
    print('ServiceNow Access Validator')
    print('')
    print('Usage: python ./servicenow_access_validator.py [options...]')
    print('')
    print('General options')
    print('    -h, --help                   Show this help')
    print('    -d, --daemonize              Daemonize servicenow_access_validator')
    print('    -e, --environment            Set ServiceNow subdomain (e.g. dev12345)')
    print('    -t, --tables                 List of tables to validate')
    print('    -u, --user                   Dry run')
    print('    -p, --password               Verbose output')
    print('    -f, --filename               Write result to specified file')
    print('')


def parse_arguments():
    global settings
    
    options = {}
    parser = argparse.ArgumentParser(prog='PROG', add_help=False)
    options['general'] = parser.add_argument_group('General options')
    options['general'].add_argument(    '-h',   '--help', action='store_true')    
    options['general'].add_argument(    '-d',   '--daemonize', action='store_true')
    options['general'].add_argument(    '-e',   '--environment', type=str)
    options['general'].add_argument(    '-u',   '--user', type=str)
    options['general'].add_argument(    '-p',   '--password', type=str)
    options['general'].add_argument(    '-f',   '--filename', type=str)
    options['general'].add_argument(    '-t',   '--tables', nargs='+', default=[])
    options['general'].add_argument(    '-v',   '--verbose', action='store_true')
    args = parser.parse_args()
    

    if(args.help):
        help()
        exit()
    
    if args.daemonize is not None:
        settings['daemonize'] = args.daemonize
    if args.environment is not None:
        settings['environment'] = args.environment
    else:
        print("Environment is a mandatory parameter.")
        exit()
    if args.user is not None:
        settings['username'] = args.user
    if args.password is not None:
        settings['password'] = args.password
    if args.filename is not None:
        settings['filename'] = args.filename
    if args.verbose is not None:
        settings['debug'] = args.verbose
    if args.tables is not None:
        settings['tables'] = args.tables

def getSessionData():
    global sessionToken, sessionCookie
    
    def getResource(url, headers):
        # Login via URL requires a 302 redirect. With URLLib, cookies are lost. 
        # Therefore, we need to prevent a redirect, and do that ourselves 
        # while including cookies. Since it doesn't hurt to have this code in when
        # login isn't required... it's there without condition.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        
        opener = urllib.request.build_opener(NoRedirect)
        urllib.request.install_opener(opener)
        req = urllib.request.Request(url)
        if headers:
            req.add_header('cookie', headers)
        
        try:
            sessionDataResponse = urllib.request.urlopen(req)
        except UnicodeError as e:
            print('Unable to connect to server: ' + url)
            return False
        except urllib.error.HTTPError as e:
            sessionDataResponse = e
        
        return sessionDataResponse
    
    def getSessionToken():
        sessionDataResponseBody = sessionData.read().decode('utf-8')
        try:
            sessionToken = re.search(r"var g_ck = '(.*?)'", sessionDataResponseBody).group(1)
        except AttributeError as e:
            return False
            
        return sessionToken
    
    def getCookies():
        sessionDataResponseHeaders = sessionData.info().items()
        responseHeaderList = []
        for key, value in sessionDataResponseHeaders:
            if (key == 'Set-Cookie') and ('JSESSIONID' in value):
                sessionCookie = value
        
        return sessionCookie
    
  
    
    url = 'https://'+settings['environment']+'.service-now.com/login.do'
    if settings['username'] and settings['password']:
        url += '?user_name=' + settings['username'] + '&sys_action=sysverb_login&user_password=' + settings['password']
    sessionData = getResource(url, False)
    
    # If we're logging in, we need to do a 2nd call to get the Session Token (g_ck)
    if sessionData.getcode() == 302:
        url = 'https://'+settings['environment']+'.service-now.com/login_redirect.do?sysparm_stack=no'
        sessionCookie = getCookies()
        headers = {'Cookie': sessionCookie}
        sessionData = getResource(url, sessionCookie)
    else:
        if settings['username']:
            print('Unable to login, username or password seems invalid')
            exit(1)
        
        sessionCookie = getCookies()
    
    sessionToken = getSessionToken()
    
    printDebug('Session Token: ' + sessionToken)
    printDebug('Session Cookie: ' + sessionCookie)
    
    return True


def getExposedRecordCount(validateTable):
    url = 'https://'+settings['environment']+'.service-now.com/api/now/sp/widget/widget-simple-list?t='+validateTable
    headers = {'Content-Type': 'application/json', 'X-UserToken': sessionToken, 'Cookie': sessionCookie}
    req = urllib.request.Request(url, urlencode({}).encode('utf-8'), headers)
    
    response = urllib.request.urlopen(req)
    try:
        responseBody = json.loads(response.read().decode('utf-8'))
    except json.decoder.JSONDecodeError as e:
        print("JSON not valid")
        return False
    
    # If it fails, list is not available and table is not vulnerable, look at data->count instead ? isValid? can be true or false
    try:
        responseLength = responseBody['result']['data']['count']
    except KeyError as e:
        responseLength = False
    
    # Always returns guest user, so ignore if result is 1
    if (validateTable == 'sys_user') and (responseLength == 1):
        responseLength = False
    
    return responseLength

def getTableList():
    try:
        with open('tablelist.txt') as f:
            tableList = f.read().splitlines()
    except FileNotFoundError as e:
        print("Unable to find/read tablelist from file")
        exit(0)
    
    return tableList


def clean_exit(signal, frame):
    print("Exiting, initiating cleanup")
    
    exit(0)

def printDebug(message):
    if settings['debug']:
        print(message)

######## END FUNCTIONS ########

# Let's catch signals so we can cleanly exit this application.
for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
    signal.signal(sig, clean_exit)

parse_arguments()

if not settings['tables']:
    settings['tables'] = getTableList()

if not getSessionData():
    print('Failed to get session data')
    sys.exit()

outputFile = False
if settings['filename']:
    open(settings['filename'], 'a')

tableListLength = len(settings['tables'])

for currentIndex in range(tableListLength):
    currentTable = settings['tables'][currentIndex]
    
    # We'll clear this line later in terminal to keep it clean
    print("Current table: (%i / %i) %s" % (currentIndex+1, tableListLength, currentTable))
    
    exposedRecordCount = getExposedRecordCount(currentTable)
    if not exposedRecordCount == False:
        if outputFile:
            outputFile.write(currentTable+':'+str(exposedRecordCount)+"\n")
            sys.stdout.write(ERASE_LINE + CURSOR_UP_ONE + ERASE_LINE)
        else:
            sys.stdout.write(ERASE_LINE + CURSOR_UP_ONE + ERASE_LINE)
            print(f"{bcolors.FAIL}" + currentTable+':'+str(exposedRecordCount) + f"{bcolors.ENDC}")
    else:
        sys.stdout.write(ERASE_LINE + CURSOR_UP_ONE + ERASE_LINE)
        print(currentTable+': OKAY')
        
    
        

