#!/usr/bin/env python
# coding=utf-8

import sys, os, json
import logging
import requests

# For detailed exeption handling
import linecache
import inspect

# To allow for insecure HTTPS connections as spur doesn't have a validated cert
import urllib3
urllib3.disable_warnings()

#set up logging to this location
from logging.handlers import TimedRotatingFileHandler
LOG_FILENAME = os.path.join("spur_api_cli.log")

# Set up a specific logger
logger = logging.getLogger('spur')

#default logging level , can be overidden in stanza config
logger.setLevel(logging.DEBUG)

#log format
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

# Add the daily rolling log message handler to the logger
# handler = TimedRotatingFileHandler(LOG_FILENAME, when="d",interval=1,backupCount=5)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
logger.addHandler(handler)

##########################################
# Function definitions
# 
#   _____ _   _ _   _  ____ _____ ___ ___  _   _   ____  _____ _____ ____  
#  |  ___| | | | \ | |/ ___|_   _|_ _/ _ \| \ | |  |  _ \| ____|  ___/ ___| 
#  | |_  | | | |  \| | |     | |  | | | | |  \| |  | | | |  _| | |_  \___ \ 
#  |  _| | |_| | |\  | |___  | |  | | |_| | |\  |  | |_| | |___|  _|  ___) |
#  |_|    \___/|_| \_|\____| |_| |___\___/|_| \_|  |____/|_____|_|   |____/ 

# More detailed exception reporting
def detailed_exception():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    return 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


logger.info("Doing it")

try:

    logger.info("Doing it")
    ip = "68.106.192.197"
    spur_token = "ud6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxc"

    basicSanityCheck = False
#    proxies = {'http': 'http://webproxy:8080', 'https': 'http://webproxy:8080'}
    proxies = None

    # Check if it's a valid IP
    if len(ip) > 7:
        basicSanityCheck = True

    if basicSanityCheck:
        logger.debug("IP address '%s' passed sanity check" % ip)

        # Poll API if a valid IP address
        # curl -H "Token: udxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx14e79e79" "https://api.spur.us/v2/context/118.209.251.2"

        headers = {'Token': spur_token}

        url = 'https://api.spur.us/v2/context/%s' % (ip)
        logger.debug("Calling Spur with %s" % url)

        session = requests.Session()
        if proxies:
            session.proxies = self.proxies

        result = session.get(url, headers=headers, verify=False)
        result_json = json.loads(result.text)

#        response, content = rest.simpleRequest(url, sessionKey=config_parameters["sessionKey"], getargs={'output_mode': 'json'})
#        result_json = json.loads(content)
        
        logger.debug("status=%d,message=Call returned" % result.status_code)
        logger.debug("payload=%s" % result_json)

        for key in result_json:
            logger.debug("%s=%s" % (key,result_json[key]))
        
        # Output Specific fields as a test to see if these can be referenced directly.
        logger.debug("Country Code=%s" % (result_json["location"]["country"]))
        

except Exception as e:
    logger.error("Oh noes")
    logger.error(detailed_exception())
    