#!/usr/bin/python
# -*- coding: utf-8 -*-

# Comment Ascii Art
# Ref Large: http://patorjk.com/software/taag/#p=display&f=Standard 
# Ref Small: http://patorjk.com/software/taag/#p=display&f=Calvin%20S

# Test for parsing errors with
# /opt/splunk/bin/splunk cmd python /opt/splunk/etc/apps/TA-spur/bin/spuripscan.py searchargs

# Logs
# tail -f /opt/splunk/var/log/splunk/TA-spur_api.log

# Test Search
# | tstats  count FROM datamodel=Edgerouter.EdgerouterFirewall WHERE (nodename=EdgerouterFirewall.TrafficOUT.OUT_SYN "EdgerouterFirewall.SRC"="192.168.64.90") BY _time span=auto "EdgerouterFirewall.DST" | rename "EdgerouterFirewall.DST" as DST | dedup DST | spuripscan field="DST"

import sys, os, json, logging, inspect, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, os.pardir)))
import requests

# used for detecting internal IP addresses
import functools
import ipaddress

import rivium_utils as utils

# For timers
import time


####
# Splunk VS Code Debugging - https://github.com/splunk/vscode-extension-splunk/wiki/Debugging
sys.path.append(os.path.join(os.environ['SPLUNK_HOME'],'etc','apps','SA-VSCode','bin'))
# import splunk_debug as dbg
#dbg.enable_debugging(timeout=25)
####


# Load up Splunklib (App inspect recommends splunklib goes into the appname/lib directory)
libPathName = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','lib'))
sys.path.append(libPathName)
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six.moves import range

# Splunk simple REST library ($SPLUNK_HOME/splunk/lib/python3.7/site-packages/splunk/rest)
import splunk.rest as rest

# Normal Splunk REST call
# def simpleRequest(path, sessionKey=None, getargs=None, postargs=None, method='GET', raiseAllErrors=False, proxyMode=False, rawResult=False, timeout=None, jsonargs=None, token=False):


##########################################
# Search Command Definition
# ╔═╗╔═╗╔═╗╦═╗╔═╗╦ ╦  ╔═╗╔═╗╔╦╗╔╦╗╔═╗╔╗╔╔╦╗  ╔╦╗╔═╗╔═╗╦╔╗╔╦╔╦╗╦╔═╗╔╗╔
# ╚═╗║╣ ╠═╣╠╦╝║  ╠═╣  ║  ║ ║║║║║║║╠═╣║║║ ║║   ║║║╣ ╠╣ ║║║║║ ║ ║║ ║║║║
# ╚═╝╚═╝╩ ╩╩╚═╚═╝╩ ╩  ╚═╝╚═╝╩ ╩╩ ╩╩ ╩╝╚╝═╩╝  ═╩╝╚═╝╚  ╩╝╚╝╩ ╩ ╩╚═╝╝╚╝

# https://github.com/splunk/splunk-sdk-python/blob/7645d29b7fc1166c554bf9a7a03f40a02529ccc4/splunklib/searchcommands/search_command.py#L97
# https://github.com/splunk/splunk-sdk-python/blob/7645d29b7fc1166c554bf9a7a03f40a02529ccc4/splunklib/searchcommands/streaming_command.py#L26

@Configuration(distributed=False)
class spuripscanCommand(StreamingCommand):
    """
     | spuripscan [field="ip"]]
     """

    # parameters specific to this addon
    field  = Option(name='field',  require=True)
    fullPayload  = Option(name='full_payload',  require=False, default="False")
    useCache = Option(name='use_cache',  require=False, default="True")
    forceCacheRefresh = Option(name='force_cache_refresh',  require=False, default="False")
    debugTimer = Option(name='debug_timer',  require=False, default="False") # Timer is good for seeing how long calls to KVstore or Spur take
    
    API_key = "MTAxxxxxxxxxxxxxxxxxxxxxxTM="
    useKVStore = False
    debugLogging = False
    ignoreInternalIPs = True
    KVStore = "spur_cache"
    daysToCache = 30
    
    # The dummy response must contain all the same fields the real API returns or you will get weird results in Splunk when Splunk renders a table with the dummy entries first.
    dummyPrivateIpResponse = {"ip": "", "as": "",  "client": "", "client_concentration_country": "ZZ", "client_concentration_density": "", "location": "", "country_code": "ZZ", "organization": "Private or unnanounced IP", "infrastructure": "", "services": "", "risks": "", "types": "", "proxies": "", "count": 0}
    suppress_error = False
    proxies = {}
#    proxies = {
#        'http': 'http://webproxy:8080',
#        'https': 'http://webproxy:8080',
#    }

    # Some constants to make porting this app for other purposes easier
    splunkAppName = "TA-spur"
    scriptName = os.path.basename(__file__)
    confFilename = "spur"
    confStanza = "api_config"
    logLevel = logging.DEBUG
    logfileDescriptor = "api"
    appLogger = None
    # logLevel = logging.INFO

    # Simple translation of block codes from Spur to something more human friendly
    def blockTranslate(self, blockCode):
        if (blockCode == 0):
            return "residential"
        elif (blockCode == 1):
            return "non-residential"
        elif (blockCode == 2):
            return "both"
        else:
            return "unknown"


    # Retrieve configuration parameters
    # ╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╗╔╔═╗╦╔═╗╔═╗
    # ║  ║ ║╠═╣ ║║  ║  ║ ║║║║╠╣ ║║ ╦╚═╗
    # ╩═╝╚═╝╩ ╩═╩╝  ╚═╝╚═╝╝╚╝╚  ╩╚═╝╚═╝
    def loadConfigs(self):

        self.appLogger.debug("Loading configuration parameters")

        try:
            splunkSessionKey = self.metadata.searchinfo.session_key
            confSettings = utils.configLoad(self.splunkAppName,self.confFilename,splunkSessionKey)

            if "useKVStore" in confSettings: 
                if confSettings["useKVStore"] == "1":
                    self.useKVStore = True
                else:
                    self.useKVStore = False

                self.appLogger.info("%s,message=KVStore setting of %d found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.useKVStore, self.confFilename))

            else:
                self.appLogger.warning("%s,message=No KV Store config found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.confFilename))

            # Check if KVStore exists
            try:
                # Check KV Store Exists
                # curl -k -u admin:pass https://localhost:8089//servicesNS/nobody/TA-spur/storage/collections/config/spur_cache 

                KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (self.splunkAppName,self.KVStore)
                response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'})
                if response.status == 200:                
                    self.appLogger.debug("%s,section=KVStoreCheck,response.status=%d,message=Found KVStore" % (utils.fileFunctionLineNumber(),response.status))
                else:
                    self.appLogger.debug("%s,section=KVStoreCheck,response.status=%d,message=KV Store not found : %s" % (utils.fileFunctionLineNumber(),response.status,response))

            except Exception:
                self.appLogger.error("%s,section=KVStoreCheck,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))

            if "debugLogging" in confSettings: 
                if confSettings["debugLogging"] == "1":
                    self.debugLogging = True
                    self.appLogger.setLevel(logging.DEBUG)
                else:
                    self.debugLogging = False
                    self.appLogger.setLevel(logging.INFO)

                self.appLogger.info("%s,message=debugLogging setting of %d found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.debugLogging, self.confFilename))

            else:
                self.appLogger.warning("%s,message=No debug config found in local/%s.conf." % (utils.fileFunctionLineNumber(),self.confFilename))

            # Loading the spur.us API key
            self.API_key, responseStatus = utils.loadPassword(self.splunkAppName, self.confFilename, splunkSessionKey, "spur_api_key")

            # Loading the proxy server config
            try:
                if "proxy_settings" in confSettings:
                    proxy_server = confSettings["proxy_settings"]

                    # Check if blank
                    if proxy_server.strip() != "":
                    
                        # strip http:// or https:// from beginning if it is there
                        proxy_server = proxy_server.replace('https://','')
                        proxy_server = proxy_server.replace('http://','')
                        
                        # Test proxy server exists
                        proxy_test = "http://%s" % proxy_server
                        try:
                            self.proxies = {'http': 'http://' + proxy_server, 'https': 'http://' + proxy_server}
                            response = requests.get("https://example.com/", proxies=self.proxies)
                            if response.status_code == 200:
                                self.appLogger.debug("%s,section=ProxyCheck,message=Proxy Test connection successful" % (utils.fileFunctionLineNumber()))
                            else:
                                self.appLogger.error("%s,section=ProxyCheck,message=Proxy server test connection to %s failed. Not setting a proxy server." % (utils.fileFunctionLineNumber(),proxy_test))
                                self.proxies = {}


                        except requests.exceptions.ProxyError as proxy_err:
                            self.appLogger.error("%s,section=ProxyCheck,message=Proxy error %s." % (utils.fileFunctionLineNumber(), proxy_err))

                            if '407' in str(proxy_err):
                                raise Exception("Proxy test failed due to authorisation required for proxy server. Not yet supported by addon. Only workaround is to include username and password in the proxy URL like this http://proxy_user:proxy_password@my.proxy.server.com:8443")
                            else:
                                raise Exception("Proxy test failed. Proxy error was %s" % proxy_err)

                        except Exception as e:
                            self.appLogger.error("%s,section=ProxyCheck,message=Proxy server test connection to %s failed. Will skip use of proxy. Exception %s." % (utils.fileFunctionLineNumber(),proxy_server, utils.detailedException()))
                            raise e
                            
            except Exception as e:
                self.appLogger.error("%s,section=ProxyCheck,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))
                raise e

        except Exception as e:
            self.appLogger.error("%s,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))
            raise e
                    
    # Streaming Processor
    # ╔═╗╔╦╗╦═╗╔═╗╔═╗╔╦╗╦╔╗╔╔═╗  ╔═╗╦═╗╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗╦═╗
    # ╚═╗ ║ ╠╦╝║╣ ╠═╣║║║║║║║║ ╦  ╠═╝╠╦╝║ ║║  ║╣ ╚═╗╚═╗║ ║╠╦╝
    # ╚═╝ ╩ ╩╚═╚═╝╩ ╩╩ ╩╩╝╚╝╚═╝  ╩  ╩╚═╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╩╚═
    def stream(self, events):
        #dbg.set_breakpoint()

        try:

            # Setup logger
            self.appLogger = utils.loggingSetup(self.splunkAppName,self.logfileDescriptor)
            self.appLogger.setLevel(logging.DEBUG)

            self.loadConfigs()
            self.appLogger.info('%s,spurCommand=%s', (utils.fileFunctionLineNumber(),self))

            #logger.info("Config Settings %s" % self._configuration)
            #logger.info("Headers %s" % self._input_header)
            
            # Use sessions as requested by spur.us for HTTPS requests
            self.appLogger.info("%s,message=streaming started setting up session with spur." % utils.fileFunctionLineNumber())
            session = requests.Session()
            session.proxies = self.proxies
            
            splunkSessionKey = self.metadata.searchinfo.session_key

            #################
            # Parse search command args. This probably belongs in an __init__ function
            
            # fullPayload
            if not type(self.fullPayload)==bool:
                if self.fullPayload.lower() == "true" or self.fullPayload.lower() == "1" or self.fullPayload.lower() == "yes":
                    self.appLogger.debug("%s,message=fullPayload argument is on (value=%s)." % (utils.fileFunctionLineNumber(), self.fullPayload))
                    self.fullPayload = True
                else:
                    self.appLogger.debug("%s,message=fullPayload argument is off (value=%s)." % (utils.fileFunctionLineNumber(), self.fullPayload))
                    self.fullPayload = False

            # useCache
            if not type(self.useCache)==bool:
                if self.useCache.lower() == "true" or self.useCache.lower() == "1" or self.useCache.lower() == "yes":
                    self.appLogger.debug("%s,message=useCache argument is on (value=%s)." % (utils.fileFunctionLineNumber(), self.useCache))
                    self.useCache = True
                else:
                    self.appLogger.debug("%s,message=useCache argument is off (value=%s)." % (utils.fileFunctionLineNumber(), self.useCache))
                    self.useCache = False

            # forceCacheRefresh
            if not type(self.forceCacheRefresh)==bool:
                if self.forceCacheRefresh.lower() == "true" or self.forceCacheRefresh.lower() == "1" or self.forceCacheRefresh.lower() == "yes":
                    self.appLogger.debug("%s,message=useCache argument is on (value=%s)." % (utils.fileFunctionLineNumber(), self.useCache))
                    self.forceCacheRefresh = True
                else:
                    self.appLogger.debug("%s,message=useCache argument is off (value=%s)." % (utils.fileFunctionLineNumber(), self.useCache))
                    self.forceCacheRefresh = False

            # debugTimer
            if not type(self.debugTimer)==bool:
                if self.debugTimer.lower() == "true" or self.debugTimer.lower() == "1" or self.debugTimer.lower() == "yes":
                    self.appLogger.debug("%s,message=debugTimer argument is on (value=%s)." % (utils.fileFunctionLineNumber(), self.debugTimer))
                    self.debugTimer = True
                else:
                    self.appLogger.debug("%s,message=debugTimer argument is off (value=%s)." % (utils.fileFunctionLineNumber(), self.debugTimer))
                    self.debugTimer = False

            # Counters
            eventsProcessed = 0
            spurCalls = 0
            cachedEntries = 0
            skippedInternalIPs = 0
            isPrivateIP = False
            errors = 0

            for event in events:
                
                if not self.field in event :
                    continue

                try:
                    ip = event[self.field]
                    basicSanityCheck = False
                    
                    # Check if it's a valid IP
                    try:

                        # This will throw an error if this string is not an IP
                        isPrivateIP = ipaddress.IPv4Address(ip).is_private
                        basicSanityCheck = True

                    except Exception as e:
                        self.appLogger.error("%s,section=ipSanityCheck,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                        basicSanityCheck = False
                        event["spur_error"] = "not an IPV4 address"
                        eventsProcessed = eventsProcessed + 1
                        errors = errors + 1
                        yield event
                        continue

                    # Should we ignore sending internal IP address requests to spur
                    if self.ignoreInternalIPs and isPrivateIP:

                        self.appLogger.debug("%s,section=internalIP,internal_ip=1,ip=%s,message=Internal IP Address detected" % (utils.fileFunctionLineNumber(), ip))
                        self.dummyPrivateIpResponse["ip"] = ip

                        for key in self.dummyPrivateIpResponse:

                            # Skip hostname field as we already have that and spur asks not to use this field
                            if key=="hostname": continue

                            # Add all remaining fields
                            self.appLogger.debug("%s,section=reponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, self.dummyPrivateIpResponse[key]))
                            event["spur_" + key] = self.dummyPrivateIpResponse[key]

                            if (key == "block"):
                                event["spur_block_desc"] = self.blockTranslate(self.dummyPrivateIpResponse[key])

                        # set cache value to 2 as a signal it was skipped due to internal IP address checks
                        event["spur_cached"] = 2

                        # Return enriched event back to Splunk
                        eventsProcessed = eventsProcessed + 1
                        skippedInternalIPs = skippedInternalIPs + 1
                        yield event
                        continue

                    if basicSanityCheck:

                        # timer for performance testing
                        startTimer = time.perf_counter()
                            
                        self.appLogger.debug("%s,section=ipSanityCheck,passed=1,ip=%s" % (utils.fileFunctionLineNumber(), ip))

                        # Check KV Store for entry
                        self.appLogger.debug("%s,section=checkKvStore,ip=%s" % (utils.fileFunctionLineNumber(), ip))
                        hasKVStoreEntry = False
                        
                        # Should we ignore the cache?
                        if (self.useCache):
                            query = {"ip": ip}
                            resp = utils.queryKVStore(self.splunkAppName, splunkSessionKey, self.KVStore, query)
                            response = json.loads(resp.decode("utf-8"))
                            self.appLogger.debug("%s,section=KVStoreResponse,response=%s" % (utils.fileFunctionLineNumber(), response))

                            # Multiple sanity checks on the data
                            if response is not None:
                                if(isinstance(response,list)):
                                    if len(response) > 0:
                                        if 'date_modified' in response[0] and '_key' in response[0]:
                                            # Check if date_modified is still within valid cache time limit or if they passed force cache refresh as a search parameter
                                            if int(response[0]['date_modified']) > time.time() - (self.daysToCache*24*60*60) and not self.forceCacheRefresh:
                                                self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry still valid using it instead of looking up spur for new one,date_modified=%s,_key=%s" % (utils.fileFunctionLineNumber(), response[0]['date_modified'], response[0]['_key']))
                                                hasKVStoreEntry = True

                                            # It's OLD purge from KV Store
                                            else:
                                                self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry expired we are going to delete it get a new one" % (utils.fileFunctionLineNumber()))
                                                utils.deleteKVStoreEntry(self.splunkAppName, splunkSessionKey, self.KVStore, response[0]['_key'])
                                        else:
                                            self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse didn't have date_modified or _key field,response=%s" % (utils.fileFunctionLineNumber(),response[0]))
                                    else:
                                        self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse was zero length" % (utils.fileFunctionLineNumber()))
                                else:
                                    self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse wasn't a list" % (utils.fileFunctionLineNumber()))
                            else:
                                self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse didn't exist" % (utils.fileFunctionLineNumber()))

                
                            
                        if(hasKVStoreEntry):

                            # Increment Counter
                            cachedEntries = cachedEntries + 1

                            entry = response[0]['response']

                            # Marker field to tell if this result was cached from KVStore or not
                            event["spur_cached"] = 1
                            
                            # Force base level fields into results in case they don't exist in the first record. This is needed due to a "feature" in Splunk
                            event["spur_as"] = ""
                            event["spur_client"] = ""
                            event["spur_client_concentration_country"] = ""
                            event["spur_client_concentration_density"] = ""
                            event["spur_location"] = ""
                            event["spur_organization"] = ""
                            event["spur_infrastructure"] = ""
                            event["spur_services"] = ""
                            event["spur_tunnels"] = ""
                            event["spur_risks"] = ""
                          
                            for key in entry:
                                
                                # Skip hostname, _user, _key or date_modified fields
                                if key=="hostname" or key=="_user" or key=="_key" or key=="date_modified": continue

                                # Add all remaining fields
                                self.appLogger.debug("%s,section=KVStoreReponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, entry[key]))
                                event["spur_" + key] = entry[key]

                            # Throw in the full payload too
                            if self.fullPayload:
                                event["spur_full_payload"] = entry

                            # Extract specific fields which we will also store in the KVStore for searchability. 
                            # Spur is inconsistent with the data returned so we need some serious sanity checked before referencing fields in the results or Python will have a big old cry about it.
                            result_json = entry
                            if "organization" in result_json:
                                event["spur_organization"] = result_json["organization"]
                            elif "organization" in result_json["as"]:
                                event["spur_organization"] = result_json["as"]["organization"]
                            else:
                                event["spur_organization"] = "unknown"

                            if "risks" in result_json:
                                event["spur_risks"] = result_json["risks"]
                            else:
                                event["spur_risks"] = ""
                            
                            # location things
                            if "location" in result_json:
                                if "country" in result_json["location"]:
                                    event["spur_country_code"] = result_json["location"]["country"]
                                else:
                                    event["spur_country_code"] = ""
                            else:
                                event["spur_country_code"] = ""
                                
                            # client things
                            if "client" in result_json:
                                if "types" in result_json["client"]:
                                    event["spur_types"] = result_json["client"]["types"]
                                else:
                                    event["spur_types"] = ""
                                    
                                if "proxies" in result_json["client"]:
                                    event["spur_proxies"] = result_json["client"]["proxies"]
                                else:
                                    event["spur_proxies"] = ""

                                if "count" in result_json["client"]:
                                    event["spur_count"] = result_json["client"]["count"]
                                else:
                                    event["spur_count"] = 0

                                if "concentration" in result_json["client"]:
                                    if "country" in  result_json["client"]["concentration"]:
                                        event["spur_client_concentration_country"] = result_json["client"]["concentration"]["country"]
                                    else:
                                        event["spur_client_concentration_country"] = "unknown"
                                    
                                    if "density" in  result_json["client"]["concentration"]:
                                        event["spur_client_concentration_density"] = result_json["client"]["concentration"]["density"]
                                    else:
                                        event["spur_client_concentration_density"] = "unknown"
                                    
                                else:
                                    event["spur_client_concentration_country"] = ""
                                    event["spur_client_concentration_density"] = ""
                                    

                            else:
                                event["spur_types"] = ""
                                event["spur_proxies"] = ""
                                event["spur_count"] = 0
                                event["spur_client_concentration_country"] = ""
                                event["spur_client_concentration_density"] = ""



                            if self.debugTimer:
                                event["debug_timer"] = (time.perf_counter() - startTimer)*1000
                            

                        # Poll spur.us for result
                        else:
                            try:
                                # Increment Counter
                                spurCalls = spurCalls + 1

                                # Marker field to tell if this result was cached from KVStore or not
                                event["spur_cached"] = 0

                                # Poll API if a valid IP address
                                # curl -H "Token: ud64f212.............dba82cc5e314e79" "https://api.spur.us/v2/context/118.209.251.2"
                                headers = {'Token': self.API_key}

                                url = 'https://api.spur.us/v2/context/%s' % (ip)
                                self.appLogger.debug("%s,section=spurCall,requestUrl=%s" % (utils.fileFunctionLineNumber(), url))

                                result = session.get(url, headers=headers, verify=False)
                                result_json = json.loads(result.text)

                                self.appLogger.debug("%s,section=reponseParsing,status=%d,message=Call returned" % (utils.fileFunctionLineNumber(), result.status_code))
                                

                                self.appLogger.debug("%s,section=reponseParsing,payload=%s" % (utils.fileFunctionLineNumber(), result_json))

                                if result.status_code==429:
                                    self.appLogger.error("%s,section=reponseParsing,message=Spur API call quota exceeded" % (utils.fileFunctionLineNumber()))
                                    raise Exception("Spur API call quota exceeded.")

                                elif result.status_code==403:
                                    self.appLogger.error("%s,section=reponseParsing,message=Couldn't authenticate with Spur API. Spur API key likely incorrect. Reconfigure in Splunk addon setup tab." % (utils.fileFunctionLineNumber()))
                                    raise Exception("Couldn't authenticate with Spur API. Spur API key likely incorrect. Reconfigure in Splunk addon setup tab.")

                                elif result.status_code==401:
                                    self.appLogger.error("%s,section=reponseParsing,message=Couldn't authenticate with Spur API. Spur API key likely incorrect. Reconfigure in Splunk addon setup tab." % (utils.fileFunctionLineNumber()))
                                    raise Exception("Couldn't authenticate with Spur API. Spur API key likely incorrect. Reconfigure in Splunk addon setup tab.")

                                # Force base level fields into results in case they don't exist in the first record. This is needed due to a "feature" in Splunk
                                event["spur_as"] = ""
                                event["spur_client"] = ""
                                event["spur_client_concentration_country"] = ""
                                event["spur_client_concentration_density"] = ""
                                event["spur_location"] = ""
                                event["spur_organization"] = ""
                                event["spur_infrastructure"] = ""
                                event["spur_services"] = ""
                                event["spur_tunnels"] = ""
                                event["spur_risks"] = ""

                                for key in result_json:

                                    # Skip hostname field as we already have that
                                    if key=="hostname": continue

                                    # Add all remaining fields
                                    self.appLogger.debug("%s,section=reponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, result_json[key]))
                                    event["spur_" + key] = result_json[key]

#                                    if (key == "block"):
#                                        event["spur_block_desc"] = self.blockTranslate(result_json[key])

                                # Throw in the full payload too
                                if self.fullPayload:
                                    event["spur_full_payload"] = result_json
                                
                                # Extract specific fields which we will also store in the KVStore for searchability. 
                                # Spur is inconsistent with the data returned so we need some serious sanity checked before referencing fields in the results or Python will have a big old cry about it.
                                if "organization" in result_json:
                                    event["spur_organization"] = result_json["organization"]
                                elif "as" in result_json and "organization" in result_json["as"]:
                                    event["spur_organization"] = result_json["as"]["organization"]
                                else:
                                    event["spur_organization"] = "unknown"

                                if "risks" in result_json:
                                    event["spur_risks"] = result_json["risks"]
                                else:
                                    event["spur_risks"] = ""
                                
                                # location things
                                if "location" in result_json:
                                    if "country" in result_json["location"]:
                                        event["spur_country_code"] = result_json["location"]["country"]
                                    else:
                                        event["spur_country_code"] = ""
                                else:
                                    event["spur_country_code"] = ""
                                    
                                # client things
                                if "client" in result_json:
                                    if "types" in result_json["client"]:
                                        event["spur_types"] = result_json["client"]["types"]
                                    else:
                                        event["spur_types"] = ""
                                        
                                    if "proxies" in result_json["client"]:
                                        event["spur_proxies"] = result_json["client"]["proxies"]
                                    else:
                                        event["spur_proxies"] = ""

                                    if "count" in result_json["client"]:
                                        event["spur_count"] = result_json["client"]["count"]
                                    else:
                                        event["spur_count"] = 0

                                    if "concentration" in result_json["client"]:
                                        if "country" in  result_json["client"]["concentration"]:
                                            event["spur_client_concentration_country"] = result_json["client"]["concentration"]["country"]
                                        else:
                                            event["spur_client_concentration_country"] = "unknown"
                                        
                                        if "density" in  result_json["client"]["concentration"]:
                                            event["spur_client_concentration_density"] = result_json["client"]["concentration"]["density"]
                                        else:
                                            event["spur_client_concentration_density"] = "unknown"
                                        
                                    else:
                                        event["spur_client_concentration_country"] = ""
                                        event["spur_client_concentration_density"] = ""

                                else:
                                    event["spur_types"] = ""
                                    event["spur_proxies"] = ""
                                    event["spur_count"] = 0
                                    event["spur_client_concentration_country"] = ""
                                    event["spur_client_concentration_density"] = ""



                                # Insert/Update spur results to KV Store
                                # fields ip,response,date_modified,country_code,organization,risks,types,proxies,count
                                record = {}
                                record["ip"] = result_json["ip"]
                                record["date_modified"] = int(time.time())
                                record["response"] = result_json
                                record["country_code"] = event["spur_country_code"]
                                record["organization"] = event["spur_organization"]
                                record["risks"] = event["spur_risks"]
                                record["types"] = event["spur_types"]
                                record["proxies"] = event["spur_proxies"]
                                record["count"] = event["spur_count"]
                                record["spur_client_concentration_country"] = event["spur_client_concentration_country"]
                                record["spur_client_concentration_density"] = event["spur_client_concentration_density"]
                                
 #                               record["block_desc"] = event["iphub_block_desc"]

                                utils.writeToKVStore(self.splunkAppName, splunkSessionKey, self.KVStore, record, keyFields = ["ip"])

                                # Stop timer after kvstore written
                                if self.debugTimer:
                                    event["debug_timer"] = (time.perf_counter() - startTimer)*1000

                            except Exception as e:
                                self.appLogger.error("%s,section=spurpolling,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                                if not self.suppress_error:
                                    raise e


                    else:
                        self.appLogger.warning("%s,section=ipSanityCheck,passed=0,ip=%s" % (utils.fileFunctionLineNumber(), ip))


                except Exception as e:
                    self.appLogger.error("%s,section=spurpolling,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                    if not self.suppress_error:
                        raise e

                # Return enriched event back to Splunk
                eventsProcessed = eventsProcessed + 1
                yield event

            self.appLogger.info("%s,eventCount=%d,spurCalls=%d,cachedEntries=%d,skippedInternalIPs=%d,message=streaming ended" % (utils.fileFunctionLineNumber(),eventsProcessed,spurCalls,cachedEntries,skippedInternalIPs))

        except Exception as e:
            self.appLogger.error("%s,section=outerTry,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
#            self.appLogger.error(utils.detailedException())
            raise e

# logger.debug("section=argumentsPassed,%s" % (sys.argv))

# for line in sys.stdin:
#    logger.debug("section=stdIn,%s" % (line))
    
dispatch(spuripscanCommand, sys.argv, sys.stdin, sys.stdout, __name__)

