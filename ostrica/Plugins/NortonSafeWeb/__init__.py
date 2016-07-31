#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - NortonSafeWeb Plugin
# Purpose:		Collection and visualization of Threat Intelligence data
#
# Author:      	Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#
# Created:     	20/12/2015
# Licence:     	This file is part of OSTrICa.
#
#				OSTrICa is free software: you can redistribute it and/or modify
#				it under the terms of the GNU General Public License as published by
#				the Free Software Foundation, either version 3 of the License, or
#				(at your option) any later version.
#
#				OSTrICa is distributed in the hope that it will be useful,
#				but WITHOUT ANY WARRANTY; without even the implied warranty of
#				MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#				GNU General Public License for more details.
#
#				You should have received a copy of the GNU General Public License
#				along with OSTrICa. If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
import sys
if sys.version_info < (3, 0):
    import httplib
else:
    import http.client as httplib
import ssl

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to check if a domain or an ip is in SafeWeb'
visual_data = False

def str_if_bytes(data):
    if type(data) == bytes:
        return data.decode("utf-8")
    return data

class NortonSafeWeb:

    def __init__(self):
        self.safeweb_host = 'safeweb.norton.com'
        self.intelligence = {}
        self.server_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup NortonSafeWeb...')
        self.intelligence = {}

    def extract_intelligence(self):
        if self.server_response.find('<b>WARNING</b>') != -1:
            self.intelligence['safeweb'] = 'WARNING'
        elif self.server_response.find('<b>SAFE</b>') != -1:
            self.intelligence['safeweb'] = 'SAFE'
        elif self.server_response.find('<b>UNTESTED</b>') != -1:
            self.intelligence['safeweb'] = 'UNTESTED'
        else:
            self.intelligence['safeweb'] = ''
        return True

    def extract_server_info(self, data_to_analyze):
        ssl_context = ssl._create_unverified_context()
        query = '/report/show_mobile?name=%s' % (data_to_analyze)
        hhandle = httplib.HTTPSConnection(self.safeweb_host, context=ssl_context, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('referer', 'https://safeweb.norton.com/rate_limit')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if response.status == 200:
            self.server_response = str_if_bytes(response.read())
            if self.extract_intelligence() != False:
                return True
            else:
                return False
        else:
            return False


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running NortonSafeWeb() on %s' % intelligence)

    intel_collector = NortonSafeWeb()
    if (extraction_type == cfg.intelligence_type['ip']) or (extraction_type == cfg.intelligence_type['domain']):
        if intel_collector.extract_server_info(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    return nodes, edges
