#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - WhoisXmlApi Plugin
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

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect whois information from WhoisXmlApi'
visual_data = False

def str_if_bytes(data):
  if type(data) == bytes:
      return data.decode("utf-8")
  return data

class WhoisXmlApi:

    def __init__(self):
        self.host = 'www.whoisxmlapi.com'
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup WhoisXmlApi...')
        self.intelligence = {}

    def whois(self, domain):
        query = '/whoisserver/WhoisService?domainName=%s&outputFormat=json' % (domain)
        hhandle = httplib.HTTPConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', '*/*')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if response.status == 200:
            self.intelligence['whois'] = str_if_bytes(response.read()).replace('\n', '')
            return True
        else:
            return False


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running WhoisXmlApi() on %s' % intelligence)

    intel_collector = WhoisXmlApi()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.whois(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    return nodes, edges
