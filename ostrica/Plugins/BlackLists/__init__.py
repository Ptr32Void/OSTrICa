#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - BlackList Plugin
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
  import StringIO
else:
  import http.client as httplib
  import io as StringIO
import gzip

def get_zip_obj(data):
  if sys.version_info < (3, 0):
    return StringIO.StringIO(data)
  else:
    return StringIO.BytesIO(data)
  return data

def str_if_bytes(data):
  if type(data) == bytes:
      return data.decode("utf-8")
  return data

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['domain'], cfg.intelligence_type['ip']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to check if a domain or an ip is blacklisted'
visual_data = False

class BlackListChecker:

    emerging_threats_host = 'rules.emergingthreats.net'
    alienvault_host = 'reputation.alienvault.com'
    tor_nodes_host =  'torstatus.blutmagie.de'
    blocklist_de = 'lists.blocklist.de'
    dragon_research = 'dragonresearchgroup.org'
    bambenekconsulting = 'osint.bambenekconsulting.com'

    def __init__(self):
        self.intelligence = {}
        self.host_to_check = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup BlackListChecker...')
        self.intelligence = {}

    def _check_page(self, domain, query):
        hhandle = httplib.HTTPConnection(domain, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if response.status == 200:
            if response.getheader('Content-Encoding') == 'gzip':
                content = get_zip_obj(response.read())
                server_response = str_if_bytes(gzip.GzipFile(fileobj=content).read())
                if self.host_to_check in server_response:
                    return True
            else:
                server_response = str_if_bytes(response.read())
                if self.host_to_check in server_response:
                    return True
        return False

    def check_blacklist(self, host):
        self.host_to_check = host
        self.intelligence['emerging_threats'] = self.emerging_threats()
        self.intelligence['alienvault'] = self.alienvault()
        self.intelligence['tor_exit_nodes'] = self.tor_exit_nodes()
        self.intelligence['de_blocklist'] = self.de_blocklist()
        self.intelligence['dragon_research'] = self.dragon_research_bl()
        self.intelligence['bambenekconsulting'] = self.bambenekconsulting_feed()


    def emerging_threats(self):
        return self._check_page(self.emerging_threats_host, '/blockrules/compromised-ips.txt')

    def alienvault(self):
        return self._check_page(self.alienvault_host, '/reputation.data')

    def tor_exit_nodes(self):
        return self._check_page(self.tor_nodes_host, '/ip_list_exit.php/Tor_ip_list_EXIT.csv')

    def de_blocklist(self):
        return self._check_page(self.blocklist_de, '/lists/all.txt')

    def dragon_research_bl(self):
        return self._check_page(self.blocklist_de, '/insight/sshpwauth.txt')

    def bambenekconsulting_feed(self):
        return self._check_page(self.bambenekconsulting, '/feeds/c2-masterlist.txt')

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running BlackListChecker() on %s' % intelligence)

    intel_collector = BlackListChecker()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.check_blacklist(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['domain']:
        if intel_collector.check_blacklist(intelligence.replace('www.', '')) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    return nodes, edges
