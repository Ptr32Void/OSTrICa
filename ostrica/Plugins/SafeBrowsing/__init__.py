#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - SafeBrowsing Plugin
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
import httplib
import string
import socket
import gzip
import re
import StringIO
import json
from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain'], cfg.intelligence_type['asn']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about IPs, domains or ASNs on SafeBrowsing'
visual_data = True

class SafeBrowsing:

    def __init__(self):
        self.safebrowsing_host = 'www.google.com'
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup SafeBrowsing...'
        self.intelligence = {}

    def extract_json(self, server_response):
        pos = server_response.find('({')
        if pos == -1:
            return False

        pos1 = server_response.rfind('});')
        if pos1 == -1:
            return False

        try:
            self.json_response = json.loads(server_response[pos+1:pos1+1])
        except:
            return False

    def extract_intelligence(self):
        self.intelligence['safebrowsing'] = self.json_response

    def extract_server_info(self, data_to_analyze):
        query = '/safebrowsing/diagnostic?output=jsonp&site=%s' % (data_to_analyze)
        hhandle = httplib.HTTPSConnection(self.safebrowsing_host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', '*/*')
        hhandle.putheader('referer', 'https://www.google.com/transparencyreport/safebrowsing/diagnostic/index.html')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if response.status == 200:
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                if self.extract_json(gzip.GzipFile(fileobj=content).read()) != False:
                    self.extract_intelligence()
                    return True
                else:
                    return False
        else:
            return False


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running SafeBrowsing() on %s' % intelligence

    intel_collector = SafeBrowsing()
    if (extraction_type == cfg.intelligence_type['ip']) or (extraction_type == cfg.intelligence_type['domain']):
        if intel_collector.extract_server_info(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['asn']:
        if intelligence.startswith('AS'):
            intelligence = intelligence.replace('AS', 'AS:')
        else:
            intelligence = 'AS:%s' % (intelligence)
        if intel_collector.extract_server_info(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'SafeBrowsing':
        visual_report = SafeBrowsingVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class SafeBrowsingVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#a00000'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        example_attacks = ''
        example_intermediary = ''
        example_landing = ''

        if self.json_data['intelligence'] is None:
            return False

        if 'safebrowsing' not in self.json_data['intelligence']['intelligence_information']:
            return False

        if 'as' not in self.json_data['intelligence']['intelligence_information']['safebrowsing']:
            return False

        if 'malwareSites' not in self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']:
            return False

        if 'exampleAttack' in self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']:
            exampleAttacks = self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']['exampleAttack']

        if 'exampleIntermediary' in self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']:
            example_intermediary = self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']['exampleIntermediary']

        if 'exampleLanding' in self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']:
            example_landing = self.json_data['intelligence']['intelligence_information']['safebrowsing']['as']['malwareSites']['exampleLanding']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'SafeBrowsing': [{'example_attacks': exampleAttacks}, {'example_intermediary': example_intermediary}, {'exampleLanding': example_landing}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'SafeBrowsing': [{'example_attacks': exampleAttacks}, {'example_intermediary': example_intermediary}, {'example_landing': example_landing}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['SafeBrowsing']:
            for key, value in intel.iteritems():
                if key == 'example_attacks' or key == 'example_intermediary' or key == 'example_landing':
                    self._manage_safebrowsing_example_attacks(value)

    def _manage_safebrowsing_example_attacks(self, domains):
        size = 30
        for domain in domains:
            domain = domain[:-1]
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'detected_domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)
