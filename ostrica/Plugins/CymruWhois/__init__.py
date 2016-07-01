#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - CymruWhois Plugin
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
import dns
import dns.resolver
from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about IP from CymruWhois'
visual_data = False

class CymruWhois:

    def __init__(self):
        self.intelligence = {}
        self.host_to_check = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup CymruWhois...'
        self.intelligence = {}

    def extract_ip_info(self, ip_address):
        domain = '%s.origin.asn.cymru.com' % '.'.join(reversed(ip_address.split('.')))
        ip_information = dns.resolver.query(domain, 'TXT')[0].strings[0].split('|')

        if len(ip_information) != 5:
            return False
        else:
            self.intelligence['asn'] = ip_information[0]
            self.intelligence['ip_mask'] = ip_information[1]
            self.intelligence['ip_country'] = ip_information[2]
            self.intelligence['registrar'] = ip_information[3]
            self.intelligence['registration_date'] = ip_information[4]
            return True


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running CymruWhois() on %s' % intelligence

    intel_collector = CymruWhois()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.extract_ip_info(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'CymruWhois':
        visual_report = CymruWhoisVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class CymruWhoisVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#ff0000'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        country = ''
        asn = ''

        if self.json_data['intelligence'] is None:
            return False

        if 'ip_country' in self.json_data['intelligence']['intelligence_information']:
            country = self.json_data['intelligence']['intelligence_information']['ip_country']

        if 'asn' in self.json_data['intelligence']['intelligence_information']:
            asn = self.json_data['intelligence']['intelligence_information']['asn'].strip()


        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'CymruWhois': [{'asn': asn}, {'country': country}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'CymruWhois': [{'asn': asn}, {'country': country}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['CymruWhois']:
            for key, value in intel.iteritems():
                if key == 'country':
                    self._manage_cymru_country(value)
                elif key == 'asn':
                    self._manage_cymru_asn(value)

    def _manage_cymru_asn(self, asn):
        size = 30
        if asn in self.nodes.keys():
            self.nodes[asn] = (self.nodes[asn][0] + 5, self.nodes[asn][1], self.nodes[asn][2])
        else:
            self.nodes[asn] = (size, self.color, 'asn')

        if asn not in self.edges[self.origin]:
            self.edges[self.origin].append(asn)

    def _manage_cymru_country(self, country):
        size = 30
        if country in self.nodes.keys():
            self.nodes[country] = (self.nodes[country][0] + 5, self.nodes[country][1], self.nodes[country][2])
        else:
            self.nodes[country] = (size, self.color, 'country')

        if country not in self.edges[self.origin]:
            self.edges[self.origin].append(country)