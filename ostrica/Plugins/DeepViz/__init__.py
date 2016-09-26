#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - DeepViz Plugin
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
import traceback
import datetime
import httplib
import urllib
import string
import socket
import sys
import os
import re
from deepviz.sandbox import Sandbox
from deepviz.result import *
import json

from ostrica.utilities.cfg import Config as cfg

extraction_type =   [cfg.intelligence_type['md5']]
enabled = False
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information from DeepViz (Basic SandBox Search)'
visual_data = True

class DeepViz:

    def __init__(self):
        self.sbx = Sandbox()
        self.api_key = cfg.deep_viz_api
        self.intelligence = {}

    def get_deepviz_behavior_by_md5(self, md5):
        self.intelligence['ip'] = []
        self.intelligence['connections_tcp'] = []
        self.intelligence['connections_udp'] = []
        self.intelligence['dns_lookup'] = []

        sbx_result = self.sbx.sample_report(md5=md5, api_key=self.api_key)
        if sbx_result.status == 'DEEPVIZ_STATUS_SUCCESS':
            if 'ip' in sbx_result.msg:
            	for ip in sbx_result.msg['ip']:
                    self.intelligence['ip'].append(ip['ip'])

            if 'connections_tcp' in sbx_result.msg:
            	for ip in sbx_result.msg['connections_tcp']:
                    self.intelligence['connections_tcp'].append(ip['ip'])

            if 'connections_udp' in sbx_result.msg:
            	for host in sbx_result.msg['connections_udp']:
                    self.intelligence['connections_udp'].append(ip['ip'])

            if 'dns_lookup' in sbx_result.msg:
            	for lookup in sbx_result.msg['dns_lookup']:
                    self.intelligence['dns_lookup'].append({'host': lookup['host'], 'IPlist': lookup['IPlist']})
        else:
            return False


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running DeepViz() on %s' % intelligence
    if enabled == False:
        return {'extraction_type': extraction_type, 'intelligence_information':{}}
    intel_collector = DeepViz()
    if intel_collector.api_key == 'YOUR_KEY_HERE':
        print '[!!] DeepViz() module requires your API key. Please add it in the plugin.'
        return {'extraction_type': extraction_type, 'intelligence_information':{}}
    if extraction_type == cfg.intelligence_type['md5']:
        md5_intel = intel_collector.get_deepviz_behavior_by_md5(intelligence)
        collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
        del intel_collector
        return collected_intel

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'DeepViz':
        visual_report = DeepVizVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class DeepVizVisual:
    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#660066'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):

        if self.json_data['intelligence'] is None:
            return False

        if 'ip' in self.json_data['intelligence']['intelligence_information']:
            ip = self.json_data['intelligence']['intelligence_information']['ip']
        else:
            ip = []

        if 'connections_tcp' in self.json_data['intelligence']['intelligence_information']:
            tcp_connections = self.json_data['intelligence']['intelligence_information']['connections_tcp']
        else:
            tcp_connections = []

        if 'connections_udp' in self.json_data['intelligence']['intelligence_information']:
            udp_connections = self.json_data['intelligence']['intelligence_information']['connections_udp']
        else:
            udp_connections = []

        if 'dns_lookup' in self.json_data['intelligence']['intelligence_information']:
            dns_lookup = self.json_data['intelligence']['intelligence_information']['dns_lookup']
        else:
            dns_lookup = []

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'DeepViz': [{'ips': ip},
                                    {'tcp_connections': tcp_connections}, {'udp_connections': udp_connections},
                                    {'dns_lookups': dns_lookup}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'DeepViz': [{'ips': ip},
                                    {'tcp_connections': tcp_connections}, {'udp_connections': udp_connections},
                                    {'dns_lookups': dns_lookup}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['DeepViz']:
            for key, value in intel.iteritems():
                if key == 'ips':
                    self._manage_deepviz_ips(value)
                elif key == 'tcp_connections':
                    self._manage_deepviz_tcp(value)
                elif key == 'udp_connections':
                    self._manage_deepviz_udp(value)
                elif key == 'dns_lookups':
                    self._manage_deepviz_lookups(value)

    def _manage_deepviz_ips(self, ips):
        size = 30
        for ip in ips:
            if ip in self.nodes.keys():
                self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], self.nodes[ip][2])
            else:
                self.nodes[ip] = (size, self.color, 'ip')

            if ip not in self.edges[self.origin]:
                self.edges[self.origin].append(ip)

    def _manage_deepviz_tcp(self, tcps):
        size = 30
        for tcp_ip in tcps:
            if tcp_ip not in self.nodes.keys():
                self.nodes[tcp_ip] = (size, self.color, 'tcp_ip')

            if tcp_ip not in self.edges[self.origin]:
                self.edges[self.origin].append(tcp_ip)

    def _manage_deepviz_udp(self, udps):
        size = 30
        for udp_ip in udps:
            if udp_ip not in self.nodes.keys():
                self.nodes[udp_ip] = (size, self.color, 'udp_ip')

            if udp_ip not in self.edges[self.origin]:
                self.edges[self.origin].append(udp_ip)

    def _manage_deepviz_lookups(self, lookups):
        for lookup in lookups:
            if 'host' in lookup:
                self._save_host_in_nodes(lookup['host'])
                if 'IPlist' in lookup:
                    self._save_ip_list_in_nodes(lookup['IPlist'], lookup['host'])

    def _save_host_in_nodes(self, host):
        size = 30
        if host not in self.nodes.keys():
            self.nodes[host] = (size, self.color, 'domain')

        if host not in self.edges[self.origin]:
            self.edges[self.origin].append(host)

    def _save_ip_list_in_nodes(self, ips, origin_host):
        size = 30
        for lookup_ip in ips:
            if lookup_ip not in self.nodes.keys():
                self.nodes[lookup_ip] = (size, self.color, 'ip')

            if origin_host not in self.edges.keys():
                self.edges.setdefault(origin_host, [])

            if lookup_ip not in self.edges[origin_host]:
                self.edges[origin_host].append(lookup_ip)