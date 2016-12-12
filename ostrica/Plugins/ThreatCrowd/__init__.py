#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - SafeBrowsing Plugin
# Purpose:		Collection and visualization of Threat Intelligence data
#
# Author:      	Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#
# Created:     	16/07/2016
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
import json
import requests
import time

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain'], cfg.intelligence_type['md5'], cfg.intelligence_type['email']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about IPs, domains or ASNs on SafeBrowsing'
visual_data = True

class ThreatCrowd:

    def __init__(self):
        self.threatcrowd_host = 'www.threatcrowd.org'
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup ThreatCrowd...')
        self.intelligence = {}

    def fill_intelligence_dictionary(self, intel):
        if intel['response_code'] == '1':
            if 'domains' in intel:
                self.intelligence['domains'] = intel['domains']

            if 'hashes' in intel:
                self.intelligence['md5s'] = intel['hashes']

            if 'resolutions' in intel:
                self.intelligence['resolutions'] = intel['resolutions']

            if 'emails' in intel:
                self.intelligence['emails'] = intel['emails']

            if 'ips' in intel:
                self.intelligence['ips'] = intel['ips']

            if 'scans' in intel:
                self.intelligence['scans'] = intel['scans']

    def extract_intelligence(self, typology, intel):
        if cfg.threat_crowd_limit:
            time.sleep(cfg.threat_crowd_limit_seconds)
        if typology == 'domain' or typology == 'ip' or typology == 'email':
            query = 'https://www.threatcrowd.org/searchApi/v2/%s/report/' % (typology)
            returned_intel = json.loads(requests.get(query, params={typology: intel}).text)
            self.fill_intelligence_dictionary(returned_intel)
        elif typology == 'md5':
            query = 'https://www.threatcrowd.org/searchApi/v2/file/report/'
            returned_intel = json.loads(requests.get(query, params={'resource': intel}).text)
            self.fill_intelligence_dictionary(returned_intel)

        return self.intelligence

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running ThreatCrowd() on %s' % intelligence)
    if cfg.threat_crowd_limit:
        print('ThreatCrowd limit is set (as per limits described on GitHub ThreatCrowd ApiV2)')

    intel_collector = ThreatCrowd()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.extract_intelligence('ip', intelligence) is not None:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['domain']:
        if intel_collector.extract_intelligence('domain', intelligence) is not None:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    if extraction_type == cfg.intelligence_type['email']:
        if intel_collector.extract_intelligence('email', intelligence) is not None:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    if extraction_type == cfg.intelligence_type['md5']:
        if intel_collector.extract_intelligence('md5', intelligence) is not None:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'ThreatCrowd':
        visual_report = ThreatCrowdVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class ThreatCrowdVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#ffe033'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        md5s = []
        domains = []
        emails = []
        resolutions = []
        ips = []
        detections = []

        if self.json_data['intelligence'] is None:
            return False

        if 'md5s' in self.json_data['intelligence']['intelligence_information']:
            md5s = self.json_data['intelligence']['intelligence_information']['md5s']

        if 'domains' in self.json_data['intelligence']['intelligence_information']:
            domains = self.json_data['intelligence']['intelligence_information']['domains']

        if 'emails' in self.json_data['intelligence']['intelligence_information']:
            emails = self.json_data['intelligence']['intelligence_information']['emails']

        if 'resolutions' in self.json_data['intelligence']['intelligence_information']:
            resolutions = self.json_data['intelligence']['intelligence_information']['resolutions']

        if 'ips' in self.json_data['intelligence']['intelligence_information']:
            ips = self.json_data['intelligence']['intelligence_information']['ips']

        if 'scans' in self.json_data['intelligence']['intelligence_information']:
            detections = self.json_data['intelligence']['intelligence_information']['scans']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'ThreatCrowd': [{'md5s': md5s}, {'domains': domains}, {'emails': emails}, {'resolutions': resolutions}, {'ips': ips}, {'detections': detections}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'ThreatCrowd': [{'md5s': md5s}, {'domains': domains}, {'emails': emails}, {'resolutions': resolutions}, {'ips': ips}, {'detections': detections}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['ThreatCrowd']:
            for key, value in intel.items():
                if key == 'md5s':
                    self._manage_threatcrowd_md5s(value)
                elif key == 'domains':
                    self._manage_threatcrowd_domains(value)
                elif key == 'emails':
                    self._manage_threatcrowd_emails(value)
                elif key == 'resolutions':
                    self._manage_threatcrowd_resolutions(value)
                elif key == 'ips':
                    self._manage_threatcrowd_ips(value)
                elif key == 'detections':
                    self._manage_threatcrowd_scans(value)

    def _manage_threatcrowd_md5s(self, md5s):
        size = 30
        for md5 in md5s:
            if md5 in self.nodes.keys():
                self.nodes[md5] = (self.nodes[md5][0] + 5, self.nodes[md5][1], self.nodes[md5][2])
            else:
                self.nodes[md5] = (size, self.color, 'associated_md5')

            if md5 not in self.edges[self.origin]:
                self.edges[self.origin].append(md5)

    def _manage_threatcrowd_domains(self, domains):
        size = 30
        for domain in domains:
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'associated domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_threatcrowd_emails(self, emails):
        size = 30
        for email in emails:
            if email in self.nodes.keys():
                self.nodes[email] = (self.nodes[email][0] + 5, self.nodes[email][1], self.nodes[email][2])
            else:
                self.nodes[email] = (size, self.color, 'associated domain')

            if email not in self.edges[self.origin]:
                self.edges[self.origin].append(email)

    def _manage_threatcrowd_resolutions(self, resolutions):
        size = 30
        type = 'associated domain'
        for resolution in resolutions:
            if 'domain' in resolution:
                value = resolution['domain'].replace('\n', '').replace('\r', '').replace('\a', '')
                type = 'associated domain'
            elif 'ip_address' in resolution:
                value = resolution['ip_address'].replace('\n', '').replace('\r', '').replace('\a', '')
                type = 'ip'
            else:
                break

            # quick hack to bypass tainted data from ThreatCrowd
            if value == '-':
                continue

            if value in self.nodes.keys():
                self.nodes[value] = (self.nodes[value][0] + 5, self.nodes[value][1], self.nodes[value][2])
            else:
                self.nodes[value] = (size, self.color, type)

            if value not in self.edges[self.origin]:
                self.edges[self.origin].append(value)

    def _manage_threatcrowd_ips(self, ips):
        size = 30
        for ip in ips:
            if ip in self.nodes.keys():
                self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], self.nodes[ip][2])
            else:
                self.nodes[ip] = (size, self.color, 'ip')

            if ip not in self.edges[self.origin]:
                self.edges[self.origin].append(ip)

    def _manage_threatcrowd_scans(self, detections):
        size = 30
        for detection in detections:
            if detection == '':
                continue

            if detection in self.nodes.keys():
                self.nodes[detection] = (self.nodes[detection][0] + 5, self.nodes[detection][1], self.nodes[detection][2])
            else:
                self.nodes[detection] = (size, self.color, 'detection')

            if detection not in self.edges[self.origin]:
                self.edges[self.origin].append(detection)
            break
