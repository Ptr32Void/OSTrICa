#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - SafeBrowsing Plugin
# Purpose:		Collection and visualization of Threat Intelligence data
#
# Author:      	Roberto Sponchioni - <rsponchioni@yahoo.it> @Ptr32Void
#
# Created:     	03/11/2016
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
import string
import socket
import json
import requests
import time

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain'], cfg.intelligence_type['md5'], cfg.intelligence_type['email']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about IPs, domains, emails or MD5s on ThreatMiner'
visual_data = True

class ThreatMiner:

    def __init__(self):
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup ThreatMiner...'
        self.intelligence = {}

    def extract_whois_emails(self, intel):
        if 'admin' in intel:
            self.intelligence['whois_admin_email'] = intel['admin']

        if 'tech' in intel:
            self.intelligence['whois_tech_email'] = intel['tech']

        if 'registrant' in intel:
            self.intelligence['whois_registrant_email'] = intel['registrant']

    def extract_whois(self, intel):
        if 'updated_date' in intel['whois']:
            self.intelligence['whois_updated_date'] = intel['whois']['updated_date']

        if 'creation_date' in intel['whois']:
            self.intelligence['whois_creation_date'] = intel['whois']['creation_date']

        if 'registrant_info' in intel['whois']:
            self.intelligence['whois_registrant_info'] = intel['whois']['registrant_info']

        if 'emails' in intel['whois']:
            self.extract_whois_emails(intel['whois']['emails'])

        if 'expiration_date' in intel['whois']:
            self.intelligence['whois_expiration_date'] = intel['whois']['expiration_date']

    def extract_whois_emails(self, intel):
        if 'admin' in intel:
            self.intelligence['whois_admin_email'] = intel['admin']

        if 'tech' in intel:
            self.intelligence['whois_tech_email'] = intel['tech']

        if 'registrant' in intel:
            self.intelligence['whois_registrant_email'] = intel['registrant']

    def extract_passive_dns_info(self, intel):
        passive_dns_information = []
        for passive_info in intel:
            passive_dns_information.append(passive_info)

        self.intelligence['passive_dns_information'] = passive_dns_information


    def extract_passive_dns_info_ip(self, intel):
        passive_dns_information = []
        for passive_info in intel:
            passive_dns_information.append(passive_info)

        self.intelligence['passive_dns_information_ip'] = passive_dns_information


    def extract_all_intel(self, intel, typology):
        if typology == 'whois' and 'whois' in intel[0]:
            self.extract_whois(intel[0])
        elif typology == 'passive_dns':
            self.extract_passive_dns_info(intel)
        elif typology == 'related_hashes':
            self.intelligence['sha256'] = intel
        elif typology == 'subdomains':
            self.intelligence['subdomains'] = intel

        elif typology == 'passive_dns_ip':
            self.extract_passive_dns_info_ip(intel)
        elif typology == 'related_ssl':
            self.intelligence['ssl'] = intel

        elif typology == 'connections':
            if 'domains' in intel[0]:
                self.intelligence['connection_domains'] = intel[0]['domains']
            if 'hosts' in intel[0]:
                self.intelligence['connection_ips'] = intel[0]['hosts']
        elif typology == 'mutants':
            if 'mutants' in intel[0]:
                self.intelligence['mutants'] = intel[0]['mutants']

        elif typology == 'emails':
            self.intelligence['domains_email'] = intel

    def fill_intelligence_dictionary(self, intel, typology):
        if intel['status_code'] == '200':

            if 'results' in intel:
                self.extract_all_intel(intel['results'], typology)

    def extract_intelligence(self, typology, intel):
        if cfg.threat_miner_limit:
            time.sleep(cfg.threat_miner_limit_seconds)
        if typology == 'domain':
            query = 'https://www.threatminer.org/domain.php?q=%s&api=True&rt=1' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'whois')

            query = 'https://www.threatminer.org/domain.php?q=%s&api=True&rt=2' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'passive_dns')

            query = 'https://www.threatminer.org/domain.php?q=%s&api=True&rt=4' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'related_hashes')

            query = 'https://www.threatminer.org/domain.php?q=%s&api=True&rt=5' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'subdomains')

        elif typology == 'ip':
            query = 'https://www.threatminer.org/host.php?q=%s&api=True&rt=2' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'passive_dns_ip')

            query = 'https://www.threatminer.org/host.php?q=%s&api=True&rt=4' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'related_hashes')

            query = 'https://www.threatminer.org/host.php?q=%s&api=True&rt=5' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'related_ssl')

        elif typology == 'md5':
            query = 'https://www.threatminer.org/sample.php?q=%s&api=True&rt=3' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'connections')

            query = 'https://www.threatminer.org/sample.php?q=%s&api=True&rt=4' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'mutants')

        elif typology == 'email':
            query = 'https://www.threatminer.org/email.php?q=%s&api=True&rt=1' % (intel)
            returned_intel = json.loads(requests.get(query).text)
            self.fill_intelligence_dictionary(returned_intel, 'emails')

        return self.intelligence

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running ThreatMiner() on %s' % intelligence
    if cfg.threat_miner_limit and cfg.DEBUG:
        print 'ThreatMiner limit is set...'

    intel_collector = ThreatMiner()
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
    if json_data['plugin_name'] == 'ThreatMiner':
        visual_report = ThreatMinerVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class ThreatMinerVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#66ccff'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        sha256 = []
        subdomains = []
        emails = []
        passive_dns_information = []
        passive_dns_information_ip = []
        ssl = []
        mutants = []
        ips = []
        domains = []
        domains_email = []

        if self.json_data['intelligence'] is None:
            return False

        if 'sha256' in self.json_data['intelligence']['intelligence_information']:
            sha256 = self.json_data['intelligence']['intelligence_information']['sha256']

        if 'subdomains' in self.json_data['intelligence']['intelligence_information']:
            subdomains = self.json_data['intelligence']['intelligence_information']['subdomains']

        if 'whois_admin_email' in self.json_data['intelligence']['intelligence_information']:
            emails.append(self.json_data['intelligence']['intelligence_information']['whois_admin_email'])

        if 'whois_tech_email' in self.json_data['intelligence']['intelligence_information']:
            emails.append(self.json_data['intelligence']['intelligence_information']['whois_tech_email'])

        if 'whois_registrant_email' in self.json_data['intelligence']['intelligence_information']:
            emails.append(self.json_data['intelligence']['intelligence_information']['whois_registrant_email'])

        if 'passive_dns_information' in self.json_data['intelligence']['intelligence_information']:
            for passive_dns in self.json_data['intelligence']['intelligence_information']['passive_dns_information']:
                passive_dns_information.append(passive_dns['ip'])

        if 'passive_dns_information_ip' in self.json_data['intelligence']['intelligence_information']:
            for passive_dns in self.json_data['intelligence']['intelligence_information']['passive_dns_information_ip']:
                passive_dns_information_ip.append(passive_dns['domain'])

        if 'ssl' in self.json_data['intelligence']['intelligence_information']:
            ssl = self.json_data['intelligence']['intelligence_information']['ssl']

        if 'mutants' in self.json_data['intelligence']['intelligence_information']:
            for mutex in self.json_data['intelligence']['intelligence_information']['mutants']:
                mutants.append(mutex.strip('"'))

        if 'connection_domains' in self.json_data['intelligence']['intelligence_information']:
            for domain in self.json_data['intelligence']['intelligence_information']['connection_domains']:
                if 'ip' in domain:
                    ips.append(domain['ip'])
                if 'domain' in domain:
                    domains.append(domain['domain'])

        if 'connection_ips' in self.json_data['intelligence']['intelligence_information']:
            for ip in self.json_data['intelligence']['intelligence_information']['connection_ips']:
                ips.append(ip)

        if 'domains_email' in self.json_data['intelligence']['intelligence_information']:
            domains_email = self.json_data['intelligence']['intelligence_information']['domains_email']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'ThreatMiner': [{'sha256': sha256}, {'subdomains': subdomains},
                                                                                 {'emails': emails},{'passive_dns_information': emails},
                                                                                 {'passive_dns_information_ip': passive_dns_information_ip},
                                                                                 {'ssl': ssl},
                                                                                 {'mutants': mutants},
                                                                                 {'ips': ips},
                                                                                 {'domains': domains},
                                                                                 {'domains_email': domains_email}
                                                                                 ]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'ThreatMiner': [{'sha256': sha256},
                                                                                    {'subdomains': subdomains}, {'emails': emails},
                                                                                    {'passive_dns_information': passive_dns_information},
                                                                                    {'passive_dns_information_ip': passive_dns_information_ip},
                                                                                    {'ssl': ssl},
                                                                                    {'mutants': mutants},
                                                                                    {'ips': ips},
                                                                                    {'domains': domains},
                                                                                    {'domains_email': domains_email}
                                                                                    ]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['ThreatMiner']:
            for key, value in intel.iteritems():
                if key == 'sha256':
                    self._manage_threatminer_sha256(value)
                elif key == 'subdomains':
                    self._manage_threatminer_subdomains(value)
                elif key == 'emails':
                    self._manage_threatminer_emails(value)
                elif key == 'passive_dns_information':
                    self._manage_threatminer_passive_dns_information(value)
                elif key == 'passive_dns_information_ip':
                    self._manage_threatminer_passive_dns_information_ip(value)
                elif key == 'ssl':
                    self._manage_threatminer_ssl(value)
                elif key == 'mutants':
                    self._manage_threatminer_mutants(value)
                elif key == 'ips':
                    self._manage_threatminer_ips(value)
                elif key == 'domains':
                    self._manage_threatminer_domains(value)
                elif key == 'domains_email':
                    self._manage_threatminer_domains_email(value)

    def _manage_threatminer_sha256(self, sha256s):
        size = 30
        idx = 0
        for sha256 in sha256s:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if sha256 in self.nodes.keys():
                self.nodes[sha256] = (self.nodes[sha256][0] + 5, self.nodes[sha256][1], self.nodes[sha256][2])
            else:
                self.nodes[sha256] = (size, self.color, 'associated sha256')

            if sha256 not in self.edges[self.origin]:
                self.edges[self.origin].append(sha256)

    def _manage_threatminer_emails(self, emails):
        size = 30
        for email in emails:
            if email in self.nodes.keys():
                self.nodes[email] = (self.nodes[email][0] + 5, self.nodes[email][1], self.nodes[email][2])
            else:
                self.nodes[email] = (size, self.color, 'associated email')

            if email not in self.edges[self.origin]:
                self.edges[self.origin].append(email)

    def _manage_threatminer_subdomains(self, subdomains):
        size = 30
        idx = 0
        for subdomain in subdomains:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if subdomain in self.nodes.keys():
                self.nodes[subdomain] = (self.nodes[subdomain][0] + 5, self.nodes[subdomain][1], self.nodes[subdomain][2])
            else:
                self.nodes[subdomain] = (size, self.color, 'associated subdomain')

            if subdomain not in self.edges[self.origin]:
                self.edges[self.origin].append(subdomain)

    def _manage_threatminer_passive_dns_information(self, passive_infos):
        size = 30
        idx = 0
        for pinfo in passive_infos:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if pinfo in self.nodes.keys():
                self.nodes[pinfo] = (self.nodes[pinfo][0] + 5, self.nodes[pinfo][1], self.nodes[pinfo][2])
            else:
                self.nodes[pinfo] = (size, self.color, 'associated ip')

            if pinfo not in self.edges[self.origin]:
                self.edges[self.origin].append(pinfo)

    def _manage_threatminer_passive_dns_information_ip(self, passive_infos):
        size = 30
        idx = 0
        for pinfo in passive_infos:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if pinfo in self.nodes.keys():
                self.nodes[pinfo] = (self.nodes[pinfo][0] + 5, self.nodes[pinfo][1], self.nodes[pinfo][2])
            else:
                self.nodes[pinfo] = (size, self.color, 'associated domain')

            if pinfo not in self.edges[self.origin]:
                self.edges[self.origin].append(pinfo)

    def _manage_threatminer_ssl(self, certs):
        size = 30
        idx = 0
        for ssl in certs:
            ssl = 'SSL_Cert_%s' % (ssl)
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if ssl in self.nodes.keys():
                self.nodes[ssl] = (self.nodes[ssl][0] + 5, self.nodes[ssl][1], self.nodes[ssl][2])
            else:
                self.nodes[ssl] = (size, self.color, 'SSL certificate')

            if ssl not in self.edges[self.origin]:
                self.edges[self.origin].append(ssl)

    def _manage_threatminer_mutants(self, mutants):
        size = 30
        idx = 0
        for mutex in mutants:
            if mutex in self.nodes.keys():
                self.nodes[mutex] = (self.nodes[mutex][0] + 5, self.nodes[mutex][1], self.nodes[mutex][2])
            else:
                self.nodes[mutex] = (size, self.color, 'Mutex')

            if mutex not in self.edges[self.origin]:
                self.edges[self.origin].append(mutex)

    def _manage_threatminer_ips(self, ips):
        size = 30
        idx = 0
        for ip in ips:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if ip in self.nodes.keys():
                self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], self.nodes[ip][2])
            else:
                self.nodes[ip] = (size, self.color, 'associated ip')

            if ip not in self.edges[self.origin]:
                self.edges[self.origin].append(ip)

    def _manage_threatminer_domains(self, domains):
        size = 30
        idx = 0
        for domain in domains:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'associated domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_threatminer_domains_email(self, domains):
        size = 30
        idx = 0
        for domain in domains:
            if idx >= cfg.threat_miner_limit_report:
                break
            idx += 1

            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'associated domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)