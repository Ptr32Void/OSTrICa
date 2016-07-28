#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - PyWhois Plugin
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
import whois
import pythonwhois
from ipwhois import IPWhois

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect Whois information about domains or IPs'
visual_data = True

class PyWhoIs:

    def __init__(self):
        self.intelligence = {}
        pass

    def domain_whois(self, domain):
        try:
            self.intelligence['whois'] = pythonwhois.get_whois(domain)
        except:
            #FIXME add exception
            pass

        if 'whois' in self.intelligence:
            if 'creation_date' in self.intelligence['whois']:
                date_to_string = []
                if (self.intelligence['whois']['creation_date'] != None and
                    hasattr(self.intelligence['whois']['creation_date'], '__iter__')):
                    for date_info in self.intelligence['whois']['creation_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois']['creation_date'] = date_to_string
                else:
                    self.intelligence['whois']['creation_date'] = str(self.intelligence['whois']['creation_date'])

            if 'updated_date' in self.intelligence['whois']:
                date_to_string = []
                if (self.intelligence['whois']['updated_date'] != None and
                   hasattr(self.intelligence['whois']['updated_date'], '__iter__')):
                    for date_info in self.intelligence['whois']['updated_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois']['updated_date'] = date_to_string
                else:
                    self.intelligence['whois']['updated_date'] = str(self.intelligence['whois']['updated_date'])

            if 'expiration_date' in self.intelligence['whois']:
                date_to_string = []
                if (self.intelligence['whois']['expiration_date'] != None and
                   hasattr(self.intelligence['whois']['expiration_date'], '__iter__')):
                    for date_info in self.intelligence['whois']['expiration_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois']['expiration_date'] = date_to_string
                else:
                    self.intelligence['whois']['expiration_date'] = str(self.intelligence['whois']['expiration_date'])

        try:
            self.intelligence['whois1'] = whois.whois(domain)
        except:
            #FIXME add exception
            pass

        if 'whois1' in self.intelligence:
            if 'creation_date' in self.intelligence['whois1']:
                date_to_string = []
                if (self.intelligence['whois1']['creation_date'] != None and
                   hasattr(self.intelligence['whois1']['creation_date'], '__iter__')):
                    for date_info in self.intelligence['whois1']['creation_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois1']['creation_date'] = date_to_string
                else:
                    self.intelligence['whois1']['creation_date'] = str(self.intelligence['whois1']['creation_date'])

            if 'updated_date' in self.intelligence['whois1']:
                date_to_string = []
                if (self.intelligence['whois1']['updated_date'] != None and
                   hasattr(self.intelligence['whois1']['updated_date'], '__iter__')):
                    for date_info in self.intelligence['whois1']['updated_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois1']['updated_date'] = date_to_string
                else:
                    self.intelligence['whois1']['updated_date'] = str(self.intelligence['whois1']['updated_date'])

            if 'expiration_date' in self.intelligence['whois1']:
                date_to_string = []
                if (self.intelligence['whois1']['expiration_date'] != None and
                   hasattr(self.intelligence['whois1']['expiration_date'], '__iter__')):
                    for date_info in self.intelligence['whois1']['expiration_date']:
                        date_to_string.append(str(date_info))
                    self.intelligence['whois1']['expiration_date'] = date_to_string
                else:
                    self.intelligence['whois1']['expiration_date'] = str(self.intelligence['whois1']['expiration_date'])

        return True

    def ip_whois(self, ip_address):
        try:
            self.intelligence['ip_whois'] = IPWhois(ip_address).lookup_rdap()

        except:
            #FIXME add exception
            pass

        return True

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup PyWhoIs...')
        self.intelligence = {}


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running PyWhoIs() on %s' % intelligence)

    intel_collector = PyWhoIs()
    if extraction_type == cfg.intelligence_type['ip']:
        if intel_collector.ip_whois(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['domain']:
        if intel_collector.domain_whois(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'PyWhois':
        visual_report = PyWhoisVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class PyWhoisVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#009900'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        email = ''
        emails = []
        asn = ''

        if self.json_data['intelligence'] is None:
            return False

        if 'whois1' in self.json_data['intelligence']['intelligence_information']:
            if 'emails' in self.json_data['intelligence']['intelligence_information']['whois1']:
                if type(self.json_data['intelligence']['intelligence_information']['whois1']['emails']) is list:
                    for eml in self.json_data['intelligence']['intelligence_information']['whois1']['emails']:
                        emails.append(eml)
                else:
                    emails.append(self.json_data['intelligence']['intelligence_information']['whois1']['emails'])

        if 'whois' in self.json_data['intelligence']['intelligence_information']:
            if 'emails' in self.json_data['intelligence']['intelligence_information']['whois']:
                if type(self.json_data['intelligence']['intelligence_information']['whois']['emails']) is list:
                    for eml in self.json_data['intelligence']['intelligence_information']['whois']['emails']:
                        emails.append(eml)
                else:
                    emails.append(self.json_data['intelligence']['intelligence_information']['whois']['emails'])


            if 'contacts' in self.json_data['intelligence']['intelligence_information']['whois']:

                if 'registrant' in self.json_data['intelligence']['intelligence_information']['whois']['contacts']:

                    if self.json_data['intelligence']['intelligence_information']['whois']['contacts']['registrant'] != None:
                        if 'email' in self.json_data['intelligence']['intelligence_information']['whois']['contacts']['registrant']:
                            email = self.json_data['intelligence']['intelligence_information']['whois']['contacts']['registrant']['email']

        elif 'ip_whois' in self.json_data['intelligence']['intelligence_information']:
            if 'asn' in self.json_data['intelligence']['intelligence_information']['ip_whois']:
                asn = self.json_data['intelligence']['intelligence_information']['ip_whois']['asn']

        else:
            return False

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'PyWhois': [{'emails': set(emails)}, {'registrant_email': email}, {'asn': asn}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'PyWhois': [{'emails': set(emails)}, {'registrant_email': email}, {'asn': asn}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['PyWhois']:
            for key, value in intel.items():
                if key == 'emails':
                    self._manage_pywhois_emails(value)
                elif key == 'email':
                    self._manage_pywhois_email(value)
                elif key == 'asn':
                    self._manage_pywhois_asn(value)

    def _manage_pywhois_emails(self, emails):
        size = 30
        for email in emails:
            if email is None:
                continue
            if email in self.nodes.keys():
                self.nodes[email] = (self.nodes[email][0] + 5, self.nodes[email][1], self.nodes[email][2])
            else:
                self.nodes[email] = (size, self.color, 'email')

            if email not in self.edges[self.origin]:
                self.edges[self.origin].append(email)

    def _manage_pywhois_email(self, email):
        size = 30
        if email is None:
            return
        if email in self.nodes.keys():
            self.nodes[email] = (self.nodes[email][0] + 5, self.nodes[email][1], self.nodes[email][2])
        else:
            self.nodes[email] = (size, self.color, 'email')

        if email not in self.edges[self.origin]:
            self.edges[self.origin].append(email)

    def _manage_pywhois_asn(self, asn):
        size = 30
        if asn in self.nodes.keys():
            self.nodes[asn] = (self.nodes[asn][0] + 5, self.nodes[asn][1], self.nodes[asn][2])
        else:
            self.nodes[asn] = (size, self.color, 'asn')

        if asn not in self.edges[self.origin]:
            self.edges[self.origin].append(asn)
