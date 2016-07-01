#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - WebSiteInformer Plugin
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
import httplib
import string
import socket
import gzip
import re
import StringIO
from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['email']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about email addresses from WebSiteInformer'
visual_data = False

class WebSiteInformer:

    host = "website.informer.com"

    def __init__(self):
        self.intelligence = {}
        self.related_websites = []
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup WebSiteInformer...'
        self.intelligence = {}

    def email_information(self, email):
        query = '/email/%s' % (email)
        hhandle = httplib.HTTPConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()

        if (response.status == 200):
            server_response = response.read()
            self.collect_intelligence(server_response)
            return True
        else:
            return False

    def collect_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        related_sites = soup.findAll('div', {'class':'list-sites-e'})
        associated_registrants = soup.findAll('div', {'class':'one-accordion'})

        if len(related_sites) == 1:
            self.extract_related_websites(related_sites[0])

        if len(associated_registrants) != 0:
            self.extract_associated_registrants(associated_registrants)

    def extract_related_websites(self, soup):
        related_sites = soup.findAll('a', {'class':'textfill'})
        for site in related_sites:
            self.related_websites.append(site.get_text())
        self.intelligence['related_websites'] = self.related_websites

    def extract_associated_registrants(self, soups):
        idx = 0
        for soup in soups:
            collected_information = soup.findAll('li')
            if len(collected_information) >= 3:
                registrant_idx = 'registrant_%d' % (idx)
                typology = collected_information[0].span.get_text().lower()
                phone_contact = collected_information[1].span.get_text().lower()
                address_contact = collected_information[2].span.get_text().lower()

                name = collected_information[0].p.get_text().lower()
                number = collected_information[1].p.get_text().lower()
                address = collected_information[2].p.get_text().lower()

                self.intelligence[registrant_idx] = {   typology: name,
                                                        phone_contact: number,
                                                        address_contact: address
                                                    }

                idx += 1

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running WebSiteInformer() on %s' % intelligence
    intel_collector = WebSiteInformer()
    if extraction_type == cfg.intelligence_type['email']:
        if intel_collector.email_information(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'WebSiteInformer':
        visual_report = WebSiteInformerVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class WebSiteInformerVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#00ff00'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        related_websites = []
        companies = []

        if self.json_data['intelligence'] is None:
            return False

        for key, value in self.json_data['intelligence']['intelligence_information'].iteritems():
            if key == 'related_websites':
                related_websites = value
            elif key.startswith('registrant_'):
                if 'company' in value:
                    companies.append(value['company'])

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'WebSiteInformer': [{'related_websites': related_websites}, {'companies': companies}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'WebSiteInformer': [{'related_websites': related_websites}, {'companies': companies}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['WebSiteInformer']:
            for key, value in intel.iteritems():
                if key == 'related_websites':
                    self._manage_websiteinformer_relatedwebsites(value)
                elif key == 'companies':
                    self._manage_websiteinformer_companies(value)

    def _manage_websiteinformer_relatedwebsites(self, sites):
        size = 30
        for site in sites:
            if site in self.nodes.keys():
                self.nodes[site] = (self.nodes[site][0] + 5, self.nodes[site][1], self.nodes[site][2])
            else:
                self.nodes[site] = (size, self.color, 'associated domain')

            if site not in self.edges[self.origin]:
                self.edges[self.origin].append(site)

    def _manage_websiteinformer_companies(self, companies):
        size = 30
        for company in companies:
            if company in self.nodes.keys():
                self.nodes[company] = (self.nodes[company][0] + 5, self.nodes[company][1], self.nodes[company][2])
            else:
                self.nodes[company] = (size, self.color, 'company')

            if company not in self.edges[self.origin]:
                self.edges[self.origin].append(company)