#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - SpyOnWeb Plugin
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

extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about domains related to IP, Google Adsense and Google Analytics IDs'
visual_data = False

class SpyOnWeb:

    def __init__(self):
        self.host = 'spyonweb.com'
        self.intelligence = {}
        self.server_response = ''
        self.ip_address = ''
        self.n_domains = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup SpyOnWeb...'
        self.intelligence = {}


    def extract_ip_associated_to_url(self, soup):
        url_to_ip = soup.findAll('h3', {'class':'panel-title'})

        if len(url_to_ip) != 1:
            return False

        try:
            self.ip_address = url_to_ip[0].contents[0].get_text()
            pos = url_to_ip[0].contents[2].get_text().find(' ')
            if pos != -1:
                self.n_domains = url_to_ip[0].contents[2].get_text()[:pos]
            else:
                self.n_domains = ''
        except:
            return False
        return True

    def extract_associated_urls(self, soup):
        associated_urls = []
        same_ip_url = soup.findAll('div', {'class':'links'})
        if len(same_ip_url) == 0:
            return False

        urls = same_ip_url[0].findAll('a')
        if len(urls) == 0:
            False

        for url in urls:
            if url.get_text() != '':
                associated_urls.append(url.get_text())
        return associated_urls

    def extract_urls(self, soup):
        related_domains = []

        all_available_ips = soup.findAll('div', {'class':'panel panel-default'})

        for available_ip in all_available_ips:
            if self.extract_ip_associated_to_url(available_ip) == False:
                continue

            associated_urls = self.extract_associated_urls(available_ip)
            if associated_urls == False:
                self.ip_address = ''
                self.n_domains = ''
                continue

            if self.ip_address.startswith('pub-'):
                related_domains.append({ 'GoogleAdsense': self.ip_address, 'url_details': (self.n_domains, associated_urls) })
            elif self.ip_address.startswith('UA-'):
                related_domains.append({ 'GoogleAnalytics': self.ip_address, 'url_details': (self.n_domains, associated_urls) })
            else:
                related_domains.append({ 'ip': self.ip_address, 'url_details': (self.n_domains, associated_urls) })

        return related_domains

    def extract_intelligence(self):
        soup = BeautifulSoup(self.server_response, 'html.parser')
        self.intelligence['associated_urls'] = self.extract_urls(soup)

        pass

    def extract_server_info(self, data_to_analyze):
        query = '/%s' % (data_to_analyze)
        hhandle = httplib.HTTPConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('referer', 'http://spyonweb.com')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if response.status == 200:
            self.server_response = response.read()
            if self.extract_intelligence() != False:
                return True
            else:
                return False
        else:
            return False


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running SpyOnWeb() on %s' % intelligence

    intel_collector = SpyOnWeb()
    if (extraction_type == cfg.intelligence_type['ip']) or (extraction_type == cfg.intelligence_type['domain']):
        if intel_collector.extract_server_info(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'SpyOnWeb':
        visual_report = SpyOnWebVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class SpyOnWebVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#999966'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        related_websites = {}

        if self.json_data['intelligence'] is None:
            return False

        if 'associated_urls' in self.json_data['intelligence']['intelligence_information']:
            for associated_urls in self.json_data['intelligence']['intelligence_information']['associated_urls']:
                if 'url_details' in associated_urls and 'GoogleAdsense' in associated_urls:
                    related_websites['GoogleAdSense'] = (associated_urls['GoogleAdsense'], associated_urls['url_details'][1])
                elif 'url_details' in associated_urls and 'ip' in associated_urls:
                    related_websites['ip'] = (associated_urls['ip'], associated_urls['url_details'][1])
                elif 'url_details' in associated_urls and 'GoogleAnalytics' in associated_urls:
                    related_websites['GoogleAnalytics'] = (associated_urls['GoogleAnalytics'], associated_urls['url_details'][1])


        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'SpyOnWeb': [{'related_websites': related_websites}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'SpyOnWeb': [{'related_websites': related_websites}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['SpyOnWeb']:
            for key, value in intel.iteritems():
                if key == 'related_websites':
                    self._manage_spyonweb_relatedwebsites(value)

    def _manage_spyonweb_relatedwebsites(self, sites):
        for key, value in sites.iteritems():
            if key == 'ip':
                self._manage_associated_hosts_to_ip(value)
            elif key == 'GoogleAdSense':
                self._manage_associated_google_adsense_hosts(value)
            if key == 'GoogleAnalytics':
                self._manage_associated_google_analytics_hosts(value)

    def _manage_associated_hosts_to_ip(self, hosts):
        size = 30
        ip = hosts[0]
        for host in hosts[1]:
            if host in self.nodes.keys():
                self.nodes[host] = (self.nodes[host][0] + 5, self.nodes[host][1], self.nodes[host][2])
            else:
                self.nodes[host] = (size, self.color, 'associated domain')

            if ip not in self.edges.keys():
                self.edges.setdefault(ip, [])
                self.edges[ip].append(host)
            else:
                self.edges[ip].append(host)

    def _manage_associated_google_adsense_hosts(self, hosts):
        size = 30
        google_adsense_id = hosts[0]

        if google_adsense_id in self.nodes.keys():
            self.nodes[google_adsense_id] = (self.nodes[google_adsense_id][0] + 5, self.nodes[google_adsense_id][1], self.nodes[google_adsense_id][2])
        else:
            self.nodes[google_adsense_id] = (size, self.color, 'analytics associated domain')

        for host in hosts[1]:
            if host in self.nodes.keys():
                self.nodes[host] = (self.nodes[host][0] + 5, self.nodes[host][1], self.nodes[host][2])
            else:
                self.nodes[host] = (size, self.color, 'adsense associated domain')

            if google_adsense_id not in self.edges.keys():
                self.edges.setdefault(google_adsense_id, [])
                self.edges[google_adsense_id].append(host)
            else:
                self.edges[google_adsense_id].append(host)

    def _manage_associated_google_analytics_hosts(self, hosts):
        size = 30
        google_adnalytics_id = hosts[0]

        if google_adnalytics_id in self.nodes.keys():
            self.nodes[google_adnalytics_id] = (self.nodes[google_adnalytics_id][0] + 5, self.nodes[google_adnalytics_id][1], self.nodes[google_adnalytics_id][2])
        else:
            self.nodes[google_adnalytics_id] = (size, self.color, 'analytics associated domain')

        for host in hosts[1]:
            if host in self.nodes.keys():
                self.nodes[host] = (self.nodes[host][0] + 5, self.nodes[host][1], self.nodes[host][2])
            else:
                self.nodes[host] = (size, self.color, 'analytics associated domain')

            if google_adnalytics_id not in self.edges.keys():
                self.edges.setdefault(google_adnalytics_id, [])
                self.edges[google_adnalytics_id].append(host)
            else:
                self.edges[google_adnalytics_id].append(host)