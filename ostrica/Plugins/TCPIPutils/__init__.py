#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - TCPIPUtils Plugin
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
import re
from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['domain'], cfg.intelligence_type['asn']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about domains or ASNs on TCPIPUtils'
visual_data = True

class TCPIPUtils(object):

    def __init__(self):
        self.host = 'www.utlsapi.com'
        self.asn_host = 'www.tcpiputils.com'
        self.version = '1.0'
        self.extversion = '0.1'
        self.intelligence = {}
        pass


    def __del__(self):
        if cfg.DEBUG:
            print('cleanup TCPIPutils...')
        self.intelligence = {}

    def asn_information(self, asn):
        query = '/browse/as/%s' % (asn)
        hhandle = httplib.HTTPConnection(self.asn_host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if (response.status == 200):
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                server_response = gzip.GzipFile(fileobj=content).read()
                if (server_response.find('No valid IPv4 address found!') != 1):
                    self.extract_asn_intelligence(server_response)
                    return True
                else:
                    return False
        else:
            return False

    def domain_information(self, domain):
        query = '/plugin.php?version=%s&type=ipv4info&hostname=%s&source=chromeext&extversion=%s' % (self.version, domain, self.extversion)
        hhandle = httplib.HTTPSConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        hhandle.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if (response.status == 200):
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                server_response = gzip.GzipFile(fileobj=content).read()
                if (server_response.find('No valid IPv4 address found!') != 1):
                    self.extract_domain_intelligence(server_response)
                    return True
                else:
                    return False
        else:
            return False

    def extract_domain_intelligence(self, server_response):
        ip_address = False
        description = False
        location = False
        subnet = False
        asn_number = False


        soup = BeautifulSoup(server_response, 'html.parser')
        all_tds = soup.findAll('td')
        for td in all_tds:
            if td.get_text() == unicode('IP address'):
                ip_address = True
                continue
            elif td.get_text() == unicode('Description'):
                description = True
                continue
            elif td.get_text() == unicode('Location'):
                location = True
                continue
            elif td.get_text() == unicode('IP-range/subnet'):
                subnet = True
                continue
            elif td.get_text() == unicode('ASN number'):
                asn_number = True
                continue

            if ip_address == True:
                if 'ip_address' not in self.intelligence.keys():
                    self.intelligence['ip_address'] = td.get_text()
                ip_address = False
                continue
            elif description == True:
                if 'description' not in self.intelligence.keys():
                    self.intelligence['description'] = td.get_text()
                description = False
                continue
            elif location == True:
                if 'location' not in self.intelligence.keys():
                    self.intelligence['location'] = td.get_text().replace(u'\xa0', '')
                location = False
                continue
            elif subnet == True:
                if 'subnet' not in self.intelligence.keys():
                    self.intelligence['subnet'] = td.contents[2]
                    self.intelligence['subnet_cidr'] = td.contents[0].get_text()
                subnet = False
                continue
            elif asn_number == True:
                if 'asn_number' not in self.intelligence.keys():
                    self.intelligence['asn_number'] = td.get_text()
                location = False
                continue

        if 'ip_address' not in self.intelligence.keys():
            self.intelligence['ip_address'] = ''
        if 'description' not in self.intelligence.keys():
            self.intelligence['description'] = ''
        if 'location' not in self.intelligence.keys():
            self.intelligence['location'] = ''
        if 'subnet' not in self.intelligence.keys():
            self.intelligence['subnet'] = ''
        if 'asn_number' not in self.intelligence.keys():
            self.intelligence['asn_number'] = ''
        if 'n_domains' not in self.intelligence.keys():
            self.intelligence['n_domains'] = ''
        if 'adult_domains' not in self.intelligence.keys():
            self.intelligence['adult_domains'] = ''
        if 'name_servers' not in self.intelligence.keys():
            self.intelligence['name_servers'] = ''
        if 'spam_hosts' not in self.intelligence.keys():
            self.intelligence['spam_hosts'] = ''
        if 'open_proxies' not in self.intelligence.keys():
            self.intelligence['open_proxies'] = ''
        if 'mail_servers' not in self.intelligence.keys():
            self.intelligence['mail_servers'] = ''

    def extract_mailservers_associated_to_asn(self, soup):
        mail_servers = []
        idx = 0
        all_tds = soup.findAll('td')
        while idx < len(all_tds):
            if all_tds[idx].get_text() == unicode('See more items'):
                idx += 1
                continue
            elif all_tds[idx].get_text().find(u'Note:') != -1:
                break
            mail_servers.append(all_tds[idx].get_text())
            idx += 3
        self.intelligence['mail_servers'] = mail_servers


    def extract_domains_associated_to_asn(self, soup):
        associated_domains = []
        idx = 0
        all_tds = soup.findAll('td')
        while idx < len(all_tds):
            if all_tds[idx].get_text() == unicode('See more items'):
                idx += 1
                continue
            elif all_tds[idx].get_text().find(u'Note:') != -1:
                break
            domain_name = all_tds[idx].get_text()
            idx += 1
            ip_address = all_tds[idx].get_text()
            idx += 1
            associated_domains.append((domain_name, ip_address))
        self.intelligence['associated_domains'] = associated_domains

    def extract_asn_intelligence(self, server_response):
        n_domains = False
        adult_domains = False
        name_servers = False
        spam_hosts = False
        open_proxies = False
        mail_servers = False

        soup = BeautifulSoup(server_response, 'html.parser')

        if not soup.findAll(text=re.compile(r'No hosted mail servers found on')):
            self.extract_mailservers_associated_to_asn(soup.findAll('table')[6]) # mail servers

        if not soup.findAll(text=re.compile(r'No hosted domains found on')):
            self.extract_domains_associated_to_asn(soup.findAll('table')[4]) # domains

        all_tds = soup.findAll('td')
        for td in all_tds:
            if td.get_text() == unicode('Number of domains hosted'):
                n_domains = True
                continue
            elif td.get_text() == unicode('Number of adult domains hosted'):
                adult_domains = True
                continue
            elif td.get_text() == unicode('Number of name servers hosted'):
                name_servers = True
                continue
            elif td.get_text() == unicode('Number of SPAM hosts hosted'):
                spam_hosts = True
                continue
            elif td.get_text() == unicode('Number of open proxies hosted'):
                open_proxies = True
                continue
            elif td.get_text() == unicode('Number of mail servers hosted'):
                mail_servers = True
                continue

            if n_domains == True:
                if 'n_domains' not in self.intelligence.keys():
                    self.intelligence['n_domains'] = td.get_text()
                n_domains = False
                continue
            elif adult_domains == True:
                if 'adult_domains' not in self.intelligence.keys():
                    self.intelligence['adult_domains'] = td.get_text()
                adult_domains = False
                continue
            elif name_servers == True:
                if 'name_servers' not in self.intelligence.keys():
                    self.intelligence['name_servers'] = td.get_text()
                name_servers = False
                continue
            elif spam_hosts == True:
                if 'spam_hosts' not in self.intelligence.keys():
                    self.intelligence['spam_hosts'] = td.get_text()
                spam_hosts = False
                continue
            elif open_proxies == True:
                if 'open_proxies' not in self.intelligence.keys():
                    self.intelligence['open_proxies'] = td.get_text()
                open_proxies = False
                continue
            elif mail_servers == True:
                if 'mail_servers' not in self.intelligence.keys():
                    self.intelligence['mail_servers'] = td.get_text()
                mail_servers = False
                continue

        if 'ip_address' not in self.intelligence.keys():
            self.intelligence['ip_address'] = ''
        if 'description' not in self.intelligence.keys():
            self.intelligence['description'] = ''
        if 'location' not in self.intelligence.keys():
            self.intelligence['location'] = ''
        if 'subnet' not in self.intelligence.keys():
            self.intelligence['subnet'] = ''
        if 'asn_number' not in self.intelligence.keys():
            self.intelligence['asn_number'] = ''
        if 'n_domains' not in self.intelligence.keys():
            self.intelligence['n_domains'] = ''
        if 'adult_domains' not in self.intelligence.keys():
            self.intelligence['adult_domains'] = ''
        if 'name_servers' not in self.intelligence.keys():
            self.intelligence['name_servers'] = ''
        if 'spam_hosts' not in self.intelligence.keys():
            self.intelligence['spam_hosts'] = ''
        if 'open_proxies' not in self.intelligence.keys():
            self.intelligence['open_proxies'] = ''
        if 'mail_servers' not in self.intelligence.keys():
            self.intelligence['mail_servers'] = ''


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running TCPIPUtils() on %s' % intelligence)
    intel_collector = TCPIPUtils()
    if extraction_type == cfg.intelligence_type['domain']:
        if intel_collector.domain_information(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['asn']:
        if intel_collector.asn_information(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    else:
        return {}

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'TCPIPutils':
        visual_report = TCPIPutilsVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class TCPIPutilsVisual:
    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#bf00ff'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):

        if self.json_data['intelligence'] is None:
            return False

        if 'asn' in self.json_data['intelligence']['intelligence_information']:
            asn = self.json_data['intelligence']['intelligence_information']['asn_number']
        else:
            asn = ''

        if 'ip_address' in self.json_data['intelligence']['intelligence_information']:
            ip_address = self.json_data['intelligence']['intelligence_information']['ip_address']
        else:
            ip_address = ''

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'TCPIPutils': [{'asn': asn}, {'ip_address': ip_address}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'TCPIPutils': [{'asn': asn}, {'ip_address': ip_address}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['TCPIPutils']:
            for key, value in intel.iteritems():
                if key == 'asn':
                    self._manage_tcpiputils_asn(value)
                elif key == 'ip_address':
                    self._manage_tcpiputils_ip_address(value)

    def _manage_tcpiputils_asn(self, asn):
        size = 30
        if asn in self.nodes.keys():
            self.nodes[asn] = (self.nodes[asn][0] + 5, self.nodes[asn][1], 'asn')
        else:
            self.nodes[asn] = (size, self.color, 'asn')

        if asn not in self.edges[self.origin]:
            self.edges[self.origin].append(asn)

    def _manage_tcpiputils_ip_address(self, ip):
        size = 30
        if ip in self.nodes.keys():
            self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], 'ip')
        else:
            self.nodes[ip] =  (size, self.color, 'ip')

        if ip not in self.edges[self.origin]:
            self.edges[self.origin].append(ip)
