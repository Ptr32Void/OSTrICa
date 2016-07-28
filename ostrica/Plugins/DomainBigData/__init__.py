#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - DomainBigData plugin
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

from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['domain'], cfg.intelligence_type['email']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about domains or emails on DomainBigData'
visual_data = True

class DomainBigData:

    host = "domainbigdata.com"

    def __init__(self):
        self.intelligence = {}
        self.index_value = ''
        self.intelligence_list = []
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup DomainBigData...')
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
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                server_response = gzip.GzipFile(fileobj=content).read()
                self.collect_email_intelligence(server_response)
                return True
            else:
                return False
        else:
            return False

    def collect_email_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        associated_sites = soup.findAll('table', {'class':'t1'})

        if len(associated_sites) == 1:
            self.extract_associated_sites(associated_sites[0].tbody)

    def extract_associated_sites(self, soup):
        associated_sites = []
        idx = 0
        related_sites = soup.findAll('td')
        for site in related_sites:
            if idx == 0:
                associated_site = site.get_text()
                idx += 1
                continue
            elif idx == 1:
                creation_date = site.get_text()
                idx += 1
                continue
            elif idx == 2:
                registrar = site.get_text()
                idx = 0
                associated_sites.append({'associated_site':associated_site, 'creation_date':creation_date, 'registrar':registrar})
                continue
        self.intelligence['associated_sites'] = associated_sites


    def domain_information(self, domain):
        query = '/%s' % (domain)
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
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                server_response = gzip.GzipFile(fileobj=content).read()
                self.collect_domain_intelligence(server_response)
                return True
            else:
                return False
        else:
            return False

    def collect_domain_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        records = soup.findAll('div', {'id':'divDNSRecords'})

        if len(records) == 1:
            dns_records = records[0].findAll('table', {'class':'t1'})
            self.extract_associated_records(dns_records)

        records = soup.findAll('div', {'id':'divListOtherTLD'})
        if len(records) == 1:
            tdls = []
            other_tdls = records[0].findAll('a')
            for tdl in other_tdls:
                tdls.append(tdl.string)
            self.intelligence['other_tdls'] = tdls

        records = soup.findAll('div', {'id':'MainMaster_divRegistrantIDCard'})
        if len(records) == 1:
            self.collect_registrant_information(records[0])

    def collect_registrant_information(self, soup):
        registrant_organization = ''
        registrant_email = ''
        registrant_name = ''
        registrant_city = ''
        registrant_country = ''
        registrant_phone = ''

        organization_soup = soup.findAll('tr', {'id':'MainMaster_trRegistrantOrganization'})
        email_soup = soup.findAll('tr', {'id':'trRegistrantEmail'})
        name_soup = soup.findAll('tr', {'id':'trRegistrantName'})
        city_soup = soup.findAll('tr', {'id':'trRegistrantCity'})
        country_soup = soup.findAll('tr', {'id':'trRegistrantCountry'})
        phone_soup = soup.findAll('tr', {'id':'trRegistrantTel'})

        if len(organization_soup) == 1:
            registrant_organization = self.extract_information_from_registrant(organization_soup[0])

        if len(email_soup) == 1:
            registrant_email = self.extract_information_from_registrant(email_soup[0])

        if len(name_soup) == 1:
            registrant_name = self.extract_information_from_registrant(name_soup[0])

        if len(city_soup) == 1:
            registrant_city = self.extract_information_from_registrant(city_soup[0])

        if len(country_soup) == 1:
            registrant_country = self.extract_information_from_registrant(country_soup[0])

        if len(phone_soup) == 1:
            registrant_phone = self.extract_information_from_registrant(phone_soup[0])

        self.intelligence['organization'] = registrant_organization
        self.intelligence['email'] = registrant_email
        self.intelligence['registrant_name'] = registrant_name
        self.intelligence['registrant_city'] = registrant_city
        self.intelligence['registrant_country'] = registrant_country
        self.intelligence['registrant_phone'] = registrant_phone

    def extract_information_from_registrant(self, soup):
        soup = soup.findAll('td')
        if len(soup) == 3:
            soup_img = soup[1].findAll('img')
            if len(soup_img) == 1:
                return soup[1].contents[1]
            else:
                return soup[1].string
        elif len(soup) == 2:
            return soup[1].string
        return ''



    def extract_associated_records(self, soups):
        for soup in soups:
            all_trs = soup.findAll('tr')
            self.extract_trs(all_trs)
            self.intelligence[self.index_value] = self.intelligence_list
            self.intelligence_list = []

    def extract_trs(self, soup):
        for tr in soup:
            self.extract_tds(tr)

    def extract_tds(self, soup):
        idx = True # idx flags the type of record that will be added in the dictionary if True
        record_list = []
        for td in soup:
            if idx and td.get_text() not in self.intelligence.keys():
                self.index_value = td.get_text()
                self.intelligence[self.index_value] = ''
            idx = False
            record_list.append(td.get_text())
        self.intelligence_list.append(record_list)


    def related_domains_information(self, domain):
        query = '/name/%s' % (domain)
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
            if response.getheader('Content-Encoding') == 'gzip':
                content = StringIO.StringIO(response.read())
                server_response = gzip.GzipFile(fileobj=content).read()
                self.collect_domain_related_intelligence(server_response)
                return True
            else:
                return False
        else:
            return False

    def collect_domain_related_intelligence(self, server_response):
        soup = BeautifulSoup(server_response, 'html.parser')
        associated_sites = soup.findAll('table', {'class':'t1'})

        if len(associated_sites) == 1:
            self.extract_associated_sites(associated_sites[0].tbody)

    def extract_associated_sites(self, soup):
        associated_sites = []
        idx = 0
        related_sites = soup.findAll('td')
        for site in related_sites:
            if idx == 0:
                associated_site = site.get_text()
                idx += 1
                continue
            elif idx == 1:
                creation_date = site.get_text()
                idx += 1
                continue
            elif idx == 2:
                registrar = site.get_text()
                idx = 0
                associated_sites.append({'associated_site':associated_site, 'creation_date':creation_date, 'registrar':registrar})
                continue
        self.intelligence['possible_associated_sites'] = associated_sites

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running DomainBigData() on %s' % intelligence)

    intel_collector = DomainBigData()
    if extraction_type == cfg.intelligence_type['email']:
        if intel_collector.email_information(intelligence.replace('www.', '')) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['domain']:
        if (intel_collector.related_domains_information(intelligence.replace('www.', '')) == True or
            intel_collector.domain_information(intelligence.replace('www.', '')) == True):
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    else:
        return {}


def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'DomainBigData':
        visual_report = DomainBigDataVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class DomainBigDataVisual:
    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#000099'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        associated_domain = []
        other_tdls = []
        email = ''
        if self.json_data['intelligence'] is None:
            return False

        if 'possible_associated_sites' in self.json_data['intelligence']['intelligence_information']:
            associated_domains = self.json_data['intelligence']['intelligence_information']['possible_associated_sites']
            for domain in associated_domains:
                associated_domain.append(domain['associated_site'])
        else:
            associated_domains = ''

        if 'other_tdls' in self.json_data['intelligence']['intelligence_information'].keys():
            for domain in self.json_data['intelligence']['intelligence_information']['other_tdls']:
                other_tdls.append(domain)

        if 'email' in self.json_data['intelligence']['intelligence_information'].keys():
            email = self.json_data['intelligence']['intelligence_information']['email']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'DomainBigData':
                                                        [{'associated_domain': associated_domain}, {'other_tdls': other_tdls},
                                                        {'email': email}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'DomainBigData':
                                                        [{'associated_domain': associated_domain}, {'other_tdls': other_tdls},
                                                        {'email': email}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['DomainBigData']:
            for key, value in intel.iteritems():
                if key == 'associated_domain':
                    self._manage_bigdata_associated_domains(value)
                elif key == 'other_tdls':
                    self._manage_bigdata_other_tdls(value)
                elif key == 'email':
                    self._manage_bigdata_email(value)

    def _manage_bigdata_associated_domains(self, domains):
        size = 30
        for domain in domains:
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'associated domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_bigdata_other_tdls(self, domains):
        size = 30
        for domain in domains:
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'other TDL')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_bigdata_email(self, email):
        size = 30
        if email in self.nodes.keys():
            self.nodes[email] = (self.nodes[email][0] + 5, self.nodes[email][1], self.nodes[email][2])
        else:
            self.nodes[email] = (size, self.color, 'email')

        if email not in self.edges[self.origin]:
            self.edges[self.origin].append(email)
