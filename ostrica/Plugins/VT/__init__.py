#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector - VirusTotal Plugin
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
import traceback
if sys.version_info < (3, 0):
    import httplib
else:
    import http.client as httplib
import re
from bs4 import BeautifulSoup

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['md5'], cfg.intelligence_type['sha256'],
                   cfg.intelligence_type['domain'], cfg.intelligence_type['ip']]
enabled = True
version = 0.1
developer = 'Roberto Sponchioni <rsponchioni@yahoo.it>'
description = 'Plugin used to collect information about domains, IPs, md5s, sha256s on VirusTotal'
visual_data = True

class VT:

    host = "www.virustotal.com"

    def __init__(self):
        self.page_content = ''
        self.av_results = {}
        self.first_submission_date = 0
        self.last_submission_date = 0
        self.submitted_filenames = []
        self.threat_traits = {}
        self.file_details = {}
        self.intelligence = {}
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup VirusTotal...')
        self.intelligence = {}

    @staticmethod
    def extract_sha256(location_link):
        if location_link.find('/file/') == -1 and location_link.find('/analysis/') == -1:
            return False
        else:
            file_pos = location_link.find('/file/')
            analysis_pos = location_link.find('/analysis/')
            return location_link[file_pos+6:analysis_pos]

    def detection_to_dict(self, detections):
        i = 0
        while i < len(detections):
            av_name = detections[i].get_text().replace('\n', '').strip()
            detection = detections[i+1].get_text().replace('\n', '').strip()
            if detection == '':
                detection = 'Not detected'
            update = detections[i+2].get_text().replace('\n', '').strip()
            self.av_results[av_name] = (detection, update)
            i += 3
        return True

    def get_av_result(self):
        soup = BeautifulSoup(self.page_content, 'html.parser')
        detection_table = soup.findAll('table', {'id':'antivirus-results'})
        if len(detection_table) != 1:
            return False
        detections = detection_table[0].findAll('td')
        if len(detections) != 0:
            self.detection_to_dict(detections)
            return True
        else:
            return False

    def get_detections_by_md5(self, md5):
        body = 'query=%s' % (md5)
        hhandle = httplib.HTTPSConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('POST', '/en/search/')
        hhandle.putheader('Host', 'www.virustotal.com')
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Cache-Control', 'max-age=0')
        hhandle.putheader('Referer', 'https://www.virustotal.com/')
        hhandle.putheader('Origin', 'https://www.virustotal.com')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Content-Type', 'application/x-www-form-urlencoded')
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.putheader('Content-Length', str(len(body)))

        hhandle.endheaders()
        hhandle.send(body)

        response = hhandle.getresponse()

        if (response.status == 302):
            sha256hash = self.extract_sha256(response.getheader('Location'))
            if (sha256hash == False):
                return False
            else:
                return self.get_detections_by_sha256(sha256hash)
        else:
            return False


    def extract_intelligece(self):
        self.intelligence['filenames'] = self.submitted_filenames
        self.intelligence['first_submission_date'] = self.first_submission_date
        self.intelligence['last_submission_date'] = self.last_submission_date
        self.intelligence['av_results'] = self.av_results
        self.intelligence['threat_behaviour'] = self.threat_traits
        self.intelligence['file_details'] = self.file_details

    def get_detections_by_sha256(self, sha256hash):
        query = '/en/file/%s/analysis/' % (sha256hash)
        hhandle = httplib.HTTPSConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Host', 'www.virustotal.com')
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Cache-Control', 'max-age=0')
        hhandle.putheader('Referer', 'https://www.virustotal.com/')
        hhandle.putheader('Origin', 'https://www.virustotal.com')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if (response.status == 200):
            self.page_content = response.read()
            self.get_behaviour()
            self.get_file_details()
            self.get_av_result()
            self.get_vt_metadata()
            self.extract_intelligece()
            return True
        else:
            return False

    def get_file_details(self):
        soup = BeautifulSoup(self.page_content, 'html.parser')
        file_details_information = soup.findAll('div', {'id':'file-details'})
        if len(file_details_information) == 0 or len(file_details_information) > 2:
            return False

        file_details = file_details_information[0].findAll('h5')
        for file_detail_info in file_details:
            if file_detail_info.get_text().strip() == u'Risk summary':
                self.extract_file_details('risk_summary', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Required permissions':
                self.extract_file_details('required_permission', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Permission-related API calls':
                self.extract_file_details('permission_related_api_calls', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Main Activity':
                self.extract_file_details('main_activitiy', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Activities':
                self.extract_file_details('activities', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Services':
                self.extract_file_details('services', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Activity-related intent filters':
                self.extract_file_details('activity_related_intent_filters', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Application certificate information':
                self.extract_file_details('application_certificate_information', file_detail_info.find_next('textarea'), 'textarea')
            elif file_detail_info.get_text().strip() == u'Interesting strings':
                self.extract_file_details('interesting_strings', file_detail_info.find_next('textarea'), 'textarea')
            elif file_detail_info.get_text().strip() == u'Application bundle files':
                self.extract_file_details('bundled_files', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Contained files':
                self.extract_file_details('contained_files', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Receivers':
                self.extract_file_details('receivers', file_detail_info.find_next('div'))
            elif file_detail_info.get_text().strip() == u'Providers':
                self.extract_file_details('providers', file_detail_info.find_next('div'))

    def extract_file_details(self, typology, soup, tag_type=''):
        file_detail_list = []
        if tag_type == '':
            details = soup.findAll('div', {'class':'enum'})
        elif tag_type == 'textarea':
            self.file_details[typology] = soup.get_text().strip()
            return

        for detail in details:
            file_detail_list.append(detail.get_text().strip())
        self.file_details[typology] = file_detail_list

    def get_behaviour(self):
        soup = BeautifulSoup(self.page_content, 'html.parser')
        behavioural_information = soup.findAll('div', {'id':'behavioural-info'})
        if len(behavioural_information) != 1:
            return False

        threat_actions = behavioural_information[0].findAll('h5')
        for threat_action in threat_actions:
            if threat_action.get_text().strip() == u'Opened files':
                self.extract_behavioural_traits('opened_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Read files':
                self.extract_behavioural_traits('read_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Created processes':
                self.extract_behavioural_traits('created_processes', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Terminated processes':
                self.extract_behavioural_traits('terminated_processes', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Opened mutexes':
                self.extract_behavioural_traits('opened_mutexes', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Runtime DLLs':
                self.extract_behavioural_traits('runtime_dlls', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Created mutexes':
                self.extract_behavioural_traits('created_mutexes', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Deleted files':
                self.extract_behavioural_traits('deleted_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Copied files':
                self.extract_behavioural_traits('copied_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Additional details':
                self.extract_behavioural_traits('additional_details', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Written files':
                self.extract_behavioural_traits('written_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Contacted URLs':
                self.extract_behavioural_traits('contacted_urls', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'TCP connections':
                self.extract_behavioural_traits('tcp_connections', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'DNS requests':
                self.extract_behavioural_traits('dns_requests', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'HTTP requests':
                self.extract_behavioural_traits('http_requests', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Interesting calls':
                self.extract_behavioural_traits('interesting_calls', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Started services':
                self.extract_behavioural_traits('started_services', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Accessed files':
                self.extract_behavioural_traits('accessed_files', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Started receivers':
                self.extract_behavioural_traits('started_receivers', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Accessed URIs':
                self.extract_behavioural_traits('accessed_uris', threat_action.find_next('div'))
            elif threat_action.get_text().strip() == u'Permissions checked':
                self.extract_behavioural_traits('permission_chcked', threat_action.find_next('div'))

    def extract_behavioural_traits(self, typology, soup):
        trait_list = []
        traits = soup.findAll('div', {'class':'enum'})
        for trait in traits:
            trait_list.append(trait.get_text().strip())
        self.threat_traits[typology] = trait_list

    def extract_submissions_date(self, date_to_convert, typology):
        pos = date_to_convert.find('UTC')
        if pos == -1:
            return False
        try:
            if typology == 'first_submission':
                #FIXME: TypeError: datetime.datetime(2015, 1, 18, 1, 42, 26) is not JSON serializable
                #self.first_submission_date = datetime.datetime.strptime(date_to_convert[:pos].strip(), '%Y-%m-%d %H:%M:%S')
                self.first_submission_date = date_to_convert[:pos].strip()
            else:
                #FIXME: TypeError: datetime.datetime(2015, 1, 18, 1, 42, 26) is not JSON serializable
                #self.last_submission_date = datetime.datetime.strptime(date_to_convert[:pos].strip(), '%Y-%m-%d %H:%M:%S')
                self.last_submission_date = date_to_convert[:pos].strip()
            return True
        except:
            print(traceback.print_exc())
            return False


    def extract_filenames(self, filenames):
        filenames = filenames.split('\n')
        for filename in filenames:
            if filename.strip() != '':
                # TODO: fix it. It is a quick hack around unicode filenames
                filename = filename.encode('utf8', 'ignore').strip()
                filename = re.sub(r'[^\x00-\x7f]',r'',filename)
                self.submitted_filenames.append(filename)

    def get_vt_metadata(self):
        soup = BeautifulSoup(self.page_content, 'html.parser')
        metadatas = soup.findAll('div', {'class':'enum'})
        if len(metadatas) == 0:
            return False
        for metadata in metadatas:
            if hasattr(metadata.span, 'get_text'):
                if metadata.span.get_text() == u'First submission':
                    splitted_data = metadata.get_text().split('\n')
                    if len(splitted_data) == 4:
                        self.extract_submissions_date(splitted_data[2].strip(), 'first_submission')
                elif metadata.span.get_text() == u'Last submission':
                    splitted_data = metadata.get_text().split('\n')
                    if len(splitted_data) == 4:
                        self.extract_submissions_date(splitted_data[2].strip(), 'last_submission')
            elif hasattr(metadata.table, 'get_text'):
                if metadata.table.get_text().find(u'File names') != -1:
                    filenames = soup.findAll('td', {'class':'field-value'})
                    if len(filenames) == 2:
                        self.extract_filenames(filenames[1].get_text())

class VTNetwork:

    host = "www.virustotal.com"

    def __init__(self):
        self.domain_page_content = ''
        self.ips_associated_to_domain = []
        self.domains_associated_to_ip = []
        self.detected_domains = []
        self.detected_ips = []
        self.AS = ''
        self.ASN = 0
        self.country = ''
        self.intelligence= {}
        pass

    def __del__(self):
        if cfg.DEBUG:
            print('cleanup VirusTotal Network...')
        self.intelligence = {}

    def get_domain_intelligence(self, domain):
        query = '/en/domain/%s/information/' % (domain)
        hhandle = httplib.HTTPSConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Host', 'www.virustotal.com')
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Cache-Control', 'max-age=0')
        hhandle.putheader('Referer', 'https://www.virustotal.com/')
        hhandle.putheader('Origin', 'https://www.virustotal.com')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if (response.status == 200):
            self.domain_page_content = response.read()
            self.extract_domain_intelligence()
            self.extract_intelligence()
            return True
        else:
            return False

    def extract_intelligence(self):
        self.intelligence['as'] = self.AS
        self.intelligence['asn'] = self.ASN
        self.intelligence['domains_associated_to_ip'] = self.domains_associated_to_ip
        self.intelligence['ips_associated_to_domain'] = self.ips_associated_to_domain
        self.intelligence['detected_domains'] = self.detected_domains
        self.intelligence['detected_ips'] = self.detected_ips

    def extract_domain_intelligence(self):
        soup = BeautifulSoup(self.domain_page_content, 'html.parser')
        self.extract_latest_detected_url('domain', soup)
        intelligence = soup.findAll('div', {'class':'enum'})
        if len(intelligence) == 0:
            return False

        for intel in intelligence:
            if len(intel) == 3:
                if len(intel.findAll('a')) == 1:
                    if intel.contents[0].strip() == '':
                        continue
                    #FIXME: TypeError: datetime.datetime(2015, 1, 18, 1, 42, 26) is not JSON serializable
                    #date_associated = datetime.datetime.strptime(intel.contents[0].strip(), '%Y-%m-%d')
                    date_associated = intel.contents[0].strip()
                    domain_associated = intel.contents[1].get_text()
                    self.ips_associated_to_domain.append((date_associated, domain_associated))

    def get_ip_intelligence(self, ip_address):
        query = '/en/ip-address/%s/information/' % (ip_address)
        hhandle = httplib.HTTPSConnection(self.host, timeout=cfg.timeout)
        hhandle.putrequest('GET', query)
        hhandle.putheader('Host', 'www.virustotal.com')
        hhandle.putheader('Connection', 'keep-alive')
        hhandle.putheader('Cache-Control', 'max-age=0')
        hhandle.putheader('Referer', 'https://www.virustotal.com/')
        hhandle.putheader('Origin', 'https://www.virustotal.com')
        hhandle.putheader('User-Agent', cfg.user_agent)
        hhandle.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        hhandle.endheaders()

        response = hhandle.getresponse()
        if (response.status == 200):
            self.domain_page_content = response.read()
            self.extract_ip_intelligence()
            self.extract_intelligence()
            return True
        else:
            return False

    def extract_ip_intelligence(self):
        soup = BeautifulSoup(self.domain_page_content, 'html.parser')
        self.extract_latest_detected_url('ip', soup)
        intelligence = soup.findAll('div', {'class':'enum'})
        if len(intelligence) == 0:
            return False

        for intel in intelligence:
            if hasattr(intel, 'div') and len(intel) == 7:
                if len(intel.findAll('a')) != 0:
                    continue
                if intel.div.get_text() == u'Country':
                    self.country = intel.contents[3].get_text().strip()
            if hasattr(intel, 'div') and len(intel) == 7:
                if len(intel.findAll('a')) != 0:
                    continue
                if intel.div.get_text() == u'Autonomous System':
                    self.AS = intel.contents[3].get_text().strip()
                    pos = intel.contents[3].get_text().find('(')
                    if pos != -1:
                        self.ASN = int(intel.contents[3].get_text()[:pos].strip())
            if len(intel) == 3:
                if len(intel.findAll('a')) == 1:
                    #FIXME: TypeError: datetime.datetime(2015, 1, 18, 1, 42, 26) is not JSON serializable
                    #date_associated = datetime.datetime.strptime(intel.contents[0].strip(), '%Y-%m-%d')
                    date_associated = intel.contents[0].strip()
                    domain_associated = intel.contents[1].get_text()
                    self.domains_associated_to_ip.append((date_associated, domain_associated))

    def extract_latest_detected_url(self, typology, soup):
        detected_domains_information = soup.findAll('div', {'id':'detected-urls'})
        detected_list = []
        if len(detected_domains_information) != 1:
            return False

        detected_domains = detected_domains_information[0].findAll('div')
        for detected_domain in detected_domains:
            if len(detected_domain) == 7:
                detection_rate = detected_domain.contents[1].get_text().strip()
                detection_time = detected_domain.contents[3].get_text().strip()
                detection_url = detected_domain.a.get_text().strip()
                if typology == 'domain':
                    self.detected_domains.append((detection_rate, detection_time, detection_url))
                elif typology == 'ip':
                    self.detected_ips.append((detection_rate, detection_time, detection_url))


def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print('Running VT() on %s' % intelligence)
    if extraction_type == cfg.intelligence_type['sha256']:
        intel_collector = VT()
        if intel_collector.get_detections_by_sha256(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['md5']:
        intel_collector = VT()
        if intel_collector.get_detections_by_md5(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['ip']:
        intel_collector = VTNetwork()
        if intel_collector.get_ip_intelligence(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    elif extraction_type == cfg.intelligence_type['domain']:
        intel_collector = VTNetwork()
        if intel_collector.get_domain_intelligence(intelligence) == True:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel
    else:
        return {}

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'VT':
        visual_report = VTVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

class VTVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#ff8000'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        vt_filenames = ''
        domains = []
        ips_associated_to_domain = []
        detected_ips = []
        domains_associated_to_ip = []
        http_requests = []
        tcp_connections = []
        mutexes = []
        av_results = {}

        if self.json_data['intelligence'] is None:
            return False

        if 'filenames' in self.json_data['intelligence']['intelligence_information']:
            vt_filenames = self.json_data['intelligence']['intelligence_information']['filenames']

        if 'detected_domains' in self.json_data['intelligence']['intelligence_information']:
            for detected_domains in self.json_data['intelligence']['intelligence_information']['detected_domains']:
                domains.append(detected_domains[2])

        if 'ips_associated_to_domain' in self.json_data['intelligence']['intelligence_information']:
            for related_ips in self.json_data['intelligence']['intelligence_information']['ips_associated_to_domain']:
                ips_associated_to_domain.append(related_ips[1])

        if 'domains_associated_to_ip' in self.json_data['intelligence']['intelligence_information']:
            for domain_associated_to_ip in self.json_data['intelligence']['intelligence_information']['domains_associated_to_ip']:
                domains_associated_to_ip.append(domain_associated_to_ip[1])

        if 'detected_ips' in self.json_data['intelligence']['intelligence_information']:
            for detected_ip in self.json_data['intelligence']['intelligence_information']['detected_ips']:
                detected_ips.append(detected_ip[2])

        if 'threat_behaviour' in self.json_data['intelligence']['intelligence_information']:
            mutexes, http_requests, tcp_connections = self.parse_threat_behavior()

        if 'av_results' in self.json_data['intelligence']['intelligence_information']:
            av_results = self.json_data['intelligence']['intelligence_information']['av_results']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'VT': [{'domains': domains},
                                {'ip_addresses': ips_associated_to_domain},
                                {'detected_ips': detected_ips},
                                {'http_requests': http_requests},
                                {'tcp_connections': tcp_connections},
                                {'mutexes': mutexes},
                                {'av_results': av_results},
                                {'filenames': vt_filenames}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'VT': [{'domains': domains},
                                {'ip_addresses': ips_associated_to_domain},
                                {'detected_ips': detected_ips},
                                {'http_requests': http_requests},
                                {'tcp_connections': tcp_connections},
                                {'mutexes': mutexes},
                                {'av_results': av_results},
                                {'filenames': vt_filenames}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_threat_behavior(self):
        http_requests = []
        tcp_connections = []
        mutexes = []

        if 'http_requests' in self.json_data['intelligence']['intelligence_information']['threat_behaviour']:
            for request in self.json_data['intelligence']['intelligence_information']['threat_behaviour']['http_requests']:
                request_pos = request.find(' ')
                if request_pos == -1:
                    continue
                request_pos_end = request.find('\n', request_pos)
                if request_pos_end == -1:
                    continue
                http_requests.append(request[request_pos+1:request_pos_end])

        if 'tcp_connections' in self.json_data['intelligence']['intelligence_information']['threat_behaviour']:
            for tcp_connection in self.json_data['intelligence']['intelligence_information']['threat_behaviour']['tcp_connections']:
                pos = tcp_connection.find(':')
                if pos == -1:
                    continue
                tcp_connections.append(tcp_connection[:pos])

        if 'created_mutexes' in self.json_data['intelligence']['intelligence_information']['threat_behaviour']:
            for mutex in self.json_data['intelligence']['intelligence_information']['threat_behaviour']['created_mutexes']:
                pos = mutex.find(' ')
                if pos == -1:
                    mutexes.append(mutex)
                else:
                    mutexes.append(mutex[:pos])

        return mutexes, http_requests, tcp_connections


    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['VT']:
            for key, value in intel.items():
                if key == 'domains':
                    self._manage_vt_domains(value)
                elif key == 'ip_addresses':
                    self._manage_vt_ip_addresses(value)
                elif key == 'detected_ips':
                    self._manage_vt_detected_domains(value)
                elif key == 'filenames':
                    self._manage_vt_filenames(value)
                elif key == 'http_requests':
                    self._manage_vt_http_requests(value)
                elif key == 'tcp_connections':
                    self._manage_vt_tcp_connections(value)
                elif key == 'mutexes':
                    self._manage_vt_mutexes(value)
                elif key == 'av_results':
                    self._manage_av_results(value)

    def _manage_vt_domains(self, domains):
        size = 30
        for domain in domains:
            # FIXME: quick fix for issues related to the visualization module (eg.: when running on shortly.im)
            domain = domain.replace('"', '')
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_vt_ip_addresses(self, ips):
        size = 30
        for ip in ips:
            # FIXME: quick fix for issues related to the visualization module (eg.: when running on 195.22.26.248)
            ip = ip.replace('"', '')
            if ip in self.nodes.keys():
                self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], self.nodes[ip][2])
            else:
                self.nodes[ip] = (size, self.color, 'ip')

            if ip not in self.edges[self.origin]:
                self.edges[self.origin].append(ip)

    def _manage_vt_detected_domains(self, domains):
        size = 30
        for domain in domains:
            # FIXME: quick fix for issues related to the visualization module (eg.: when running on 195.22.26.248)
            domain = domain.replace('"', '')
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'detected_domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_vt_filenames(self, filenames):
        size = 30
        for fn in filenames:
            # FIXME: quick fix for issues related to the visualization module
            fn = fn.replace('"', '')
            if fn in self.nodes.keys():
                self.nodes[fn] = (self.nodes[fn][0] + 5, self.nodes[fn][1], self.nodes[fn][2])
            else:
                self.nodes[fn] = (size, self.color, 'filename')

            if fn not in self.edges[self.origin]:
                self.edges[self.origin].append(fn)

    def _manage_vt_http_requests(self, http_reqs):
        size = 30
        for http_request in http_reqs:
            # FIXME: quick fix for issues related to the visualization module
            http_request = http_request.replace('"', '')
            if http_request in self.nodes.keys():
                self.nodes[http_request] = (self.nodes[http_request][0] + 5, self.nodes[http_request][1], self.nodes[http_request][2])
            else:
                self.nodes[http_request] = (size, self.color, 'http_request')

            if http_request not in self.edges[self.origin]:
                self.edges[self.origin].append(http_request)

    def _manage_vt_tcp_connections(self, tcps):
        size = 30
        for tcp in tcps:
            # FIXME: quick fix for issues related to the visualization module
            tcp = tcp.replace('"', '')
            if tcp in self.nodes.keys():
                self.nodes[tcp] = (self.nodes[tcp][0] + 5, self.nodes[tcp][1], self.nodes[tcp][2])
            else:
                self.nodes[tcp] = (size, self.color, 'tcp connection')

            if tcp not in self.edges[self.origin]:
                self.edges[self.origin].append(tcp)

    def _manage_vt_mutexes(self, mutexes):
        size = 30
        for mutex in mutexes:
            # FIXME: quick fix for issues related to the visualization module
            mutex = mutex.replace('"', '')
            if mutex in self.nodes.keys():
                self.nodes[mutex] = (self.nodes[mutex][0] + 5, self.nodes[mutex][1], self.nodes[mutex][2])
            else:
                self.nodes[mutex] = (size, self.color, 'mutex')

            if mutex not in self.edges[self.origin]:
                self.edges[self.origin].append(mutex)

    def _manage_av_results(self, av_reults):
        size = 30
        detection = ''
        for av_name, av_values in av_reults.items():
            if av_name == 'Symantec' and av_values[0] != 'Not detected':
                detection = av_values[0]
                break
            elif av_name == 'Microsoft' and av_values[0] != 'Not detected':
                detection = av_values[0]
                break

            if av_values[0] != 'Not detected':
                detection = av_values[0]

        if detection == '':
            return

        if detection not in self.nodes.keys():
            self.nodes[detection] = (size, self.color, 'detection')

        if detection not in self.edges[self.origin]:
            self.edges[self.origin].append(detection)
