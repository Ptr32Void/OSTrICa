#-------------------------------------------------------------------------------
# Name:        	OSTrICa - Open Source Threat Intelligence Collector 
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
import json
import sys
import uuid
import os

from ostrica.utilities.Ostrica import OSTrICa
from ostrica.utilities.cfg import Config as cfg
from ostrica.utilities.OstriViz import OstriViz


class OstricaConsole:

    def __init__(self):
        self.ostrica = OSTrICa()
        self.visualization = OstriViz()
        self.domains = []
        self.ips = []
        self.asn = []
        self.sha256 = []
        self.md5 = []
        self.email = []

        self.nodes = {}
        self.edges = {}
        self.rnd_fn = None
        self.rnd_report_fn = None
        self.original_intel = []

    def generate_ostrica_graph(self, graph_typology=''):
        if self.rnd_fn is None:
            self.rnd_fn = '%s.html' % (str(uuid.uuid4()))

        self.visualization.generate_graph(self.rnd_fn, self.nodes, self.edges, self.original_intel, graph_typology)

    def help(self):
        print 'Following options are available\n'
        print '\tdomain - used to collect domains information'
        print '\tExample: domain=google.com or domain=google.com,yahoo.com'
        print '\tip - used to collect IP information'
        print '\tExample: ip=8.8.8.8 or ip=8.8.8.8,173.194.68.99'
        print '\tmd5 - used to collect MD5 information'
        print '\tsha256 - used to collect SHA256 information'
        print '\tasn - used to collect ASN information'
        print '\temail - used to collect email information'
        print '\tgraph - generate a graph based on all the information collected'
        print '\tcola_graph - generate a graph based on all the information collected where nodes do not overlap (it might take a while to generate the graph if there are lots of nodes)'
        print '\tgclean - clear graph information'
        print '\tshow - show all information that will be collected'
        print '\trun - extract intelligece information'
        print '\thelp - this help'
        print '\tplugins - show available plugins'

    def clean_ostrica_graph(self):
        self.edges = {}
        self.edges = {}
        self.rnd_fn = None
        self.rnd_report_fn = None

    def run_ostrica(self):
        if self.rnd_report_fn == None:
            self.rnd_report_fn = str(uuid.uuid4())
	#add sanity check to ensure 'report' directory is there
	checkdir=os.path.join(os.getcwd(),'report')
	if not os.path.exists(checkdir):
		os.makedirs(checkdir)
        filename = os.path.join(os.getcwd(), 'report', self.rnd_report_fn)
        fh = open(filename, 'a')
        self.ostrica.intelligence_gathering()
        for intel in self.ostrica.intelligence:
            self.nodes, self.edges = self.ostrica.plugin_data_visualization(self.nodes, self.edges, intel)
            fh.write( json.dumps(intel, sort_keys=True, indent=4, separators=(',', ': ')) )

        print 'Output created in %s' % (filename)
        fh.close()

    def plugins_info(self):
        self.ostrica.plugins_info()

    def clear_ostrica_queue(self):
        self.ostrica.clear_intelligence_queue()

    def show_ostrica_queue_elements(self):
        for ostrica_queue in self.ostrica.extract_intelligence_queue_items():
            print ostrica_queue

    def domain_intelligence(self, domains):
        for domain in domains:
            self.original_intel.append(domain)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['domain'], 'intelligence_information': domain})

    def ip_intelligence(self, ips):
        for ip in ips:
            self.original_intel.append(ip)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['ip'], 'intelligence_information': ip})

    def asn_intelligence(self, asns):
        for asn in asns:
            self.original_intel.append(asn)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['asn'], 'intelligence_information': asn})

    def email_intelligence(self, emails):
        for email in emails:
            self.original_intel.append(email)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['email'], 'intelligence_information': email})

    def md5_intelligence(self, md5s):
        for md5 in md5s:
            self.original_intel.append(md5)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['md5'], 'intelligence_information': md5})

    def sha256_intelligence(self, sha256s):
        for sha256 in sha256s:
            self.original_intel.append(sha256)
            self.ostrica.update_intelligence_queue({'extraction_type': cfg.intelligence_type['sha256'], 'intelligence_information': sha256})

    def parse_intelligence_type(self, intelligence_type, intelligence_data):
        if intelligence_type.strip() == 'run':
            self.run_ostrica()
            self.clear_ostrica_queue()
        elif (intelligence_type.strip() == 'quit' or
              intelligence_type.strip() == 'exit' or
              intelligence_type.strip() == 'q'):
            sys.exit(0)
        elif intelligence_type.strip() == 'clear':
            self.clear_ostrica_queue()
        elif intelligence_type.strip() == 'show':
            self.show_ostrica_queue_elements()
        elif intelligence_type.strip() == 'graph':
            self.generate_ostrica_graph()
        elif intelligence_type.strip() == 'cola_graph':
            self.generate_ostrica_graph('cola')
        elif intelligence_type.strip() == 'gclean':
            self.clean_ostrica_graph()
        elif intelligence_type.strip() == 'domain':
            self.domain_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'ip':
            self.ip_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'asn':
            self.asn_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'md5':
            self.md5_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'sha256':
            self.sha256_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'email':
            self.email_intelligence(intelligence_data)
        elif intelligence_type.strip() == 'help':
            self.help()
        elif intelligence_type.strip() == 'plugins':
            self.plugins_info()
        else:
            print 'Unknown command.'

    def console(self):
        while 1:
            data_input = raw_input("> ")
            intelligence = data_input.split('=')
            if len(intelligence) == 2:
                intelligence_type = intelligence[0].strip()
                intelligence_data = intelligence[1].split(',')
                self.parse_intelligence_type(intelligence_type, intelligence_data)
            else:
                intelligence_type = intelligence[0].strip()
                self.parse_intelligence_type(intelligence_type, '')

def main():
    print '%s v.%s - %s' % (cfg.tool_name, cfg.version, cfg.tool_description)
    print 'Developed by: %s <%s>' % (cfg.developer, cfg.developer_email)
    print 'write "help" for help'

    ostrica_console = OstricaConsole()
    ostrica_console.console()


if __name__ == '__main__':
    main()

