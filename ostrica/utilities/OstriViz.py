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
import os
import uuid

class OstriViz:

    def __init__(self, ):
        self.nodes = {}
        self.edges = {}
        self.nodes_html = ''
        self.original_intel = []

        self.script_path = os.getcwd()

    def generate_graph(self, rnd_fn, ext_nodes, ext_edges, ext_original_intel, graph_typology=''):

        self.nodes_html = '<table style="width:100%" cellpadding="0" cellspacing="0"><tbody><tr><td><img style="border: none" \
                           src="resource/reg_mod.gif"></td><td class="h3" width="100%">Original Intelligence Indicator(s)</td></tr></tbody></table>'
        self.nodes_html += '<br/>'

        self._load_nodes(ext_nodes, ext_edges, ext_original_intel)
        if len(self.original_intel) == 0:
            self.nodes_html += '<ul><li><font color="#990000"><b>Original Indicators is Empty!</b></font></li></ul><br/>'
        else:
            self.nodes_html += '<ul>'
            for original_node_name in self.original_intel:
                self.nodes_html += '<li>%s</li>' % (original_node_name)

            self.nodes_html += '</ul><br/>'

        if len(self.nodes) == 0:
            self.nodes_html += '<ul><li><font color="#990000"><b>No intelligence found!</b></font></li></ul><br/>'
        else:
            self.nodes_html += '<table style="width:100%" cellpadding="0" cellspacing="0"><tbody><tr><td><img style="border: none" \
                           src="resource/threat.gif"></td><td class="h3" width="100%">Related Indicator(s)</td></tr></tbody></table>'
            self.nodes_html += '<br/>'
            self.nodes_html += '<ul>'
            for node_name, value in self.nodes.iteritems():
                if node_name is None:
                    continue
                if len(node_name) != 0:
                    self.nodes_html += '<li><a onclick="selectNodeByInfoClick(\'%s\')" style="cursor:pointer;"> \
                                        %s</a> (<font color="#00BFFF">%s</font>)</li>' % (node_name, node_name, value[2])

            self.nodes_html += '</ul><br/>'

        #add sanity check to ensure 'report' directory is there
	checkdir=os.path.join(os.getcwd(),'viz')
	if not os.path.exists(checkdir):
		os.makedirs(checkdir)
        filename = os.path.join(self.script_path, 'viz', rnd_fn)
        fh = open(filename, 'w')
        fh.write(self.generate_html_header())
        fh.write(self.generate_html_nodes())
        fh.write(self.generate_html_mid_page(graph_typology))
        fh.write(self.nodes_html)
        fh.write(self.generate_html_footer())
        fh.close()
        print 'Graph generated in %s' % (filename)

    def _load_nodes(self, ext_nodes, ext_edges, ext_original_intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.original_intel = ext_original_intel

    def generate_html_header(self):
        #added this to fix the path issues
	dirname=os.path.dirname
	dirname=os.path.dirname(dirname(__file__))
	#fname = os.path.join(self.script_path, 'ostrica', 'utilities', 'header.cfg')
	fname=os.path.join(dirname,'utilities','header.cfg')
        fh = open(fname, 'r')
        buff_header = fh.read()
        fh.close()
        return buff_header

    def generate_html_mid_page(self, graph_typology=''):
        dirname=os.path.dirname
	dirname=os.path.dirname(dirname(__file__))
	fname=os.path.join(dirname,'utilities','mid_page.cfg')
	#fname = os.path.join(self.script_path, 'ostrica', 'utilities', 'mid_page.cfg')
        fh = open(fname, 'r')
        buff_header = fh.read()
        fh.close()
        if graph_typology == 'cola':
            replacement = 'name: \'cola\',\n \
                           nodeSpacing: 5,\n \
                           edgeLengthVal: 45,\n \
                           randomize: false,\n \
                           maxSimulationTime: 1500,\n'
            return buff_header.replace('OSTRICA_VARS_IN_OSTRIVIZ', replacement)
        else:
            replacement = 'name: \'cose\',\n'
            return buff_header.replace('OSTRICA_VARS_IN_OSTRIVIZ', replacement)

    def generate_html_footer(self):
        dirname=os.path.dirname
	dirname=os.path.dirname(dirname(__file__))
	fname=os.path.join(dirname,'utilities','footer.cfg')
	#fname = os.path.join(self.script_path, 'ostrica', 'utilities', 'footer.cfg')
        fh = open(fname, 'r')
        buff_footer = fh.read()
        fh.close()
        return buff_footer

    def generate_html_nodes(self):
        check_targets = []
        buff = 'nodes: ['
        idx_action = 0

        for original_node_name in self.original_intel:
            buff += '{data: {id: "%s", name: "%s", size: %d, color: "%s", label: "original"}},\n' \
                     % (original_node_name, original_node_name, 60, '#666699')

        for node_name, value in self.nodes.iteritems():
            idx_action += 1
            if node_name in self.original_intel:
                continue
            buff += '{data: {id: "%s", name: "%s", size: %d, color: "%s", label: "%s"}},\n' \
                     % (node_name, node_name, value[0], value[1], value[2])

        buff = buff[:-1]

        buff += '], edges: ['

        for key, value in self.edges.iteritems():
            for target in value:
                if (key, target) not in check_targets:
                    buff += '{data: {source: "%s", target: "%s", label: "%s"}, classes: "autorotate"},\n' % (key, target, self.nodes[target][2])
                check_targets.append((key, target))
        buff = buff[:-1]

        buff += '] },'

        return buff
