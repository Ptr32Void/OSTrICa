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
import traceback
import threading
import PluginLoader
import Queue

from cfg import Config as cfg

class OSTrICa:

    def __init__(self, input_data=''):
        self.DEBUG = False
        self.intelligence = []
        self.intellingece_q = Queue.Queue()
        self.loader = PluginLoader.PluginLoader()
        if input_data != '':
            self.intellingece_q.put(input_data)

    def update_intelligence_queue(self, input_data):
        self.intellingece_q.put(input_data)

    def clear_intelligence_queue(self):
        self.intelligence = []
        while True:
            try:
                self.intellingece_q.get(block=False)
            except Queue.Empty:
                if self.DEBUG:
                    print 'clear_intelligence_queue() Queue Empty.'
                break
            except Exception, e:
                if self.DEBUG:
                    print 'clear_intelligence_queue() exception triggered %s' % (str(e))
                print traceback.print_exc()

    def extract_intelligence_queue_items(self):
        items = []
        i = 0
        while i < len(self.intellingece_q.queue):
            items.append(self.intellingece_q.queue[i])
            i += 1
        return items

    def parsing_intelligence_queue(self):
        raw_data_for_intel = self.intellingece_q.get(block=False)
        if raw_data_for_intel['extraction_type'] in cfg.intelligence_type.values():
            if self.DEBUG:
                print 'Working on %s' % (raw_data_for_intel['intelligence_information'])
            self.loading_plugins(raw_data_for_intel)
        else:
            if self.DEBUG:
                print 'Plugin for %s not implemented' % (raw_data_for_intel['extraction_type'])

    def intelligence_gathering(self):
        while True:
            try:
                self.parsing_intelligence_queue()
            except Queue.Empty:
                if self.DEBUG:
                    print 'intelligence_gathering() Queue Empty'
                break
            except Exception, e:
                if self.DEBUG:
                    print 'intelligence_gathering() exception triggered %s' % (str(e))
                print traceback.print_exc()

    def loading_plugins(self, raw_data_for_intel):
        for plugin in self.loader.plugins:
            self.call_plugin_method(plugin, raw_data_for_intel['extraction_type'], raw_data_for_intel['intelligence_information'])

    def call_plugin_method(self, plugin, intelligence_type, intelligence_information):
        for extraction_type in plugin['extraction_type']:
            if extraction_type == intelligence_type:
                if self.DEBUG:
                    print 'Requested intelligence method %s is valid for %s!' % (intelligence_type, plugin['name'])
                try:
                    self.save_intelligence(intelligence_information, intelligence_type, plugin['name'], plugin['plugin'].run(intelligence_information, extraction_type))
                except Exception, e:
                    if self.DEBUG:
                        print 'call_plugin_method() exception %s (%s)!' % (str(e), plugin['name'])
                        print traceback.print_exc()

    def fill_intelligence_queue(self, requested_intel, requested_intel_type, plugin_name, extracted_intelligence):
        if extracted_intelligence is not None:
            self.save_intelligence(requested_intel, requested_intel_type, plugin_name, extracted_intelligence)
            for key, intel in extracted_intelligence['intelligence_information'].iteritems():
                self.intellingece_q.put({'extraction_type': key, 'intelligence_information':intel})

    def save_intelligence(self, requested_intel, requested_intel_type, plugin_name, extracted_intelligence):
        self.intelligence.append({'requested_intel': requested_intel, 'requested_intel_type': requested_intel_type, 'plugin_name': plugin_name, 'intelligence':extracted_intelligence})

    def plugin_data_visualization(self, nodes, edges, json_data):
        for plugin in self.loader.plugins:
            try:
                nodes, edges = plugin['plugin'].data_visualization(nodes, edges, json_data)
            except Exception, e:
                if self.DEBUG:
                    print 'plugin_data_visualization() exception %s (%s)!' % (str(e), plugin['name'])
                    print traceback.print_exc()
        return nodes, edges

    def plugins_info(self):
        for plugin in self.loader.plugins:
            try:
                if plugin['plugin'].enabled:
                    print 'Plugin %s (v%s) [ENABLED]' % (plugin['name'], plugin['plugin'].version)
                else:
                    print 'Plugin %s (v%s) [DISABLED]' % (plugin['plugin'], plugin['plugin'].version)

                print 'Developed by %s' % (plugin['plugin'].developer)
                print 'Description: %s' % (plugin['plugin'].description)
                if plugin['plugin'].visual_data:
                    print 'Visual data ENABLED'
                else:
                    print 'Visual data DISABLED'
                print 'Available extraction types:'
                for ext_type in plugin['plugin'].extraction_type:
                    print '\t %s' % ext_type
                print '\n\n'
            except Exception, e:
                if self.DEBUG:
                    print 'plugins_info() exception %s (%s)!' % (str(e), plugin['plugin'])
                    print traceback.print_exc()