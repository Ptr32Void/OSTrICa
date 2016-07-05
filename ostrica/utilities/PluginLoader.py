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
import traceback
import inspect
import imp
import os

plugin_folder = os.path.join("..", "Plugins")
main_module = "__init__"

class PluginLoader(object):

    def __init__(self):
        self.DEBUG = False
        self.plugins = []
        tool_path = os.path.dirname(__file__)
        plugins_directory = os.path.join(tool_path, plugin_folder)
        for plugin_name in os.listdir(plugins_directory):
            plugin_location = os.path.join(plugins_directory, plugin_name)
            if not os.path.isdir(plugin_location):
                continue
            self.load_plugin(plugin_location, plugin_name)

    def load_plugin(self, plugin_location, plugin_name):
        try:
            f, filename, description = imp.find_module(main_module, [plugin_location])
            if self.DEBUG:
                print 'Plugin location: %s (%s)' % (plugin_location, plugin_name)
            self.load_module(plugin_name, f, filename, description)
        except ImportError, e:
            print e

    def load_module(self, plugin_name, f, filename, description):
        loaded_plugin_info = imp.load_module(plugin_name, f, filename, description)
        if loaded_plugin_info.enabled:
            try:
                if self.DEBUG:
                    print 'Loading %s' % (plugin_name)
                self.plugins.append({'name': plugin_name, 'extraction_type':loaded_plugin_info.extraction_type, 'plugin':loaded_plugin_info})
            except AttributeError, e:
                if self.DEBUG:
                    print 'No extraction_types for plugin %s' % (plugin_name)
                print traceback.print_exc()
                self.plugins.append({'name': plugin_name, 'extraction_type':'', 'plugin':loaded_plugin_info})
        else:
            if self.DEBUG:
                print 'Plugin %s disabled' % (plugin_name)