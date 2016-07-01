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

class Config(object):
    timeout = 60
    DEBUG = True
    tool_name = "OSTrICa"
    tool_description = "Open Source Threat Intellicence Collector"
    version = '0.5'
    developer = 'Roberto Sponchioni - @Ptr32Void'
    developer_email = 'rsponchioni@yahoo.it'
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'

    intelligence_type = {}
    intelligence_type['email'] = 'email_information'
    intelligence_type['domain'] = 'domain_information'
    intelligence_type['asn'] = 'asn_number'
    intelligence_type['md5'] = 'md5'
    intelligence_type['sha256'] = 'sha256'
    intelligence_type['ip'] = 'ip_information'

    deep_viz_api = 'YOUR_KEY_HERE'