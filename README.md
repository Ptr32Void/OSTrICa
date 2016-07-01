OSTrICa - Open Source Threat Intelligence Collector (An Open Source plugin-oriented framework to collect and visualize Threat Intelligence Information)
========
![OSTrICa Graph]( https://github.com/Ptr32Void/OSTrICa/blob/master/docs/OSTrICaLogo.png "OSTrICa Graph" )

**OSTrICa** stands for Open Source Threat Intelligence Collector and is an Open Source **plugin-oriented framework** to **collect and visualize** Threat Intelligence Information. Furthermore, OSTrICa is also the Italian word for oyster: that's where the logo come from.

SOC analysts, incident responders, attack investigators or cyber-security analysts need to correlate IoCs (Indicator of Compromise), network traffic patterns and any other collected data in order to get a real advantage against cyber-enemies. 
This is where **threat intelligence** comes into play, but unfortunately, not all the companies have enough budget to spend on Threat Intelligence Platform and Programs (TIPP); this is the main motivation behind OSTrICa's development. 

OSTrICa is a free and open source framework that allows everyone to automatically collect and visualize any sort of threat intelligence data harvested (IoCs), from open, internal and commercial sources using a **plugin based architecture**. The collected intelligence can be analysed by analysts but it can also be **visualized** in a graph format, **suitable for link analysis**. The visualized information can be filtered dynamically and can show, for example, connections between multiple malware based on remote connections, file names, mutex and so on so forth.


## Licence
OSTrICa is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

OSTrICa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with OSTrICa. If not, see <http://www.gnu.org/licenses/>.


## Documentation
Documentation can be found in the docs directory. For example:
* OSTrICa presentation (BSidesUK, London)
* OSTrICa whitepaper that describes its purpose and how it works


## Dependencies
OSTrICa by itself does not need any external library.
Dependencies depends on the installed Plugins. For example:
* `BeautifulSoup`, used by almost all the plugins to scrape web pages
* `dnspython-1.12.0`, mainly used by CymruWhois plugin
* `ipwhois-0.11.1`, used by PyWhois plugin
* `python-deepviz-master`, used by DeepViz plugin (it requires an API key)
* `python-whois-0.5.2`, used by PyWhois plugin
* `pythonwhois-2.4.3`, used by PyWhois plugin


## How to use OSTrICa
In order to use OSTrICa you need to execute the file `main.py`; and to get a list of available commands you need to run the command `help`.

```
> python main.py
OSTrICa v.0.5 - Open Source Threat Intellicence Collector
Developed by: Roberto Sponchioni - @Ptr32Void <rsponchioni@yahoo.it>
write "help" for help
> help
Following options are available

        domain - used to collect domains information
        Example: domain=google.com or domain=google.com,yahoo.com
        ip - used to collect IP information
        Example: ip=8.8.8.8 or ip=8.8.8.8,173.194.68.99
        md5 - used to collect MD5 information
        sha256 - used to collect SHA256 information
        asn - used to collect ASN information
        email - used to collect email information
        graph - generate a graph based on all the information collected
        cola_graph - generate a graph based on all the information collected where nodes do not overlap (it might take a while to generate the graph if there are lots of nodes)
        gclean - clear graph information
        show - show all information that will be collected
        run - extract intelligece information
        help - this help
        plugins - show available plugins
```

To collect the information about specific IoCs you can execute the following commands:
```
>md5=747b3fd525de1af0a56985aa29779b86,2fdeb22d2fa29878dca12fb493df24df
>domain=tinyor.info
>ip=195.22.26.248
>email=jgou.veia@gmail.com
>asn=16276
>run
Output created in C:\Users\Roberto\Documents\GitHub\OSTrICa_development\report\a0b983ae-e30a-46dc-a1d0-b59e661595c0
> graph
Graph generated in C:\Users\Roberto\Documents\GitHub\OSTrICa_development\viz\f4da8f02-ec9c-4700-9345-bd715de7789f.html
```

In case a verbose output is needed, it is possible to enable the `DEBUG` option in the `cfg.py`. 
The output will be a little bit noisy but it will show more details as per example below:
```
> run
Running DeepViz() on 747b3fd525de1af0a56985aa29779b86
Running VT() on 747b3fd525de1af0a56985aa29779b86
cleanup VirusTotal...
Running DeepViz() on 2fdeb22d2fa29878dca12fb493df24df
Running VT() on 2fdeb22d2fa29878dca12fb493df24df
cleanup VirusTotal...
Running BlackListChecker() on tinyor.info
cleanup BlackListChecker...
Running DomainBigData() on tinyor.info
cleanup DomainBigData...
```

To generate the graph 2 commands are available:
* `graph`, it generates the graph based on all the collected information
* `cola_graph`, it generates the graph based on all the collected information without nodes overlapping

![OSTrICa Graph]( https://github.com/Ptr32Void/OSTrICa/blob/master/docs/OstricaGraph.png "OSTrICa Graph" )

## Currently available plugins
The following list contains the currently available plugins:
* `BlackLists` - Developer `Ptr32Void`
* `CymruWhois` - Developer `Ptr32Void`
* `DeepViz` - Developer `Ptr32Void`
* `DomainBigData` - Developer `Ptr32Void`
* `NortonSafeWeb` - Developer `Ptr32Void`
* `PyWhois` - Developer `Ptr32Void`
* `SafeBrowsing` - Developer `Ptr32Void`7
* `SpyOnWeb` - Developer `Ptr32Void`
* `TCPIPutils` - Developer `Ptr32Void`
* `VirusTotal` - Developer `Ptr32Void`
* `WebSiteInformer` - Developer `Ptr32Void`
* `WhoisXmlApi` - Developer `Ptr32Void`

## How to develop new Plugins
Plugins are stored in the directory named `Plugins`. 
To create a new Plugin you need to create a new subdirectory under `Plugins` and within that new directory a new `__init__.py` should be added.

OSTrICa will call 2 functions within each plugins `run` and `data_visualization`, defined as follow:
```python
# intelligence is the IoC provided (eg.: something@yahoo.com)
# extraction_type is the typology (eg.: an MD5 or email, etc)
def run(intelligence, extraction_type):
# function run is the core part of the plugin. It is used to collect the information and afterwards it returns back JSON data as per below:
    .... code used to collect Intelligence ....
	# a dictionary where extraction_type is the type (md5, email, etc) and intelligence_dictionary is the JSON data collected by the plugin
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

	

# nodes are passed by OSTrICa itself and should never be overwritten but updated because they might contain details related to the previously collected information
# edges are passed by OSTrICa itself and should never be overwritten but updated because they might contain details related to the previously collected information
# json_data is the json output collected by the plugin
def data_visualization(nodes, edges, json_data):
```

It is also mandatory to return `nodes` and `edges` from `data_visualization` as they are used by OSTrICa. If there is no data to be visualized it is possible to return the nodes/edges with following code:
```python
def data_visualization(nodes, edges, json_data):
    return nodes, edges
```

You should also add the following import and variables at the top of the file.
```python
from ostrica.utilities.cfg import Config as cfg # used to include configuration data

# used to identify what kind of data the plugin can extract:
# ip = IP Address information
# domain = Domain information
# asn = ASN information
# md5 = MD5 information
# sha256 = SHA256 information
# email = Email information
extraction_type = [cfg.intelligence_type['ip'], cfg.intelligence_type['domain'], cfg.intelligence_type['asn']]
# True if plugin is enabled, False if not
enabled = True
# Plugin Version
version = 0.1
# Developer(s) name and contact
developer = 'Your Name <Your Email>'
# Plugin Description
description = 'Plugin used to collect information about IPs, domains or ASNs on SafeBrowsing'
# True if visualization module is available for the plugin, False otherwise
visual_data = True
```
