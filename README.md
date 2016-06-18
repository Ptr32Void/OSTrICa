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

