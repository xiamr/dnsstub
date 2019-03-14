## DNSSTUB

### A tiny dns cache server implementation for avoiding dns contamination
### 一个抵抗域名污染的小型实现

##### Requirements:
- language : C++14
- third-party libraries : boost 1.67 or above, pugixml (optional), JSON for Modern C++ (include by this package)

##### Supported Platforms:
- current only Linux OS is supported because Linux-specific APIs (such as epoll) are used

##### Supported Features:

- great firewall mode :<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;contruct special packet which do not analyzed by gfw, but can be recoganized by remote server<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(this mode only supported by google dns server as far as I know)

- multiple addresses and ports for listening

- multiple upstream dns server suppport (current support only two upstream server)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;this feature use to realize what ChinaDNS does, only domains in gfwlist are parsed by oversea servers

- ipv6 mode : force return ipv6 address when available <br>


---

##### command line options
```bash
   -d  debug information out
   -c [--config] config_file
```

---

#### config file format
- json config file example:
```json
{
  "locals": [
     { "address": "::", "port": 53},
     { "address": "127.0.0.1","port": 66 }
  ],
  "pollution": "gfwlist",
  "statisticsFile": "statistics.log",
  "su" : "nobody",
  "enableCache": true,
  "enableTcp": true,
  "ipv6First": 1,
  "gfwMode": true,
  "daemonMode": false,
  "severity": "info",
  "remote_server": {
    "address": "8.8.8.8",
    "port": 53
  },
  "localnet_server": {
    "address": "202.122.33.70",
    "port": 53
  },
  "mappings": [
    { "domain" : "scholar.google.com*", "type" : "AAAA", "address" : "2404:6800:4008:c06::be", "scopes" : ["192.168.0.0/16"]}
  ]
}
```

- xml config file example
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<config>
    <locals>
        <local address="::" port="53"/>
        <local address="127.0.0.1" port="66"/>
    </locals>
    <pollution>gfwlist</pollution>
    <statisticsFile>statistics.log</statisticsFile>
    <su>nobody</su>
    <enableCache>true</enableCache>
    <enableTcp>true</enableTcp>
    <ipv6First>1</ipv6First>
    <gfwMode>true</gfwMode>
    <daemonMode>false</daemonMode>
    <severity>info</severity>
    <remote_server address="8.8.8.8" port="53"/>
    <localnet_server address="202.122.37.87" port="53"/>
    <mappings>
        <mapping domain="scholar.google.com*" type="AAAA" address="2404:6800:4008:c06::be" />
            <scopes>
                <scope>192.168.0.0/16</scope>
            </scopes>
    </mappings>
</config>
```
<br>
<br>

###### syntax details:
- locals \[required] : local addresses that program binding to, include address and port(default is 53)<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; at least one address must be assigined
- pollution \[requried] : set the gfw list filename
- statisticsFile \[optional] : set the filename to print statistics information, default is termial
- su  \[optinal] : change usr account after start up
- enableCache \[optional] : enable internal dns cache, recommand, default is false
- enableTcp \[optional] : enable tcp query support, both local and remote, defulat is false
- ipv6First \[optional] : ipv6 mode, force return ipv6 address when available, default is 0<br>
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;three levels supported:<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0 : turn off this feature<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1 : only for domains in gfwlist<br>
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2 : for all domains<br>
- daemonMode \[optional]: become daemon after start up, default is false
- severity \[optional]: verbose level for logging facility, default is info:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;can be one of the following value:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;trace<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;debug<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;info<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;warning<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;error<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;fatal<br>
- remote_server \[required]:  oversea dns server , default is 8.8.8.8
- localnet_server \[required]: localNet dns server, provide by your ISP
- mappings \[optinal] : set custom domain-address mappings
- scopes  \[optinal] : set effective scope for specific address range




<br>

#### gfwlist file format
- the filename is set in \<pollution\> option<br>
- support glob to represent domains
- line starts with # is comment and not parse by program<br>
<br>
<span style="color:red"> Note: must include dot in the end<span>

```
#----- Youtube --------
*.youtube.com.
*.ytimg.com.
*.googlevideo.com.

#----- Google --------
*.google.com.
*.google.com.hk.

#----- Facebook --------
*.facebook.com.
```


