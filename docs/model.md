# NmapRun

With the NmapRun model, you can parse Nmap’s XML output into Python objects (thanks to [pydantic-xml](https://github.com/dapper91/pydantic-xml)), making it super convenient to handle scan results in Python code. You can access attributes, validate types, convert to JSON, CSV, or HTML (using XSLT), and more!

The structure and data types of the NmapRun model align as closely as possible with [Nmap's document type definition (DTD)](https://nmap.org/book/nmap-dtd.html).

Returns an NmapRun object after the scan is complete:

```ipython
In [1]: from nmass import Nmap

In [2]: result = Nmap().with_targets("172.20.0.2").with_ports(9200,9300).run()

In [3]: result
Out[3]: NmapRun(scanner='nmap', args='/usr/bin/nmap -oX - -vvv --noninteractive -p 9200,9300 172.20.0.2', start=1730376449, start_time='Thu Oct 31 20:07:29 2024', version='7.95', xmloutputversion='1.05', scaninfo=ScanInfo(type=<ScanType.connect: 'connect'>, protocol=<PortProtocol.tcp: 'tcp'>, numservices=2, services='9200,9300'), verbose={'level': 3}, debugging={'level': 0}, hosthint=HostHint(status=Status(state=<HostState.up: 'up'>, reason='unknown-response', reason_ttl='0'), address=[Address(addr='172.20.0.2', addrtype='ipv4')], hostnames=[]), taskprogress=None, hosts=[Host(status=Status(state=<HostState.up: 'up'>, reason='conn-refused', reason_ttl='0'), address=[Address(addr='172.20.0.2', addrtype='ipv4')], hostnames=[], ports=Ports(extraports=None, ports=[Port(protocol=<PortProtocol.tcp: 'tcp'>, portid=9200, state=State(state=<PortState.open: 'open'>, reason='syn-ack', reason_ttl='0'), service=Service(name='wap-wsp', banner=None, product=None, version=None, method='table', confidence=3, cpe=None), scripts=None), Port(protocol=<PortProtocol.tcp: 'tcp'>, portid=9300, state=State(state=<PortState.open: 'open'>, reason='syn-ack', reason_ttl='0'), service=Service(name='vrace', banner=None, product=None, version=None, method='table', confidence=3, cpe=None), scripts=None)]), os=None, uptime=None, distance=None, tcpsequence=None, ipidsequence=None, tcptssequence=None, trace=None, times={'srtt': 89, 'rttvar': 2829, 'to': 100000})], stats=Stats(finished={'time': '1730376449', 'timestr': 'Thu Oct 31 20:07:29 2024', 'summary': 'Nmap done at Thu Oct 31 20:07:29 2024; 1 IP address (1 host up) scanned in 0.04 seconds', 'elapsed': '0.04', 'exit': 'success'}, hosts={'up': 1, 'down': 0, 'total': 1}))
```

With the awesome [pydantic](https://github.com/pydantic/pydantic) package, you can easily convert the result to JSON.

```ipython
In [4]: result.model_dump_json()
Out[4]: '{"scanner":"nmap","args":"/usr/bin/nmap -oX - -vvv --noninteractive -p 9200,9300 172.20.0.2","start":1730376449,"start_time":"Thu Oct 31 20:07:29 2024","version":"7.95","xmloutputversion":"1.05","scaninfo":{"type":"connect","protocol":"tcp","numservices":2,"services":"9200,9300"},"verbose":{"level":3},"debugging":{"level":0},"hosthint":{"status":{"state":"up","reason":"unknown-response","reason_ttl":"0"},"address":[{"addr":"172.20.0.2","addrtype":"ipv4"}],"hostnames":[]},"taskprogress":null,"hosts":[{"status":{"state":"up","reason":"conn-refused","reason_ttl":"0"},"address":[{"addr":"172.20.0.2","addrtype":"ipv4"}],"hostnames":[],"ports":{"extraports":null,"ports":[{"protocol":"tcp","portid":9200,"state":{"state":"open","reason":"syn-ack","reason_ttl":"0"},"service":{"name":"wap-wsp","banner":null,"product":null,"version":null,"method":"table","confidence":3,"cpe":null},"scripts":null},{"protocol":"tcp","portid":9300,"state":{"state":"open","reason":"syn-ack","reason_ttl":"0"},"service":{"name":"vrace","banner":null,"product":null,"version":null,"method":"table","confidence":3,"cpe":null},"scripts":null}]},"os":null,"uptime":null,"distance":null,"tcpsequence":null,"ipidsequence":null,"tcptssequence":null,"trace":null,"times":{"srtt":89,"rttvar":2829,"to":100000}}],"stats":{"finished":{"time":"1730376449","timestr":"Thu Oct 31 20:07:29 2024","summary":"Nmap done at Thu Oct 31 20:07:29 2024; 1 IP address (1 host up) scanned in 0.04 seconds","elapsed":"0.04","exit":"success"},"hosts":{"up":1,"down":0,"total":1}}}'
```

Want to convert the result into a nice HTML file? Easy!

```python
with open("/tmp/nmap.html", "w") as f:
    html_code = result.to_html(xslt_path="https://raw.githubusercontent.com/Haxxnet/nmap-bootstrap-xsl/main/nmap-bootstrap.xsl")
    f.write(html_code)
```

![nmap.html](screenshot.png)
