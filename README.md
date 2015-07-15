# pathspider
ECN-Spider is an active measurement tool, built in a modular manner using mPlane components and an associated client, to test Explicit Congestion Notification (ECN) connectivity failures and readiness for ECN negotiation.

## Requirements
 * Quality of Flow (QoF), use the `develop` branch : https://github.com/britram/qof/wiki/Howto
 * Scamper (contains tracebox) : https://github.com/fp7mplane/components/blob/master/scamper/source/scamper.tar.gz

## Installation
First create a Python 3.4 virtual environment:
```
$ virtualenv -p python3.4 venv
$ source venv/bin/activate
```

Install tornado
```
(venv) $ pip install tornado
```

Installing the sdk-multival branch of mPlane using git and pip:
```
(venv) $ git clone https://github.com/fp7mplane/protocol-ri.git
(venv) $ cd protocol-ri
(venv) $ git checkout sdk-multival
(venv) $ cd ..
(venv) $ git clone https://github.com/britram/pathtools.git

(venv) $ pip install -v -e protocol-ri
```

And finally to install pathspider type:
(note: dependencies numpy and pandas need some time to install):
```
(venv) $ pip install -v -e pathtools
```

## Configuration
pathspider operates in three modes:
 * service : Just run mPlane components, acting as a measurement probe.
 * client : A client implementation analyzing results from multiple probes.
 * standalone : A standalone implementation where the measurements and analysis
                are performed on the same computer.

Each operating mode has its own configuration file. Either service.conf,
client.conf or standalone.conf. standalone.conf basically includes all configuration
options from the client and serivce mode.

### Client Configuration
Adjust URLs to point to your mPlane probes:
```
[probes]
nyc = http://path-nyc.corvid.ch:18888/
ams = http://path-ams.corvid.ch:18888/
sin = http://path-sin.corvid.ch:18888/
sfo = http://path-sfo.corvid.ch:18888/
lon = http://path-lon.corvid.ch:18888/

[main]
use_tracebox = false
resolver = http://path-ams.corvid.ch:18888/
```

### Service Configuration
You will probably want to change interface_uri to the network interface the
traffic flows.

```
[module_ecnspider]
module = pathspider.ecnspider2
worker_count = 200			# num of connection attempts in parallel (threads)
connection_timeout = 4		# timeout for a single connection attempt
interface_uri = ring:eth0	# libtrace uri, interface to listen on
qof_port = 54739			# port for inter-process communication with QoF.
enable_ipv6 = true			# enable/disable ipv6 capabilities
ip4addr = 0.0.0.0   		# bind measurement connections to this IPv4 address
ip6addr = ::        		# bind measurement connections to this IPv4 address

[module_btdhtresolver]
module = pathspider.btdhtresolver
enable_ipv6 = true			# enable/disable ipv6 capabilities
ip4addr = 0.0.0.0   		# bind resolver to this IPv4 address
ip6addr = ::        		# bind resolver to this IPv4 address
port4 = 9881   				# bind address collector to this IPv4 address
port6 = 9882   				# bind address collector to this IPv6 address

[module_scamper]
module = pathspider.scamper.scamper
ip4addr = 1.2.3.4
ip6addr = ::1

#[module_webresolver]
#module = pathspider.webresolver
```

### mPlane-Capabilities
Given a set of target IPv4 or IPv6 addresses, ecnspider2 returns connectivity
with ECN negotiation attempted and without, as well as TCP and IP ECN codepoint
information in order to diagnose ECN signaling issues.
The core IPv4 capability is as follows:

{ "capability": "measure",
"parameters": { "destination.ip4": "[*]",
"destination.port", "[*]" },
"results": { "source.port",
"destination.ip4",
"destination.port",
"connectivity.ip",
"ecnspider.ecnstate",
"ecnspider.initflags.fwd",
"ecnspider.synflags.fwd",
"ecnspider.unionflags.fwd",
"ecnspider.initflags.rev",
"ecnspider.synflags.rev",
"ecnspider.unionflags.rev",
"ecnspider.ttl.rev.min" }
}

The ecnspider. elements are included in a custom registry inheriting from the core registry, included with the component.

## Examples
To run the examples, change to the pathspider directory.
(The configuration files have to be in the same directory or they have to be explicetly specified by --config FILE.)
```
cd pathtools/pathspider
```

Print all available options with `pathspider -h`

Running a standalone measurement of 1000 IPv4 addresses using BitTorrent DHT as address source:
```
pathspider --mode standalone --resolver-btdht --count 1000
```


  
