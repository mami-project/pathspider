# pathspider
ECN-Spider is an active measurement tool, built in a modular manner using mPlane components and an associated client, to test Explicit Congestion Notification (ECN) connectivity failures and readiness for ECN negotiation.

## Requirements
 * Quality of Flow (QoF) : https://github.com/britram/qof/wiki/Howto
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
worker_count = 200
connection_timeout = 4
interface_uri = ring:eth0
qof_port = 54739
enable_ipv6 = true

[module_btdhtresolver]
module = pathspider.btdhtresolver
enable_ipv6 = true

# other optional arguments:
# ip4addr = 0.0.0.0   # bind ecnspider to this IPv4 address
# ip6addr = ::        # bind ecnspider to this IPv6 address
# port4 = 9881   # bind address collector to this IPv4 address
# port6 = 9882   # bind address collector to this IPv6 address

# other optional arguments:
# ip4addr = 0.0.0.0   # bind ecnspider to this IPv4 address
# ip6addr = ::        # bind ecnspider to this IPv6 address

[module_scamper]
module = pathspider.scamper.scamper
ip4addr = 1.2.3.4
ip6addr = ::1

#[module_webresolver]
#module = pathspider.webresolver
```

## Examples
To run the examples, change to the pathspider directory.
(The configuration files have to be in the same directory or they have to be explicetly specified by --config FILE.)
```
cd pathtools/pathspider
```

Print all available options with `pathspider -h`

Running a standalone measurement using BitTorrent DHT as address source:
```
pathspider --mode standalone --resolver-btdht --count 1000
```


  
