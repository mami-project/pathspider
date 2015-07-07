#Scamper probe

The Scamper probe setup consists of 3 main parts:

- Scamper source - C measurement module, available on the Components GitHub (<https://github.com/fp7mplane/components/tree/master/scamper/source>). It's a parallelised packet-prober capable of large-scale Internet measurement using many different measurement techniques.
- mPlane protocol Reference Implementation - Available on GitHub (<https://github.com/fp7mplane/protocol-ri>), Component-based framework written in Python to enable cooperation of mPlane compliant devices.
- Scamper probe - mPlane SDK interface, available on GitHub (<https://github.com/fp7mplane/components/tree/master/scamper>). Python interface connecting the Scamper probe to the mPlane.

##Installing Scamper
Prerequisite for the C module:

Scamper should compile and run under FreeBSD, OpenBSD, NetBSD, Linux, MacOS X, Solaris, Windows, and DragonFly. Not all of scamper will run on all systems: for example, the sting and tbit modules currently require IPFW, which is found on FreeBSD and MacOS X. All releases of scamper are licensed under the GPL v2.

Scamper sources are available at <https://github.com/fp7mplane/components/tree/master/scamper/source>.

```
$ ./configure
$ make
$ make install
```

Scamper is also available in FreeBSD ports, NetBSD pkgsrc, OpenBSD ports, and in Debian/Ubuntu packages (NOTE: Tracebox is not available in repository packages). The FreeBSD, NetBSD, and OpenBSD packages should be up to date with the latest version of scamper. When building on PlanetLab, pass the --without-privsep option to configure. When building on systems that use the Clang compiler, spurious warnings can be suppressed with: 
```
CFLAGS='-Wno-unneeded-internal-declaration -Wno-unused-const-variable -Wno-deprecated-declarations' ./configure
```

If there is any problem please contact <korian.edeline@ulg.ac.be>.


##Installing the mPlane framework and the Scamper component

Checkout the protocol reference implementation and the components.

Copy files from the Scamper mPlane interface (from the components GitHub) into `protocol-ri/`:

- `registry.json`    The registry.json file, copy it into `protocol-ri/mplane/`.
- `scamper.py`    The Python interface, copy it into `protocol-ri/mplane/components/`.
- `scamper.conf`    The Scamper config file, copy it into `protocol-ri/mplane/components/`.
- `supervisor.conf` and `client.conf`, The configuration file, copy them into `protocol-ri/conf/`.

Adjust the parameters in the `scamper.conf` file if needed (e.g. IPv4/IPv6 source addresses, path to certificates, supervisor address, client port and address, roles, etc).


##Running Scamper from an mPlane client
sudo python3 -m mplane.component --config ./conf/component.conf

First, run the supervisor:
```
ko@host:~/protocol-ri# python3 -m mplane.supervisor --config ./conf/supervisor.conf

```

In another terminal, run the Scamper probe component (NOTE: Certain capabilities need Scamper probe to be run as root because of the use of raw/link-layer sockets). The probe component should register to the supervisor and output the registration status:
```
ko@host:~/protocol-ri# sudo python3 -m mplane.component --config ./conf/scamper.conf
Added <Service for <capability: measure (tracebox-standard-ip4) when now ... future token 7faab371 schema 3c5e225e p/m/r 2/3/2>>
Added <Service for <capability: measure (tracebox-specific-ip4) when now ... future token 055c06f7 schema 720d393b p/m/r 5/3/2>>
...
tracebox-specific-ip6: Ok
tracebox-specific-quotesize-ip6: Ok
tracelb-standard-ip6: Ok

Checking for Specifications...

```
Then, run a clientshell in another terminal to run measurements:
```
ko@host:~/protocol-ri#  python3 -m mplane.clientshell --config ./conf/client.conf
ok
mPlane client shell (rev 20.1.2015, sdk branch)
Type help or ? to list commands. ^D to exit.

|mplane| 
```

Now, depending on whether or not you have IPv4 and/or IPv6 access, you should the according capabilities when typing `listcap`:
```
|mplane| listcap
Capability ping-average-ip4 (token 500e872425184cd11ba886aac0f16c6c)
Capability ping-detail-ip4 (token 8e56bdb4b00500045473ff212ee3fc87)
Capability trace-standard-ip4 (token a5d0803b027cfe85fe4754aabb387cf5)
Capability trace-standard-ip6 (token 5dc10db0fd138036d755e0d5624c7899)
Capability tracebox-specific-ip4 (token 055c06f737bde23a73d8a2b3bec82f46)
Capability tracebox-specific-ip6 (token ba43836a3ddde493c642d4b5b613eeaa)
Capability tracebox-specific-quotesize-ip4 (token 16dde5316e640b4f511586884859f194)
Capability tracebox-specific-quotesize-ip6 (token 65652f7b6ca8db0a24f21cc3cb89e65d)
Capability tracebox-standard-ip4 (token 7faab37151c11ffaf278ef09c560b61a)
Capability tracebox-standard-ip6 (token a3c0f8541b6d6b7079b90480df8a4d04)
Capability tracelb-standard-ip4 (token 47e5a127ec9c087b1ec4897e0950ae80)
Capability tracelb-standard-ip6 (token 889b5b1d3f509e93cd7a7bc02f3fbef7)
```

To run a measurement, type `runcap <name-of-capability>`:

```

|mplane| runcap tracebox-specific-ip4
|when| = now ... future
destination.ip4 = 208.97.177.124
scamper.tracebox.dport = 80
scamper.tracebox.probe = IP/TCP/MSS(1460)/ECE/CE/MPCAPABLE
ok
|mplane| listmeas
Result  tracebox-specific-ip4-3 (token cbf1b16bb37744b87d860ca03b557610): 2015-07-01 10:59:29.061422 ... 2015-07-01 10:59:29.063330

|mplane|
```
You should observe scheduling activity on the supervisor terminal and measurements on the component terminal. Then, you can check the results in the client terminal:
```
|mplane| listmeas
Result  tracebox-specific-ip4-3 (token cbf1b16bb37744b87d860ca03b557610): 2015-07-01 10:59:29.061422 ... 2015-07-01 10:59:29.063330

|mplane| showmeas tracebox-specific-ip4-3
result: measure
    label       : tracebox-specific-ip4-3
    token       : cbf1b16bb37744b87d860ca03b557610
    when        : 2015-07-01 10:59:29.061422 ... 2015-07-01 10:59:29.063330
    parameters  ( 4): 
                  scamper.tracebox.probe: IP/TCP/MSS(1460)/ECE/CE/MPCAPABLE
                         destination.ip4: 208.97.177.124
                  scamper.tracebox.dport: 80
                              source.ip4: 1.2.3.4
    metadata    ( 3): 
                               System_ID: Scamper-Proxy
                             System_type: Scamper
                          System_version: 0.1
    resultvalues(14):
          result 0:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: 
          result 1:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::TTL IP::Checksum
          result 2:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::TTL IP::Checksum
          result 3:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::TTL IP::Checksum
          result 4:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::TTL IP::Checksum IP::ECT IP::CE
          result 5:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 6:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 7:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 8:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 9:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: TCP::Checksum IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 10:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 11:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 12:
                    scamper.tracebox.hop.ip4: *.*.*.*
            scamper.tracebox.hop.modifications: IP::DiffServicesCP IP::TTL IP::Checksum IP::ECT IP::CE
          result 13:
                    scamper.tracebox.hop.ip4: 208.97.177.124
            scamper.tracebox.hop.modifications: +TCP::Options::MSS

```

##Default Values
Certain capabilities will asks for a lot parameters, here are the values to specifiy if you don't know. Not all capabilities are listed here, those not listed involves less parameters or documentation can be found by typing `man scamper` in the related section:

#ping

- scamper.ping.dport = 80
- scamper.ping.method = icmp-echo
- scamper.ping.rr = 0
- scamper.ping.size = 84
- scamper.ping.sport = 33
- scamper.ping.tos = 0
- scamper.ping.ttl = 6

#trace

- scamper.trace.M = 0
- scamper.trace.Q = 0
- scamper.trace.T = 0
- scamper.trace.attempts = 2
- scamper.trace.confidence = 95
- scamper.trace.dport = 33435
- scamper.trace.firsthop = 1
- scamper.trace.gapaction = 1
- scamper.trace.gaplimit = 5
- scamper.trace.loopaction = 0
- scamper.trace.loops = 1
- scamper.trace.maxttl = 255
- scamper.trace.method = UDP-paris
- scamper.trace.sport = 33436
- scamper.trace.tos = 0
- scamper.trace.wait = 5
- scamper.trace.waitprobe = 0

#tracelb

- scamper.tracelb.attempts = 2
- scamper.tracelb.confidence = 95
- scamper.tracelb.dport = 33435
- scamper.tracelb.firsthop = 1
- scamper.tracelb.gaplimit = 5
- scamper.tracelb.maxprobec = 3000
- scamper.tracelb.method = udp-dport
- scamper.tracelb.sport = 33436
- scamper.tracelb.tos = 0
- scamper.tracelb.waitprobe = 5
- scamper.tracelb.waittimeout = 0

