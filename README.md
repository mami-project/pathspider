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


  
