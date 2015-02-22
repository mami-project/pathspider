# ECN Spider Component Redesign

A Spider takes a list of IP addresses and turns it into a list of tuples as follows:

- `destination.ip4` *or*
- `destination.ip6`
- `ecnspider.ecnstate`
- `connectivity.ip`
- `octets.layer5`
- `ecnspider.initflags.fwd`
- `ecnspider.synflags.fwd`
- `ecnspider.unionflags.fwd`
- `ecnspider.initflags.rev`
- `ecnspider.synflags.rev`
- `ecnspider.unionflags.rev`

It does this using the following threads:

- *filler* enqueues IP addresses from a source list (extracted from a specification)
- *master* changes system ECN state (synchronized to workers through four semaphores)
- *worker* dequeues addresses, makes connections with and without ECN, retrieves webpages, and places preliminary results in a table (containing source port, destination IP, and measured connection state each for ECN on and ECN off)
- *qofowner* starts qof and makes sure it keeps running
- *qofcollector* (started from socketserver) reads flows from qof and places them in a table
- *merger* merges worker and collector results into single results and emits them (to be placed in an mplane result)

The ecnspider.py part of this is mPlane-neutral; all mplane integration is done in component.py