import mplane
import mplane.tls
import mplane.utils
import mplane.client
import argparse
import configparser
import time

def retrieve_addresses(client, ipv, count, label, url, unique = True, when = "now ... future"):
    try:
        spec = client.invoke_capability(label, when, { "btdhtspider.count": count, "btdhtspider.unique": unique })
        token_label = spec.get_token()
    except KeyError as e:
        print("Specified URL does not support '"+label+"' capability.")
        raise e

    addrs = []

    while True:
        time.sleep(1)
        try:
            res = client.result_for(token_label)
        except KeyError:
            continue

        if isinstance(res, mplane.model.Exception):
            print(res.__repr__())
        elif isinstance(res, mplane.model.Receipt):
            continue
        elif isinstance(res, mplane.model.Result):
            for row in res.schema_dict_iterator():
                addrs.append((row['destination.'+ipv], row['destination.port'], row['btdhtspider.nodeid']))
        else:
            print(res)

        return addrs

def perform_measurement(clients, ipv, addrs, when = "now ... future"):
    # invoke on all probes
    ips = [str(addr[0]) for addr in addrs]
    ports = [addr[1] for addr in addrs]

    tokens = []
    for label, client in clients:
        try:
            spec = client.invoke_capability('ecnspider-'+ipv, when, { 'destination.'+ipv: ips, 'destination.port': ports })
            tokens.append((spec.get_token(), label, client))
        except KeyError as e:
            print("Specified URL does not support '"+label+"' capability.")
            raise e

    addrs = []
    for token, label, client in tokens:
        while True:
            time.sleep(1)
            try:
                res = client.result_for(token)
            except KeyError:
                continue

            if isinstance(res, mplane.model.Exception):
                print(res.__repr__())
            elif isinstance(res, mplane.model.Receipt):
                continue
            elif isinstance(res, mplane.model.Result):
                print("Receiving data from "+label)
                for row in res.schema_dict_iterator():
                    yield (label, row)
            else:
                print(res)

            break

if __name__ == "__main__":
    mplane.model.initialize_registry()

    # look for TLS configuration
    parser = argparse.ArgumentParser(description="mPlane ecnspider client")
    parser.add_argument('--config', metavar="config-file", required=True,
                        help="Configuration file")
    parser.add_argument('--count', metavar="N", type=int, required=True,
                        help="Number of test subjects for the measurement. (N > 0)")
    parser.add_argument('--file', '-f', metavar='FILENAME', help='Write results into CSV-File.', dest='outfile', required=True, type=argparse.FileType('w'))
    args = parser.parse_args()

    # check arguments
    if args.count < 1:
        print('\nERROR: Number of test subjects (--count) must be integer greater than 0.)')
        exit(1)

    # read the configuration file
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(mplane.utils.search_path(args.config))

    tls_state = mplane.tls.TlsState(config)
    chunk_size = config['client'].getint('chunk_size')
    outfile = args.outfile

    # setup address collector
    if 'btdhtspider-ip6' in config['client']:
        ipv = 'ip6'
        btdht_label = 'btdhtspider-ip6'
        btdht_url = config['client'].get('btdhtspider-ip6')
    else:
        ipv = 'ip4'
        btdht_label = 'btdhtspider-ip4'
        btdht_url = config['client'].get('btdhtspider-ip4')

    btdhtspider = mplane.client.HttpInitiatorClient(tls_state)
    btdhtspider.retrieve_capabilities(btdht_url)

    # setup ecnspider probes
    probes_config = config.items('ecnspider')
    if len(probes_config) == 0:
        print('\nERROR: no ecnspider probes specified in configuration file.')
        exit(1)

    probes = []
    column_names = None
    for probe_label, probe_url in probes_config:
        probe_client = mplane.client.HttpInitiatorClient(tls_state)
        probe_client.retrieve_capabilities(probe_url)

        if column_names == None:
            cap = probe_client.capability_for('ecnspider-'+ipv)
            column_names = cap.result_column_names()

        probes.append((probe_label, probe_client))


    # write file header
    outfile.write("site,ip,port,rport,ecnstate,connstate,fif,fsf,fuf,fir,fsr,fur,ttl\n")

    recorded = 0
    try:
        while recorded < args.count:
            num_request = chunk_size if recorded + chunk_size < args.count else args.count - recorded
            assert(num_request > 0)

            print("Retrieving the next {} addresses.\n".format(num_request))
            addrs = retrieve_addresses(btdhtspider, ipv, num_request, btdht_label, btdht_url, unique=True)

            print("Performing measurement.")
            results = perform_measurement(probes, ipv, addrs)
            for label, result in results:
                outfile.write('{label},{ip},{port},{rport},{ecnstate},{connstate},{fif},{fsf},{fuf},{fir},{fsr},{fur},{ttl}\n'.format(
                    label=label,
                    ip=result['destination.'+ipv],
                    port=result['source.port'],
                    rport=result['destination.port'],
                    ecnstate=result['ecnspider.ecnstate'],
                    connstate=result['connectivity.ip'],
                    fif=result['ecnspider.initflags.fwd'],
                    fsf=result['ecnspider.synflags.fwd'],
                    fuf=result['ecnspider.unionflags.fwd'],
                    fir=result['ecnspider.initflags.rev'],
                    fsr=result['ecnspider.synflags.rev'],
                    fur=result['ecnspider.unionflags.rev'],
                    ttl=result['ecnspider.ttl.rev.min']
                ))

            recorded += num_request
            print("Finished {} of {}".format(recorded, args.count))
    except KeyboardInterrupt:
        print("Keyboard interrupt, closing file...")
    finally:
        outfile.close()

