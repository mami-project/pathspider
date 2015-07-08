import argparse
import configparser
import os
import mplane.component
import mplane.tls
import mplane.utils
import pathspider.client
import pathspider.client.resolver
import time

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

def run_service(args, config):
    if config["component"]["workflow"] == "component-initiated":
        component = mplane.component.InitiatorHttpComponent(config)
    elif config["component"]["workflow"] == "client-initiated":
        component = mplane.component.ListenerHttpComponent(config)
    else:
        raise ValueError("workflow setting in " + args.config + " can only be 'client-initiated' or 'component-initiated'")

    while True:
        time.sleep(10)

def run_standalone(args, config):
    config["component"]["workflow"] = "client-initiated"

    # run service
    mplane.component.ListenerHttpComponent(config)

    # run supervisor locally
    while True:
        time.sleep(10)

def run_client(args, config):
    tls_state = mplane.tls.TlsState(config)

    ecnspider = None

    ecnspider_urls = config.items('probes')
    print("Probes specified in configuration file:")
    for name, url in ecnspider_urls:
        print('label: {}, url: {}'.format(name, url))

    if args.btdht_count is not None:
        resolver = pathspider.client.resolver.BtDhtResolverClient(tls_state, config['main']['resolver'])
        ecnspider = pathspider.client.PathSpiderClient(args.btdht_count, tls_state, ecnspider_urls, resolver)
    elif args.hostnames_file is not None:
        resolver = pathspider.client.resolver.WebResolverClient(tls_state, config['main']['resolver'], urls=args.hostnames_file.readlines())
        ecnspider = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver)
    elif args.iplist_file is not None:
        resolver = pathspider.client.resolver.IPListDummyResolver([(ip, int(port)) for ip, port in [line.split(':', 1) for line in args.iplist_file.readlines() if len(line) > 0]])
        ecnspider = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver)

    while True:
        time.sleep(10)


def main():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('--mode', '-m', choices=['standalone', 'client', 'service'], required=True, help='Set the operating mode.')
    parser.add_argument('--config', '-c', default='AUTO', help='Set pathspider configuration file.')

    parser_client = parser.add_argument_group('Options for client and standalone mode')
    parser_client.add_argument('--btdht-count', type=int, dest='btdht_count', metavar='NUM', help='Using IP/port addresses from the BitTorrent DHT network, tell pathspider how many ecnspider TCP measurements to perform.')
    parser_client.add_argument('--hostnames-file', dest='hostnames_file', type=argparse.FileType('rt'), metavar='FILENAME', help='Using the hostnames specified in this file, pathspider will resolve them to ip addresses and perform ecnspider HTTP measurements.')
    parser_client.add_argument('--iplist-file', dest='iplist_file', type=argparse.FileType('rt'), metavar='FILENAME', help='Perform ecnspider TCP measurements on ips specified in the given file (format: one \'ipaddress:port\' per line)')

    args = parser.parse_args()

    if args.config == 'AUTO':
        if args.mode == 'standalone':
            args.config = 'standalone.conf'
        elif args.mode == 'client':
            args.config = 'client.conf'
        elif args.mode == 'service':
            args.config = 'service.conf'

    # read the configuration file
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(mplane.utils.search_path(args.config))

    if args.mode == 'standalone':
        run_standalone(args, config)
    elif args.mode == 'client':
        run_client(args, config)
    elif args.mode == 'service':
        run_service(args, config)

if __name__ == '__main__':
    main()

