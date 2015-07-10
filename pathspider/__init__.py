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

def run_standalone(args, config):
    config["component"]["workflow"] = "client-initiated"

    print("standalone mode: starting service...")
    # run service
    run_service(args, config)

    time.sleep(5)

    print("standalone mode: starting client...")
    # run client
    run_client(args, config)

def skip_and_truncate(iterable, filename, skip, count):
    if skip != 0:
            if skip < len(iterable):
                print("Skipping {} hostnames.".format(skip))
                iterable = iterable[skip:]
            else:
                raise ValueError("You want to skip {} entries, but there are only {} entries in the given file '{}'".format(skip, len(iterable), filename))

    if count != 0 and count < len(iterable):
        iterable = iterable[0:count]

    return iterable

def run_client(args, config):
    tls_state = mplane.tls.TlsState(config)
    ecnspider = None

    ecnspider_urls = config.items('probes')
    print("Probes specified in configuration file:")
    for name, url in ecnspider_urls:
        print('# {} at {}'.format(name, url))

    if args.chunk_size > args.count:
        args.chunk_size = args.count
        print("chunk size has been set to {}".format(args.count))

    if args.resolver_btdht is True:
        count = args.count if args.count > 0 else 10000
        resolver = pathspider.client.resolver.BtDhtResolverClient(tls_state, config['main']['resolver'])
        ecnspider = pathspider.client.PathSpiderClient(count, tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)

    elif args.resolver_web is not None:
        hostnames = skip_and_truncate(args.resolver_web.readlines(), args.resolver_web, args.skip, args.count)

        print("Ordering measurement of {} hostnames.".format(len(hostnames)))
        resolver = pathspider.client.resolver.WebResolverClient(tls_state, config['main']['resolver'], urls=hostnames)
        ecnspider = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)

    elif args.resolver_ipfile is not None:
        addrs = [(ip, int(port)) for ip, port in [line.split(':', 1) for line in args.iplist_file.readlines() if len(line) > 0]]

        addrs = skip_and_truncate(addrs, args.resolver_ipfile, args.skip, args.count)
        resolver = pathspider.client.resolver.IPListDummyResolver(addrs)
        ecnspider = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)


def main():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('--mode', '-m', choices=['standalone', 'client', 'service'], required=True, help='Set operating mode.')
    parser.add_argument('--config', '-C', default='AUTO', help='Set pathspider configuration file. If set to AUTO, try to open either standalone.conf, client.conf or service.conf depending on operating mode. Default: AUTO.')

    parser_client = parser.add_argument_group('Options for client and standalone mode')
    parser_client_ip = parser_client.add_mutually_exclusive_group()
    parser_client_ip.add_argument('--ip4', '-4', action='store_const', dest='ipv', const='ip4', default='ip4', help='Use IP version 4 (default).')
    parser_client_ip.add_argument('--ip6', '-6', action='store_const', dest='ipv', const='ip6', help='Use IP version 6.')

    parser_client_resolver = parser_client.add_mutually_exclusive_group()
    parser_client_resolver.add_argument('--resolver-btdht', '-B', action='store_true',
                                        help='Use a BitTorrent DHT resolver. Acquires addresses by browsing BitTorrent\'s Distributed Hash Table network.')
    parser_client_resolver.add_argument('--resolver-web', '-W', metavar='FILE', type=argparse.FileType('rt'),
                                        help='Use a file containing a list of hostnames, separated by newline. The hostnames are resolved on a remote server.')
    parser_client_resolver.add_argument('--resolver-ipfile', '-I', metavar='FILE', type=argparse.FileType('rt'),
                                        help='Use a file containing a list of \'ipaddress:port\' entries, separated by newline. IP addresses are directly fed to ecnspider.')

    parser_client.add_argument('--count', '-c', type=int, default=0, metavar='N', help='Measure N addresses. Default is 0 (all), except when using -B the default is 10\'000.')
    parser_client.add_argument('--skip', '-s', type=int, default=0, metavar='N', help='Skip N addresses before starting to measure. Default is 0.')

    parser_client.add_argument('--chunk-size', type=int, default=1000, metavar='N', help='Number of addresses sent in a chunk to ecnspider. Default is 1000.')

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

    while True:
        time.sleep(300)

if __name__ == '__main__':
    main()

