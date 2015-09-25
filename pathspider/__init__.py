import argparse
import configparser
import os
import mplane.component
import mplane.tls
import mplane.utils
import pathspider.client
import pathspider.client.resolver
import time
import logging
import json
import threading
import ipaddress

import tornado.web
import tornado.ioloop

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

mplane.model.initialize_registry('ecnregistry.json')

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

    time.sleep(2)

    print("standalone mode: starting client...")
    # run client
    return run_client(args, config)

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

class MainHandler(tornado.web.RequestHandler):
    class IPAddressEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, ipaddress.IPv4Address) or isinstance(obj, ipaddress.IPv6Address):
                return obj.compressed
            return json.JSONEncoder.default(self, obj)

    def initialize(self, ps):
        self.ps = ps

    def get(self, cmd):
        if cmd == 'status':
            status = json.dumps(self.ps.status(), cls=MainHandler.IPAddressEncoder)
            self.set_header("Content-Type", "application/json")
            self.write(status)
        elif cmd == 'stats':
            statistics = self.ps.ecn_results.to_json()
            self.set_header("Content-Type", "application/json")
            self.write(statistics)
        elif cmd == 'graph':
            graph = json.dumps(self.ps.tb_results, cls=MainHandler.IPAddressEncoder)
            self.set_header("Content-Type", "application/json")
            self.write(graph)
        else:
            self.send_error(404)

class DefaultHandler(tornado.web.RequestHandler):
    def get(self, cmd=None):
        if cmd is None or cmd == '':
            self.render('gui/control.html')
        elif cmd == 'd3.min.js':
            self.render('gui/d3.min.js')
        else:
            self.send_error(404)

class WebInterface(threading.Thread):
    def __init__(self, addr, ps):
        super().__init__(name='webif', daemon=True)

        self.addr = addr
        self.ps = ps

    def run(self):
        # run user interface server
        self.app = tornado.web.Application([
                (r"/engine/(.*)", MainHandler, {'ps': self.ps}),
                (r"/(.*)", DefaultHandler)
            ],
            debug=True
        )

        self.app.listen(address=self.addr[0], port=self.addr[1])

        tornado.ioloop.IOLoop.current().start()

def run_client(args, config):
    tls_state = mplane.tls.TlsState(config)
    ps = None

    ecnspider_urls = config.items('probes')
    print("Probes specified in configuration file:")
    for name, url in ecnspider_urls:
        print('# {} at {}'.format(name, url))

    if args.count != 0 and args.chunk_size > args.count:
        args.chunk_size = args.count
        print("chunk size has been set to {}".format(args.count))

    if args.resolver_btdht is True:
        count = args.count if args.count > 0 else 10000
        resolver_url = config['main']['resolver']
        print("Resolver specified in configuration file:")
        print("# "+resolver_url)
        resolver = pathspider.client.resolver.BtDhtResolverClient(tls_state, resolver_url)
        ps = pathspider.client.PathSpiderClient(count, tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)

    elif args.resolver_web is not None:
        hostnames = skip_and_truncate(args.resolver_web.readlines(), args.resolver_web, args.skip, args.count)

        print("Ordering measurement of {} hostnames.".format(len(hostnames)))
        resolver = pathspider.client.resolver.WebResolverClient(tls_state, config['main']['resolver'], urls=hostnames)
        ps = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)

    elif args.resolver_ipfile is not None:
        addrs = [(ip, int(port)) for ip, port in [line.split(':', 1) for line in args.resolver_ipfile.readlines() if len(line) > 0]]

        addrs = skip_and_truncate(addrs, args.resolver_ipfile, args.skip, args.count)
        resolver = pathspider.client.resolver.IPListDummyResolver(addrs)
        ps = pathspider.client.PathSpiderClient(len(resolver), tls_state, ecnspider_urls, resolver, ipv=args.ipv, chunk_size=args.chunk_size)

    if args.webui:
        wi = WebInterface(addr=('localhost', 37100), ps=ps)
        wi.start()

    return ps


def main():
    # parse command line
    parser = argparse.ArgumentParser(usage='Usage: %(prog)s <mode> [options]')
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('mode', choices=['standalone', 'client', 'service'], help='Set operating mode.')
    parser.add_argument('--config', '-C', default='AUTO', help='Set pathspider configuration file. If set to AUTO, try to open either standalone.conf, client.conf or service.conf depending on operating mode. Default: AUTO.')
    parser.add_argument('-v', action='store_const', const=logging.INFO, dest='loglevel', help='Be verbose.')
    parser.add_argument('-vv', action='store_const', const=logging.DEBUG, dest='loglevel', help='Enable debug messages.')

    parser_client = parser.add_argument_group('client and standalone mode')
    parser_client.add_argument('-u', '--webui', action='store_true', dest='webui', default=False, help='Start web interface.')
    #parser_client.add_argument('--webui-listen', metavar='HOST:PORT', dest='webui_listen', default=('localhost', 31343), help='Listen to ')
    parser_client.add_argument('--report', metavar='FILENAME', type=argparse.FileType('wt'), help='Save a report of all data in json format.')
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

    logging.basicConfig(level=args.loglevel or logging.WARNING, format='%(asctime)s [%(name)-10.10s: %(threadName)-10.10s] [%(levelname)-5.5s]  %(message)s')
    # disable tornado messages
    logging.getLogger('tornado').setLevel(logging.ERROR)

    if args.report is not None:
        print("Saving report to {}".format(args.report.name))

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

    pathspider = None
    if args.mode == 'standalone':
        pathspider = run_standalone(args, config)
    elif args.mode == 'client':
        pathspider = run_client(args, config)
    elif args.mode == 'service':
        run_service(args, config)

    while True:
        if pathspider is not None:
            print(pathspider.status())
            if pathspider.running is False:
                if args.report is not None:
                    print("Save report...")
                    json.dump(pathspider.results, args.report)
                    print("Report saved into {}".format(args.report.name))
                break
        time.sleep(4)

    print("Shutdown complete.")

if __name__ == '__main__':
    main()

