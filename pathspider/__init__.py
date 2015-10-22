import argparse
import configparser
import os
import mplane.component
import mplane.tls
import mplane.utils
import mplane.client
import pathspider.client.ecnclient as ecnclient
import pathspider.client.tbclient as tbclient
import pathspider.client.resolver as resolver
import time
import logging
import json
import threading
import ipaddress
import itertools

import tornado.web
import tornado.websocket
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

class GraphGenerator:
    def add_node(self, name, x = None, y = None):
        if name in self.nodes_idx:
            return

        self.nodes.append({
            'caption': name,
            'x': x or 0,
            'y': y or 0,
            'fixed': x is not None or y is not None
        })
        self.nodes_idx.append(name)

    def add_link(self, source_name, target_name, probe, mode='normal'):
        self.links.append({
            'source': self.nodes_idx.index(source_name),
            'target': self.nodes_idx.index(target_name),
            'mode': mode,
            'probe': probe
        })

    def __init__(self, ips, probes, tb_results):
        self.nodes = []
        self.nodes_idx = []
        self.links = []

        self.probe_step = 200
        self.target_step = 200

        # add probes
        for idx, (name, _) in enumerate(probes):
            self.add_node(name, 10, idx*self.probe_step)

        for idx, ip in enumerate(ips):
            self.add_node(ip, 800, idx*self.target_step)

            graph = tb_results.get(ip) or {}
            for probe, trace in graph.items():
                prev = probe
                gap = False
                hop_ip = None
                for hop in trace:
                    if hop is None:
                        gap = True
                        continue

                    hop_ip = str(hop)

                    self.add_node(hop_ip)

                    self.add_link(prev, hop_ip, probe, 'missing' if gap else 'normal')
                    gap = False

                    prev = hop_ip

                if hop_ip != ip:
                    self.add_link(prev, str(ip), probe, 'missing')


class IPAddressEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ipaddress.IPv4Address) or isinstance(obj, ipaddress.IPv6Address):
            return obj.compressed
        return json.JSONEncoder.default(self, obj)

class CommandHandler(tornado.web.RequestHandler):
    def initialize(self, engine):
        self.engine = engine

    def post(self, cmd):
        if cmd == 'resolve_btdht':
            count = self.get_body_argument('count')
            self.engine.resolve_btdht(count)
        elif cmd == 'resolve_ips':
            ips = self.get_body_argument('iplist').splitlines()
            self.engine.resolve_ips(ips)
        elif cmd == 'resolve_web':
            hostnames = self.get_body_argument('hostnames').splitlines()
            self.engine.resolve_web(hostnames)
        elif cmd == 'order_tb':
            order_ip = self.get_body_argument('ip')
            self.engine.order_tb(order_ip)
        elif cmd == 'get_graph':
            pass

class StatusHandler(tornado.websocket.WebSocketHandler):
    def __init__(self, *args, **kwargs):
        self.engine = kwargs.pop('engine')
        super(StatusHandler, self).__init__(*args, **kwargs)


    def open(self):
        self.engine.sockets.add(self)
        print("WebSocket opened")

    def on_close(self):
        self.engine.sockets.remove(self)
        print("WebSocket closed")

    def on_message(self, message):
        pass
        """

        if cmd == 'status':
            status = json.dumps(self.engine.get_status(), cls=MainHandler.IPAddressEncoder)
            self.set_header("Content-Type", "application/json")
            self.write(status)
        elif cmd == 'count':
            self.write({'count': len(self.ps.subjects)})

        elif cmd == 'subjects':
            start = int(self.get_query_argument('start'))
            count = int(self.get_query_argument('count', 50))

            filters = self.get_query_arguments('filter')

            subset = reversed(self.ps.subjects)
            if 'ecnonly' in filters:
                subset = (subject for subject in subset if 'ecnresult' in subject and 'tbresult' not in subject and subject['ecnresult'] != 'offline' and subject['ecnresult'] != 'incomplete')

            if 'tbonly' in filters:
                subset = (subject for subject in subset if 'tbresult' in subject and subject['ecnresult'] != 'offline' and subject['ecnresult'] != 'incomplete')

            answer = list(itertools.islice(subset, start, start+count))

            ansstr = json.dumps({'subjects': answer, 'filters': filters}, cls=MainHandler.IPAddressEncoder)

            self.set_header("Content-Type", "application/json")
            self.write(ansstr)
        elif cmd == 'stats':
            statistics = self.ps.ecn_results.to_json()
            self.set_header("Content-Type", "application/json")
            self.write(statistics)
        elif cmd == 'savegraph':
            import pickle
            pickle.dump(self.ps.tb_results, open('tb.pickle', 'wb'))
        elif cmd == 'graph':
            ips = self.get_arguments('ip')
            if len(ips) == 0:
                self.write({'ips': list(self.ps.tb_results.keys())})
                #self.write({'ips': list(self.tb_results.keys())})
            else:

                gg = GraphGenerator(ips, self.ps.probes, self.ps.tb_results)
                #gg = GraphGenerator(ips, self.ps.probes, self.tb_results)
                self.write({
                    'nodes': gg.nodes,
                    'links': gg.links
                })
        elif cmd == 'order':
            self.ps.resolve_one()
        elif cmd == 'trace':
            ip = self.get_query_argument('ip')
            if ip not in self.ps.subjects_map:
                self.write_error(500, "ip not a subject")
            self.ps.trace(ip)
        else:
            self.send_error(404)"""

class ClientPool:
    def __init__(self, tls_state):
        self.pool = {}
        self.tls_state = tls_state

    def get(self, url):
        if url in self.pool:
            return self.pool[url]
        else:
            client = mplane.client.HttpInitiatorClient({}, self.tls_state, default_url=url)
            self.pool[url] = client
            return client

    def __iter__(self):
        return iter(self.pool.items())

class Subject:
    def __init__(self, ip, port, hostname=None):
        # inherent information
        self.hostname = hostname
        self.ip = ip
        self.port = port

        # set after ecn measurement
        self.ecn = None

        # set after tracebox measurement
        self.tb = None

class WebInterface:
    def __init__(self, addr, tls_state, resolver_url, probe_urls, ipv, chunk_size):
        self.ipv = ipv
        self.sockets = set()

        self.clientpool = ClientPool(tls_state)

        self.resolver = resolver.ResolverApi(self.clientpool.get(resolver_url), ipv)
        self.ecnclient = ecnclient.EcnClient(self.ecn_result_sink, tls_state, probe_urls, ipv)
        self.tbclient = tbclient.TbClient(self.tb_result_sink, tls_state, probe_urls, ipv)

        self.chunk_size = chunk_size

        self.next_chunk_id = 0

        self.subjects = []
        self.subjects_map = {}

        self.addr = addr
        self.app = tornado.web.Application([
                (r"/", tornado.web.RedirectHandler, {"url": "/control.html"}),
                (r"/command/(.*)", CommandHandler, {'engine': self}),
                (r"/status/(.*)", StatusHandler, {'engine': self}),
                (r"/(.*)", tornado.web.StaticFileHandler, {'path': 'gui'})
            ],
            debug=True
        )

        self.server_thread = threading.Thread(target=self.server_func, name='webserver', args=(addr,), daemon=True)
        self.state_thread = threading.Thread(target=self.state_func, name='state', daemon=True)
        self.server_thread.start()
        self.state_thread.start()

    def server_func(self, addr):
        self.app.listen(address=addr[0], port=addr[1])

        tornado.ioloop.IOLoop.current().start()

    def state_func(self):
        while True:
            for url, client in self.clientpool:
                client.retrieve_capabilities(url)

            self.resolver.process()

            #TODO: rewrite ecn and tb client to do a similar workflow as in resolver
            #for client in clients: client.process() etc..

            time.sleep(5)

    def resolve_btdht(self, count):
        self.resolver.resolve_btdht(count, self.resolve_result_sink)

    def resolve_web(self, hostnames):
        self.resolver.resolve_web(hostnames, self.resolve_result_sink)

    def resolve_ips(self, ips):
        self.resolve_result_sink(result=[(ip, 80, ip) for ip in ips])

    def resolve_result_sink(self, label, token, error=None, result=None):
        """
        :param result: Expects a tuple of (ip, port, hostname)
        """
        if error is not None:
            #TODO: report error
            print("error resolving")
            return

        # create subjects
        for ip, port, hostname in result:
            subject = Subject(ip, port, hostname)
            self.subjects.append(subject)
            self.subjects_map[ip] = subject


        flavor = 'tcp'
        if label.startswith('webresolver-'):
            flavor = 'http'

        self.order_ecn(result, flavor)

    def order_ecn(self, addrs, flavor):
        chunk_id = self.next_chunk_id
        self.next_chunk_id+=1
        self.ecnclient.add_job(addrs, chunk_id, self.ipv, flavor)

    def ecn_result_sink(self, result, chunk_id):
        for ip, status in result.get_ip_and_result():
            self.subjects_map[str(ip)].ecn = status

    def tb_result_sink(self, ip, graph):
        self.subjects_map[str(ip)].tb = graph

def run_client(args, config):
    tls_state = mplane.tls.TlsState(config)

    probe_urls = config.items('probes')
    print("Probes specified in configuration file:")
    for name, url in probe_urls:
        print('# {} at {}'.format(name, url))


    resolver_url = config['main']['resolver']
    """
    if args.resolver_web is not None:
        resolver_url = config['main']['resolver']

        # strip whitespaces and \n
        hostnames = [hostname.strip() for hostname in args.resolver_web.readlines()]

        # detect <RANk>,<HOSTNAME>\n format. used by alexa top 1m list.
        hostnames = [line.split(',')[1] for line in hostnames if ',' in line]

        print("Using Web-resolver with {} Domains. Probe URL: {}".format(len(hostnames), resolver_url))
        resolvers['web'] = pathspider.client.resolver.WebResolverClient(tls_state, resolver_url, hostnames=hostnames)

    elif args.resolver_ipfile is not None:
        addrs = [(ip, int(port)) for ip, port in [line.split(':', 1) for line in args.resolver_ipfile.readlines() if len(line) > 0]]

        resolvers['ips'] = pathspider.client.resolver.IPListDummyResolver(addrs)
    """
    if args.webui:
        WebInterface(addr=('localhost', 37100), tls_state=tls_state, resolver_url=resolver_url, probe_urls=probe_urls, ipv=args.ipv, chunk_size=args.chunk_size)


def main():
    # parse command line
    parser = argparse.ArgumentParser(usage='Usage: %(prog)s <mode> [options]')
    parser.add_argument('--version', action='version', version='%(prog)s '+version)

    # TODO: add mode 'cli' for command line interface, mode 'client' is the web interface. need a solution for standalone though...
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

    parser_client.add_argument('--resolver-btdht', '-B', action='store_true',
                                  help='Enable BitTorrent DHT resolver. Acquires addresses by browsing BitTorrent\'s Distributed Hash Table network.')
    parser_client.add_argument('--resolver-web', '-W', metavar='FILE', type=argparse.FileType('rt'),
                                  help='Enable domain resolution. Given a file containing a list of hostnames, separated by newline. The format "<RANK>,<HOSTNAME>\n" is also supported. The hostnames are resolved on a remote server.')
    parser_client.add_argument('--resolver-ipfile', '-I', metavar='FILE', type=argparse.FileType('rt'),
                                  help='Use a file containing a list of \'ipaddress:port\' entries, separated by newline. IP addresses are directly fed to ecnspider.')

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

    if args.mode == 'standalone':
        run_standalone(args, config)
    elif args.mode == 'client':
        run_client(args, config)
    elif args.mode == 'service':
        run_service(args, config)

    while True:
        time.sleep(4)

    print("Shutdown complete.")

if __name__ == '__main__':
    main()

