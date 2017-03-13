
import sys
import logging
import subprocess
import traceback
import io
import json

import pycurl

import stem
import stem.control

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count
from pathspider.observer.tcp import tcp_state_setup
from pathspider.observer.tcp import tcp_state
from pathspider.observer.tcp import TCP_SEC

from pathspider.plugins.ecn import ecn_setup
from pathspider.plugins.ecn import ecn_code

from pathspider.network import ipv4_address

class ECN(SynchronizedSpider, PluggableSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=1, # Currently this plugin can not cope with more than 1 worker
                         libtrace_uri=libtrace_uri,
                         args=args, server_mode=True)
        self.conn_timeout = args.timeout
        self.comparetab = {}
        self.ipv4_address = ipv4_address(libtrace_uri[4:])
        self.url = 'http://' + self.ipv4_address + ':' + str(self.args.www_port) # TODO: this will die if libtrace uri isn't an interface
        self.controller = stem.control.Controller.from_port("127.0.0.1", self.args.tor_control_port)
        self.controller.authenticate(password=self.args.tor_control_password)
        self.controller.set_conf('__LeaveStreamsUnattached', '1')    # leave stream management to us

    def config_zero(self):
        """
        Disables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=0'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator disabled ECN")

    def config_one(self):
        """
        Enables ECN server-mode negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")

    def pre_connect(self, job):
        job['dp'] = self.args.www_port
        job['dip'] = self.ipv4_address

    def _make_request(self):
        output = io.BytesIO()
        
        query = pycurl.Curl()
        query.setopt(pycurl.URL, self.url)
        query.setopt(pycurl.PROXY, 'localhost')
        query.setopt(pycurl.PROXYPORT, self.args.tor_socks_port)
        query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
        query.setopt(pycurl.CONNECTTIMEOUT, self.args.timeout)
        query.setopt(pycurl.WRITEFUNCTION, output.write)
        
        try:
            query.perform()
            return output.getvalue().decode('utf-8')
        except pycurl.error as exc:
            raise ValueError("Unable to reach %s (%s)" % (self.url, exc))

    def connect(self, job, config):
        path = ["25C6A6B60CFB9E8201145011A900E38F349C02D9", job['exit_fingerprint']] # TODO: Make the path configurable

        try:
            circuit_id = self.controller.new_circuit(path, await_build = True)
        except stem.CircuitExtensionFailed:
            return {'sp': 0, 'spdr_state': CONN_FAILED}

        def attach_stream(stream):
            if stream.status == 'NEW':
                self.controller.attach_stream(stream.id, circuit_id)

        self.controller.add_event_listener(attach_stream, stem.control.EventType.STREAM) # pylint: disable=E1101
    
        try:
            check_page = self._make_request()
    
            result = json.loads(check_page)

            job['sip'] = result['sip'] # In case the exit uses a different IP to the OR Port for exit traffic

            return {'sp': result['sp'], 'spdr_state': CONN_OK}
        except ValueError:
            return {'sp': 0, 'spdr_state': CONN_FAILED}
        finally:
            self.controller.remove_event_listener(attach_stream)

    def create_observer(self):
        """
        Creates an observer with ECN-related chain functions.
        """

        logger = logging.getLogger('ecn')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tcp_state_setup, ecn_setup],
                            ip4_chain=[basic_count, ecn_code],
                            ip6_chain=[basic_count, ecn_code],
                            tcp_chain=[tcp_state])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def combine_flows(self, flows):
        conditions = []

        if flows[1]['observed'] and flows[1]['tcp_connected']:
            if flows[1]['tcp_synflags_fwd'] & TCP_SEC == TCP_SEC:
                conditions.append('ecn.client.enabled')
                if flows[0]['spdr_state'] == CONN_OK and flows[1]['spdr_state'] == CONN_OK:
                    conditions.append('ecn.connectivity.works')
                elif flows[0]['spdr_state'] == CONN_OK and not flows[1]['spdr_state'] == CONN_OK:
                    conditions.append('ecn.connectivity.broken')
                elif not flows[0]['spdr_state'] == CONN_OK and flows[1]['spdr_state'] == CONN_OK:
                    conditions.append('ecn.connectivity.transient')
                else:
                    conditions.append('ecn.connectivity.offline')

                conditions.append('ecn.ipmark.ect0.seen' if flows[1]['ecn_ect0_fwd'] else 'ecn.ipmark.ect0.not_seen')
                conditions.append('ecn.ipmark.ect1.seen' if flows[1]['ecn_ect1_fwd'] else 'ecn.ipmark.ect1.not_seen')
                conditions.append('ecn.ipmark.ce.seen' if flows[1]['ecn_ce_fwd'] else 'ecn.ipmark.ce.not_seen')
            else:
                conditions.append('ecn.client.disabled')
    

        return conditions

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn', help="Explicit Congestion Notification")
        parser.add_argument("--timeout", default=5, type=int, help="The timeout to use for attempted connections in seconds (Default: 5)")
        parser.add_argument("--www-port", default=8080, type=int, help="The port on which a webserver is running (Default: 8080)")
        parser.add_argument("--tor-socks-port", default=9050, type=int, help="The port that Tor is listening on for SOCKS5 connections (Default: 9050)")
        parser.add_argument("--tor-control-port", default=9051, type=int, help="The port that Tor is listening on for control connections (Default: 9051)")
        parser.add_argument("--tor-control-password", type=str, help="The authentication password for Tor's control port")
        parser.set_defaults(spider=ECN)
