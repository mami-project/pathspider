import argparse
import configparser
import os
import mplane.component
import mplane.tls
import mplane.utils
import threading
import pathspider.client
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

    # run service
    tc = threading.Thread(target=mplane.component.ListenerHttpComponent, args=(config,), daemon=True)
    tc.start()

    # run supervisor locally


def run_client(args, config):
    tls_state = mplane.tls.TlsState(config)
    resolver = pathspider.client.BtDhtResolverClient(tls_state, "http://localhost:18888/")

    ecnspider = pathspider.client.EcnSpiderClient(1000, tls_state, [('local', "http://localhost:18888/")], resolver)

    while True:
        time.sleep(10)


def main():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('--mode', '-m', choices=['standalone', 'client', 'service'], required=True, help='Set the operating mode.')
    parser.add_argument('--config', '-c', default='AUTO', help='Set pathspider configuration file.')

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

