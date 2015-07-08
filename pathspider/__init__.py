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
    resolver = pathspider.client.resolver.BtDhtResolverClient(tls_state, "http://localhost:18888/")

    if True:
        ecnspider = pathspider.client.PathSpiderClient(100000, tls_state, [('local', "http://localhost:18888/")], resolver)
    elif False:
        import pickle
        chunk = pickle.load(open('compiled_chunk.pickle', 'rb'))
        ecnspider = pathspider.client.PathSpiderClient(0, tls_state, [('local', "http://localhost:18888/")], resolver)

        ecnspider.reasoner_process_chunk({'local': chunk})

        print("done")
    else:
        imp = pathspider.client.TraceboxImp('local', tls_state, "http://localhost:18888/")
        imp.add('192.33.91.96', 22)

    while True:
        time.sleep(10)


def main():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('--mode', '-m', choices=['standalone', 'client', 'service', 'reasoner'], required=True, help='Set the operating mode.')
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

