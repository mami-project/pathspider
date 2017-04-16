import logging
import json

import stem.control

def main(args):
    # Hide all but the most important stem logs
    logging.getLogger('stem').setLevel(logging.ERROR)

    with stem.control.Controller.from_port("127.0.0.1", args.tor_control_port) as controller:
        controller.authenticate(password=args.tor_control_password)

        for relay in controller.get_server_descriptors():
            if args.exits_only and 'Exit' not in relay.flags:
                continue

            job = {
                'sip' if args.server_mode else 'dip': relay.address,
                'torrelay_nickname': relay.nickname,
                'torrelay_fingerprint': relay.fingerprint,
                'torrelay_platform': relay.platform.decode('utf-8'),
            }

            if not args.server_mode:
                job['dp'] = relay.or_port

            print(json.dumps(job))

def register_args(subparsers):
    parser = subparsers.add_parser('torrelays', help="Tor Relay Target List Generator")
    parser.set_defaults(func=main)
    parser.add_argument("--exits-only", action='store_true',
                        help="Only generate jobs for relays with the Exit flag")
    parser.add_argument("--server-mode", action='store_true',
                        help="Generate a 'server mode' target list for incoming connections")
    parser.add_argument("--tor-control-port", default=9051, type=int,
                        help=("The port that Tor is listening on for control connections "
                              "(Default: 9051)"))
    parser.add_argument("--tor-control-password", type=str,
                        help="The authentication password for Tor's control port")
