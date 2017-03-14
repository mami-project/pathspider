import json

import stem.control

def main(args):
    with stem.control.Controller.from_port("127.0.0.1", args.tor_control_port) as controller:
        controller.authenticate(password=args.tor_control_password)

        for relay in controller.get_network_statuses():
            if 'Exit' not in relay.flags:
                continue

            print(json.dumps({
                'sip': relay.address,
                'exit_nickname': relay.nickname,
                'exit_fingerprint': relay.fingerprint,
            }))

def register_args(subparsers):
    parser = subparsers.add_parser('torrelays', help="Tor Relay Target List Generator")
    parser.set_defaults(func=main)
    parser.add_argument("--exits-only", action='store_true',
                        help="Only generate jobs for relays with the Exit flag")
    parser.add_argument("--tor-control-port", default=9051, type=int,
                        help=("The port that Tor is listening on for control connections "
                              "(Default: 9051)"))
    parser.add_argument("--tor-control-password", type=str,
                        help="The authentication password for Tor's control port")
