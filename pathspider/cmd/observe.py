
import argparse
import logging
import json
import queue
import signal
import sys
import threading

from straight.plugin import load

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.base import QUEUE_SIZE

from pathspider.chains.base import Chain

from pathspider.observer import Observer

from pathspider.network import interface_up

chains = load("pathspider.chains", subclasses=Chain)

def run_observer(args):
    logger = logging.getLogger("pathspider")

    if args.list_chains:
        print("The following chains are available:\n")
        for chain in chains:
            print(chain.__name__.lower()[:-5])
        print("\nSpider safely!")
        sys.exit(0)

    if not interface_up(args.interface):
        logger.error("The chosen interface is not up! Cannot continue.")
        logger.error("Try --help for more information.")
        sys.exit(1)

    logger.info("creating observer...")

    chosen_chains = []
    for chosen_chain in args.chains:
        for chain in chains:
            if chosen_chain.lower() + "chain" == chain.__name__.lower():
                chosen_chains.append(chain)

    if len(args.chains) > len(chosen_chains):
        logger.error("Unable to find one or more of the requested chains.")
        logger.error("Try --list-chains to list the available chains.")

    observer_shutdown_queue = queue.Queue(QUEUE_SIZE)
    flowqueue = queue.Queue(QUEUE_SIZE)
    observer = Observer("int:" + args.interface, chosen_chains)

    logger.info("starting observer...")
    threading.Thread(target=observer.run_flow_enqueuer, args=(flowqueue,observer_shutdown_queue)).start()

    logger.info("opening output file " + args.output)
    with open(args.output, 'w') as outputfile:
        logger.info("registering interrupt...")
        def signal_handler(signal, frame):
            observer_shutdown_queue.put(True)
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            result = flowqueue.get()
            if result == SHUTDOWN_SENTINEL:
                logger.info("output complete")
                break
            outputfile.write(json.dumps(result) + "\n")
            logger.debug("wrote a result")

def register_args(subparsers):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = subparsers.add_parser(name='observe',
                                   help="Passively observe network traffic",
                                   formatter_class=SubcommandHelpFormatter)
    parser.add_argument('--list-chains', help="Prints a list of available chains",
                        action='store_true')
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))
    parser.add_argument('chains', nargs='*', help="Observer chains to use")

    # Set the command entry point
    parser.set_defaults(cmd=run_observer)
