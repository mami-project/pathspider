
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
from pathspider.chains.basic import BasicChain

from pathspider.observer import Observer

from pathspider.network import interface_up

plugins = load("pathspider.chains", subclasses=Chain)

def run_observer(args):
    logger = logging.getLogger("pathspider")

    if not interface_up(args.interface):
        logger.error("The chosen interface is not up! Cannot continue.")
        sys.exit(1)

    logger.info("creating observer...")

    observer_shutdown_queue = queue.Queue(QUEUE_SIZE)
    flowqueue = queue.Queue(QUEUE_SIZE)
    observer = Observer("int:" + args.interface, [BasicChain])

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
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))

    # Set the command entry point
    parser.set_defaults(cmd=run_observer)
