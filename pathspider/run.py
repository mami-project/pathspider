
import argparse
import csv
import logging
import time
import threading
import json


from straight.plugin import load

from pathspider.base import Spider
from pathspider.base import SHUTDOWN_SENTINEL

import pathspider.util.dnsresolv

import sys

plugins = load("pathspider.plugins", subclasses=Spider)

def job_feeder(inputfile, spider):
    logger = logging.getLogger("feeder")
    with open(inputfile) as fp:
        logger.debug("job_feeder: started")
        reader = csv.reader(fp, delimiter=',', quotechar='"')
        for row in reader:
            if len(row) > 0:
                # port numbers should be integers
                row[1] = int(row[1])
                spider.add_job(row)

        logger.info("job_feeder: all jobs added, waiting for spider to finish")
        spider.shutdown()
        logger.debug("job_feeder: stopped")

def run_pathspider():
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]
                                   if 'template' not in line])
                parts += "\n\nSpider safely!"
            return parts

    parser = argparse.ArgumentParser(description=('Pathspider will spider the '
            'paths.'), formatter_class=SubcommandHelpFormatter)
    parser.add_argument('-s', '--standalone', action='store_true', help='''run in
        standalone mode. this is the default mode (and currently the only supported
        mode). in the future, mplane will be supported as a mode of operation.''')
    parser.add_argument('-i', '--interface', help='''the interface to use for the observer''', default="eth0")
    parser.add_argument('-w', '--workers', type=int, help='''number of workers to use''', default=100)
    parser.add_argument('--input', default='/dev/stdin', metavar='INPUTFILE', help='''a file
            containing a list of remote hosts to test, with any accompanying
            metadata expected by the pathspider test. this file should be formatted
            as a comma-seperated values file.''')
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE', help='''the file to output results data to''')

    # Add plugins
    subparsers = parser.add_subparsers(title="Plugins", description="The following plugins are available for use:", metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        plugin.register_args(subparsers)

    pathspider.util.dnsresolv.register_args(subparsers)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    logger = logging.getLogger("pathspider")

    if hasattr(args, "func"):
        # Run a utility function
        sys.exit(args.func(args))

    try:
        if hasattr(args, "spider"):
            spider = args.spider(args.workers, "int:" + args.interface, args)
        else:
            logger.error("Plugin not found! Cannot continue.")
            logger.error("Use --help to list all plugins.")
            sys.exit(1)

        logger.info("activating spider...")

        spider.start()

        logger.info("starting to add jobs")
        threading.Thread(target=job_feeder, args=(args.input, spider)).start()

        with open(args.output, 'w') as outputfile:
            while True:
                result = spider.outqueue.get()
                if result == SHUTDOWN_SENTINEL:
                    break
                outputfile.write(json.dumps(result) + "\n")
                spider.outqueue.task_done()

    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, dying now.")

if __name__ == "__main__":
    run_pathspider()
