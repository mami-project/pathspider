
import argparse
import logging
import json
import sys
import threading
import csv

from straight.plugin import load

from pathspider.base import PluggableSpider
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.network import interface_up

plugins = load("pathspider.plugins", subclasses=PluggableSpider)

def job_feeder_ndjson(inputfile, spider):
    logger = logging.getLogger("feeder")
    seen_targets = set()
    with open(inputfile) as fh:
        logger.debug("job_feeder: started")
        for line in fh:
            try:
                job = json.loads(line)
                if 'dip' in job.keys():
                    if job['dip'] in seen_targets:
                        logger.debug("This target has already had a job submitted, skipping.")
                        continue
                    seen_targets.add(job['dip'])
                spider.add_job(job)
            except ValueError:
                logger.warning("Unable to decode JSON for a job, skipping...")

        logger.info("job_feeder: all jobs added, waiting for spider to finish")
        spider.shutdown()
        logger.debug("job_feeder: stopped")

def job_feeder_csv(inputfile, spider):
    logger = logging.getLogger("feeder")
    seen_targets = set()
    with open(inputfile) as csvfile:
        reader = csv.reader(csvfile)
        logger.debug("job_feeder: started")
        for row in reader:
            if len(row) == 4:
                job = {'dip': row[0], 'dp': row[1], 'domain': row[2], 'rank': row[3]}
                if 'dip' in job.keys():
                    if job['dip'] in seen_targets:
                        logger.debug("This target has already had a job submitted, skipping.")
                        continue
                    seen_targets.add(job['dip'])
                spider.add_job(job)
            else:
                logger.warning("Unable to read row for a job, skipping...")

        logger.info("job_feeder: all jobs added, waiting for spider to finish")
        spider.shutdown()
        logger.debug("job_feeder: stopped")




def run_measurement(args):
    logger = logging.getLogger("pathspider")

    try:
        if hasattr(args, "spider"):
            if interface_up(args.interface):
                spider = args.spider(args.workers, "int:" + args.interface, args)
            else:
                logger.error("The chosen interface is not up! Cannot continue.")
                sys.exit(1)
        else:
            logger.error("Plugin not found! Cannot continue.")
            logger.error("Use --help to list all plugins.")
            sys.exit(1)

        logger.info("activating spider...")

        spider.start()

        logger.debug("starting job feeder...")
        if args.csv_input:
            job_feeder = job_feeder_csv
        else:
            job_feeder = job_feeder_ndjson

        threading.Thread(target=job_feeder, args=(args.input, spider)).start()

        with open(args.output, 'w') as outputfile:
            logger.info("opening output file "+args.output)
            while True:
                result = spider.outqueue.get()
                if result == SHUTDOWN_SENTINEL:
                    logger.info("output complete")
                    break
                if not args.output_flows:
                    result.pop("flow_results", None)
                    result.pop("missed_flows", None)
                outputfile.write(json.dumps(result) + "\n")
                logger.debug("wrote a result")
                spider.outqueue.task_done()

    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, dying now.")

def register_args(subparsers):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = subparsers.add_parser(name='measure',
                                   help="Perform a PATHspider measurement",
                                   formatter_class=SubcommandHelpFormatter)
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('-w', '--workers', type=int, default=100,
                        help="Number of workers to use. (Default: 100)")
    parser.add_argument('--input', default='/dev/stdin', metavar='INPUTFILE',
                        help=("A file containing a list of PATHspider jobs. "
                              "Defaults to standard input."))
    parser.add_argument('--csv-input', action='store_true',
                        help=("Indicate CSV format."))
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))
    parser.add_argument('--output-flows', action='store_true',
                        help="Include flow results in output.")

    # Set the command entry point
    parser.set_defaults(cmd=run_measurement)

    # Add plugins
    plugin_subparsers = parser.add_subparsers(title="Plugins",
                                              description="The following plugins are available for use:",
                                              metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        plugin.register_args(plugin_subparsers)
