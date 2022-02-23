
import argparse
import logging
import json
import sys
import threading
import csv

from straight.plugin import load

from pathspider.base import PluggableSpider
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.cmd.measure import job_feeder_csv
from pathspider.cmd.measure import job_feeder_ndjson
from pathspider.cmd.measure import run_measurement
from pathspider.network import interface_up

plugins = load("pathspider.plugins", subclasses=PluggableSpider)

def run_traceroute(args):
    run_measurement(args, traceroute=True)

def register_args(subparsers):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = subparsers.add_parser(name='trace',
                                   help="Perform a PATHspider traceroute",
                                   formatter_class=SubcommandHelpFormatter)
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('-w', '--workers', type=int, default=20,
                        help="Number of workers to use. (Default: 20)")
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
    parser.set_defaults(cmd=run_traceroute)

    # Add plugins
    plugin_subparsers = parser.add_subparsers(title="Plugins",
                                              description="The following plugins are available for use:",
                                              metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        plugin.register_args(plugin_subparsers)
