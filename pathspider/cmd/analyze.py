import logging
import json

from straight.plugin import load

from pathspider.cmd.measure import plugins

def make_result_feeder(filename):
    logger = logging.getLogger("analyzer")
    def result_feeder():
        with open(filename) as fh:
            logger.debug("result_feeder: started")
            for line in fh:
                try:
                    yield json.loads(line)
                except ValueError:
                    logger.warning("Unable to decode JSON for a result, skipping...")
            logger.debug("result_feeder: stopped")

    return result_feeder

def analyze(args):
    result_feeder = make_result_feeder("/dev/stdin")
    print(json.dumps(args.spider.aggregate(result_feeder)))

def register_args(subparsers):
    parser = subparsers.add_parser(name='analyze',
                                   help="Perform an analysis of measurement results")
    # Set the command entry point
    parser.set_defaults(cmd=analyze)

    plugin_subparsers = parser.add_subparsers(title="Plugins",
                                              description="The following plugins are available for use:",
                                              metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        if hasattr(plugin, "aggregate"):
            plugin_subparser = plugin_subparsers.add_parser(plugin.name, help=plugin.description)
            parser.set_defaults(spider=plugin)
