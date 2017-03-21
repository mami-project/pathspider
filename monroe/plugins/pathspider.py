import argparse
import sys

from monroe.cli import MonroeCliPlugin
from monroe.cli import mnr_crt
from monroe.cli import mnr_key
from monroe.core import Scheduler

from pathspider.run import plugins


def handle_args(args):

    if not hasattr(args, "spider"):
        print("No plugin was specified. Run 'monroe pathspider --help' for more "
              "information.")
        return

    spider_args = None
    for i in range(0, len(sys.argv)):
        if sys.argv[i] == args.spider.name:
            spider_args = sys.argv[i:]

    if spider_args == None:
        raise RuntimeError("Unable to decode arguments") 

    scheduler = Scheduler(mnr_crt, mnr_key)
    print(scheduler.auth())

    experiment = scheduler.new_experiment(script="pathspider/monroe-test",
                                          nodecount=args.nodecount,
                                          testing=True)

    experiment.jsonstr({'spider_args': spider_args})

    rep = scheduler.submit_experiment(experiment)

    print(rep.message())
    print()
    print("Once your experiment is completed, you can retrieve the results with:")
    print()
    print("    monroe results --exp {}".format(rep.experiment()))
    print()

class Pathspider(MonroeCliPlugin):
    @classmethod
    def register_args(cls, subparsers):
        class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
            def _format_action(self, action):
                parts = super()._format_action(action)
                if action.nargs == argparse.PARSER:
                    parts = "\n".join([line for line in parts.split("\n")[1:]])
                    parts += "\n\nSpider safely!"
                return parts

        parser = subparsers.add_parser(
            "pathspider",
            help="Submit a PATHspider experiment on MONROE",
            formatter_class=SubcommandHelpFormatter)

        parser.add_argument(
            "--name", metavar="NAME", help="Sets the experiment name")
        parser.add_argument(
            "--nodecount",
            metavar="NODECOUNT",
            help="Sets the number of nodes to deploy on (Default: 1)",
            default=1,
            type=int)

        parser.set_defaults(func=handle_args)

        # Add plugins
        subparsers = parser.add_subparsers(
            title="Plugins",
            description="The following plugins are available for use:",
            metavar='PLUGIN',
            help='plugin to use')
        for plugin in plugins:
            plugin.register_args(subparsers)
