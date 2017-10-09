
import argparse
import sys
import logging

import pathspider.cmd.filter
import pathspider.cmd.measure
import pathspider.cmd.observe
import pathspider.cmd.test

cmds = [
    pathspider.cmd.filter,
    pathspider.cmd.measure,
    pathspider.cmd.observe,
    pathspider.cmd.test,
]

def handle_args(argv):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = argparse.ArgumentParser(description=('PATHspider will spider the '
                                                  'paths.'),
                                     formatter_class=SubcommandHelpFormatter)

    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")

    # Add commands
    subparsers = parser.add_subparsers(title="Commands",
                                       metavar='COMMAND', help='command to run')

    # Register commands arguments
    for cmd in cmds:
        cmd.register_args(subparsers)

    args = parser.parse_args(argv[1:])

    # Set up logging
    logging.basicConfig()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # If it's a valid command, run it, or help the user if not
    if hasattr(args, 'cmd'):
        args.cmd(args)
    else:
        parser.print_help()

def handle_args_wrapper():
    handle_args(sys.argv)

if __name__ == "__main__":
    handle_args_wrapper()
