
import argparse
import sys
import logging

from straight.plugin import load

from pathspider.base import PluggableSpider

import pathspider.util.dnsresolv


plugins = load("pathspider.plugins", subclasses=PluggableSpider)

def handle_args(argv):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = argparse.ArgumentParser(description=('Pathspider will spider the '
            'paths.'), formatter_class=SubcommandHelpFormatter)
    parser.add_argument('-s', '--standalone', action='store_true', help='''run in
        standalone mode. this is the default mode (and currently the only supported
        mode). in the future, mplane will be supported as a mode of operation.''', default=True)
    parser.add_argument('-i', '--interface', help='''the interface to use for the observer''', default="eth0")
    parser.add_argument('-w', '--workers', type=int, help='''number of workers to use''', default=100)
    parser.add_argument('--input', default='/dev/stdin', metavar='INPUTFILE', help='''a file
            containing a list of remote hosts to test, with any accompanying
            metadata expected by the pathspider test. this file should be formatted
            as a comma-seperated values file. Defaults to standard input.''')
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE', 
            help='''the file to output results data to. Defaults to standard output.''')
    parser.add_argument('-v', '--verbose', action='store_true', help='''log debug-level output.''')

    # Add plugins
    subparsers = parser.add_subparsers(title="Plugins", description="The following plugins are available for use:", metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        try:
            plugin.register_args(subparsers)
        except AttributeError:
            # Don't try to register arguments for subclasses that don't care.
            pass

    pathspider.util.dnsresolv.register_args(subparsers)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(argv[1:])

    logging.basicConfig()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if hasattr(args, "func"):
        # Run a utility function
        sys.exit(args.func(args))

    if args.standalone:
        # we're running in standalone mode
        from pathspider.standalone import run_standalone
        run_standalone(args)

def handle_args_wrapper():
    handle_args(sys.argv)

if __name__ == "__main__":
    handle_args_wrapper()
