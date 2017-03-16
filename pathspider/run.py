
import argparse
import sys
import logging

from straight.plugin import load

from pathspider.base import PluggableSpider

import pathspider.util.dnsresolv
import pathspider.util.torrelays

utils = []

if "--tor-exits" in sys.argv:
    plugins = load("pathspider.plugins.torexits", subclasses=PluggableSpider)
else:
    plugins = load("pathspider.plugins", subclasses=PluggableSpider)
    utils.append(pathspider.util.dnsresolv)
    utils.append(pathspider.util.torrelays)

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
    parser.add_argument('-s', '--standalone', action='store_true',
                        help="Run in standalone mode.", default=True)
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('-w', '--workers', type=int, default=100,
                        help="Number of workers to use. (Default: 100)")
    parser.add_argument('--input', default='/dev/stdin', metavar='INPUTFILE',
                        help=("A file containing a list of PATHspider jobs. "
                              "Defaults to standard input."))
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))
    parser.add_argument('--output-flows', action='store_true',
                        help="Include flow results in output.")
    parser.add_argument('--tor-exits', action='store_true',
                        help="Tor exit plugins (server mode).")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Log debug-level output.")

    # Add plugins
    subparsers = parser.add_subparsers(title="Plugins",
                                       description="The following plugins are available for use:",
                                       metavar='PLUGIN', help='plugin to use')
    for plugin in plugins:
        print("Registering plugin {}".format(repr(plugin)))
        plugin.register_args(subparsers)

    for util in utils:
        util.register_args(subparsers)

    if (len(sys.argv) == 1 or
            len(sys.argv) == 2 and sys.argv[1] == "--tor-exits"):
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
