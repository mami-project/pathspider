
import logging
import pathspider
import nose

def runtestsuite(args):
    # Undo the logging basic config to allow for log capture
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Collect and run tests
    nose.run(argv=['nosetests', '-v', 'pathspider'])

def register_args(subparsers):
    parser = subparsers.add_parser(name='test',
                                   help="Run the built in test suite")

    # Set the command entry point
    parser.set_defaults(cmd=runtestsuite)
