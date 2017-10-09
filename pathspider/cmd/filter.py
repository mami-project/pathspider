
import logging
import json

from pathspider.cmd.measure import job_feeder_ndjson
from pathspider.cmd.measure import job_feeder_csv

class FilterSpider:

    def __init__(self, dp=None):
        self.dp = dp

    def add_job(self, job):
        if self.dp is not None:
            job['dp'] = self.dp
        print(json.dumps(job))

    def shutdown(self):
        pass

def filter(args):
    if args.csv_input:
        job_feeder = job_feeder_csv
    else:
        job_feeder = job_feeder_ndjson

    spider = FilterSpider(dp=args.dp)

    job_feeder("/dev/stdin", spider)

def register_args(subparsers):
    parser = subparsers.add_parser(name='filter',
                                   help="Pre-process a target list")
    parser.add_argument('--csv-input', action='store_true',
                        help=("Indicate CSV format."))
    parser.add_argument('--dp', type=int, default=None,
                        help=("A destination port to add to the targets."))

    # Set the command entry point
    parser.set_defaults(cmd=filter)
