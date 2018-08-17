import argparse
import bz2
import dateutil.parser
import json
import logging
import sys

from straight.plugin import load

def metadata_from_ps_ndjson(fp):
    y = None
    z = None

    for line in fp:
        d = json.loads(line)

        a = dateutil.parser.parse(d['time']['from'])
        b = dateutil.parser.parse(d['time']['to'])

        if y is None or a < y:
            y = a
        
        if z is None or b > z:
            z = b    

    return {'_time_start': y.strftime("%Y-%m-%dT%H:%M:%SZ"),
            '_time_end': z.strftime("%Y-%m-%dT%H:%M:%SZ")}

def write_metadata_for(filename, metadata_fn):
    metafilename = filename + ".meta.json"

    if filename.endswith(".bz2"):
        open_fn = bz2.open
    else:
        open_fn = open
    
    with open_fn(filename) as fp:
        metadata = metadata_fn(fp)
    
    with open(metafilename, mode="w") as mfp:
        json.dump(metadata, mfp, indent=2)

FILETYPE_MAP = { 'ps-ndjson': metadata_from_ps_ndjson }

def metadata(args):
    logger = logging.getLogger("metadata")

    for filename in args.files:
        logger.info('processing %s...' % (filename,))
        sys.stdout.flush()
        write_metadata_for(filename, FILETYPE_MAP[args.filetype])

def register_args(subparsers):
    parser = subparsers.add_parser(name='metadata',
                                   help="Create PTOv3 metadata files from results")
    parser.add_argument("files", nargs="*", help="input files", metavar="INPUTFILE")
    parser.add_argument("-t", "--filetype", help="filetype [ps-ndjson]",
                        metavar="FILETYPE", default="ps-ndjson")
    # Set the command entry point
    parser.set_defaults(cmd=metadata)
