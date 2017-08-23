
import argparse
import logging
import json
import queue
import signal
import sys
import threading
import time

from straight.plugin import load

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.base import QUEUE_SIZE

from pathspider.chains.base import Chain

from pathspider.observer import Observer

from pathspider.network import interface_up

from pathspider.traceroute_send import send_pkts
from pathspider.traceroute_base import traceroute

import multiprocessing as mp


chains = load("pathspider.chains", subclasses=Chain)

def run_traceroute(args):
    logger = logging.getLogger("pathspider")


    if not interface_up(args.interface):
        logger.error("The chosen interface is not up! Cannot continue.")
        logger.error("Try --help for more information.")
        sys.exit(1)

    """Check if inputfile or single IP was given as an input argument"""    
    if args.input != 'null':
        file = True
    elif args.ip != 'null':
        file = False
    else:
        logger.error('Please chose either an inputfile or a single IP to traceroute')
        sys.exit(1)

    
    logger.info("Creating observer...")

    chosen_chains = []
    
    """geht besser oder???"""    
    for abc in chains:
        if "traceroutechain" == abc.__name__.lower():
            chosen_chains.append(abc)


    """Setting up observer"""
    observer_shutdown_queue = queue.Queue(QUEUE_SIZE)
    flowqueue = queue.Queue(QUEUE_SIZE)
    resultqueue = queue.Queue(QUEUE_SIZE)
    observer = Observer("int:" + args.interface, chosen_chains)

    logger.info("Starting observer...")
    threading.Thread(target=observer.run_flow_enqueuer, args=(flowqueue,observer_shutdown_queue),daemon = True).start()
    
    mergequeue = queue.Queue(QUEUE_SIZE)
    filter_queue = threading.Thread(target = filter, args=(flowqueue, mergequeue), daemon = True).start()
    
    """ Setting up merger"""
    logger.info("Starting merger...")
    outqueue = queue.Queue(QUEUE_SIZE)
    merge = threading.Thread(target=traceroute.trace_merger, args=(mergequeue, mergequeue, outqueue), daemon = True)
    merge.start()
    
    """Setting up sender"""
    logger.info("Starting sender...")
    ipqueue = mp.Queue(QUEUE_SIZE) 
    send = mp.Process(target=traceroute.sender, args=(ipqueue,ipqueue), daemon = True)
    send.start()
    
    """Read ips to file and add them to ipqueue for sender, if no file, just put single ip"""
    if file:
        threading.Thread(target=queue_feeder, args=(args.cond, args.input, ipqueue), daemon = True).start()
    else:
        ipqueue.put(args.ip)
        ipqueue.put(SHUTDOWN_SENTINEL)

    logger.info("Opening output file " + args.output)
    with open(args.output, 'w') as outputfile:
        logger.info("Registering interrupt...")
        def signal_handler(signal, frame):          #ctrl-c shutdown
            observer_shutdown_queue.put(True)
        signal.signal(signal.SIGINT, signal_handler)
        
        signal.signal(signal.SIGALRM, signal_handler)  #shutdown after sender has finished               
        first = False
        
        while True:
            if not send.is_alive() and not first: #check if sender is finished but do only first time after finishing
                signal.alarm(3)
                first = True
            result = outqueue.get()
               
            if result == SHUTDOWN_SENTINEL:
                logger.info("Output complete")
                break

            outputfile.write(json.dumps(result) + "\n")
            logger.debug("wrote a result")

def filter(res, merge): #Only flows with trace flag should go to merger
    while True:
        entry = res.get()
        if entry == SHUTDOWN_SENTINEL:
            merge.put(SHUTDOWN_SENTINEL)
            break
        try:
            if entry['trace'] == True:
                merge.put(entry)
        except KeyError:
            pass

def queue_feeder(cond, inputfile, ipqueue):
    logger = logging.getLogger("pathspider")
    with open(inputfile) as fh:
        for line in fh:
            job = json.loads(line)
            if cond != None:   #Check if condition in cmd line is given for tracerouting
                try:
                    if cond in job['conditions']:
                        inp = {'dip': job['dip'], 'hops': 30}
                        ipqueue.put(inp)
                except KeyError:
                    logger.debug("Job has no 'conditions' field, skipping")
                    pass
            else:
                inp = {'dip': job['dip'], 'hops': 30} #fixed number of hops at the moment!!!!
                ipqueue.put(inp)  
            
    ipqueue.put(SHUTDOWN_SENTINEL)


       
def register_args(subparsers):
    class SubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def _format_action(self, action):
            parts = super()._format_action(action)
            if action.nargs == argparse.PARSER:
                parts = "\n".join([line for line in parts.split("\n")[1:]])
                parts += "\n\nSpider safely!"
            return parts

    parser = subparsers.add_parser(name='traceroute',help="Perform a traceroute",
                                   formatter_class=SubcommandHelpFormatter)
    parser.add_argument('-hops', type = int, help="Number of hops to destination IP", default = 25)
    parser.add_argument('--ip', type = str, default = 'null', help="IP or URL for which traceroute should be performed")
    parser.add_argument('-i', '--interface', default="eth0",
                        help="The interface to use for the observer. (Default: eth0)")
    parser.add_argument('-f','--flows', type = int, default = 1, 
                        help="Number of times the traceroute should be conducted with different flows. (Default: 1)")
    parser.add_argument('-cond', type = str, default = None, help="Condition in inputfile for doing tracerouting")
    parser.add_argument('--input', default='null', metavar='INPUTFILE', help=("A file containing a list of IPs to traceroute. "
                              "Defaults to standard input."))
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))
    

    # Set the command entry point
    parser.set_defaults(cmd=run_traceroute)
