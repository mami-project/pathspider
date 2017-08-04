
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

import multiprocessing as mp
from pathspider.base import SHUTDOWN_SENTINEL


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
    
    """Setting up sender"""
    ipqueue = mp.Queue(QUEUE_SIZE)
    timequeue = mp.Queue(QUEUE_SIZE)
    
    """Read ips to file and add them to ipqueue for sender, if no file, just put single ip"""
    if file:
        threading.Thread(target=queue_feeder, args=(args.input, ipqueue), daemon = True).start()
    else:
        ipqueue.put(args.ip)
        ipqueue.put(SHUTDOWN_SENTINEL)
    
    send = mp.Process(target=send_pkts,args=(args.hops,args.flows,ipqueue))
    send.start()
    
    """ Setting up merger"""
    #merge = threading.Thread(target=output_merger, args=(flowqueue, timequeue))
    #merge.start

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
      
            result = flowqueue.get()
                           
            if result == SHUTDOWN_SENTINEL:
                logger.info("Output complete")
                break
            
            #Only get the flows with the ttl_exceeded message
            if filter(result):
                continue
             
            #get rtt and additional stuff 
            result = operations(result)
            outputfile.write(json.dumps(str(result)) + "\n")
            logger.debug("wrote a result")

def filter(res): #TODO what happens when we get SHUTDOWN SENTINEL?
    
    #only flows with icmp ttl_exceeded messages are wanted
    for entry in res:
        if entry == 'trace' and res[entry] == False:
            return True
    
def operations(res):    
    """delete unnecessary things and calculate round-trip time in milliseconds"""
    for entry in res.copy():
        if entry == 'trace' or entry == '_idle_bin' or entry == 'pkt_first' or entry == 'pkt_last' or entry == 'seq':
                del res[entry]
        elif entry == 'Destination':
            pass
        else:
            for entry2 in res.copy():
                diff = bytearray()
                if entry2 == 'trace' or entry2 == '_idle_bin' or entry2 == 'pkt_first' or entry2 == 'pkt_last' or entry2 == 'seq':
                    del entry2
                elif entry2 == 'Destination':
                    pass
                elif (int(entry)+9999) == int(entry2):  #comparing sequencenumber of upstream entry2 with hopnumber of downstream entry
                    rtt= (res[entry][1]- res[entry2][0])*1000
                    rtt = round(rtt,3)
                    
                    """bytearray comparison """
                    length = int(len(res[entry][3])/2-1)
                    fail = []
                    for i in range(length): #TODO whats the problem with the length... why isnt it working ?
                        try:
                            bts = res[entry][3][i]^res[entry2][1][i]
                            diff = diff + bts.to_bytes(1, byteorder='big')
                        except IndexError:
                            pass
                        else:
                            if bts != 0:# and i != 8 and i != 10 and i != 11:  #check for differences beside ttl and checksum
                                fail.append("%d: %d" % (i, bts))
                    
                        
                    res[entry] = [res[entry][0], rtt, res[entry][2], res[entry][4], res[entry][5], res[entry][6], res[entry][7], res[entry][8], str(fail)]
                    del res[entry2]
    
    # remove sequence number entries that have not been used                
    for entrytest in res.copy():
        try:
            if int(entrytest) > 100:
                del res[entrytest]
        except ValueError:
            pass
                
    return res.copy()

def queue_feeder(inputfile, ipqueue):
    with open(inputfile) as fh:
        for line in fh:
            try:
                job = json.loads(line)
                if job['conditions'][0] == "ecn.connectivity.broken":# in job.keys():
                    
                    ipqueue.put(job['dip'])  #old
            except ValueError:
                pass
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
    parser.add_argument('--input', default='null', metavar='INPUTFILE', help=("A file containing a list of IPs to traceroute. "
                              "Defaults to standard input."))
    parser.add_argument('--output', default='/dev/stdout', metavar='OUTPUTFILE',
                        help=("The file to output results data to. "
                              "Defaults to standard output."))
    

    # Set the command entry point
    parser.set_defaults(cmd=run_traceroute)
