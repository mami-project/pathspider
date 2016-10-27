import csv
import logging
import json
import sys
import threading

import pathspider.pto_upload as pto_upload
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.network import interface_up

def job_feeder(inputfile, spider):
    logger = logging.getLogger("feeder")
    with open(inputfile) as fp:
        logger.debug("job_feeder: started")
        reader = csv.reader(fp, delimiter=',', quotechar='"')
        for row in reader:
            if len(row) >= 2:
                # port numbers should be integers
                try:
                    row[1] = int(row[1])
                except ValueError:
                    logger.warning("Invalid port number in job! Skipping!")
                    continue
                spider.add_job(row)

        logger.info("job_feeder: all jobs added, waiting for spider to finish")
        spider.shutdown()
        logger.debug("job_feeder: stopped")

def open_uploader(args):
    """
    If a config file is supplied, create and return an uploader
    
    :param Namespace args: the arguments supplied to the program
    :rtype: None or pto_upload.Uploader
    :returns: either None or an Uploader
    """
    
    if args.pto_config_file == None:
        return None
    
    # args.pto_campaign and args.pto_filename default to None
    # so if they are not supplied, the Uploader will ignore them
    # if they are supplied, they can override values in the configfile
    uploader =  pto_upload.Uploader(
        config_file = args.pto_config_file,
        campaign = args.pto_campaign,
        filename = args.pto_filename)
    
    logging.getLogger("patspider").info('Created uploader')

    return uploader
        

def run_standalone(args):

    logger = logging.getLogger("pathspider")
    
    #set up the pto-uploader
    uploader = open_uploader(args)
   
    try:
        if hasattr(args, "spider"):
            if interface_up(args.interface):
                spider = args.spider(args.workers,
                        "int:" + args.interface, args)
            else:
                logger.error("The chosen interface is not up! Cannot continue.")
                sys.exit(1)
        else:
            logger.error("Plugin not found! Cannot continue.")
            logger.error("Use --help to list all plugins.")
            sys.exit(1)

        logger.info("activating spider...")

        spider.start()

        logger.debug("starting job feeder...")
        threading.Thread(target=job_feeder, args=(args.input, spider)).start()

        with open(args.output, 'w') as outputfile:

            logger.info("opening output file "+args.output)
            while True:
                result = spider.outqueue.get()
                if result == SHUTDOWN_SENTINEL:
                    logger.info("output complete")
                    break
                
                result_line = json.dumps(result) + "\n"
                outputfile.write(result_line)
                if uploader: uploader.add_line(result_line)

                logger.debug("wrote a result")
                spider.outqueue.task_done()

        if uploader:
            result = uploader.upload(verify=False)
            # Do we want to do this? How bad is a couple of MiB in /tmp?
            #if result == True:
            #    uploader.rm_local_file()

    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, dying now.")
