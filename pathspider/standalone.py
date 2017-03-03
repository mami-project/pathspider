
import csv
import logging
import json
import sys
import threading

from pathspider.base import SHUTDOWN_SENTINEL

from pathspider.network import interface_up

def job_feeder(inputfile, spider):
    logger = logging.getLogger("feeder")
    with open(inputfile) as fh:
        logger.debug("job_feeder: started")
        for line in fh:
            try:
                job = json.loads(line)
                if 'dip' not in job.keys():
                    if 'ip' in job.keys():
                        job['dip'] = job.pop('ip')
                        logger.warning("Job specified 'ip' not 'dip'. This is deprecated and will fail in future PATHspider releases.")
                    else:
                        logger.warning("Skipping job due to lack of a target. 'dip' key not present.")
                        continue
                if 'dp' not in job.keys():
                    if 'port' in job.keys():
                        job['dp'] = job.pop('port')
                        logger.warning("Job specified 'port' not 'dp'. This is deprecated and will fail in future PATHspider releases.")
                spider.add_job(job)
            except ValueError:
                logger.warning("Unable to decode JSON for a job, skipping...")

        logger.info("job_feeder: all jobs added, waiting for spider to finish")
        spider.shutdown()
        logger.debug("job_feeder: stopped")

def run_standalone(args):
    logger = logging.getLogger("pathspider")

    try:
        if hasattr(args, "spider"):
            if interface_up(args.interface):
                spider = args.spider(args.workers, "int:" + args.interface, args)
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
                outputfile.write(json.dumps(result) + "\n")
                logger.debug("wrote a result")
                spider.outqueue.task_done()

    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, dying now.")
