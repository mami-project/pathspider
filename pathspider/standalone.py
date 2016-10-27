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

def run_standalone(args):
    do_pto_upload = False

    logger = logging.getLogger("pathspider")
    
    # Read the pto configuration
    if args.pto_config_file:
        try:
            conf_file = open(args.pto_config_file)
            pto_config = json.loads(conf_file.read())
        except FileNotFoundError:
            logger.error('PTO config file does not exist')
        except PermissionError:
            logger.error('Insufficient permissions for PTO config file')
        except json.JSONDecodeError:
            logger.error('PTO config file is not formatted properly')
        else:
            if ('hostname' in pto_config) and ('api_key' in pto_config):
                do_pto_upload = True
            else:
                logger.error('PTO config file is not complete')
        finally:
            conf_file.close()

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

        # set up the Uploader to send the data to the observatory
        if do_pto_upload:
            logger.info("I will upload these results to your observatory")
            pto_uploader = pto_upload.Uploader(pto_config['hostname'], 
                                               pto_config['api_key'])
            if args.pto_filename:
                pto_uploader.set_target_filename(args.pto_filename)
            if args.pto_campaign:
                pto_uploader.set_campaign(args.pto_campaign)

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
                if do_pto_upload: pto_uploader.add_line(result_line)

                logger.debug("wrote a result")
                spider.outqueue.task_done()

        if do_pto_upload:
            response=pto_uploader.upload(verify=False)
            print(response.text)
            logger.info('PTO upload completed')

    except KeyboardInterrupt:
        logger.error("Received keyboard interrupt, dying now.")
