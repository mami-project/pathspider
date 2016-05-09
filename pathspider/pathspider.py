import argparse
from ecnspider3 import ECNSpider
import collections 
import csv
import time
import logging

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='''Pathspider will spider the
            paths.''')
    parser.add_argument('-s', '--standalone', action='store_true', help='''run in
        standalone mode. this is the default mode (and currently the only supported
        mode). in the future, mplane will be supported as a mode of operation.''')
    parser.add_argument('-i', '--input-file', dest='inputfile', metavar='INPUTFILE', help='''a file
            containing a list of remote hosts to test, with any accompanying
            metadata expected by the pathspider test. this file should be formatted
            as a comma-seperated values file.''')
    parser.add_argument('-o', '--output-file', dest='outputfile', metavar='OUTPUTFILE')

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)
    
    try:
        ecnspider = ECNSpider(2, "int:enp0s25")
        ecnspider.run()

        with open(args.inputfile) as inputfile:
            reader = csv.reader(inputfile, delimiter=',', quotechar='"')
            for row in reader:
                # port numbers should be integers
                row[1] = int(row[1])

                ecnspider.add_job(row)

        with open(args.outputfile, 'w') as outputfile:
            while ecnspider.running:
                try:
                    result = ecnspider.merged_results.popleft()
                except IndexError:
                    time.sleep(1)
                else:
                    outputfile.write(str(result) + "\n")

    except KeyboardInterrupt:
        print("kthxbye")

