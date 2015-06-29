import argparse
import os
import json

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

def main():
    # setup command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='%(prog)s '+version)
    parser.add_argument('--mode', '-m', choices=['standalone', 'client', 'service'], required=True, help='Set the operating mode.')
    parser.add_argument('--config', '-c', default='pathspider.cfg', help='Set pathspider configuration')

    args = parser.parse_args()
    cfg = json.load(open(os.path.join(here, 'pathspider.cfg'), 'rt'))



if __name__ == '__main__':
    main()

