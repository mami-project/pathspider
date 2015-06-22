import argparse
import os

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

def main():
    # setup command line arguments
    print("pathspider {}".format(version))

if __name__ == '__main__':
    main()
