
import pycurl
import argparse
import logging
import json
import bz2
import os
import sys

from io import BytesIO
from argparse import Namespace
import pathspider.cmd.metadata as metadata 

def compress_file(filename):
    '''
        compress file to bz2 if not already done
        
        :param filename: filename of file to compress
        :type filename: str
        :return: str -- filename of compressed file
    '''
    if filename.endswith(".bz2"):
        return filename
    else:
        new_filename = filename + ".bz2"
        compressionLevel = 9
        with open(filename, 'rb') as data:
            fh = open(new_filename, "wb")
            fh.write(bz2.compress(data.read(), compressionLevel))
            fh.close()
        return new_filename

def is_duplicate(url):
    '''
        True if file is in campaign else False
        
        :param url: filename of file to check
        :type url: str
        :return: bool -- True if file is duplicate else False
    '''
    answer = send_http_request(url)
    try:
        json.loads(answer)
        return True
    except:
        return False

def send_http_request(url, headers=[], filename=None):
    '''
        Uploads file to campaign on PTO server
        
        :param url: name of campaign the data belongs to
        :type url: str
        :param filename: filename of file to compress
        :type filename: str
        :param headers: additional http headers
        :type headers: str
        :return: str -- answer from server
    '''
    buffer = BytesIO()
    c = pycurl.Curl()
    #set curl options
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    # add extra headers
    c.setopt(pycurl.HTTPHEADER, ["Authorization: APIKEY " + TOKEN] + headers)
    if not filename == None:
        # upload the contents of this file --data-binary @file
        c.setopt(c.UPLOAD, 1)
        file = open(filename, "rb")
        c.setopt(c.READDATA, file)
        c.perform()
        c.close()
        # File must be kept open while Curl object is using it
        file.close()
    else:
        c.perform()
        c.close()
    return buffer.getvalue().decode('iso-8859-1')

def upload_data(filename, url, filetype):
    '''
        Uploads datafile to campaign on PTO server
        
        :param url: url to upload file to
        :type url: str
        :param filename: filename of file to upload
        :type filename: str
        :param filetyp: "data" or "metadata"
        :type filetype: str    
    '''
    if filetype == 'metadata':
        headers = ["Content-type: application/json"]
    else:
        headers=["Content-type: application/bzip2"]
    answer = send_http_request(url, headers=headers, filename=filename)
    try:
        data = json.loads(answer)
        return (True, data["__data"])
    except:
        return (False, answer)

def main(url, campaign, token, filename, metafilename):
    '''
        Uploads a given file to a campaign on the PTO using the provided token.
        Also creates and uploads the neccessary meta data.
        Prevents overwriting existing files on PTO
        
        :param campaign: name of campaign the data belongs to
        :type campaign: str
        :param filename: filename of file to compress and upload
        :type filename: str
        :param token: authentification tocken for PTO API
        :type token: str
        :param entry: Additional meta data tags
        :type entry: list of str
    '''
    logger = logging.getLogger("uploader")
    logger.debug("started uploader")

    global TOKEN
    TOKEN = token

    BASELINK = url + campaign + "/" if url.endswith('/') else url + "/" + campaign + "/"

    # check if metadata already exist on server
    url = BASELINK + os.path.basename(filename + '.bz2')
    logger.debug("checking url: " + url)
    if not is_duplicate(url):
        link = BASELINK + os.path.basename(metafilename).split(".")[0] + ".ndjson.bz2"
        for filetype in ['metadata', 'data']:
            logger.debug('Start processing %s' % filetype)
            if filetype == 'metadata':
                #upload and read out data link for data upload
                success, data_link = upload_data(metafilename, link, filetype)
            else:
                # compress data if necessary and upload data
                success, data_link = upload_data(compress_file(filename), data_link, filetype)
            if not success:
                logger.info('Uploading %s failed' % filetype)
                logger.debug('Unexpected answer. Excepted .json. Instead was: %s' % str(data_link))
                break
            else:
                logger.info('Uploaded %s' % filetype)
        logger.info('Upload complete')
    else:
        logger.info('File %s already exists.' % os.path.basename(filename))
        sys.exit(1)

def uploader(args):
    if args.metadata is None:
        #create metadata
        metadata_args = Namespace(files=[args.filename], filetype="ps-ndjson", extra=args.add)
        metadata.metadata(metadata_args)
        metafilename = args.filename +  ".meta.json"
    else:
        metafilename = args.metadata
    main(args.url, args.campaign, args.token, args.filename, metafilename)

def register_args(subparsers):
    parser = subparsers.add_parser(name='upload',
                                   help="Uploads data to PTO\nCreates metadata if not provided")

    parser.add_argument("filename", help="Data file in .ndjson", metavar="FILENAME")
    parser.add_argument("--campaign", help="Campaign the data belongs to")
    parser.add_argument("--token", help="Authentification token")
    parser.add_argument("--metadata", help="Metadata filename. Ignores --add", metavar="FILENAME")
    parser.add_argument("--add", nargs='+', help="Additional metadata entry", metavar="TAG:VAL")
    parser.add_argument("--url", default='https://v3.pto.mami-project.eu/raw/', help="URL for PTO data upload")

    # Set the command entry point
    parser.set_defaults(cmd=uploader)
