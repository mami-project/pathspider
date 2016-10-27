import requests
import random
import bz2
import json
import time
import logging
import hashlib
import os

class Uploader():
    """
    Class used to upload data to the pto-observatory.

    Writes measurement results to a bzip2 compressed file,
    and then uploads that file to the observatory.
    """

    BASE_URL = 'https://{hostname}/hdfs/up/{filename}'
    FORMAT = 'fjson-bz2'
    DATA_FILE_EXTENSION = '.bz2'
    META_FILE_EXTENSION = '.meta'

    def __init__(self, config_file=None, hostname=None, api_key=None,
                        campaign=None, filename=None):
        """
        Create a new uploader.

        An uploader represents a single file to be uploaden to the observatory.

        :param str config_file: The path the a JSON formated config file
        :param str hostname: The hostname of the server running the observatory
        :param str api_key: The api-key to use to authenticate
        :param str campaign: The campaign the file belongs to.
                             Defaults to 'testing'
        :param str filename: How to name the file on the server.  Defaults to a
                             complex, long but unique filename.
        """

        self.logger = logging.getLogger('uploader')
        self.open_file_bz2()
        self.open = True

        # set defaults
        self.campaign = 'testing'
        self.set_target_filename(self.local_filename)
        self.hostname = None
        self.api_key = None

        # if we have a config file, read it first
        if config_file:
            self.read_config_file(config_file)

        # if kwargs are supplied, override values from config file
        if hostname:
            self.hostname = hostname
        if api_key:
            self.api_key = api_key
        if campaign:
            self.campaign = campaign
        if filename:
            self.set_target_filename(filename)

        # check if hostname and api_key are set
        if self.hostname == None:
            self.logger.warning('Hostname not set, Uploader will _not_ upload')
            return
        if self.api_key == None:
            self.logger.warning('Api_key not set, Uploader will _not_ upload')
            return

        self.headers = {'X-API-KEY': self.api_key}

    #def __del__(self):
        #self.rm_local_file()

    def read_config_file(self, path):
        """
        Read out a JSON formated config file

        The config file can contain the following keys:
        'hostname': the hostname of the server to connect to
        'api_key': the api key to use for the connection
        'campaign': the campaign to add the measurement to
        'filename': how to name the uploaded file on the server

        :param str path: the path to the config file
        """
        try:
            config_file = open(path)
        except (FileNotFoundError, PermissionError):
            self.logger.error('Could not read config file')
            return

        try:
            config_data = json.loads(config_file.read())
        # TODO: catch the right exceptions here
        except: # json.JSONDecodeError:
            self.logger.error('Config file is not properly JSON formated')
        finally:
            config_file.close()

        if 'hostname' in config_data:
            self.hostname = config_data['hostname']
        if 'api_key' in config_data:
            self.api_key = config_data['api_key']
        if 'campaign' in config_data:
            self.campaign = config_data['campaign']
        if 'filename' in config_data:
            self.set_target_filename(config_data['filename'])


    def open_file_bz2(self):
        """
        Open the local buffer file witht he bz2 library
        """

        # create and open the local buffer file
        random.seed()
        self.start_time = int(time.time())
        self.local_filename = "pathspider-output-{}-{}.bz2".format(
                int(self.start_time), random.getrandbits(50))
        self.local_filepath = "/tmp/{}".format(self.local_filename)
        self.local_file_bz2 = bz2.open(self.local_filepath, 'wt')

    def close_file(self):
        if self.open:
            self.local_file_bz2.close()
            self.open = False

    def rm_local_file(self):
        """
        Remove the local buffer file
        """

        self.close_file()

        try:
            os.remove(self.local_filepath)
        except FileNotFoundError:
            # File does noet exist, so we are happy
            pass
        except PermissionError:
            self.logger.error("Tried to delete local file, "
            "but did not have sufficient permissions")


    def add_line(self, line):
        """
        Add an extra line of data to the file

        :param str line: the data to add
        """

        if not self.open:
            self.logger.warning("Trying to write to Uploader after it has been"
            " closed. Data not saved.")
            return

        if line[-1] != '\n':
            line = line + '\n'
        self.local_file_bz2.write(line)

    def set_target_filename(self, name):
        """
        Set the name the file will have once uploaded to the server
        If the filename does not end with the right extension, append it.

        :param str name: the filename
        """

        if not name.endswith(self.DATA_FILE_EXTENSION):
            name = name + self.DATA_FILE_EXTENSION
        self.target_filename = name

    def set_campaign(self, campaign):
        """
        Set the campaign the file belongs to

        :param str campaign: the name of the campaign
        """

        self.campaign = campaign

    def get_metadata_json(self, stop_time=None):
        """
        Get a JSON formated string containing the metadata for the upload

        :param int stop_time: Should be a unix timestamp. If set it will be used
                              to populate the 'stop_time' field of the metadata.
                              If not set, the current time will be used
        :rtype: int
        :returns: A JSON formated string
        """

        metadata = {'msmntCampaign': self.campaign,
                    'format': self.FORMAT,
                    'start_time': self.start_time}
        if stop_time:
            metadata['stop_time'] = int(stop_time)
        else:
            metadata['stop_time'] = int(time.time())

        return json.dumps(metadata)

    def get_upload_url(self):
        """
        Get the url to be used to upload the file

        :rtype: string
        :returns: the url to be used to upload the file
        """

        # check if hostname and api_key are set
        if self.hostname == None:
            self.logger.error('Hostname not set, Uploader will _not_ upload')
            return
        if self.api_key == None:
            self.logger.error('Api_key not set, Uploader will _not_ upload')
            return

        url = self.BASE_URL.format(
                hostname = self.hostname,
                #port = self.port,
                filename = self.target_filename)
        return url

    def sha1(self):
        """
        Calculate the SHA1 hash of the local buffer file

        :rtype: str
        :returns: the SHA1 has
        """

        buffer_size = 1024*1024 # read 1 MiB at the time
        inputfile = open(self.local_filepath, 'rb')
        sha1 = hashlib.sha1()

        while True:
            data = inputfile.read(buffer_size)
            if not data:
                break
            sha1.update(data)

        inputfile.close()

        return sha1.hexdigest()

    def upload(self, verify=True):
        """
        Upload the file to the PTO observatory

        :param bool verify: If False, SSL certifcate will not be verified
        :rtype: bool
        :returns: True if upload was successfull, False otherwise
        """

        self.close_file()

        data_filename = self.target_filename
        meta_filename = self.target_filename + self.META_FILE_EXTENSION

        files = \
            [ ('data', (data_filename, open(self.local_filepath, 'rb'))),
              ('meta', (meta_filename, self.get_metadata_json())) ]

        url = self.get_upload_url()
        # This will load the entire file in to memory before sending.
        # Just so you know.
        response =  requests.post(url, files=files, headers=self.headers,
                verify=verify)

        if self.sha1() == response.text:
            self.logger.info("Results successfully uploaded to PTO")
            return True

        else:
            self.logger.error("Upload to PTO failed")
            self.logger.error("Expected resonse: '{}'".format(self.sha1()))
            self.logger.error("Received resonse: '{}'".format(response.text))
            return False

## Just some debug tests, safe to ignore
if __name__ == "__main__":
    import mami_secrets

    hostname = mami_secrets.PTO_HOSTNAME
    api_key = mami_secrets.PTO_API_KEY

    u = Uploader(hostname, api_key)

    for i in range(100):
        u.add_line(str(i))
    u.set_campaign('testing')
