import requests
import random
import bz2
import json
import time
import mami_secrets

server = mami_secrets.PTO_HOSTNAME
api_key = mami_secrets.PTO_API_KEY

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

    def __init__(self, server, api_key, campaign=None, target_file_name=None):
        """
        Create a new uploader.

        An uploader represents a single file to be uploaden to the observatory.
        
        :param str server: The hostname of the server running the observatory
        :param str api_key: The api-key to use to authenticate
        :param str campaing: The campaign the file belongs to.
                             Defaults to 'testing'
        :param str target_file_name: How to name the file on the server.
                                     Defaults to a complex, long but unique
                                     filename.
        """

        # create and open the local buffer file
        random.seed()
        self.start_time = int(time.time())
        self.local_filename = "pathspider-output-{}-{}.bz2".format(
                int(self.start_time), random.getrandbits(50))
        self.local_filepath = "/tmp/{}".format(self.local_filename)
        self.local_file_bz2 = bz2.open(self.local_filepath, 'wt')
        
        # store some info about the server
        self.server = server
        self.api_key = api_key
        self.headers = {'X-API-KEY': api_key}

        # and some information about the measurement
        ## I recently found out that Python has  a ternary conditional operator
        ## And I really wanted to use it somewhere.
        self.campaign = campaign if campaign else 'testing'
        ## I also did not know that this was possible,
        ## so I also wanted to use it
        self.target_filename = target_file_name or self.local_filename


    def add_line(self, line):
        """
        Add an extra line of data to the file
        
        :param str line: the data to add
        """
        
        self.local_file_bz2.write(line + '\n')
    
    def set_target_filename(self, name):
        """
        Set the name the file will have once uploaded to the server
        
        :param str name: the filename, without extension
        """
        
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

        url = self.BASE_URL.format(
                hostname = self.server,
                #port = self.port,
                filename = self.target_filename + self.DATA_FILE_EXTENSION)
        return url
                                    

    def upload(self, verify=True):
        """
        Upload the file to the PTO observatory

        :param bool verify: If False, SSL certifcate will not be verified
        :rtype: requests.Response
        :returns: The http response
        """
        
        self.local_file_bz2.close()
        data_filename = self.target_filename + self.DATA_FILE_EXTENSION
        meta_filename = self.target_filename + self.META_FILE_EXTENSION

        files = \
            [ ('data', (data_filename, open(self.local_filepath, 'rb'))),
              ('meta', (meta_filename, self.get_metadata_json())) ]
        
        url = self.get_upload_url()
        
        return requests.post(url, files=files, headers=self.headers,
                verify=verify)

u = Uploader(server, api_key)

for i in range(100):
    u.add_line(str(i))
u.set_campaign('testing')
u.set_target_filename('test11')

print(u.upload(verify=False).text)
