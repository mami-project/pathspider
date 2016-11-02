Uploading to a Path Transparancy Observatory (PTO)
===================================================

PATHspider has build in support to automaticaly upload measurement results to a Path Transparancy observatory (PTO).
The PTO can be used to aggregate measurement results from different PATHspider instances, and run analysis on them.
At the time of this writing, the PTO is not released yet, but when it is, it will be linked here.

Basic usage
-----------

In order for pathspider to upload information to a PTO, a number of parameters can be provided.
These are: 

+--------------+---------------------------------------------------------------------+
| Parameter    | Description                                                         |
+==============+=====================================================================+
| PTO URL      | The URL of the PTO upload service                                   |
+--------------+---------------------------------------------------------------------+
| PTO Filename | How to call the file containing the measurement results on the  PTO |
+--------------+---------------------------------------------------------------------+
| PTO API key  | The API key used to authenticate against the PTO                    |
+--------------+---------------------------------------------------------------------+
| PTO Campaign | The campaign the measurement should be added to                     |
+--------------+---------------------------------------------------------------------+

``PTO URL`` and ``PTO API key`` are mandatory. ``PTO Campaign`` defaults to "testing", and
``PTO Filename`` defaults to a long but unique string.

All of the parameters can be supplied in two ways:
Either by passing a config file using the ``--pto-config`` flag,
or by specifying them with the ``--pto-url``, ``--pto-filename``, ``--pto-api-key`` and ``--pto-campaign`` flags.
Values in the config file will be overriden by values passed as flags.

An example of a valid PATHspider command with automatic PTO upload is:

.. code-block:: shell

 pathspider -i eth0 -w50 --pto-url https://my.observatory.example.com/hdsf/ --pto-api-key abcdefg123456 --pto-campaign my-campaign --pto-filename measurement9001 ecn

Config file
-----------

The config file should be JSON formated. It can contain the following members:
``url``, ``api_key``, ``campaign``, ``filename``.
A config file may contain any subset of these members.

An example of a valid PATHspider command with automatic PTO upload and a PTO config file is:

.. code-block:: shell

 pathspider -i eth0 -w50 --pto-config config.json --pto-api-key abcdefg123456 ecn

where config.json contains the following:

.. code-block:: JSON

 {
     "url": "https://my.observatory.example.com/hdsf/",
     "campaign": "my-campaign",
     "filename": "measurement9001"
 }