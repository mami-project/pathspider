Using the DNS Resolver
==================

The resolver accepts input formatted as CSV in the style of the Alexa top 1 million website listing:

::

 rank,domain

The output format is the native input format for PATHspider plugins.

Basic Usage
-----------

::

 usage: pathspider dnsresolv [-h] [--timeout TIMEOUT] [--sleep SLEEP]
                             [--add-port ADD_PORT] [--only-first] [--unique-ip]
                             [--www {never,preferred,always,both}]
                             [--debug-skip DEBUG_SKIP]
                             [--debug-count DEBUG_COUNT]
 
 optional arguments:
   -h, --help            show this help message and exit
   --timeout TIMEOUT, -t TIMEOUT
                         Timeout for DNS resolution.
   --sleep SLEEP, -s SLEEP
                         Sleep before every request. Useful for rate-limiting.
   --add-port ADD_PORT, -p ADD_PORT
                         If specified, this port number will be added to every
                         line in the output file.
   --only-first          Only process the first record of every DNS querry. If
                         this is true, at most one A and and one AAAA record
                         will be returned for every domain
   --unique-ip           If set, any output entries with duplicate IP addresses
                         will be discarted
   --www {never,preferred,always,both}
                         Mode for prepending "www." to every domain before
                         resolution. "never" will never prepend "www.".
                         "preferred" will prepend "www." if the resolution of
                         the domain including "www." is successful (more
                         specifically: an A record is returned), and otherwise
                         fall back to omitting the "www.". "always" will
                         prepend "www." and will return no IP address in the
                         output file, even when the domain without "www." can
                         be resolved to one. "both" behaves as "always" and
                         "never" together, that is, it resolves each domain
                         with and without a prepended "www.". All values for
                         this option will never stack the www's, that is
                         "www.example.com" will never be expanded to
                         "www.www.example.com". An existing "www." prefix from
                         a domain from the input file will never be dropped. If
                         this value is not "never", then the output file may
                         contain different FQDNs from the input file, as
                         "example.com" might be turned into "www.example.com".
   --debug-skip DEBUG_SKIP
                         Skip the first N domains, and do not resolve them.
   --debug-count DEBUG_COUNT
                         Perform resolution for at most N domains. All of them
                         if this value is set to 0.
 
Example Usage
-------------

::

 pathspider dnsresolv --add-port 80 <alexa-1m.csv >input-list.txt
