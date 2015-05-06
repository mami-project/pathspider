import mplane
import mplane.tls
import mplane.client
import argparse
import configparser
import time
import torrent

class EcnspiderClient():
    def __init__(self, config, url):
        # boot the model
        mplane.model.initialize_registry()
        self._caps = []
        self.config = config
        tls_state = mplane.tls.TlsState(config)

        self._client = mplane.client.HttpInitiatorClient(tls_state)

        self._client.retrieve_capabilities(url)

        dht = torrent.TorrentDhtSpider(unique=True)
        dht.start()
        addrs = [next(dht) for _ in range(0, 100)]
        dht.stop()

        params = {
            "list.destination.ip4": [addr[0][0] for addr in addrs],
            "list.destination.port": [addr[0][1] for addr in addrs],
            "btdhtspider.nodeid": ["whatever" for _ in addrs]
        }

        try:
            self.spec = self._client.invoke_capability('ecnspider-ip4', "now ... future", params)
        except KeyError:
            print("Specified URL does not support 'ecnspider-ip4' capability.")
            exit(1)

        self.receiver()

    def receiver(self):
        while True:
            for label in self._client.receipt_labels():
                rec = self._client.result_for(label)
                if isinstance(rec, mplane.model.Receipt):
                    print("Receipt %s (token %s): %s" %
                        (label, rec.get_token(), rec.when()))

            for token in self._client.receipt_tokens():
                rec = self._client.result_for(token)
                if isinstance(rec, mplane.model.Receipt):
                    if rec.get_label() is None:
                        print("Receipt (token %s): %s" % (token, rec.when()))

            for label in self._client.result_labels():
                res = self._client.result_for(label)
                if not isinstance(res, mplane.model.Exception):
                    print("Result  %s (token %s): %s" %
                          (label, res.get_token(), res.when()))

            for token in self._client.result_tokens():
                res = self._client.result_for(token)
                if isinstance(res, mplane.model.Exception):
                    print(res.__repr__())
                elif res.get_label() is None:
                    print("Result  (token %s): %s" % (token, res.when()))

            time.sleep(0.5)

if __name__ == "__main__":
    mplane.model.initialize_registry()

    # look for TLS configuration
    parser = argparse.ArgumentParser(description="mPlane ecnspider client")
    parser.add_argument('--config', metavar="config-file",
                        help="Configuration file")
    args = parser.parse_args()

    # check if conf file parameter has been inserted in the command line
    if not args.config:
        print('\nERROR: missing --config\n')
        parser.print_help()
        exit(1)

    # Read the configuration file
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(mplane.utils.search_path(args.config))

    # Start the supervisor
    supervisor = EcnspiderClient(config, "localhost:8888")
