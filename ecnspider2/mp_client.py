import mplane
import mplane.tls
import mplane.utils
import mplane.client
import argparse
import configparser
import time

def retrieve_addresses(count, url, config, when = "now ... future"):
    tls_state = mplane.tls.TlsState(config)

    client = mplane.client.HttpInitiatorClient(tls_state)

    client.retrieve_capabilities(url)

    cap_label = 'btdhtspider-ip4'

    try:
        spec = client.invoke_capability(cap_label, when, { "btdhtspider.count": count })
        token_label = spec.get_token()
    except KeyError as e:
        print("Specified URL does not support '"+label+"' capability.")
        raise e

    addrs = []

    while True:
        time.sleep(0.5)
        try:
            res = client.result_for(token_label)
        except KeyError:
            continue

        if isinstance(res, mplane.model.Exception):
            print(res.__repr__())
        elif isinstance(res, mplane.model.Receipt):
            continue
        elif isinstance(res, mplane.model.Result):
            for row in res.schema_dict_iterator():
                addrs.append((row['destination.ip4'], row['destination.port'], row['btdhtspider.nodeid']))
        else:
            print(res)

        return addrs


class EcnspiderClient:
    def __init__(self, config, url):
        # boot the model
        self.config = config
        tls_state = mplane.tls.TlsState(config)

        self._client = mplane.client.HttpInitiatorClient(tls_state)

        self._client.retrieve_capabilities(url)

        addrs = retrieve_addresses(200, url, config)
        print("got addresses")

        params = {
            "destination.ip4": [addr[0] for addr in addrs],
            "destination.port": [addr[1] for addr in addrs],
            "dhtbtspider.nodeid": [addr[2] for addr in addrs]
        }

        try:
            self.spec = self._client.invoke_capability('ecnspider-ip4', "now ... future", params)
        except KeyError as e:
            print("Specified URL does not support 'ecnspider-ip4' capability.")
            raise e

        self.receiver()

    def receiver(self):
        i = 0
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

            for token in self._client.result_tokens():
                res = self._client.result_for(token)
                if isinstance(res, mplane.model.Exception):
                    print(res.__repr__())
                else:
                    print("Result  (token %s): %s" % (token, res.when()))
                    for row in res.schema_dict_iterator():
                        print(row)

                self._client.forget(token)
            time.sleep(1)



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

    addrs = retrieve_addresses(200, config['client'].get('dhtbtspider_url'), config)
    print(len(addrs), addrs)
    # Start the supervisor
    #supervisor = EcnspiderClient(config, "localhost:8888")
