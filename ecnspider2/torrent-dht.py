import hashlib
import random
import struct
import socket
import threading
import bencodepy
import logging
import queue
import sys
import collections
import time

def create_id():
    h = hashlib.sha1()
    for _ in range(0, 20):
        h.update(struct.pack('B', random.randint(0, 255)))
    return h.digest()

def parse_compact_node_info(data):
    for frame in struct.iter_unpack("!20s4BH", data):
        # (id, (ip, port))
        yield {'id':frame[0], 'addr':("{}.{}.{}.{}".format(frame[1], frame[2], frame[3], frame[4]), frame[5])}

class DHT:
    def __init__(self, bindaddr, bindaddr6):
        self.tid = 0
        self.log = logging.getLogger("DHT")

        self.myid = create_id()

        self.requests = {}

        self.running = True

        self.sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock4.bind(bindaddr)

        self.sock6 = None
        #self.sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #self.sock6.bind(bindaddr6)

        self.thread = threading.Thread(target=self._serverproc, daemon=True)
        self.thread.start()

    def close(self):
        self.running = False

    def _generate_tid(self):
        self.tid += 1
        if self.tid >= 65536:
            self.tid = 0
        return struct.pack("H", self.tid)

    def _send(self, data, addr, callback, user):
        try:
            # determine if ipv4 or ipv6 address
            self.sock4.sendto(bencodepy.encode(data), addr)
            #self.sock6.sendto(bencodepy.encode(data), addr)

            self.requests[data["t"]] = (callback, user)
        except bencodepy.EncodingError:
            self.log.exception("encoding {} to bencode failed.".format(data))
        except Exception:
            self.log.exception("sending {} to {} failed.".format(data, addr))

    def ping(self, addr, target, callback, user=None):
        query = {
            "t": self._generate_tid(),
            "y": "q",
            "q": "ping",
            "a": {"id":target}
        }

        self._send(query, addr, callback, user)

    def find_node(self, addr, target, callback, user=None):
        query = {
            "t": self._generate_tid(),
            "y": "q",
            "q": "find_node",
            "want": ['n4', 'n6'],
            "a": {"id": self.myid, "target": target}
        }

        self._send(query, addr, callback, user)

    def get_peers(self, addr, infohash, callback, user=None):
        raise NotImplemented()

    def announce_peer(self, addr, infohash, token, port, callback, user=None):
        raise NotImplemented()

    def _serverproc(self):
        self.log.info("Running dht server.")
        while self.running:
            try:
                recvd = bencodepy.decode(self.sock4.recv(4096))
                if recvd[b'y'] == b'r':
                    tid = recvd[b't']
                    req = self.requests.get(tid)
                    if req is None:
                        self.log.error("Received response to unknown request.")
                    else:
                        del self.requests[tid]
                        req[0](recvd[b'r'], req[1])

            except bencodepy.DecodingError:
                self.log.exception("bencode decoding of incoming packet failed.")
            except KeyError:
                self.log.exception("Malformed? packet received.")
            except Exception:
                self.log.exception("Other exception...")

        self.log.info("Shutting down dht server.")
        self.sock4.close()
        #self.sock6.close()


def crawler_on_find_node(recvd, nodes_learned):
    try:
        # add every node learned from request. if the queue is full the information is dropped.
        for node in parse_compact_node_info(recvd[b'nodes']):
            nodes_learned.put(node)

    except (KeyError, struct.error, queue.Full):
        pass

def crawler(seed: list, chunk_size = 10, to_ask_queue_size = 100000, bootstrap_size = 1000, extra_info = False):
    # start dht server
    dht = DHT(("0.0.0.0", 6882), ("::", 6882))

    # where new nodes are stored.
    nodes_learned = queue.Queue()

    addrs_to_ask = collections.deque(maxlen=to_ask_queue_size)

    bootstrap = set(seed)

    call_find_node = lambda addr: dht.find_node(addr, create_id(), callback=crawler_on_find_node, user=nodes_learned)

    time_last_request = 0

    try:
        while True:
            if nodes_learned.qsize() < 1000 and time_last_request+0.1 <= time.time():
                time_last_request = time.time()

                if len(addrs_to_ask) == 0:
                    print("queue empty.. restarting")
                    addrs_to_ask.extend(bootstrap)

                for _ in range(0, chunk_size):
                    try:
                        addr = addrs_to_ask.popleft()
                    except IndexError:
                        break

                    # try to retrieve c.a. 64 endpoints per node
                    for _ in range(0, 8):
                        call_find_node(addr)

            try:
                node = nodes_learned.get(block=True, timeout=0.1)

                if extra_info:
                    yield node
                else:
                    yield (node, nodes_learned.qsize(), len(addrs_to_ask), len(bootstrap))

                addrs_to_ask.append(node['addr'])

                # remember some nodes to get back to if we get stuck and need to restart.
                if len(bootstrap) < bootstrap_size:
                    bootstrap.add(node['addr'])

            except queue.Empty:
                pass


    except GeneratorExit:
        dht.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("{} <number_of_ips> <filename>".format(sys.argv[0]))

    count = int(sys.argv[1])
    filename = sys.argv[2]

    #seed = [("dht.transmissionbt.com", 6881)]
    seed = [("212.129.33.50", 6881)]

    addrs_unique = set()

    dummy = 0
    index = 0
    with open(filename, "wt") as f:
        for index, (node, learned_queue_len, to_ask_queue_len, bootstrap_len) in enumerate(crawler(seed)):
            try:
                if node['addr'] in addrs_unique:
                    continue

                addrs_unique.add(node['addr'])

                f.write("{addr[0]} {addr[1]} {id}\n".format(**node))

                if index >= count:
                    break

                if dummy == 100:
                    print("collected {} of {} (learned queue: {}, to ask queue: {}, bootstrap set: {})".format(index, count, learned_queue_len, to_ask_queue_len, bootstrap_len))
                    dummy = 0
                dummy += 1
            except KeyboardInterrupt:
                break

    print("nodes written to file: {}".format(index))
