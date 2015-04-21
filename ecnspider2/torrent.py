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
import itertools
from ipaddress import ip_address

def randbytes(num):
    return struct.pack('{}B'.format(num), *[random.randint(0, 255) for _ in range(0, num)])

def create_id():
    #rest = randbytes(12)
    #id = b'-TR2480-'+rest
    #print(id, len(id))
    return randbytes(20)

def parse_compact_node_info(data):
    for frame in struct.iter_unpack("!20s4BH", data):
        # (id, (ip, port))
        yield {'id':frame[0], 'addr':("{}.{}.{}.{}".format(frame[1], frame[2], frame[3], frame[4]), frame[5])}

def parse_compact_node6_info(data):
    for frame in struct.iter_unpack("!20s8HH", data):
        # (id, (ipv6, port))
        yield {'id':frame[0], 'addr':('{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}:{:04X}'.format(*frame[1:9]), frame[9])}

REQUEST_TYPE_PING = 0x01
REQUEST_TYPE_FIND_NODE = 0x02
Request = collections.namedtuple("Request", ['tid', 'time', 'addr', 'type'])
QUEUE_SLEEP = 0.1

class TorrentDhtSpider:
    def __init__(self, bindaddr=('', 6881), ip_version=4, unique=False, bootstrap=(('router.bittorrent.com', 6881), ('dht.transmissionbt.com', 6881))):
        self.tid = 0

        self.myid = create_id()

        self.lock = threading.RLock()
        self.requests = collections.OrderedDict()

        # addresses for the user
        self.addr_cache = queue.Queue()

        self.unique = set() if unique else None

        self.requests_timeout = 0
        self.requests_success = 0

        # addresses to ask for more addresses
        self.addr_pool = collections.deque(bootstrap)

        self.running = False

        self.ip_version = ip_version

        if self.ip_version != 4 and self.ip_version != 6:
            raise ValueError('ip_version needs to be either 4 or 6.')

        if self.ip_version == 4:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 100000)
        self.sock.bind(bindaddr)
        self.sock.settimeout(0.1)

    def start(self):
        self.running = True
        threading.Thread(name="dht sender", target=self.sender, daemon=True).start()
        threading.Thread(name="dht receiver", target=self.receiver, daemon=True).start()

    def stop(self):
        self.running = False

    def __iter__(self):
        return self

    def __next__(self):
        addr = self.addr_cache.get()

        return addr

    def _generate_tid(self):
        self.tid += 1
        if self.tid >= 65536:
            self.tid = 0
        return struct.pack("H", self.tid)

    def _send(self, tid, data, addr, type):
        bytes_sent = self.sock.sendto(bencodepy.encode(data), addr)

        with self.lock:
            self.requests[tid] = Request(tid, time.time(), addr, type)

        return bytes_sent

    def ping(self, addr, sender):
        tid = self._generate_tid()
        query = {
            "t": tid,
            "y": "q",
            "q": "ping",
            "a": {"id":sender}
        }

        return self._send(tid, query, addr, REQUEST_TYPE_PING)

    def find_node(self, addr, target):
        tid = self._generate_tid()
        query = {
            "t": tid,
            "y": "q",
            "q": "find_node",
            #"want": ['n4', 'n6'],
            "a": {"id": self.myid, "target": target}
        }

        return self._send(tid, query, addr, REQUEST_TYPE_FIND_NODE)

    def get_peers(self, addr, infohash, callback, user=None):
        raise NotImplemented()

    def announce_peer(self, addr, infohash, token, port, callback, user=None):
        raise NotImplemented()

    def sender(self):
        """

        """
        logger = logging.getLogger("torrent-dht")
        logger.debug("Sender thread started.")

        max_bandwidth = 5*1024 # bytes/sec

        slot_time = 0.1

        track = collections.deque()
        amount = 0
        slot_amount = max_bandwidth*slot_time

        last = int(time.time())
        while self.running:
            tnow = time.time()

            bandwidth = amount/1024/slot_time
            if last != int(tnow) and bandwidth > 0:
                last = int(tnow)
                success_rate = self.requests_success / (self.requests_timeout + self.requests_success) if self.requests_success > 0 else 0
                logger.debug("bandwidth: {:0.3f} kiB/s, addr_cache: {}, addr_pool: {}, requests: {}, success: {}, success rate: {:0.0%}".format(bandwidth, self.addr_cache.qsize(), len(self.addr_pool), len(self.requests), self.requests_success, success_rate))

            # cleanup bandwidth track
            while len(track) > 0:
                if track[0][0] + slot_time < tnow:
                    _, value = track.popleft()
                    amount -= value
                else:
                    break

            # cleanup requests
            with self.lock:
                to_delete = []
                for key in self.requests:
                    if self.requests[key].time + 15 < tnow:
                        to_delete.append(key)
                        self.requests_timeout += 1
                    else:
                        break

                for key in to_delete:
                    del self.requests[key]

            # are there enough addresses in the cache?
            if self.addr_cache.qsize() > 10:
                time.sleep(QUEUE_SLEEP)
                continue

            # am i below maximum requests running?
            if len(self.requests) > 100:
                time.sleep(QUEUE_SLEEP)
                continue

            # is there bandwidth available for another request?
            if amount > slot_amount:
                time.sleep(QUEUE_SLEEP)
                continue

            # get an address
            with self.lock:
                addr = self.addr_pool.popleft()

                # if there are not enough addr in the pool, fill it in again
                if len(self.addr_pool) < 100:
                    self.addr_pool.append(addr)

            # send request

            try:
                bytes_sent = self.find_node(addr, create_id())
            except bencodepy.EncodingError:
                logger.exception("encoding packet failed.")
            except Exception:
                logger.exception("sending {} failed.".format(addr))
            else:
                track.append((time.time(), bytes_sent))
                amount += bytes_sent

    def receiver(self):
        """

        """
        logger = logging.getLogger("torrent-dht")
        logger.info("Receiver thread started.")
        while self.running:
            try:
                data = self.sock.recv(4096)
            except OSError:
                time.sleep(QUEUE_SLEEP)
                continue

            try:
                recvd = bencodepy.decode(data)
                if recvd[b'y'] == b'r':
                    tid = recvd[b't']

                    response = recvd[b'r']

                    with self.lock:
                        try:
                            req = self.requests[tid]
                        except KeyError:
                            logger.warning("Received response to unknown request.")
                        else:
                            del self.requests[tid]

                            if req.type == REQUEST_TYPE_FIND_NODE:
                                if self.ip_version == 4:
                                    nodes = parse_compact_node_info(response[b'nodes'])
                                else:
                                    nodes = parse_compact_node6_info(response[b'nodes6'])

                                for node in nodes:
                                    addr = node['addr']
                                    nodeid = node['id']

                                    # if the unique option is enabled, ignore duplicates
                                    if self.unique is not None:
                                        if addr[0] in self.unique:
                                            continue
                                        self.unique.add(addr[0])

                                    self.addr_cache.put((addr, nodeid))
                                    self.requests_success += 1

                                    if len(self.addr_pool) > 100:
                                        self.addr_pool.popleft()
                                    self.addr_pool.append(addr)

                            elif req.type == REQUEST_TYPE_PING:
                                print("addr: {}, id: {}".format(req.addr, response[b'id']))
                            else:
                                logger.warning("Unknown request type: {}. Seems like I've created a Request record with a unexpected request type.".format(req.type))
            except bencodepy.DecodingError:
                logger.exception("bencode decoding of incoming packet failed.")
            except KeyError:
                logger.exception("Malformed? packet received.")
            except Exception:
                logger.exception("Other exception...")


        logger.info("Shutting down receiver.")
        self.sock.close()

if __name__ == "__main__":
    logger = logging.getLogger('torrent-dht')
    logger.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler(sys.stderr)
    consoleFormatter = logging.Formatter('%(asctime)s [%(threadName)-10.10s] [%(levelname)-5.5s]  %(message)s')
    consoleHandler.setFormatter(consoleFormatter)
    consoleHandler.setLevel(logging.DEBUG)
    logger.addHandler(consoleHandler)

    logger.info("Logging started")

    dht = TorrentDhtSpider(('', 3710), ip_version=4, unique=True)
    dht.start()

    for addr, nodeid in dht:
        print(addr)
        time.sleep(random.uniform(0.01, 0.1))
