
import pkg_resources
import queue
import nose
import threading
import unittest

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

class ChainTestCase(unittest.TestCase):

    def setUp(self):
        try:
            import plt # libtrace may not be available
        except ImportError:
            raise nose.SkipTest

    def create_observer(self, test_trace, chains):
        self.lturi = "pcap:" + pkg_resources.resource_filename("pathspider", "tests/data/" +
                                                               test_trace)
        self.observer = Observer(self.lturi, chains)
        self.flowqueue = queue.Queue()

    def run_observer(self):
        self.observer_thread = threading.Thread(target=self.observer.run_flow_enqueuer,
                                                args=(self.flowqueue,),
                                                daemon=True)
        self.observer_thread.start()

        flows = []

        while True:
            f = self.flowqueue.get()
            if f == SHUTDOWN_SENTINEL:
                break
            flows.append(f)

        return flows

    def tearDown(self):
        self.observer_thread.join(3)
        assert not self.observer_thread.is_alive()
