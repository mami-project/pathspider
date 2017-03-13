
from pathspider.observer import SHUTDOWN_SENTINEL

class Observer:
    def __init__(self):
        pass

    def run_flow_enqueuer(self, flowqueue, irqueue=None): # pylint: disable=R0201
        irqueue.get()
        flowqueue.put(SHUTDOWN_SENTINEL)
