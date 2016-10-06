
import queue

from pathspider.observer import SHUTDOWN_SENTINEL

class Observer:
    def __init__(self):
        pass

    def run_flow_enqueuer(self, flowqueue, irqueue=None):
        while True:
            try:
                if irqueue:
                    irqueue.get()
                    flowqueue.put(SHUTDOWN_SENTINEL)
                    break
            except queue.Empty:
                pass
