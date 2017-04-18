
import multiprocessing as mp

from pathspider.base import QUEUE_SIZE
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import DummyObserver

def test_dummy_observer():
    flowqueue = mp.Queue(QUEUE_SIZE)
    observer_shutdown_queue = mp.Queue(QUEUE_SIZE)

    observer = DummyObserver()
    observer_process = mp.Process(
        args=(flowqueue,
              observer_shutdown_queue),
        target=observer.run_flow_enqueuer,
        name='observer',
        daemon=True)
    observer_process.start()

    observer_shutdown_queue.put(True)

    assert flowqueue.get(True, timeout=3) == SHUTDOWN_SENTINEL

    observer_process.join(3)

    assert not observer_process.is_alive()
