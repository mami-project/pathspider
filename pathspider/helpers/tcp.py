
import socket

from pathspider.base import CONN_OK
from pathspider.base import CONN_TIMEOUT
from pathspider.base import CONN_FAILED

def connect_tcp(source, job, conn_timeout, sockopts=None):
    """
    This helper function will perform a TCP connection. It will not perform
    any special action in the event that this is the experimental flow,
    it only performs a TCP connection.
    """

    if sockopts is None:
        sockopts = []

    if not isinstance(conn_timeout, int):
        raise RuntimeError("Plugin did not set TCP connect conn_timeout.")

    try:
        if ":" in job['dip']:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((source[1], 0))
        else:
            sock = socket.socket(socket.AF_INET)
            sock.bind((source[0], 0))

        for o in sockopts:
            sock.setsockopt(*o)

        sock.settimeout(conn_timeout)
        sock.connect((job['dip'], job['dp']))

        sp = sock.getsockname()[1]

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        return {'sp': sp, 'spdr_state': CONN_OK}
    except TimeoutError:
        return {'sp': sock.getsockname()[1], 'spdr_state': CONN_TIMEOUT}
    except TypeError: # Caused by not having a v4/v6 address when trying to bind
        return {'sp': 0, 'spdr_state': CONN_FAILED}
    except OSError:
        return {'sp': 0, 'spdr_state': CONN_FAILED}
