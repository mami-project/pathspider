import stem
import stem.control
import pycurl

from pathspider.base import CONN_DISCARD
from pathspider.helpers.http import connect_http


def connect_tor_http(controller,
                     circuit_path,
                     job,
                     conn_timeout,
                     curlopts=None,
                     curlinfos=None):
    """
    This helper function will perform an HTTP request over Tor. It will not
    perform any special action in the event that this is the experimental flow,
    but can be customised on a per-call basis through the curlopts argument.
    """

    if curlopts is None:
        curlopts = {}

    curlopts[pycurl.PROXY] = "localhost"
    curlopts[pycurl.PROXYPORT] = 9050
    curlopts[pycurl.PROXYTYPE] = pycurl.PROXYTYPE_SOCKS5_HOSTNAME

    attach_error = []

    try:
        if circuit_path is not None:
            circuit_path = circuit_path.split(",")
        circuit_id = controller.new_circuit(circuit_path, await_build=True)
    except stem.CircuitExtensionFailed:
        return {"spdr_state": CONN_DISCARD}

    def attach_stream(stream):
        try:
            if stream.status == 'NEW':
                if (stream.target_address == job['dip'] and
                        stream.target_port == job['dp']):
                    controller.attach_stream(stream.id, circuit_id)
        except stem.OperationFailed:
            attach_error.append(None)

    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM) # pylint: disable=no-member
    result = connect_http(None, job, conn_timeout, curlopts, curlinfos)
    controller.remove_event_listener(attach_stream)

    if len(attach_error) > 0:
        return {"spdr_state": CONN_DISCARD}

    return result
