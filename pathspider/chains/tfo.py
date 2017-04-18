"""
.. module:: pathspider.chains.tcp
   :synopsis: A flow analysis chain for TCP Fast Open

This module contains the TFOChain flow analysis chain which can be used by
PATHspider's Observer for recording TCP Fast Open [RFC7413]_ details.

.. warning: The names of fields used in this chain may be changed soon to
            more closely align with the field names used in other chains.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>
.. codeauthor:: Piet De Vaere <piet@devae.re>

"""

from pathspider.chains.base import Chain
from pathspider.chains.tcp import tcp_options
from pathspider.chains.tcp import TO_FASTOPEN
from pathspider.chains.tcp import TO_EXID_FASTOPEN
from pathspider.chains.tcp import TO_EXPA
from pathspider.chains.tcp import TO_EXPB

class TFOChain(Chain):
    """
    This flow analysis chain records details of TCP Fast Open use in
    the flow record. It will determine whether the IANA assigned TCP option
    kind or the TCP Option Experiment ID [RFC6994]_ was used to identify the
    option, and whether the data sent on the SYN was acknowledged.

    +------------------+--------+-----------------------------------------------------------------+
    | Field Name       | Type   | Meaning                                                         |
    +==================+========+=================================================================+
    | ``tfo_synkind``  | int    | Identified by ``pathspider.chains.tcp.TO_{FASTOPEN,EXPA,EXPB}`` |
    +------------------+--------+-----------------------------------------------------------------+
    | ``tfo_ackkind``  | int    | Identified by ``pathspider.chains.tcp.TO_{FASTOPEN,EXPA,EXPB}`` |
    +------------------+--------+-----------------------------------------------------------------+
    | ``tfo_synclen``  | int    | TFO cookie length in the forward direction                      |
    +------------------+--------+-----------------------------------------------------------------+
    | ``tfo_ackclen``  | int    | TFO cookie length in the reverse direction                      |
    +------------------+--------+-----------------------------------------------------------------+
    | ``tfo_dlen``     | int    | Length of SYN payload in the forward direction                  |
    +------------------+--------+-----------------------------------------------------------------+
    | ``tfo_ack``      | int    | Bytes acknowledged on the SYN in the reverse direction          |
    +------------------+--------+-----------------------------------------------------------------+
    """

    def _cookie(self, tcp):
        opts = tcp_options(tcp)

        if TO_FASTOPEN in opts:
            return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
        elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXID_FASTOPEN):
            return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
        elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXID_FASTOPEN):
            return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
        else:
            return (None, None)

    def new_flow(self, rec, ip):
        """
        For a new flow, all fields will be initialised to ``int(0)``.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        :return: Always ``True``
        :rtype: bool
        """

        rec['tfo_synkind'] = 0
        rec['tfo_ackkind'] = 0
        rec['tfo_synclen'] = 0
        rec['tfo_ackclen'] = 0
        rec['tfo_seq'] = 0
        rec['tfo_dlen'] = 0
        rec['tfo_ack'] = 0

        return True

    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument
        """
        Records TCP Fast Open details.

        TCP Option Used
            The TCP options will be parsed for options that use either the
            IANA assigned TCP option number or one of the TCP Option Experiment
            option numbers with the TCP Option Experiment ID used by TCP Fast
            Open early in its standardisiation. If an option is found, the
            method by which it was identified will be recorded in the
            ``tfo_synkind`` field for the forward direction and ``tfo_ackkind``
            field for the reverse direction.

        TCP Fast Open Cookie Length
            The length of the cookies observed on TCP options will be recorded
            in the ``tfo_synclen`` field for the forward direction and
            ``tfo_ackclen`` for the reverse direction. If no Fast Open option
            is found, this will remain at 0 when the flow is complete.

        Acknowledgement of SYN data
            The length of the data on the SYN in the forward direction will be
            recorded in the ``tfo_dlen`` field. The TCP sequence number for the
            SYN in the forward direction will be recorded in ``tfo_seq`` field
            and the TCP acknowledgement number for the SYN in the reverse
            direction will be recorded in the ``tfo_ack`` field.

        :param rec: the flow record
        :type rec: dict
        :param tcp: the TCP segment that was observed to be part of this flow
        :type ip: plt.tcp
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: Always True
        :rtype: bool
        """

        # Shortcut non-SYN
        if not tcp.syn_flag:
            return True

        # Check for TFO cookie and data on SYN
        if tcp.syn_flag and not tcp.ack_flag:
            (tfo_kind, tfo_cookie) = self._cookie(tcp)
            if tfo_kind is not None:
                rec['tfo_synkind'] = tfo_kind
                rec['tfo_synclen'] = len(tfo_cookie)
                rec['tfo_seq'] = tcp.seq_nbr
                rec['tfo_dlen'] = len(tcp.data) - tcp.doff*4
                rec['tfo_ack'] = 0

        # Look for ACK of TFO data (and cookie)
        elif tcp.syn_flag and tcp.ack_flag and rec['tfo_synkind']:
            rec['tfo_ack'] = tcp.ack_nbr
            (tfo_kind, tfo_cookie) = self._cookie(tcp)
            if tfo_kind is not None:
                rec['tfo_ackkind'] = tfo_kind
                rec['tfo_ackclen'] = len(tfo_cookie)

        # tell observer to keep going
        return True
