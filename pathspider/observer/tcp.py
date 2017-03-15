
from pathspider.observer.base import Chain

TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

TCP_SA = (TCP_SYN | TCP_ACK)
TCP_SEC = (TCP_SYN | TCP_ECE | TCP_CWR)
TCP_SAEC = (TCP_SYN | TCP_ACK | TCP_ECE | TCP_CWR)
TCP_SAE = (TCP_SYN | TCP_ACK | TCP_ECE)

class TCPChain(Chain):

    def new_flow(self, rec, ip): # pylint: disable=W0613
        rec['tcp_synflags_fwd'] = None
        rec['tcp_synflags_rev'] = None
    
        rec['tcp_fin_fwd'] = False
        rec['tcp_fin_rev'] = False
        rec['tcp_rst_fwd'] = False
        rec['tcp_rst_rev'] = False
    
        rec['tcp_connected'] = False
    
        return True
    
    def tcp(self, rec, tcp, rev):
        if tcp.syn_flag:
            rec['tcp_synflags_rev' if rev else 'tcp_synflags_fwd'] = tcp.flags
    
        # TODO: This test could perhaps be improved upon.
        # This test is intended to catch the completion of the 3WHS.
        if (not rec['tcp_connected'] and rev == 0 and
                rec['tcp_synflags_fwd'] is not None and
                rec['tcp_synflags_rev'] is not None and
                tcp.ack_flag):
            rec['tcp_connected'] = True
    
        if tcp.fin_flag and rev:
            rec['tcp_fin_fwd'] = True
        if tcp.fin_flag and not rev:
            rec['tcp_fin_rev'] = True
        if tcp.rst_flag and rev:
            rec['tcp_rst_rev'] = True
        if tcp.rst_flag and not rev:
            rec['tcp_rst_fwd'] = True
    
        return not ((rec['tcp_fin_fwd'] and rec['tcp_fin_rev']) or
                    rec['tcp_rst_fwd'] or rec['tcp_rst_rev'])
