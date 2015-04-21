import ipfix
import ipfix.reader
import pandas as pd
import numpy as np
import collections
import itertools
import ecnspider
import bz2

from ipaddress import ip_network
from datetime import datetime, timedelta

# Flags constants
TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

# QoF TCP Characteristics constants
QOF_ECT0 =    0x01
QOF_ECT1 =    0x02
QOF_CE   =    0x04
QOF_TSOPT =   0x10
QOF_SACKOPT = 0x20
QOF_WSOPT =   0x40

# Flow end reasons
END_IDLE = 0x01
END_ACTIVE = 0x02
END_FIN = 0x03
END_FORCED = 0x04
END_RESOURCE = 0x05

# Default IEs are the same you get with QoF if you don't configure it.
# Not super useful but kind of works as My First Flowmeter :)
DEFAULT_FLOW_IES = [    "flowStartMilliseconds",
                        "flowEndMilliseconds",
                        "sourceIPv4Address",
                        "destinationIPv4Address",
                        "protocolIdentifier",
                        "sourceTransportPort",
                        "destinationTransportPort",
                        "octetDeltaCount",
                        "packetDeltaCount",
                        "reverseOctetDeltaCount",
                        "reversePacketDeltaCount",
                        "flowEndReason"]

def iter_group(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

def _dataframe_iterator(tuple_iterator, columns, chunksize=100000):
    for group in iter_group(tuple_iterator, chunksize):
        yield pd.DataFrame.from_records([rec for rec in 
                  filter(lambda a: a is not None, group)], columns=columns)

def dataframe_from_ipfix_stream(stream, ienames=DEFAULT_FLOW_IES, 
                                chunksize=100000, count=None, sample=1, skip=0):
    """ 
    read an IPFIX stream into a dataframe, selecting only records
    containing all the named IEs. uses chunked reading from the ipfix iterator
    to reduce memory requirements on read.
     
    """
    ielist = ipfix.ie.spec_list(ienames)
    columns = [ie.name for ie in ielist]
    r = ipfix.reader.from_stream(stream)
    i = r.tuple_iterator(ielist)
    if count:
        i = itertools.islice(i, skip, skip + (count * sample), sample)
    
    # concatenate chunks from a dataframe iterator wrapped around
    # the stream's tuple iterator
    return pd.concat(_dataframe_iterator(i, columns, chunksize),
                     ignore_index=True)
        
def dataframe_from_ipfix(filename, ienames=DEFAULT_FLOW_IES, 
                         chunksize=100000, count=None, sample=1, skip=0, open_fn=open):
    """ 
    read an IPFIX file into a dataframe, selecting only records
    containing all the named IEs. uses chunked reading from the ipfix iterator
    to reduce memory requirements on read.
     
    """    
    with open_fn(filename, mode="rb") as f:
        # get a stream to read from
        return dataframe_from_ipfix_stream(f, ienames, chunksize, count, sample, skip)

#
# General flow processing functions
#
def coerce_timestamps(df, cols=("flowStartMilliseconds", "flowEndMilliseconds")):    
    """
    coerce timestamps to datetime64
    
    modifies the dataframe in place and returns it.
    """
    # coerce timestamps to numpy types
    for col in cols:
        try:
            df[col] = df[col].astype("datetime64[ns]")
        except KeyError:
            pass

    return df

def derive_duration(df):
    """
    add a floating point duration column
    to a dataframe including flowStartMilliseconds and flowEndMilliseconds
    
    modifies the dataframe in place and returns it.
    """
    try:
        df['durationSeconds'] = (df['flowEndMilliseconds'] - 
                                 df['flowStartMilliseconds']).map(
                                         lambda x: x.item()/1e9)
    except KeyError:
        pass
    
    return df

def _flag_string(flagnum):
    flags = ((TCP_CWR, 'C'),
             (TCP_ECE, 'E'),
             (TCP_URG, 'U'),
             (TCP_ACK, 'A'),
             (TCP_PSH, 'P'),
             (TCP_RST, 'R'),
             (TCP_SYN, 'S'),
             (TCP_FIN, 'F'))
    
    flagstr = ""
    for flag in flags: 
        if (flag[0] & flagnum):
            flagstr += flag[1]
    return flagstr

def derive_flag_strings(df):
    """
    add columns to a dataframe with textual descriptions of TCP flags
    
    modifies the dataframe in place and returns it.
    """
    
    cols = ('initialTCPFlags', 'reverseInitialTCPFlags',
            'unionTCPFlags', 'reverseUnionTCPFlags',
            'tcpControlBits', 'reverseTcpControlBits')
    
    for col in cols:
        try:
            df[col+"String"] = df[col].map(_flag_string)
        except KeyError:
            pass

###
### QoF management
###

def start_qof(yaml_path, libtrace_uri, filename):
    pass

def stop_qof(qof):
    qof.terminate()
    qof.wait()

def load_qof_df(filename, ipv6_mode=False, open_fn=open, spider_idx=None, count=None):
    # shortcut flags
    S = TCP_SYN
    R = TCP_RST
    SA = TCP_SYN | TCP_ACK
    SEW = (TCP_SYN | TCP_ECE | TCP_CWR)
    SAE = (TCP_SYN | TCP_ECE | TCP_ACK)
    SAEW = (TCP_SYN | TCP_ECE | TCP_ACK | TCP_CWR)
    QECT = (QOF_ECT0 | QOF_ECT1)
    QECT0 = QOF_ECT0
    QECT1 = QOF_ECT1
    QCE = QOF_CE

    # select destination address IE
    if ipv6_mode:
        dip_ie = "destinationIPv6Address"
    else:
        dip_ie = "destinationIPv4Address"
    
    # raw dataframe
    df = dataframe_from_ipfix(filename, open_fn=open_fn, count=count,
               ienames=(  "flowStartMilliseconds",
                          "octetDeltaCount",
                          "reverseOctetDeltaCount",
                          "transportOctetDeltaCount",
                          "reverseTransportOctetDeltaCount",
                          "tcpSequenceCount",
                          "reverseTcpSequenceCount",
                          dip_ie,
                          "sourceTransportPort",
                          "destinationTransportPort",
                          "initialTCPFlags",
                          "reverseInitialTCPFlags",
                          "unionTCPFlags",
                          "reverseUnionTCPFlags",
                          "lastSynTcpFlags",
                          "reverseLastSynTcpFlags",
                          "tcpSynTotalCount",
                          "reverseTcpSynTotalCount",
                          "qofTcpCharacteristics",
                          "reverseQofTcpCharacteristics",
                          "reverseMinimumTTL",
                          "reverseMaximumTTL"))

    # turn timestamps into pandas-friendly types
    df = coerce_timestamps(df)
    
    # cast flags down to reduce memory consumption
    df["initialTCPFlags"] = df["initialTCPFlags"].astype(np.uint8)
    df["reverseInitialTCPFlags"] = df["reverseInitialTCPFlags"].astype(np.uint8)
    df["unionTCPFlags"] = df["unionTCPFlags"].astype(np.uint8)
    df["reverseUnionTCPFlags"] = df["reverseUnionTCPFlags"].astype(np.uint8)
    df["lastSynTcpFlags"] = df["lastSynTcpFlags"].astype(np.uint8)
    df["reverseLastSynTcpFlags"] = df["reverseLastSynTcpFlags"].astype(np.uint8)
    
    # drop all flows without dport == 80
    df = df[df["destinationTransportPort"] == 80]
    del(df["destinationTransportPort"])
    
    # drop all flows without an initial SYN
    df = df[np.bitwise_and(df["initialTCPFlags"], S) > 0]
        
    # cast addresses to strings to match ecnspider data
    if ipv6_mode:
        df[dip_ie] = df[dip_ie].apply(lambda x: "["+str(x)+"]")
    else:
        df[dip_ie] = df[dip_ie].apply(str)

    # mark IPv6 mode
    df['ip6'] = ipv6_mode
        
    # now build the index
    df.index = pd.Index(df[dip_ie], name="ip")
    del(df[dip_ie])

    # filter on index if requested
    if spider_idx is not None:
        qof_idx = pd.Index((spider_idx & df.index).unique(), name=spider_idx.name)
        df = df.loc[qof_idx]

    # Now annotate the dataframe with ECN and establishment columns
    df["ecnAttempted"] = np.bitwise_and(df["lastSynTcpFlags"],SAEW) == SEW
    df["ecnNegotiated"] = np.bitwise_and(df["reverseLastSynTcpFlags"],SAEW) == SAE
    df["ecnCapable"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QECT0) > 0
    df["ecnECT1"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QECT1) > 0
    df["ecnCE"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QCE) > 0
    df["didEstablish"] = ((np.bitwise_and(df["lastSynTcpFlags"], S) == S) &
                          (np.bitwise_and(df["reverseLastSynTcpFlags"], SA) == SA))
    df["isUniflow"] = (df["reverseMaximumTTL"] == 0)

    return df

def split_qof_df(df):
    # split on attempt
    qe0_df = df[~df['ecnAttempted']]
    qe1_df = df[ df['ecnAttempted']]
    
    # take only the biggest object HACK HACK HACK
    qe0_df = qe0_df.sort("reverseTransportOctetDeltaCount",ascending=False).groupby(level=0).first()  
    qe1_df = qe1_df.sort("reverseTransportOctetDeltaCount",ascending=False).groupby(level=0).first()

    # take only rows appearing in both
    qof_idx = index_intersect([qe0_df, qe1_df])
    qe0_df = qe0_df.loc[qof_idx]
    qe1_df = qe1_df.loc[qof_idx]
    
    return (qe0_df, qe1_df)

# wrap an object around all this

class QofContext:
    def __init__(self, libtrace_uri, ipfix_file):
        self.libtrace_uri = libtrace_uri
        self.ipfix_file = ipfix_file
        self.yaml_path = os.path.join(os.path.dirname(__file__), "ecnqof.yaml")

        self.qof = None
        self.df = None

    def start(self):
        self.qof = subprocess.Popen(["qof", "--yaml", self.yaml_path, "--in", self.libtrace_uri, "--out", self.filename])
        # FIXME handle errors

    def finish(self):
        # tell qof to shut down
        self.qof.terminate()
        self.qof.wait()
        self.qof = None

    def results(self):
        # open dataframes

        # transform into columns we need for the 
        pass