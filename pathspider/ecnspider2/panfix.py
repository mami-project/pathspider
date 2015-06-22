###
# generic IPFIX to pandas dataframe
# and some QoF-specific tools

import ipfix
import ipfix.reader
import pandas as pd
import numpy as np
import collections
import itertools
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
DEFAULT_FLOW_IES = [   "flowStartMilliseconds",
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

def derive_nets(df, v4_prefix=16, v6_prefix=64):
    """
    add columns to the given dataframe for uniform networks given a prefix.
    allows aggregation by network.
    
    modifies the dataframe in place and returns it.
    """
    try:
        df["sourceIPv4Network"] = df["sourceIPv4Address"].map(
                lambda x: ip_network(str(x)+"/"+str(v4_prefix), strict=False))
    except KeyError:
        pass
    
    try:
        df["destinationIPv4Network"] = df["destinationIPv4Address"].map(
                lambda x: ip_network(str(x)+"/"+str(v4_prefix), strict=False))
    except KeyError:
        pass

    try:
        df["sourceIPv6Network"] = df["sourceIPv6Address"].map(
                lambda x: ip_network(str(x)+"/"+str(v6_prefix), strict=False))
    except KeyError:
        pass
    
    try:
        df["destinationIPv6Network"] = df["destinationIPv6Address"].map(
                lambda x: ip_network(str(x)+"/"+str(v6_prefix), strict=False))
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


def calculate_flow_iat(df, timecol="flowStartMilliseconds"):
    """
    Determine flow interarrival time across the entire set of flows.
    
    Returns a sorted, reindexed copy of the dataframe.
    
    """
    
    sdf = df.sort(timecol)
    sdf.index = pd.Index(range(len(sdf)))
    
    # Add temporary column for time, shift up by one via reindexing
    prevt = sdf[timecol]
    prevt.index = pd.Index(range(1,len(prevt)+1))
    sdf['prevt'] = prevt

    # Calculate IAT by subtraction
    sdf['flowIAT'] = sdf[timecol] - sdf['prevt']
    
    # Delete temporary shifted time column
    del(sdf['prevt'])
    
    return sdf
           
def key_timeout_groups(df, timeout_s=15, 
                           keycol="sourceIPv4Address", 
                           timecol="flowStartMilliseconds"):
    """
    Implement vector aggregation of flows into groups given a key column,
    a time column, and a timeout. Sorts by the key and time columns, then adds
    flow group identifiers and indices for grouping. Adds an interarrival time
    column for per-key interarrival times.
    
    Returns a sorted, reindexed copy of the dataframe.
    
    """
    # Created a sorted dataframe indexed in sort order.
    sdf = df.sort((keycol, timecol))
    sdf.index = pd.Index(range(len(sdf)))
    
    # Add temporary columns for key and time; 
    # shift these up by one via reindexing
    prevk = sdf[keycol]
    prevk.index = pd.Index(range(1,len(prevk)+1))
    sdf['prevk'] = prevk
    
    prevt = sdf[timecol]
    prevt.index = pd.Index(range(1,len(prevt)+1))
    sdf['prevt'] = prevt
    
    # Derive a "regroup signal": start a new group any time the key changes
    # or the time column has a difference greater than the timeout
    regroup = (sdf[keycol] != sdf['prevk']) | \
               (sdf[timecol] - sdf['prevt'] > (timeout_s * 1000000000))
    
    rekey = sdf[keycol] != sdf['prevk']
    
    # Build group ID and index columns based on the regroup signal
    gids = []
    gidxs = []
    next_gid = 0
    next_gidx = 0

    for z in regroup.values:
        if z:
            next_gid += 1
            next_gidx = 0
        gids.append(next_gid)
        gidxs.append(next_gidx)
        
        next_gidx += 1
        
    # And add them to the frame
    sdf["flowGroupId"] = pd.Series(gids)
    sdf["flowGroupIndex"] = pd.Series(gidxs)
    
    # Now derive key IAT
    sdf[keycol+"IAT"] = sdf[timecol] - sdf["prevt"]
    # to stop Stephan's whining...
    zeroiat = pd.Series(index=rekey[rekey].index, dtype="timedelta64[ns]", data=0)
    sdf[keycol+"IAT"].update(zeroiat)

    # Copy key IAT to flow group IAT, zero at beginning of group
    sdf["flowGroupIAT"] = sdf[keycol+"IAT"]
    zeroiat = pd.Series(index=sdf[sdf["flowGroupIndex"] == 0].index, 
                        dtype="timedelta64[ns]", data=0)
    sdf["flowGroupIAT"].update(zeroiat)

    # Delete temporary columns
    del(sdf['prevk'])
    del(sdf['prevt'])

    # All done
    return sdf

