'''
ECN-Spider: Crawl web pages to test the Internet's support of ECN.
Modified into a module for mPlane integration by Brian Trammell <brian@trammell.ch>

.. moduleauthor:: Damiano Boppart <hat.guy.repo@gmail.com>

    Copyright 2014 Damiano Boppart

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

'''

from collections import namedtuple
import http.client
import threading
import socketserver
import ipfix.reader


import subprocess
import platform
import sys
#import csv
#import errno
import logging
import queue
from time import sleep
import io
import time
import argparse
import datetime
import socket
import bisect
from math import floor


###
### Utility Classes
###

class SharedCounter:
    '''
    A counter object that can be shared by multiple threads.
    Based on : http://chimera.labs.oreilly.com/books/1230000000393/ch12.html#_problem_200
    '''
    def __init__(self, initial_value=0):
        self._value = initial_value
        self._value_lock = threading.Lock()
    
    def __str__(self):
        return str(self.value)

    def incr(self, delta=1):
        '''
        Increment the counter with locking
        '''
        with self._value_lock:
            self._value += delta

    def decr(self, delta=1):
        '''
        Decrement the counter with locking
        '''
        with self._value_lock:
            self._value -= delta
    
    @property
    def value(self):
        '''
        Get the value of the counter.
        '''
        with self._value_lock:
            return self._value


class SemaphoreN(threading.BoundedSemaphore):
    '''
    An extension to the standard library's BoundedSemaphore that provides functions to handle n tokens at once.
    '''
    def __init__(self, value):
        self._VALUE = value
        super().__init__(self._VALUE)
        self.empty()
    
    def __str__(self):
        return 'SemaphoreN with a maximum value of {}.'.format(self._VALUE)
    
    def acquire_n(self, value=1, blocking=True, timeout=None):
        '''
        Acquire ``value`` number of tokens at once.
        
        The parameters ``blocking`` and ``timeout`` have the same semantics as :class:`BoundedSemaphore`.
        
        :returns: The same value as the last call to `BoundedSemaphore`'s :meth:`acquire` if :meth:`acquire` were called ``value`` times instead of the call to this method.
        '''
        ret = None
        for _ in range(value):
            ret = self.acquire(blocking=blocking, timeout=timeout)
        return ret
    
    def release_n(self, value=1):
        '''
        Release ``value`` number of tokens at once.
        
        :returns: The same value as the last call to `BoundedSemaphore`'s :meth:`release` if :meth:`release` were called ``value`` times instead of the call to this method.
        '''
        ret = None
        for _ in range(value):
            ret = self.release()
        return ret
    
    def empty(self):
        '''
        Acquire all tokens of the semaphore.
        '''
        while self.acquire(blocking=False):
            pass

###
### ECN State Management
###

def get_ecn():
    '''
    Use sysctl to get the kernel's ECN behavior.
    
    :raises: subprocess.CalledProcessError when the command fails.
    '''
    ecn = subprocess.check_output(['/sbin/sysctl', '-n', 'net.ipv4.tcp_ecn'], universal_newlines=True).rstrip('\n')
    ecn = [k for k, v in ECN_STATE.items() if v == int(ecn)][0]
    return ecn

def set_ecn(value):
    '''
    Use sysctl to set the kernel's ECN behavior.
    
    This is the equivalent of calling "sudo /sbin/sysctl -w "net.ipv4.tcp_ecn=$MODE" in a shell.
    
    :raises: subprocess.CalledProcessError when the command fails.
    '''
    if value in ECN_STATE.keys():
        subprocess.check_output(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn={}'.format(ECN_STATE[value])], universal_newlines=True).rstrip('\n')
    elif value in ECN_STATE.values():
        subprocess.check_output(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn={}'.format(value)], universal_newlines=True).rstrip('\n')
    else:
        raise ValueError('Only keys or values from ECN_STATE may be used to call set_ecn.')


def disable_ecn():
    ''' Wrapper for :meth:`set_ecn` to disable ECN. '''
    set_ecn('never')


def enable_ecn():
    ''' Wrapper for :meth:`set_ecn` to enable ECN. '''
    set_ecn('always')


def check_ecn():
    '''
    Test that all the things that are done with ``sysctl`` work properly.
    
    :returns: If this function returns without raising an exception, then everything is in working order.
    '''
    state = get_ecn()
    set_ecn(state)
    
    set_ecn('never')
    set_ecn('always')
    set_ecn('on_demand')
    
    set_ecn(state)

###
### Socket Management
###

def setup_socket(ip, timeout):
    '''
    Open a socket using an instance of http.client.HTTPConnection.
    
    :param ip: IP address
    :param timeout: Timeout for socket operations
    :returns: A tuple of: Error message or None, an instance of http.client.HTTPConnection.
    '''
    logger = logging.getLogger('default')
    client = http.client.HTTPConnection(ip, timeout=timeout)
    client.auto_open = 0
    try:
        client.connect()
    except socket.timeout:
        logger.error('Connecting to {} timed out.'.format(ip))
        return ('socket.timeout', None)
    except OSError as e:
        if e.errno is None:
            logger.error('Connecting to {} failed: {}'.format(ip, e))
            return (str(e), None)
        else:
            logger.error('Connecting to {} failed: {}'.format(ip, e.strerror))
            return (e.strerror, None)
    else:
        return (None, client)



def make_get(client, domain, note):
    '''
    Make an HTTP GET request and return the important bits of information as a dictionary.
    
    :param client: The instance of http.client.HTTPConnection for making the request with.
    :param domain: The value of the ``Host`` field of the GET request.
    :param note: The string 'eoff' or 'eon'. Used as part of the keys in the returned dictionary.
    '''
    if note not in ['eoff', 'eon']:
        raise ValueError('Unsupported value for note: {}.'.format(note))
    
    logger = logging.getLogger('default')
    
    h = {'User-Agent': USER_AGENT, 'Connection': 'close'}
    if domain is not None:
        h['Host'] = domain
    
    d = {}  # Dictionary of values to be logged to the CSV output file.
    err_name = 'http_err_' + note
    stat_name = 'status_' + note
    hdr_name = 'headers_' + note
    
    try:
        client.request('GET', '/', headers=h)
        r = client.getresponse()
        client.close()
        
        logger.debug('Request for {} ({}) returned status code {}.'.format(client.host, note, r.status))
        
        d[stat_name] = r.status
        if ARGS.save_headers:
            d[hdr_name] = r.getheaders()
        else:
            d[hdr_name] = None
        d[err_name] = None
    except OSError as e:
        if e.errno is None:
            logger.error('Request for {} failed (errno None): {}'.format(client.host, e))
            d[err_name] = str(e)
            d[stat_name] = None
            d[hdr_name] = None
        else:
            logger.error('Request for {} failed (with errno): {}'.format(client.host, e.strerror))
            d[err_name] = e.strerror
            d[stat_name] = None
            d[hdr_name] = None
    except Exception as e:
        logger.error('Request for {} failed ({}): {}.'.format(client.host, type(e), e))
        d[err_name] = str(e)
        d[stat_name] = None
        d[hdr_name] = None
    return d
###
### Spider Classes
###

Job = namedtuple('Job', ['url', 'ip'])
Result = namedtuple('Result', ['time', 'url', 'ip', 'port', 'ecnstate', 'conn'])

class Spider:
    def __init__(self, job_source, result_sink, qof_context, num_workers, sock_timeout, check_interrupt):
        self.running = False

        self.job_source = job_source
        self.result_sink = result_sink
        self.qof_context = qof_context

        self.num_workers = num_workers
        self.sock_timeout = sock_timeout
        self.check_interrupt = check_interrupt

        self.ecn_on = SemaphoreN(num_workers)
        self.ecn_on.empty()
        self.ecn_on_rdy = SemaphoreN(num_workers)
        self.ecn_on_rdy.empty()
        self.ecn_off = SemaphoreN(num_workers)
        self.ecn_off.empty()
        self.ecn_off_rdy = SemaphoreN(num_workers)
        self.ecn_off_rdy.empty()

        self.jobqueue = queue.Queue(Q_SIZE)

    def master(self):
        '''
        Master thread for controlling the kernel's ECN behavior.
        '''
        logger = logging.getLogger('default')
        while self.running:
            disable_ecn()
            logger.debug('ECN off connects from here onwards.')
            self.self.ecn_off.release_n(num_workers)
            self.self.ecn_on_rdy.acquire_n(num_workers)
            enable_ecn()
            logger.debug('ECN on connects from here onwards.')
            self.self.ecn_on.release_n(num_workers)
            self.self.ecn_off_rdy.acquire_n(num_workers)
        
        # In case the master exits the run loop before all workers have, 
        # these tokens will allow all workers to run through again, 
        # until the next check at the start of the loop
        self.self.ecn_off.release_n(num_workers)
        self.self.ecn_on.release_n(num_workers)
        
        logger.debug('Master thread ending.')

    def worker(self):
        '''
        Worker thread for crawling websites with and without ECN.
        
        '''

        # WORK POINTER still unraveling the d[] references and data representation in this code

        logger = logging.getLogger('default')
        
        while RUN:
            self.queuejob = False  #: If the current job was taken from the queue this is True
            try:
                job = self.jobqueue.get_nowait()
                self.queuejob = True
            except queue.Empty:
                sleep(0.5)
                logger.debug('Not a queue job, skipping processing.')
            
            self.ecn_off.acquire()
            
            if self.queuejob:
                logger.debug('Connecting with ECN off...')
                
                eoff_err, eoff = setup_socket(job.ip, timeout=self.timeout)
                
                if isinstance(eoff, http.client.HTTPConnection):
                    eoff_port = eoff.sock.getsockname()[1]
                else:
                    eoff_port = 0
            
            self.ecn_on_rdy.release()
            self.ecn_on.acquire()
            
            if self.queuejob:
                logger.debug('Connecting with ECN on...')
                                
                if ARGS.fast_fail and eoff_err == 'socket.timeout':
                    eon_err = 'no_attempt'
                    eon = None
                else:
                    eon_err, eon = setup_socket(job.ip, timeout=self.timeout)
                
                if isinstance(eon, http.client.HTTPConnection):
                    eon_port = eon.sock.getsockname()[1]
                else:
                    eon_port = 0
            
            self.ecn_off_rdy.release()
            
            if self.queuejob:
                logger.debug('Making GET requests...')
                
                if isinstance(eon, http.client.HTTPConnection):
                    d_ = make_get(eon, job.domain, 'eon')
                    d.update(d_)
                else:
                    d['http_err_eon'] = 'no_attempt'
                    d['status_eon'] = None
                    d['headers_eon'] = None 
                
                if isinstance(eoff, http.client.HTTPConnection):
                    d_ = make_get(eoff, job.domain, 'eoff')
                    d.update(d_)
                else:
                    d['http_err_eoff'] = 'no_attempt'
                    d['status_eoff'] = None
                    d['headers_eoff'] = None
                
                # enqueue for match
                self.er_queue.add(Result(eoff_time, job.url, job.ip, eoff_port, eoff_conn, eoff_status))                
                self.er_queue.add(Result(eon_time, job.url, job.ip, eon_port, eon_conn, eon_status))
                
                self.jobqueue.task_done()
                count.incr()
        
        logger.debug('Worker thread ending.')

    def reporter(self):
        '''
        Periodically report on the length of the job queue.
        '''
        period = 1  #: Interval between log messages in seconds. Increases exponentially up to MAX_PERIOD.
        MAX_PERIOD = 120  #: Maximum interval between log messages.
        t0 = datetime.datetime.now()  # Start time of rate calculation
        tl = t0  # Time since last printed message
        completed_jobs = 0
        logger = logging.getLogger('default')
        
        while RUN:
            # FIXME Switch to semaphore with timeout here to avoid wait at the end.
            sleep(period)
            if period >= MAX_PERIOD:
                period = MAX_PERIOD
            else:
                period *= 2
            
            queue_length = self.jobqueue.qsize()
            queue_utilization = queue_length / Q_SIZE * 100
            prev_completed_jobs = completed_jobs
            completed_jobs = count.value

            tt = datetime.datetime.now()
            current_rate = float(completed_jobs - prev_completed_jobs) / (tt - tl).total_seconds()
            average_rate = float(completed_jobs) / (tt - t0).total_seconds()
            runtime = tt - START_TIME
            tl = tt
            
            # NOTE The last stats might be printed before all jobs were processed, 
            # it's a race condition.
            logger.info('Queue: {q_len:4}, {q_util:5.1f}%. Done: {jobs:6}. '+
                        'Rate: now: {cur:6.2f} Hz; avg: {avg:6.2f} Hz. '+
                        'Runtime {rtime}. Sched. retries: {rtry}'.format(
                            q_len=queue_length, q_util=queue_utilization, 
                            jobs=completed_jobs, cur=current_rate, 
                            avg=average_rate, rtime=runtime))
        
        logger.debug('Reporter thread ending.')

    def qofowner(self):
        # Start QoF in a subprocess and wait for it to shut down.
        pass

    def merger(self):
        # Read from the ecnspider and qof flow queues and merge results
        # on the ports. look out for reset storms. take the merged results
        # and send them on to the result sink.
        pass

    def filler(self):
        for job in self.job_source:
            if self.check_interrupt() 
                return
            self.jobqueue.add(job)

    class SpiderQofHandler(socketserver.StreamRequestHandler):
        def handle(self):
            # FIXME logging
            print("connection from "+str(self.client_address)+".")
            msr = ipfix.reader.from_stream(self.rfile)
            # FIXME bulletproofing

            for d in msr.namedict_iterator():
                # FIXME format flow as namedtuple
                # stick it in the spider's qr_queue
                pass

            print("connection from "+str(self.client_address)+" terminated.")

    class SpiderThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, spider):
            super().__init__(self, server_address, RequestHandlerClass)
            self.spider = spider

    def run(self):
        # start collection
        # FIXME use socketserver

        # start capture
        # FIXME use qofowner

        self.running = True # could be more thread safe

        t = threading.Thread(target=self.reporter, name='reporter', daemon=True)
        t.start()
    
        t = threading.Thread(target=self.master, name='master', , daemon=True)
        t.start()

        filler = threading.Thread(target=self.filler, name='filler', daemon=True)
        filler.start()

        for i in range(args.workers):
            t = threading.Thread(target=self.worker, name='worker_{}'.format(i), daemon=True)
            t.start()
            ts[t.name] = t

        # We're running. Wait for the job source and the queues to empty.
        filler.join()
        self.jobqueue.join()
        self.running = False

        # stop capture
        # FIXME use qofowner

        # stop collection
        # FIXME use socketserver


###
### Logging utility
###

def set_up_logging(logfile, verbosity):
    '''
    Configure logging.
    
    :param file logfile: Filename of logfile.
    :param verbosity verbosity: Stdout logging verbosity.
    '''
    #logging.basicConfig(filemode='w')
    logger = logging.getLogger('default')
    logger.setLevel(logging.DEBUG)
    
    fileHandler = logging.FileHandler(logfile)
    fileFormatter = logging.Formatter('%(created)f,%(threadName)s,%(levelname)s,%(message)s')
    fileHandler.setFormatter(fileFormatter)
    fileHandler.setLevel(logging.DEBUG)
    logger.addHandler(fileHandler)
    
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleFormatter = logging.Formatter('%(asctime)s [%(threadName)-10.10s] [%(levelname)-5.5s]  %(message)s')
    consoleHandler.setFormatter(consoleFormatter)
    consoleHandler.setLevel(verbosity)
    logger.addHandler(consoleHandler)
    
    logger.debug('All logging handlers: {}.'.format(logger.handlers))
    
    logger.info('The logging level is set to %s.', logging.getLevelName(logger.getEffectiveLevel()))
    logger.info('Running Python %s.', platform.python_version())
    logger.info('ECN: {}.'.format(get_ecn()))
    
    return logger

