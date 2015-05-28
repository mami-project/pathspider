#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Resolution: Resolve a large number of domains to IPv4 and IPv6 addresses.

.. moduleauthor:: Damiano Boppart <hat.guy.repo@gmail.com>

Copyright 2014 Damiano Boppart

This file is part of ECN-Spider.
'''

import sys
import dns.resolver
import csv
import queue
import threading
import datetime
import argparse
from time import sleep

TIMEOUT = None  #: The timeout for DNS resolution.
SLEEP = None  #: Time to sleep before each resolution, for crude rate-limiting.
WWW = None  #: The value of the -www command line option

Q_SIZE = 100  #: Maximum domain queue size


def resolve(domain, query='A'):
	'''
	Resolve a domain name to IP address(es).
	
	:param str domain: The domain to be resolved.
	:param str query: The query type. May be either 'A' or 'AAAA'.
	:returns: A list of IP addresses as strings.
	:throws: Instances of ``dns.exception``
	'''
	resolver = dns.resolver.Resolver()
	resolver.lifetime = TIMEOUT
	answers = resolver.query(domain, query)
	l = [a.to_text() for a in answers]
	return l


def resolve_both(domain):
	'''
	Helper function to handle_domain.
	'''
	try:
		a = resolve(domain)
	except dns.exception.DNSException:
		a = ['']
	
	try:
		a4 = resolve(domain, 'AAAA')
	except dns.exception.DNSException:
		a4 = ['']
	
	return (a, a4)


def csv_gen(skip=0, count=0, *args, **kwargs):
	'''
	A wrapper around :meth:`csv.reader`, that makes it a generator.
	
	:meth:`csv_gen` does not return entire records, instead it extracts one particular field from a record.
	
	:param \*args: Arguments passed to :meth:`csv.reader`.
	:param \*\*kwargs: Keyword arguments passed to :meth:`csv.reader`.
	:returns: One field from each record on each call to :meth:`next()`.
	'''
	reader = csv.reader(*args, **kwargs)
	
	# Discard the first entries
	for _ in range(skip):
		next(reader)
	
	c = 0
	for row in reader:
		yield row
		c += 1
		if c % 1000 == 0:
			print('Parsed {} records so far.'.format(c))
		if count != 0 and c >= count:
			break


# def handle_domain(fields):
# 	'''
# 	Takes a domain name and resolves it to up to one IPv4 up to one IPv6 address.
	
# 	For deciding whether a resolution was successful (and therefore no fallback must be used for www vs. no-www) only A records are considered.
	
# 	:param str fields: A list of rank and domain name to be resolved. The rank will not be interpreted, but simply passed on to the output.
# 	:returns: A list of IP addresses. The list may be empty if errors are encountered during the resolution.
# 	'''
# 	sleep(SLEEP)
# 	rank = fields[0]
# 	domain = fields[1]
	
# 	# NOTE www.com or www.co.uk would be incorrectly handled by checking for a leading "www." first. Alexa's list generally omits the almost ubiquitous "www.", but not always: www.uk.com is a counter-example.
# 	wdomain = domain
# 	#if domain[:4] != 'www.':
# 		#wdomain = 'www.' + domain
# 	wdomain = 'www.' + domain
	
# 	# ``domain`` is the 'original' passed in, and ``wdomain`` is domain with a 'www.' prepended where applicable
	
# 	if WWW == 'never':
# 		(a, a4) = resolve_both(domain)
# 	elif WWW == 'always':
# 		(a, a4) = resolve_both(wdomain)
# 		domain = wdomain
# 	elif WWW == 'both':
# 		(a, a4) = resolve_both(domain)
# 		(aw, a4w) = resolve_both(wdomain)
		
# 		if len(a) > 1:
# 			a = [a[0]]
# 		if len(a4) > 1:
# 			a4 = [a4[0]]
		
# 		if len(aw) > 1:
# 			aw = [aw[0]]
# 		if len(a4w) > 1:
# 			a4w = [a4w[0]]
		
# 		ret = [rank] + [domain] + a + a4
# 		retw = [rank] + [wdomain] + aw + a4w
# 		return [ret, retw]
# 	elif WWW == 'preferred':
# 		try:
# 			a = resolve(wdomain)
# 			try:
# 				a4 = resolve(wdomain, 'AAAA')
# 			except dns.exception.DNSException:
# 				a4 = ['']
# 			domain = wdomain
# 		except dns.exception.Timeout:
# 			# Just a timeout, using www is OK.
# 			a = ['']
# 			try:
# 				a4 = resolve(wdomain, 'AAAA')
# 			except dns.exception.DNSException:
# 				a4 = ['']
# 		except dns.exception.DNSException:
# 			# Resolution failed, falling back.
# 			(a, a4) = resolve_both(domain)
# 	else:
# 		raise Exception('Illegal value for "WWW." option.')
	
# 	# To make the code shorter, at this stage ``domain`` might actually have been assigned the value of ``wdomain``, and so, may have an added 'www.'. It depends on the WWW mode.
	
# 	# Keep only the first address of each IP version
# 	if len(a) > 1:
# 		a = [a[0]]
# 	if len(a4) > 1:
# 		a4 = [a4[0]]
	
# 	ret = [rank] + [domain] + a + a4
# 	return [ret]

def resolution_worker(iq, oq):
	while True:
		entry = iq.get()

		# Shutdown and cascade
		if entry is None:
			print("Input cascading shutdown signal")
			oq.put(None)
			iq.task_done()
			break

		try:
			rank = entry[0]
			domain = entry[1]

			# NOTE www.com or www.co.uk would be incorrectly handled by checking for a leading "www." first. Alexa's list generally omits the almost ubiquitous "www.", but not always: www.uk.com is a counter-example.
			wdomain = domain
			#if domain[:4] != 'www.':
				#wdomain = 'www.' + domain
			wdomain = 'www.' + domain
			
			# ``domain`` is the 'original' passed in, and ``wdomain`` is domain with a 'www.' prepended where applicable
			
			if WWW == 'never':
				(a, a4) = resolve_both(domain)
			elif WWW == 'always':
				(a, a4) = resolve_both(wdomain)
				domain = wdomain
			elif WWW == 'both':
				(a, a4) = resolve_both(domain)
				(aw, a4w) = resolve_both(wdomain)
				
				if len(a) > 1:
					a = [a[0]]
				if len(a4) > 1:
					a4 = [a4[0]]
				
				if len(aw) > 1:
					aw = [aw[0]]
				if len(a4w) > 1:
					a4w = [a4w[0]]
				
				ret = [rank] + [domain] + a + a4
				retw = [rank] + [wdomain] + aw + a4w
				return [ret, retw]
			elif WWW == 'preferred':
				try:
					a = resolve(wdomain)
					try:
						a4 = resolve(wdomain, 'AAAA')
					except dns.exception.DNSException:
						a4 = ['']
					domain = wdomain
				except dns.exception.Timeout:
					# Just a timeout, using www is OK.
					a = ['']
					try:
						a4 = resolve(wdomain, 'AAAA')
					except dns.exception.DNSException:
						a4 = ['']
				except dns.exception.DNSException:
					# Resolution failed, falling back.
					(a, a4) = resolve_both(domain)
			else:
				print("Internal error: illegal WWW value")
				sys.exit(1)

			# Keep only the first address of each IP version
			a = a[0]
			a4 = a4[0]
			
			oq.put((rank, domain, a, a4))
		except Exception as e:
			print("Discarding resolution for "+domain+": "+repr(e))
		finally:
			iq.task_done()

def output_worker(oq, writer):
	print("output thread started")
	while True:
		entry = oq.get()
		if entry is None:
			print("Output handling shutdown signal")
			oq.task_done()
			break
		writer.writerow(entry)
		oq.task_done()

def arguments(argv):
	'''
	Parse the command-line arguments.
	
	:param argv: The command line.
	:returns: The return value of ``argparse.ArgumentParser.parse_args``.
	'''
	parser = argparse.ArgumentParser(description='Resolution: Resolve a large number of domains to IPv4 and IPv6 addresses.', epilog='This program is part of ECN-Spider.')
	
	# FIXME use type=argparse.FileType() here
	parser.add_argument('input_file', type=str, help='CSV format input data file with one domain per line. The domain must be in one field of a record, that record is selected with the "position" argument.')
	parser.add_argument('output_file', type=str, help='CSV format output data file with domain names and associated IP addresses. Each record has the format: "domain,IPv4,IPv6".')
	
	parser.add_argument('--workers', '-w', type=int, default='5', help='The number of worker threads used for resolution.')
	parser.add_argument('--verbosity', '-v', type=int, default='50', help='Frequency of message output during the resolution phase of the program. A value of N here will print a message for every N processed domains.')
	parser.add_argument('--timeout', '-t', type=int, default='10', help='Timeout for DNS resolution.')
	parser.add_argument('--sleep', '-s', type=float, default='0', help='Sleep before every request. Useful for rate-limiting.')
	parser.add_argument('--www', default='preferred', choices=['never', 'preferred', 'always', 'both'], help='Mode for prepending "www." to every domain before resolution. "never" will never prepend "www.". "preferred" will prepend "www." if the resolution of the domain including "www." is successful (more specifically: an A record is returned), and otherwise fall back to omitting the "www.". "always" will prepend "www." and will return no IP address in the output file, even when the domain without "www." can be resolved to one. "both" behaves as "always" and "never" together, that is, it resolves each domain with and without a prepended "www.". All values for this option will never stack the www\'s, that is "www.example.com" will never be expanded to "www.www.example.com". An existing "www." prefix from a domain from the input file will never be dropped. If this value is not "never", then the output file may contain different FQDNs from the input file, as "example.com" might be turned into "www.example.com".')
	
	parser.add_argument('--debug-skip', type=int, default='0', dest='debug_skip', help='Skip the first N domains, and do not resolve them.')
	parser.add_argument('--debug-count', type=int, default='0', dest='debug_count', help='Perform resolution for at most N domains. All of them if this value is set to 0.')
	
	args = parser.parse_args(argv)
	
	# Some validation
	if args.workers <= 0:
		raise ValueError('Workers must be a positive integer, it was set to {}.'.format(args.workers))
	if args.verbosity <= 0:
		raise ValueError('Verbosity must be a positive integer, it was set to {}.'.format(args.verbosity))
	if args.sleep < 0:
		raise ValueError('Sleep must be a non-negative float, it was set to {}.'.format(args.sleep))
	if args.timeout <= 0:
		raise ValueError('Timeout must be a positive integer, it was set to {}.'.format(args.timeout))
	if args.debug_skip < 0:
		raise ValueError('Debug-skip must be a non-negative integer, it was set to {}.'.format(args.debug_skip))
	if args.debug_count < 0:
		raise ValueError('Debug-count must be a non-negative integer, it was set to {}.'.format(args.debug_count))
	
	return args


def main(argv):
	'''
	Method to be called when run from the command line.
	'''
	args = arguments(argv)
	
	global TIMEOUT
	TIMEOUT = args.timeout
	
	global WWW
	WWW = args.www
	
	global SLEEP
	SLEEP = args.sleep
	
	with open(args.input_file) as inf, open(args.output_file, 'w', newline='') as ouf:
		print('Opening input file.')
		reader = csv_gen(args.debug_skip, args.debug_count, inf)
		print('Opening output file.')
		writer = csv.writer(ouf)
		
		t0 = datetime.datetime.now()  # Start time of resolution
		tl = t0  # Time since last printed message
		
		iq = queue.Queue(Q_SIZE)
		oq = queue.Queue(Q_SIZE)
		ts = {}

		print('Starting worker threads...')
		for i in range(args.workers):
			t = threading.Thread(target=resolution_worker, name='worker_{}'.format(i), args=(iq, oq), daemon=True)
			t.start()
			ts[t.name] = t

		print('Starting output thread...')
		ot = threading.Thread(target=output_worker, name='output_worker'.format(i), args=(oq, writer), daemon=True)
		ot.start()

		print('Enqueueing domains...')

		for dc, d in enumerate(reader):
			iq.put(d)
			if (dc + 1) % args.verbosity == 0:
				tt = datetime.datetime.now()
				current_rate = float(args.verbosity) / (tt - tl).total_seconds()
				average_rate = float(dc+1) / (tt - t0).total_seconds()
				tl = tt
				print('Enqueued {num_dom:>6} domains. Rate: {cur:9.2f} Hz. Average rate: {avg:9.2f} Hz.'.format(num_dom=dc+1, cur=current_rate, avg=average_rate))

		# now enqueue a quit signal
		iq.put(None)

		# wait for queues to drain
		iq.join()
		ot.join()

	t1 = datetime.datetime.now()
	time = t1 - t0
	average_rate = float(dc+1) / time.total_seconds()
	print('Resolution completed.')
	print('Resolved {num_dom} domains. Total time: {time}. Average rate: {avg:.2f} domains per second.'.format(num_dom=dc+1, time=time, avg=average_rate))

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
