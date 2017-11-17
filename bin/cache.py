"""
# fault download client.

# HTTP client designed for downloading resources to the current working directory.

# [ Engineering ]

# The download client is rather limited in its capacity. The intention of this program
# is to provide a robust HTTP client for retrieving resources and storing them in
# the local file system.

# /Redirect Resolution
	# Location and HTML redirects are not supported.
# /Host Scanning in case of 404
	# 404 errors do not cause the client to check the other hosts.
# /Parallel Downloads
	# Only one transfer per-process is supported.
# /Security Certificate Validation
	# No checks are performed to validate certificate chains.
"""

import sys
import os
import functools
import itertools
import socket
import collections

from ...chronometry import library as libtime
from ...chronometry import rate
from ...internet import ri
from ...routes import library as libroutes
from ...computation import library as libc

from ...io import library as libio
from ...io import http
from ...io import libinternet

transfer_counter = collections.Counter()
content_length = None
start_time = None
identities = []
radar = rate.Radar()
gtls = None

def count(name, event):
	xfer = libc.sum_lengths(event)
	transfer_counter[name] += xfer

certificates = os.environ.get('SSL_CERT_FILE', '/etc/ssl/cert.pem')
try:
	from ...io import security
	with open(certificates, 'rb') as f:
		security_context = security.public(certificates=(f.read(),))
except:
	raise
	security = None
	securtiy_context = None

def response_collected(mitre, sector, request, response, flow):
	status()
	print('\n\rResponse collected.')
	mitre.terminate()

def response_endpoint(client, request, response, connect, transports=(), mitre=None, tls=None):
	global gtls
	global content_length
	sector = client.sector
	gtls = tls
	content_length = response.length

	print(request)

	if tls:
		i = tls.status()
		print('%s [%s]' %(i[0], i[3]))
		print('\thostname:', tls.hostname.decode('idna'))
		print('\tverror:', tls.verror or '[None: Verification Success]')
		print('\tapplication:', tls.application)
		print('\tprotocol:', tls.protocol)
		print('\tstandard:', tls.standard)
		fields = '\n\t'.join([
			'%s: %r' %(k, v)
			for k, v in tls.peer_certificate.subject
		])
		print('\t'+fields)
	else:
		print('TLS [none: no transport layer security]')

	print(response)

	ri = request.resource_indicator
	if ri["path"]:
		path = libroutes.File.from_path(ri["path"][-1])
	else:
		path = libroutes.File.from_path('index')

	identities.append(path)
	status()

	target = client.context.append_file(str(path))
	sector.dispatch(target)

	trace = libio.Traces()

	track = libc.compose(functools.partial(radar.track, path), libc.sum_lengths)
	trace.monitor("rate", track)

	track = libc.partial(count, path)
	trace.monitor("total", track)

	sector.dispatch(trace)
	trace.f_connect(target)

	target.atexit(functools.partial(response_collected, mitre, sector, request, response))
	connect(trace)

def request(struct):
	req = http.Request()
	path = ri.http(struct)

	req.initiate((b'GET', b'/'+path.encode('utf-8'), b'HTTP/1.1'))
	req.add_headers([
		(b'Host', struct['host'].encode('idna')),
		(b'Accept', b'application/octet-stream, */*'),
		(b'User-Agent', b'curl/5.0'),
		(b'Connection', b'close'),
	])

	req.resource_indicator = struct
	return req

def dispatch(sector, url):
	struct, endpoint = url # ri.parse(x), libio.Endpoint(y)
	req = request(struct)

	from ...terminal.format.url import f_struct
	from ...terminal import device
	dev = device.Display()
	struct['fragment'] = '[%s]' %(str(endpoint),)
	sys.stderr.buffer.write(dev.renderline(f_struct(struct)))
	sys.stderr.buffer.write(b'\n')
	sys.stderr.buffer.flush()

	mitre = http.Client(None)

	if struct['scheme'] == 'https':
		tls = security_context.connect(struct['host'].encode('idna'))
		series = sector.context.connect_subflows(endpoint, mitre, tls, http.Protocol.client())
	else:
		tls = None
		series = sector.context.connect_subflows(endpoint, mitre, http.Protocol.client())

	s = libio.Sector()
	sector.dispatch(s)
	s._flow(series)
	mitre.m_request(functools.partial(response_endpoint, mitre=mitre, tls=tls), req, None)
	series[0].process(None)

	return s

def process_exit(sector):
	"""
	# Initialize exit code based on failures and print
	"""
	pass

def status(time=None, next=libtime.Measure.of(second=1)):
	for x in identities:
		radar.track(x, 0)
		units, time = (radar.rate(x, libtime.Measure.of(second=8)))
		seconds = time.select('second')

		if seconds:
			rate = (units / time.select('second'))
			if content_length is not None:
				eta = ((content_length-transfer_counter[x]) / rate)
			else:
				eta = transfer_counter[x] / rate
			m = libtime.Measure.of(second=int(eta), subsecond=eta-int(eta))
			m = m.truncate('millisecond')
			print("\r%s %d bytes @ %f KB/sec [%r]%s" %(x, transfer_counter[x], rate / 1000, m, ' '*40), end='')
		else:
			print("\r%s %d bytes%s" %(x, transfer_counter[x], ' '*40), end='')

	return next

def initialize(unit):
	global start_time

	libio.Ports.connect(unit)

	proc = unit.context.process
	urls = proc.invocation.parameters['system']['arguments']

	# URL target; endpoint exists on a remote system.
	endpoints = [libinternet.endpoint(x) for x in urls]

	# Only load DNS if its needed.
	lendpoints = []
	for struct, x in endpoints:
		if x.protocol == 'domain':
			a = socket.getaddrinfo(x.address, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
			for i in a:
				ip = i[-1][0]
				y = libio.endpoint('ip4', ip, x.port)
				print('Possible host:', y)
			lendpoints.append((struct, y))
		else:
			lendpoints.append((struct, x))

	root_sector = libio.Sector()
	unit.dispatch(("bin", "http-control"), root_sector)

	if not lendpoints:
		root_sector.terminate()
		return

	hc = dispatch(root_sector, lendpoints[0])

	start_time = libtime.now()
	root_sector.atexit(process_exit)
	root_sector.scheduling()

	r = root_sector.scheduler.recurrence(status)
	hc.atexit(r.terminate)

if __name__ == '__main__':
	os.umask(0o137)
	libio.execute(control = (initialize,))
