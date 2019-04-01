"""
# fault download client.

# HTTP client designed for downloading resources to the current working directory.

# [ Engineering ]

# The download client is rather limited in its capacity. The intention of this program
# is to provide a robust HTTP client for retrieving resources and storing them in
# the local file system.

# /Redirect Resolution/
	# Location and HTML redirects are not supported.
# /Host Scanning in case of 404/
	# 404 errors do not cause the client to check the other hosts.
# /Parallel Downloads/
	# Only one transfer per-process is supported.
# /Security Certificate Validation/
	# No checks are performed to validate certificate chains.
"""

import sys
import os
import functools
import itertools
import socket
import collections

from ...system import files
from ...system import process

from ...time import library as libtime
from ...time import rate
from ...internet import ri
from ...internet import host
from ...computation import library as libc

from ...kernel import library as libkernel
from ...kernel import flows
from .. import http

certificates = os.environ.get('SSL_CERT_FILE', '/etc/ssl/cert.pem')
try:
	from ...kernel import security
	with open(certificates, 'rb') as f:
		security_context = security.public(certificates=(f.read(),))
except:
	raise
	security = None
	securtiy_context = None

class Download(libkernel.Executable):
	dl_start_time = None
	dl_transfer_counter = None
	dl_content_length = None
	dl_identities = None
	dl_radar = None

	def dl_count(self, name, event):
		xfer = libc.sum_lengths(event)
		self.dl_transfer_counter[name] += xfer

	def dl_pprint(self, file, screen, source):
		rp = screen.terminal_type.normal_render_parameters

		phrase = screen.Phrase.from_words(
			itertools.chain.from_iterable(
				rp.apply(textcolor=color).form(s)
				for s, color in source
			)
		)
		file.buffer.write(b''.join(screen.render(phrase)) + screen.reset_text())

	def dl_response_collected(self, target_path, mitre, sector, request, response, flow):
		self.dl_status()

		from ...terminal.format import path
		from ...terminal import matrix
		screen = matrix.Screen()
		sys.stdout.write('\n\rResponse collected; data stored in ')
		self.dl_pprint(sys.stdout, screen, path.f_route_absolute(target_path))
		sys.stdout.write('\n')

		self.exe_invocation.exit(0)

	def dl_request(self, struct):
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

	def dl_dispatch(self, url):
		struct, endpoint = url # ri.parse(x), libkernel.Endpoint(y)
		req = self.dl_request(struct)

		from ...terminal.format.url import f_struct
		from ...terminal import matrix
		screen = matrix.Screen()
		struct['fragment'] = '[%s]' %(str(endpoint),)
		self.dl_pprint(sys.stderr, screen, f_struct(struct))
		sys.stderr.write('\n')
		sys.stderr.buffer.flush()

		mitre = http.Client(None)

		if struct['scheme'] == 'https':
			tls = security_context.connect(struct['host'].encode('idna'))
			series = self.system.connect_subflows(endpoint, mitre, tls, http.Protocol.client())
		else:
			tls = None
			series = self.system.connect_subflows(endpoint, mitre, http.Protocol.client())

		#s = libkernel.Sector()
		#self.xact_dispatch(s)
		#s._flow(series)
		self.controller._flow(series)
		mitre.m_request(functools.partial(self.dl_response_endpoint, mitre=mitre, tls=tls), req, None)
		series[0].f_transfer(None)

		return series[-1]

	def dl_status(self, time=None, next=libtime.Measure.of(second=1)):
		radar = self.dl_radar
		counter = self.dl_transfer_counter
		for x in self.dl_identities:
			radar.track(x, 0)
			units, time = (radar.rate(x, libtime.Measure.of(second=8)))
			seconds = time.select('second')

			if seconds:
				rate = (units / time.select('second'))

				try:
					if self.dl_content_length is not None:
						eta = ((self.dl_content_length-counter[x]) / rate)
					else:
						eta = counter[x] / rate
					m = libtime.Measure.of(second=int(eta), subsecond=eta-int(eta))
					m = m.truncate('millisecond')
					xfer_rate = rate / 1000
				except ZeroDivisionError:
					m = libtime.never
					xfer_rate = 0.0

				print("\r%s %d bytes @ %f KB/sec [%r]%s" %(x, counter[x], xfer_rate, m, ' '*40), end='')
			else:
				print("\r%s %d bytes%s" %(x, counter[x], ' '*40), end='')

		return next

	def dl_response_endpoint(self, client, request, response, connect, transports=(), mitre=None, tls=None):
		sector = client.sector
		self.dl_content_length = response.length

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
			path = files.Path.from_path(ri["path"][-1])
		else:
			path = files.Path.from_path('index')

		self.dl_identities.append(path)
		self.dl_status()

		target = client.system.append_file(str(path))
		sector.dispatch(target)

		trace = flows.Traces()

		track = libc.compose(functools.partial(self.dl_radar.track, path), libc.sum_lengths)
		trace.monitor("rate", track)

		track = libc.partial(self.dl_count, path)
		trace.monitor("total", track)

		sector.dispatch(trace)
		trace.f_connect(target)

		target.atexit(functools.partial(self.dl_response_collected, path, mitre, sector, request, response))
		connect(trace)

	def dl_initialize(self, endpoints):
		self.dl_identities = []
		self.dl_radar = rate.Radar()
		self.dl_transfer_counter = collections.Counter()
		self.dl_start_time = libtime.now()

		urls = self.exe_invocation.args

		# Only load DNS if its needed.
		lendpoints = []
		for struct, x in endpoints:
			if x.protocol == 'internet-names':
				a = socket.getaddrinfo(x.address, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
				for i in a:
					ip = i[-1][0]
					y = libkernel.endpoint('ip4', ip, x.port)
					print('Possible host:', y)
				lendpoints.append((struct, y))
			else:
				lendpoints.append((struct, x))

		if not lendpoints:
			self.terminate()
			return

		hc = self.dl_dispatch(lendpoints[0])
		r = self.controller.scheduler.recurrence(self.dl_status)

def main(inv:process.Invocation) -> process.Exit:
	os.umask(0o137)
	# URL target; endpoint exists on a remote system.
	endpoints = [(struct, host.realize(struct)) for struct in map(ri.parse, inv.args)]

	#Download.spawn('fetch', inv, endpoints)
	exe = Download(inv, 'fetch')
	start = functools.partial(exe.dl_initialize, endpoints)
	libkernel.system.spawn('root', [exe]).boot(start)

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
