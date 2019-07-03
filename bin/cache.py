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
import collections

from ...system import files
from ...system import process

from ...time import types as timetypes
from ...internet import ri
from ...internet import host

from ...kernel import core as kcore
from ...kernel import flows as kflows
from ...kernel import io as kio

from ...system import network

from .. import http
from .. import agent

from ...security import openssl as pki
certificates = os.environ.get('SSL_CERT_FILE', '/etc/ssl/cert.pem')
try:
	with open(certificates, 'rb') as f:
		security_context = pki.Context(certificates=(f.read(),))
except:
	security = None
	securtiy_context = None

class Download(kcore.Context):
	dl_monitor = None
	dl_tls = None
	dl_transfer_counter = None
	dl_content_length = None
	dl_identities = None
	_dl_xfer = None

	def __init__(self, endpoints):
		self.dl_endpoints = endpoints

	def dl_pprint(self, file, screen, source):
		rp = screen.terminal_type.normal_render_parameters

		phrase = screen.Phrase.from_words(
			itertools.chain.from_iterable(
				rp.apply(textcolor=color).form(s)
				for s, color in source
			)
		)
		file.buffer.write(b''.join(screen.render(phrase)) + screen.reset_text())

	def dl_response_collected(self):
		target_path = self.dl_target_path
		self.dl_status()

		from ...terminal.format import path
		from ...terminal import matrix
		screen = matrix.Screen()
		sys.stdout.write('\n\rResponse collected; data stored in ')
		self.dl_pprint(sys.stdout, screen, path.f_route_absolute(target_path))
		sys.stdout.write('\n')

		self.executable.exe_invocation.exit(0)

	def xact_exit(self, subxact):
		if subxact == self._dl_xfer:
			self.dl_response_collected()

	def dl_request(self, struct):
		path = ri.http(struct)
		headers = [
			(b'Host', struct['host'].encode('idna')),
			(b'Accept', b"application/octet-stream, */*"),
			(b'User-Agent', b"curl/5.0"),
			(b'Connection', b'close'),
		]

		req = agent.RInvocation(None, b'GET', b'/'+path.encode('utf-8'), headers)
		req.parameters['ri'] = struct

		if struct['path']:
			path = files.Path.from_path(struct['path'][-1])
		else:
			path = files.Path.from_path('index')

		self.dl_target_path = path

		return req

	def dl_status(self, time=None, next=timetypes.Measure.of(millisecond=500)):
		window = timetypes.Measure.of(second=8)
		counter = self.dl_transfer_counter

		if not self.dl_identities:
			return next
		x = self.dl_identities[-1]

		if self.dl_monitor is not None:
			monitor = self.dl_monitor
			units, time = monitor.tm_rate(window)
		else:
			units, time = (0, window.__class__(1))

		seconds = time.select('second')

		if seconds:
			rate = (units / time.select('second'))

			try:
				if self.dl_content_length is not None:
					eta = ((self.dl_content_length-counter[x]) / rate)
				else:
					eta = counter[x] / rate
				m = timetypes.Measure.of(second=int(eta), subsecond=eta-int(eta))
				m = m.truncate('millisecond')
				xfer_rate = rate / 1000
			except ZeroDivisionError:
				m = 'never'
				xfer_rate = 0.0

			print("\r%s %d bytes @ %f KB/sec [%r]%s" %(x, counter[x], xfer_rate, m, ' '*40), end='')
		else:
			print("\r%s %d bytes%s" %(x, counter[x], ' '*40), end='')

		return next

	def dl_response_endpoint(self, mitre):
		(channel_id, parameters, connect_input), = mitre.m_correlate() # One response.
		(code, description, headers) = parameters

		rstruct = http.Structures(headers)
		self.dl_content_length = rstruct.length
		path = self.dl_target_path

		if self.dl_tls:
			tls = self.dl_tls
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

		print(rstruct)

		self.dl_identities.append(path)
		self.dl_status()

		target = mitre.system.append_file(str(path))

		xact = kcore.Transaction.create(kio.Transfer())
		self.xact_dispatch(xact)
		routput = kflows.Receiver(connect_input)
		self.dl_monitor = xact.xact_context.io_flow([routput, target], Terminal=kio.flows.Monitor)
		self._dl_xfer = xact
		xact.xact_context.io_execute()

	def dl_dispatch(self, url):
		struct, endpoint = url # ri.parse(x), kio.Endpoint(y)
		req = self.dl_request(struct)

		from ...terminal.format.url import f_struct
		from ...terminal import matrix
		screen = matrix.Screen()
		struct['fragment'] = '[%s]' %(str(endpoint.address),)
		struct['port'] = str(int(endpoint.port))
		self.dl_pprint(sys.stderr, screen, f_struct(struct))
		sys.stderr.write('\n')
		sys.stderr.buffer.flush()

		inv = self.dl_request(struct)
		tp = kio.Transport.from_endpoint(self.system.connect(endpoint))

		if struct['scheme'] == 'https':
			tls_transport = security_context.connect(struct['host'].encode('idna'))
			tls_ts = (tls_transport, kio.security_operations(tls_transport))
			tls_channels = (('security', tls_transport), kflows.Transports.create([tls_ts]))
			self.dl_tls = tls_transport

			tp.tp_extend([tls_channels])
		else:
			# Transparency
			self.dl_tls = None

		xact = kcore.Transaction.create(tp)
		self.xact_dispatch(xact)

		mitre = kflows.Mitre(self.dl_response_endpoint)
		tp.tp_connect(http.allocate_client_protocol(), mitre)

		(channel_id, aconnect), = mitre.m_allocate()
		rp = req.parameters['request']
		iparam = (rp['method'], rp['path'], rp['headers'], None)
		aconnect(iparam, None)
		tp.io_execute()

	def actuate(self):
		endpoints = self.dl_endpoints

		self.dl_identities = []
		self.dl_transfer_counter = collections.Counter()

		# Only load DNS if its needed.
		lendpoints = []
		for struct, x in endpoints:
			if x.protocol == 'internet-names':
				cname, a = network.select_transports(x.address, 'https')
				for tptype, af, addr, port in a:
					y = kio.endpoint(af, addr, int(port))
					print('Possible host:', y)
					lendpoints.append((struct, y))
			else:
				lendpoints.append((struct, x))

		if not lendpoints:
			self.terminate()
			return

		hc = self.dl_dispatch(lendpoints[0])
		r = self.executable.controller.scheduler.recurrence(self.dl_status)

def main(inv:process.Invocation) -> process.Exit:
	os.umask(0o137)
	# URL target; endpoint exists on a remote system.
	endpoints = [(struct, host.realize(struct)) for struct in map(ri.parse, inv.args)]

	dl = Download(endpoints)

	from ...kernel import system
	system.dispatch(inv, dl)
	system.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
