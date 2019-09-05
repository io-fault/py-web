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
from ...system import network

from ...time import types as timetypes
from ...internet import ri
from ...internet import host

from ...kernel import core as kcore
from ...kernel import flows as kflows
from ...kernel import io as kio

from .. import http
from .. import agent

from ...security import kprotocol as ksecurity

try:
	security_context = ksecurity.load('client').Context()
except ImportError:
	security_context = None

class Download(kcore.Context):
	dl_monitor = None
	dl_tls = None
	dl_content_length = None
	dl_identities = None
	dl_redirected = False
	_dl_xfer = None
	_dl_last_status = 0

	def __init__(self, endpoints):
		self.dl_endpoints = endpoints

	def _force_quit(self):
		print() # Avoid trampling on status.
		raise Exception("termination")

	def terminate(self):
		self.start_termination()
		self.critical(self._force_quit)

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
		if self.dl_redirected:
			return

		target_path = self.dl_target_path
		self.dl_status()

		from ...terminal.format import path
		from ...terminal import matrix
		screen = matrix.Screen()
		sys.stdout.write('\n\rResponse collected; data stored in ')
		self.dl_pprint(sys.stdout, screen, path.f_route_absolute(target_path))
		sys.stdout.write('\n')

		self.executable.exe_status = 0
		self._r.terminate()
		self.finish_termination()

	def xact_void(self, final):
		self.dl_response_collected()

	def dl_request(self, struct):
		path = ri.http(struct)
		headers = [
			(b'Host', struct['host'].encode('idna')),
			(b'Accept', b"application/octet-stream, */*"),
			(b'User-Agent', b"curl/7.54.0"),
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

	def dl_status(self, time=None, next=timetypes.Measure.of(millisecond=300)):
		window = timetypes.Measure.of(second=8)
		final = '\r'

		if not self.dl_identities:
			return next

		x = self.dl_identities[-1]

		if self.dl_monitor is not None:
			monitor = self.dl_monitor
			units, time = monitor.tm_rate(window)
			total = units + monitor.tm_aggregate[0]

			if monitor.terminated:
				units += monitor.tm_aggregate[0]
				time = time.increase(monitor.tm_aggregate[1])
				final = '\n'
		else:
			total = 0
			units, time = (0, window.__class__(1))

		try:
			rate = (units / time) * (1000000000) # ns
		except ZeroDivisionError:
			rate = units

		try:
			if self.dl_content_length is not None:
				eta = ((self.dl_content_length-total) / rate)
			else:
				eta = total / rate
			m = timetypes.Measure.of(second=int(eta), subsecond=eta-int(eta))
			m = m.truncate('millisecond')
			xfer_rate = rate / 1000
		except ZeroDivisionError:
			m = 'never'
			xfer_rate = 0.0

		last = self._dl_last_status
		status = ": %s %d bytes @ %f KB/sec [Estimate %r]" %(x, total, xfer_rate, m)

		current = len(status)
		self._dl_last_status = current
		change = last - current
		if change > 0:
			erase = (' ' * change)
		else:
			erase = ''

		print(status + erase, end=final)
		return next

	def dl_response_endpoint(self, invp):
		(channel_id, parameters, connect_input), = invp.m_correlate() # One response.
		(code, description, headers) = parameters

		if self.dl_tls:
			tls = self.dl_tls
			i = tls.status()
			print('%s [%s]' %(i[0], i[2]))
			print('\thostname:', tls.hostname.decode('idna'))
			print('\tapplication:', tls.application)
			print('\tprotocol:', tls.protocol)
			fields = '\n\t'.join([
				'%s: %r' %(k, v)
				for k, v in tls.peer.subject
			])
			print('\t'+fields)
		else:
			print('TLS [none: no transport layer security]')

		rstruct = http.Structures(headers)
		print(rstruct)

		# Redirect.
		if code[:1] == b'3':
			self.dl_redirected = True
			uri = rstruct.cache[b'location'].decode('utf-8')

			print("\nRedirected[%s]: %s\n" %(code.decode('utf-8'), uri))
			connect_input(None)
			endpoints = [(struct, host.realize(struct)) for struct in map(ri.parse, (uri,))]
			dl = Download(endpoints)
			self.executable.exe_enqueue(dl)

			self._r.terminate()
			self.finish_termination()
			return

		self.dl_content_length = rstruct.length
		path = self.dl_target_path

		self.dl_identities.append(path)
		self.dl_status()

		target = invp.system.append_file(str(path))

		xact = kcore.Transaction.create(kio.Transfer())
		self.xact_dispatch(xact)
		routput = kflows.Receiver(connect_input)
		self.dl_monitor = xact.xact_context.io_flow([routput, target], Terminal=kio.flows.Monitor)
		self._dl_xfer = xact
		xact.xact_context.io_execute()

	def dl_dispatch(self, struct, endpoint):
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
		fd = network.connect(endpoint)
		tp = kio.Transport.from_endpoint(self.system.allocate_transport(fd))

		if struct['scheme'] == 'https':
			tls_transport = security_context.connect(struct['host'].encode('idna'))
			tls_ts = ksecurity.allocate(tls_transport)
			tls_channels = (('security', tls_transport), tls_ts)
			self.dl_tls = tls_transport

			tp.tp_extend([tls_channels])
		else:
			# Transparency
			self.dl_tls = None

		xact = kcore.Transaction.create(tp)
		self.xact_dispatch(xact)

		inv = tp.tp_connect(self.dl_response_endpoint, http.allocate_client_protocol())

		(channel_id, aconnect), = inv.m_allocate()
		rp = req.parameters['request']
		iparam = (rp['method'], rp['path'], rp['headers'], None)
		aconnect(iparam, None)
		tp.io_execute()
		self.critical(tp.io_transmit_close)

	def actuate(self):
		endpoints = self.dl_endpoints

		self.dl_identities = []

		# Only load DNS if its needed.
		lendpoints = []
		for struct, x in endpoints:
			if x.protocol == 'internet-names':
				cname, a = network.select_endpoints(x.address, struct['scheme'])
				for ep in a:
					print('Possible host:', str(ep))
					lendpoints.append((struct, ep))
			else:
				lendpoints.append((struct, x))

		if not lendpoints:
			self.terminate()
			return

		hc = self.dl_dispatch(*lendpoints[0])
		self.sector.scheduling()
		self._r = self.sector.scheduler.recurrence(self.dl_status)

def main(inv:process.Invocation) -> process.Exit:
	os.umask(0o137)
	# URL target; endpoint exists on a remote system.
	endpoints = [(struct, host.realize(struct)) for struct in map(ri.parse, inv.args)]

	dl = Download(endpoints)

	from ...kernel import system
	process = system.dispatch(inv, dl)
	system.set_root_process(process)
	system.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
