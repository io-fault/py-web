"""
# fault download client.

# HTTP client designed for downloading resources to the current working directory.

# [ Engineering ]

# The download client is rather limited in its capacity. The intention of this program
# is to provide a robust HTTP client for retrieving resources and storing them in
# the local file system.

# /Host Scanning in case of 404/
	# 404 errors do not cause the client to check the other hosts.
# /Parallel Downloads/
	# Only one transfer per-process is supported.
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

from ...kernel import core as kcore
from ...kernel import dispatch as kdispatch
from ...kernel import flows as kflows
from ...kernel import io as kio

from .. import http
from .. import agent

from ...security import kprotocol as ksecurity

redirect_limit = 4

try:
	security_context = ksecurity.load('client').Context(applications=(b'http/1.1',))
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

	def __init__(self, status, output, depth, endpoint):
		self.dl_display = status
		self.dl_output = output
		self.dl_endpoint = endpoint
		self.dl_depth = depth
		self.dl_identities = []

	def _force_quit(self):
		self.dl_display.write('\n') # Create newline, avoid trampling on status.
		raise Exception("termination")

	def terminate(self):
		self.start_termination()
		self.critical(self._force_quit)

	def dl_pprint(self, screen, source):
		rp = screen.terminal_type.normal_render_parameters

		phrase = screen.Phrase.from_words(
			itertools.chain.from_iterable(
				rp.apply(textcolor=color).form(s)
				for s, color in source
			)
		)
		self.dl_display.buffer.write(b''.join(screen.render(phrase)) + screen.reset_text())

	def dl_response_collected(self):
		if self.dl_redirected:
			return
		self.dl_status()

		from ...terminal.format import path
		from ...terminal import matrix
		screen = matrix.Screen()
		self.dl_display.write('\n\rResponse collected; data stored in ')
		self.dl_pprint(screen, path.f_route_absolute(self.dl_output or self.dl_resource_name))
		self.dl_display.write('\n')

		self.executable.exe_status = 0
		self._r.terminate()
		del self._r
		self.finish_termination()

	def xact_void(self, final):
		self.dl_response_collected()

	def dl_request(self, struct):
		path = ri.http(struct)
		headers = [
			(b'Host', struct['host'].encode('idna')),
			(b'Accept', b"application/octet-stream, */*"),
			(b'User-Agent', b"curl/7.55.0"),
			(b'Connection', b'close'),
		]

		req = agent.RInvocation(None, b'GET', b'/'+path.encode('utf-8'), headers)
		req.parameters['ri'] = struct

		if struct['path']:
			path = files.Path.from_path(struct['path'][-1])
		else:
			path = files.Path.from_path('index')

		self.dl_resource_name = path
		return req

	def dl_status(self, time=None):
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
			m = m.truncate('second')
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

		self.dl_display.write(status + erase + '\r')
		return next

	def dl_response_endpoint(self, invp):
		report = self.dl_display.write
		self.dl_controller._correlation(*list(invp.i_correlate())[0])
		ctl = self.dl_controller

		if self.dl_tls:
			tls = self.dl_tls
			i = tls.status()
			tlsbuf = ('%s [%s]\n' %(i[0], i[2]))
			tlsbuf += ('\thostname: %s\n' % (tls.hostname.decode('idna'),))
			tlsbuf += ('\tapplication: %s\n' % (repr(tls.application),))
			tlsbuf += ('\tprotocol: %s\n' % (tls.protocol,))
			fields = '\n\t'.join(
				'%s: %r' %(k, v)
				for k, v in tls.peer.subject
			)
			tlsbuf += ('\t'+fields+'\n')
			report(tlsbuf)
		else:
			report('TLS [none: no transport layer security]\n')

		rstruct = ctl.http_response
		pdata, (rx, tx) = (invp.sector.xact_context.tp_get('http'))
		report(tx.http_version.decode('utf-8') + '\n\t')
		report('\n\t'.join(str(rstruct).split('\n')) + '\n')

		if self.dl_output is None:
			filepath = self.dl_resource_name
		else:
			filepath = self.dl_output

		# Redirect.
		if rstruct.redirected:
			ctl.accept(None)
			self.dl_redirected = True
			uri = rstruct.cache[b'location'].decode('utf-8')
			report("\n")
			report("Redirected[%d]: %s\n\n" %(ctl.http_response.status, uri))

			if self.dl_depth >= redirect_limit:
				report("Redirect limit (%d) reached.\n" %(self.redirect_limit,))
				self.executable.exe_status = 1
			else:
				dl = Download(self.dl_display, filepath, self.dl_depth + 1, ri.parse(uri))
				self.executable.exe_enqueue(dl)

			self._r.terminate()
			self.finish_termination()
			return

		self.dl_content_length = rstruct.length
		self.dl_identities.append(filepath)
		self.dl_status()
		self.dl_monitor = ctl.http_read_input_into_file(str(filepath), Terminal=kio.flows.Monitor)

	def dl_dispatch(self, struct, endpoint):
		req = self.dl_request(struct)

		from ...terminal.format.url import f_struct
		from ...terminal import matrix
		screen = matrix.Screen()

		if 'port' in struct:
			endpoint = endpoint.replace(port=int(struct['port']))

		struct['fragment'] = '[%s]' %(str(endpoint.address),)
		struct['port'] = str(int(endpoint.port))
		self.dl_pprint(screen, f_struct(struct))
		self.dl_display.write('\n')
		self.dl_display.buffer.flush()

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
		ctl = agent.Controller(inv, *list(inv.i_allocate())[0])

		rp = req.parameters['request']
		ctl.http_extend_headers(rp['headers'])
		ctl.http_set_request(rp['method'], rp['path'], None, final=True)
		ctl.connect(None)
		self.dl_controller = ctl
		tp.io_execute()
		self.critical(tp.io_transmit_close)

	def actuate(self):
		lendpoints = []

		struct = self.dl_endpoint
		host = struct['host'].strip('[').strip(']')
		cname, a = network.select_endpoints(host, struct['scheme'])
		for ep in a:
			self.dl_display.write('Possible host: %s\n' %(str(ep),))
			lendpoints.append((struct, ep))

		if not lendpoints:
			self.terminate()
			return

		hc = self.dl_dispatch(*lendpoints[0])
		freq = timetypes.Measure.of(millisecond=150)
		self._r = kdispatch.Recurrence(self.dl_status, freq)
		self.sector.dispatch(self._r)

def main(inv:process.Invocation) -> process.Exit:
	ri.strict()
	os.umask(0o137)

	path = None
	iri = inv.argv[0]
	if len(inv.argv) > 1:
		pathstr = inv.argv[1].strip()
		if pathstr and pathstr != '-':
			path = files.Path.from_path(pathstr)
		del pathstr

	dl = Download(sys.stderr, path, 1, ri.parse(iri))

	from ...kernel import system
	process = system.dispatch(inv, dl)
	system.set_root_process(process)
	system.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
