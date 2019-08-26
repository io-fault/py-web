"""
# Service contexts for accepting HTTP requests.
"""
import functools
import typing
import weakref

from ..context import match

from ..kernel import core
from ..kernel import flows
from ..kernel import io

from ..internet import ri
from . import http

class Network(core.Context):
	"""
	# System Context for managing a set of &Host instances.
	# Provides grouping for hosts that share the same system network
	# interface.

	# [ Properties ]
	# /http_default/
		# The default HTTP Host; the &Host to select in
		# cases where no (http/header)`Host` is designated by
		# a request.
	"""

	http_default_host = None

	def __init__(self, hostsrc=[]):
		self.http_hosts = weakref.WeakValueDictionary()
		self.http_headers = []
		self._hostsrc = hostsrc

	def net_dispatch(self, host):
		x = core.Transaction.create(host)

		self.xact_dispatch(x)

		for h_name in host.h_names:
			self.http_hosts[h_name] = host

	def net_select_host(self, name):
		return self.http_hosts.get(name) or self.http_hosts[self.http_default_host]

	def net_accept(self, invp):
		"""
		# Route the protocol transactions to the designated host.
		# This only enqueues the invocation for subsequent execution.
		"""

		select = self.net_select_host

		first, *remainder = zip(*invp.inv_accept())

		# Recognize host from first request.
		connect_out, inputctl = first
		channel_id, parameters, connect_input = inputctl

		method, uri, headers = parameters
		headers.extend([
			(b':Method', method),
			(b':URI', uri)
		])
		struct = http.Structures(headers)

		h = select(struct.host)
		ctl = Controller(invp, struct, connect_out, connect_input, channel_id)

		invp.i_update(h.h_accept)
		h.h_route(ctl)

		for connect_out, inputctl in remainder:
			channel_id, parameters, connect_input = inputctl

			method, uri, headers = parameters
			headers.extend([
				(b':Method', method),
				(b':URI', uri)
			])

			struct = http.Structures(headers)
			ctl = Controller(invp, struct, connect_out, connect_input, channel_id)

			h.h_route(ctl)

		return h

	def actuate(self):
		self.provide('network')

		for h in self._hostsrc:
			self.net_dispatch(h)

		del self._hostsrc

	def terminate(self):
		if not self.functioning:
			return

		self.start_termination()

		for x in self.controller.subtransactions:
			x.terminate()

		self.xact_exit_if_empty()

	def xact_void(self, final):
		if self.terminating:
			self.finish_termination()

class Host(core.Context):
	"""
	# An HTTP Host interface for managing routing of service connections,
	# and handling the representation of error cases.

	# [ Properties ]

	# /h_names/
		# The set hostnames that this host can facilitate.
		# The object can be an arbitrary container in order
		# to match patterns as well.

	# /h_canonical/
		# The first name given to &update_host_names. &None
		# if no names were given and the name should be
		# inherited from requests.

	# /h_root/
		# The root of the host's path as a &..context.match.SubsequenceScan.
		# This is the initial path of the router in order to allow "mounts"
		# at arbitrary positions. Built from &requisite prefixes.

	# /h_allowed_methods/
		# Method restrictions for the host. &None if not restricted.

	# /h_mount_point/
		# The prefix used by the proxy to select the host to connect to.
		# When present, applications can use this data to properly
		# generate URLs for redirects.

	# [ Engineering ]
	# While proper caching should be handled by a proxy, caching of "constants"
	# should be performed here as well. A constant would be a resource
	# that is designated as being the only possible version when given
	# the same path. Constants would be shared across forks using a mmap region
	# initialized by a parent process.
	"""

	@staticmethod
	@functools.lru_cache(32)
	def strcache(obj, str=str):
		"""
		# Cache for encoded identifiers often used with a host.
		"""
		return str(obj).encode('ascii')

	@staticmethod
	@functools.lru_cache(16)
	def descriptioncache(obj):
		return http.protocoldata.codes[obj].replace('_', ' ')

	h_defaults = {
		'h_options': (),
		'h_allowed_methods': frozenset({
			b'GET', b'HEAD', b'POST', b'PUT',
			b'PATCH', b'DELETE', b'OPTIONS'
		}),
	}

	h_canonical = None
	h_names = None
	h_options = None
	h_allowed_methods = h_defaults['h_allowed_methods']
	h_mount_point = None

	def actuate(self):
		self.provide('host')
		self.h_configure([y(x) for x, y in self._h_parts.items()])

	def h_enable_options(self, *option_identifiers:str):
		self.h_options.update(option_identifiers)

	def h_disable_options(self, *option_identifiers:str):
		self.h_options.difference_update(option_identifiers)

	def h_update_names(self, *names):
		"""
		# Modify the host names that this interface responds to.
		"""

		self.h_names = set(names)

		if names:
			self.h_canonical = names[0]
		else:
			self.h_canonical = None

	def __init__(self, partitions):
		self._h_parts = partitions

	def h_configure(self, partitions, root=None, Index=match.SubsequenceScan):
		"""
		# Configure and dispatch the host's partitions.
		"""

		hp = self.h_partitions = weakref.WeakValueDictionary()
		for partctx in partitions:
			hp[partctx.part_path] = partctx

		self.h_root = Index(hp.keys())
		for partctx in partitions:
			xact = core.Transaction.create(partctx)
			self.xact_dispatch(xact)

	def structure(self):
		props = [
			('h_canonical', self.h_canonical),
			('h_names', self.h_names),
			('h_options', self.h_options),
			('h_allowed_methods', self.h_allowed_methods),
		]

		return (props, None)

	def h_options_request(self, ctl):
		"""
		# Handle a request for (http/initiate)`OPTIONS * HTTP/x.x`.
		# Individual Resources may support an OPTIONS request as well.
		"""

		ctl.add_header(b'Allow', b','.join(list(self.h_allowed_methods)))
		ctl.set_response(b'204', b'NO CONTENT', None)
		ctl.accept(None)
		ctl.connect(None)

	def h_error(self, ctl, code, exc, description=None):
		"""
		# Host error handler. By default, emits an XML document with an assigned stylesheet
		# that can be retrieved for formatting the error. Additional error data may by
		# injected into the document in order to provide application-level error information.

		# Given the details about an HTTP error message and the corresponding
		# &http.IO, emit the rendered error to the client.
		"""

		strcode = str(code)
		code_bytes = self.strcache(code)

		if description is None:
			description = self.descriptioncache(code)

		description_bytes = self.strcache(description)
		errmsg = b''.join([
			b'<?xml version="1.0" encoding="ascii"?>',
			b'<?xml-stylesheet type="text/xsl" href="',
			b'/sys/error.xsl',
			b'"?>',
			b'<error xmlns="http://if.fault.io/xml/failure" domain="/internet/http">',
			b'<frame code="' + code_bytes + b'" message="' + description_bytes + b'"/>',
			b'</error>',
		])

		ctl.set_response(code_bytes, description_bytes, len(errmsg), cotype=b'text/xml')
		ctl.http_iterate_output([(errmsg,)])

	def h_fallback(self, ctl):
		"""
		# Method called when no prefix matches the request.

		# Provided for subclasses in order to override the usual (http/error)`404`.
		"""

		ctl.accept(None)
		self.h_error(ctl, 404, None)

	def h_route(self, ctl):
		"""
		# Build additional parameters for the request and select a mount point to handle it.
		"""

		path = ctl.request.pathstring
		initial = self.h_root.get(path, None)

		# No prefix match.
		if initial is None:
			if path == '*' and ctl.request.method == 'OPTIONS':
				return self.h_options_request(ctl)
			else:
				return self.h_fallback(ctl)
		else:
			partition = self.h_partitions[initial]
			return partition.part_select(ctl)

	def h_accept(self, invp):
		"""
		# Allocate a sequence of controllers and route them using &h_route.
		"""

		for connect_out, inputctl in zip(*invp.inv_accept()):
			channel_id, parameters, connect_input = inputctl

			method, uri, headers = parameters
			headers.extend([
				(b':Method', method),
				(b':URI', uri)
			])

			struct = http.Structures(headers)
			ctl = Controller(invp, struct, connect_out, connect_input, channel_id)

			self.h_route(ctl)

	def terminate(self):
		self.start_termination()

		for x in self.controller.subtransactions:
			x.terminate()

		self.xact_exit_if_empty()

	def xact_void(self, final):
		if self.terminating:
			self.finish_termination()

class Partition(core.Context):
	"""
	# Base class for host applications.
	"""

	def __init__(self, path):
		self.part_path = path
		self.part_depth = path.count('/') - 1

	def structure(self):
		props = [
			('part_path', self.part_path),
		]
		return (props, None)

	def actuate(self):
		self.part_init(self.network, self.host)

	def part_select(self, ctl):
		ctl.accept(None)
		self.host.h_error(ctl, 500, None, description='MISCONFIGURED')

	def terminate(self):
		if not self.functioning:
			return

		self.start_termination()

		for x in self.controller.subtransactions:
			x.terminate()

		self.xact_exit_if_empty()

	def xact_void(self, final):
		if self.terminating:
			self.finish_termination()

class Controller(object):
	"""
	# Request execution controller for HTTP services.
	"""

	def __init__(self, invocations, request:http.Structures, connect_output, connect_input, channel_id):
		self.invocations = invocations
		self.request = request
		self.response_headers = []
		self._response = None
		self._connect_output = connect_output
		self._connect_input = connect_input
		self._request_channel_id = channel_id

	@property
	def transport(self) -> io.Transport:
		return self.invocations.controller.xact_context

	def add_header(self, key, value):
		self.response_headers.append((key, value))

	def extend_headers(self, pairs):
		self.response_headers.extend(pairs)

	def set_response(self, code, descr, length, cotype=None):
		self._response = (code, descr, self.response_headers, length)
		if cotype is not None:
			self._http_content_headers(cotype)

	def connect(self, channel):
		"""
		# Initiate the response and connect the &channel as the HTTP response entity body.
		"""
		final = self.request.final

		if final:
			self.response_headers.append((b'Connection', b'close'))
			self._connect_output(self._response, channel)
			self.invocations.i_close()
		else:
			self._connect_output(self._response, channel)

	def accept(self, channel):
		"""
		# Connect entity body of the request to the given &channel.
		"""
		return self._connect_input(channel)

	def http_continue(self, headers):
		"""
		# Emit a (http/code)`100` continue response
		# with the given headers. Emitting a continuation
		# after a non-100 response has been sent will fault
		# the Transaction.

		# [ Engineering ]
		# Currently, the HTTP implementation presumes one response
		# per transaction which is in conflict with HTTP/1.1's CONTINUE.
		"""
		raise Exception("not supported")

	def http_redirect(self, location):
		"""
		# Location header redirect using a 302-FOUND response.
		"""
		self.add_header(b'Location', location.encode('utf-8'))
		self.set_response(b'302', b'Found', None)
		self.connect(None)
		self.accept(None)

	def _http_content_headers(self, cotype:bytes):
		"""
		# Define the type and length of the entity body to be sent.
		"""

		l = self._response[-1]
		rh = self.response_headers
		self.response_headers.append((b'Content-Type', cotype))

		if l is None:
			rh.append((b'Transfer-Encoding', b'chunked'))
		else:
			lstr = str(l).encode('ascii')
			rh.append((b'Content-Length', lstr))

	def http_iterate_output(self, iterator:typing.Iterable):
		"""
		# Construct a Flow consisting of a single &flows.Iterate instance
		# used to stream output to the connection protocol state.

		# The &io.Transfer transaction will be dispatched into the &io.Transport
		# supporting the connection to the remote peer.
		"""

		itc = flows.Iteration(iterator)
		output_source = flows.Relay(self.invocations.i_catenate, self._request_channel_id)

		xf = io.Transfer()
		ox = core.Transaction.create(xf)
		self.invocations.controller.dispatch(ox)
		xf.io_flow([itc, output_source])

		self.connect(output_source)

	def http_write_output(self, cotype:str, data:bytes):
		"""
		# Send the given &data to the remote end with the given content type, &cotype.
		# If other headers are desired, they *must* be configured before running
		# this method.
		"""

		self.set_response(b'200', b'OK', len(data), cotype=cotype.encode('ascii'))
		return self.http_iterate_output([(data,)])

	def http_write_text(self, string:str):
		"""
		# Send the given &data to the remote end with the given &mime type.
		# If other headers are desired, they *must* be configured before running
		# this method.
		"""

		d = string.encode('utf-8')
		self.set_response(b'200', b'OK', len(d), cotype=b'text/plain;charset=utf-8')
		return self.http_iterate_output(((d,),))

	def http_read_file_into_output(self, route, cotype:str=None):
		"""
		# Send the file referenced by &route to the remote end as
		# the (HTTP) entity body.

		# [ Parameters ]
		# /route/
			# Route instance selecting the file.
		# /cotype/
			# The content type to designate in the response.
		"""

		times, size = route.meta()
		lm = times[1].select('rfc').encode('utf-8')
		segments = memory.Segments.open(str(route))

		self.add_header(b'Last-Modified', lm)
		self.set_response(b'200', b'OK', size, cotype=cotype)

		self.http_iterate_output((x,) for x in segments)

	def http_send_file_head(self, route, cotype:str=None):
		"""
		# Send the file referenced by &route to the remote end as
		# the (HTTP) entity body.

		# [ Parameters ]
		# /route/
			# Route instance selecting the file.
		# /cotype/
			# The content type to designate in the response.
		"""

		times, size = route.meta()
		lm = times[1].select('rfc').encode('utf-8')

		self.add_header(b'Last-Modified', lm)
		self.set_response(b'200', b'OK', size, cotype=cotype)

		self.connect(None)

	def http_read_input_into_buffer(self, callback, *args, limit=None):
		"""
		# Connect the input Flow to a buffer that executes
		# the given callback when the entity body has been transferred.
		"""

		# Service creation.
		reader = io.Transfer()
		rx = core.Transaction.create(reader)
		storage = flows.Collection.list()
		recv = flows.Receiver(self.accept)

		cb = functools.partial(callback, self, storage.c_storage, *args)

		self.xact_dispatch(rx)
		reader.io_flow([recv, storage], completion=cb)
		recv.f_transfer(None) # connect_input
