"""
# Service contexts for accepting HTTP requests.
"""
import functools
import typing

from ..context import match

from ..kernel import core
from ..kernel import flows
from ..kernel import io

from . import http

class Invocation(object):
	"""
	# An HTTP request received by a service and its determined response headers and status.

	# The parameters should store exact bytes instances that were read by the transport.
	# Higher-level interfaces, &Structure, should often decode these field accordingly.

	# [ Properties ]

	# /headers/
		# The sequence of headers held by the parameters of the request.
	# /method/
		# The request method held by the parameters.
	# /path/
		# The request URI held by the parameters.

	# /status/
		# The code-description pair designating success or failure.
		# Usually set by &assign_status.
	# /response_headers/
		# Exact sequence of headers that should be serialized to the connection.
	"""

	projection = False
	context = None

	@property
	def headers(self) -> http.HeaderSequence:
		return self.parameters['request']['headers']

	@property
	def method(self) -> str:
		"""
		# Decoded form of the request's method.
		"""
		return self.parameters['request']['method'].decode('ascii')

	@property
	def path(self) -> str:
		"""
		# Decoded form of the request URI's path.
		"""
		return self.parameters['request']['path'].decode('ascii')

	def declare_output_length(self, length:int):
		self.response_headers.append((b'Content-Length', str(length).encode('ascii')))
		self._output_length = length

	def declare_output_chunked(self):
		self.response_headers.append((b'Transfer-Encoding', b'chunked'))
		self._output_length = None

	def __init__(self, exit_method, method:bytes, path:bytes, headers:http.HeaderSequence):
		self.exit_method = exit_method
		self.status = None # HTTP response code and string
		self.response_headers = None

		self.parameters = {
			'request': {
				'method': method,
				'path': path,
				'headers': headers,
			},
		}

	def exit(self):
		"""
		# Call the configured exit method signalling the completion of the Request.

		# This is called after all *transfers* associated with the
		# with the request have been completed. Data may still be in connection
		# buffers when this is called.
		"""
		return self.exit_method()

	def __str__(self):
		init = " ".join(str(x) for x in (self.method, self.path))
		headers = self.headers
		if not headers:
			return init

		heads = "\n\t".join(x.decode('ascii') + ': ' + y.decode('ascii') for (x,y) in headers)
		return init + "\n\t" + heads

	def set_response_ok(self):
		"""
		# Set response status to OK.
		# Shorthand for `set_response_status(200, 'OK')`.
		"""
		self.status = (200, 'OK')
		return self

	def set_response_status(self, code:int, description:str):
		"""
		# Designate the result of the Protocol Transaction.
		"""
		self.status = (code, description)
		return self

	def set_response_headers(self, headers):
		"""
		# Assign the exact sequence of response headers that are to be processed by a client.
		# Any headers already present will be forgotten.
		"""
		self.response_headers = headers
		return self

	@classmethod
	def from_request(Class, rline, headers):
		"""
		# Initialize an Invocation using a parsed request line and headers.
		# Primarily, this is used by &fork in a server context.
		"""

		method, path, version = rline
		return Class(None, method, path, headers)

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
	http_default = None
	Structures = http.Structures

	def __init__(self):
		self.http_hosts = []
		self.http_headers = []

	def net_select_host(self, name):
		pass

	def net_route(self, transports):
		"""
		# Route the protocol transactions to the designated host.
		# This only enqueues the invocation for subsequent execution.
		"""

		select = self.net_select_host
		for x in io:
			for x in mitre.m_accept():
				req = x[1][0] # (connect-output, (request, connect-input))
				s = Structures(req[0])

				h = select(s.host, self.http_default)
				h.h_route(s, x)

		return h

	def actuate(self):
		self.provide('network')

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
		# The root of the host's path as a &..computation.match.SubsequenceScan.
		# This is the initial path of the router in order to allow "mounts"
		# at arbitrary positions. Built from &requisite prefixes.

	# /h_index/
		# The handler for the root path. May be &None if &root can resolve it.

	# /h_allowed_methods/
		# Option set provided in response to (http/initiate)`OPTIONS * HTTP/1.x`.

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
	@functools.lru_cache(64)
	def path(initial, path, len=len, tuple=tuple):
		iparts = initial.split('/')[1:-1]
		nip = len(iparts)
		parts = tuple(path.split('/')[1:])
		return Path(Path(None, parts[:nip]), (parts[nip:]))

	@staticmethod
	@functools.lru_cache(16)
	def strcache(obj):
		return obj.__str__().encode('ascii')

	@staticmethod
	@functools.lru_cache(16)
	def descriptioncache(obj):
		return data_http.code_to_names[obj].replace('_', ' ')

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

	def h_update_mounts(self, prefixes, root=None, Index=match.SubsequenceScan):
		"""
		# Update the host interface's root prefixes.
		"""

		self.h_prefixes = prefixes
		self.h_root = Index(prefixes.keys())
		self.h_index = root

	def structure(self):
		props = [
			('h_canonical', self.h_canonical),
			('h_names', self.h_names),
			('h_options', self.h_options),
			('h_allowed_methods', self.h_allowed_methods),
		]

		return (props, None)

	def h_options_request(self, invocation):
		"""
		# Handle a request for (http/initiate)`OPTIONS * HTTP/x.x`.
		# Individual Resources may support an OPTIONS request as well.
		"""
		invocation.protocol_read_void()
		effect = (b'204', b'NO CONTENT', [
			(b'Allow', b','.join(list(self.h_allowed_methods)))
		])
		invocation.protocol_no_content(effect)

	def h_error(self, code, invocation, exc):
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
			description = self.descriptioncache(code_bytes)

		description_bytes = self.strcache(description)
		errmsg = (
			b'<?xml version="1.0" encoding="ascii"?>',
			b'<?xml-stylesheet type="text/xsl" href="',
			b'/sys/error.xsl',
			b'"?>',
			b'<error xmlns="http://fault.io/xml/failure" domain="/internet/http">',
			b'<frame code="' + code_bytes + b'" message="' + description_bytes + b'"/>',
			b'</error>',
		)

		px.response.initiate((version, code_bytes, description_bytes))
		px.response.add_headers([
			(b'Content-Type', b'text/xml'),
			(b'Content-Length', http.length_strings(errmsg),)
		])

		proc = flows.Iteration([errmsg])
		px.controller.acquire(proc)
		px.xact_ctx_connect_output(proc)
		proc.actuate()

	def h_fallback(self, executable):
		"""
		# Method called when no prefix matches the request.

		# Provided for subclasses in order to override the usual (http/error)`404`.
		"""

		r = self.h_error(404, Path(None, tuple(path)), query, px, None)
		executable.protocol_discard_input()
		return r

	def h_route(self, sector, invocation, dict=dict):
		"""
		# Called from an I/O (normally input) event, routes the transaction
		# to the processor bound to the prefix matching the request's.

		# Exceptions *must* fault the Connection, and normally do if called
		# from the expected mechanism.
		"""

		req = px.request
		path = req.path.decode('utf-8').split('?', 1)
		path.extend((None,None))
		path = path[:3]
		uri_path = path[0]

		parts = ri.Parts('authority', 'http', req.host+':80', *path)
		ris = ri.structure(parts)

		initial = self.h_root.get(path[0], None)

		# No prefix match.
		if initial is None:
			if uri_path == '*' and px.request.method == b"OPTIONS":
				return self.h_options_request(parts.query, px)
			else:
				return self.h_fallback(px, ris.get('path', ()), parts.query)
		else:
			xact_processor = self.h_prefixes[initial]
			path = self.path(initial, uri_path)

			xact_processor(path, ris.get('query', {}), px)

	def h_transaction_fault(self, sector):
		"""
		# Called when a protocol transaction's sector faults.
		"""

		# The connection should be abruptly interrupted if
		# the output flow has already been connected.
		self.h_error(500, path, query, px, exc)

class Dispatch(core.Executable):
	"""
	# HTTP Request Dispatch.
	"""

	def http_transfer_output(self, channels):
		"""
		# Execute a transfer targeting the output of the &Invocation.
		"""
		xact = core.Transaction.create(io.Transfer())
		self.xact_dispatch(xact)
		xact.xact_context.io_flow(channels + [self.exe_invocation._output])
		xact.io_execute()

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
		raise NotImplementedError("not supported")

	def http_redirect(self, location):
		"""
		# Location header redirect.
		"""
		res = self.response

		if self.request.connection in {b'close', None}:
			res.add_header(b'Connection', b'close')

		res.add_header(b'Location', location.encode('ascii'))
		res.initiate((b'HTTP/1.1', b'302', b'Found')) # XXX: Refer to connection version.
		self.io_write_null()

	def http_response_content(self, cotype:bytes, colength:int):
		"""
		# Define the type and length of the entity body to be sent.
		"""
		self.exe_invocation.add_headers([
			(b'Content-Type', cotype),
			(b'Content-Length', colength),
		])

	def http_iterate_output(self, iterator:typing.Iterable):
		"""
		# Construct a Flow consisting of a single &flows.Iterate instance
		# used to stream output to the connection protocol state.

		# The &flows.Channel will be dispatched into the &Connection for proper
		# fault isolation in cases that the iterator produces an exception.
		"""

		f = flows.Iteration(iterator)
		self.http_transfer(f)
		self.response.initiate((self.request.version, b'200', b'OK'))
		self.xact_ctx_connect_output(f)

		return f

	def http_write_output(self, mime:str, data:bytes):
		"""
		# Send the given &data to the remote end with the given &mime type.
		# If other headers are desired, they *must* be configured before running
		# this method.
		"""

		self.response.add_headers([
			(b'Content-Type', mime.encode('utf-8')),
			(b'Content-Length', length_string(data)),
		])

		return self.io_iterate_output([(data,)])

	def http_read_file_into_output(self, path:str, str=str):
		"""
		# Send the file referenced by &path to the remote end as
		# the (HTTP) entity body.

		# The response must be properly initialized before invoking this method.

		# [ Parameters ]
		# /path/
			# A string containing the file's path.

		# [ Engineering ]
		# The Segments instance needs to be retrieved from a cache.
		"""

		f = flows.Iteration(((x,) for x in memory.Segments.open(str(path))))
		self.xact_dispatch(f)
		self.xact_ctx_connect_output(f)

		return f

	def http_read_input_into_buffer(self, callback, limit=None):
		"""
		# Connect the input Flow to a buffer that executes
		# the given callback when the entity body has been transferred.

		# This should only be used when connecting to trusted hosts as
		# a &flows.Collection instance is used to buffer the entire
		# entire result. This risk can be mitigated by injecting
		# a &flows.Constraint into the Flow.
		"""

		f = flows.Collection.buffer()
		self.xact_dispatch(f)
		f.atexit(callback)
		self.xact_ctx_connect_input(f)

		return f

	def http_read_input_into_file(self, route):
		"""
		# Connect the input Flow's entity body to the given file.

		# The file will be truncated and data will be written in append mode.
		"""

		f = self.context.append_file(str(route))
		self.xact_dispatch(f)
		self.xact_ctx_connect_input(f)

		return f

	def http_write_kport_to_output(self, fd, limit=None):
		"""
		# Transfer data from the &kport, file descriptor, to the output
		# constrained by the limit.

		# The file descriptor will be closed after the transfer is complete.
		"""

		f = self.context.connect_input(fd)
		self.xact_dispatch(f)
		self.xact_ctx_connect_output(f)

		return f

	def http_read_input_into_kport(self, fd, limit=None):
		"""
		# Connect the input Flow's entity body to the given file descriptor.
		# The state of the open file descriptor will be used to allow inputs
		# to be connected to arbitrary parts of a file.

		# The file descriptor will be closed after the transfer is complete.
		"""

		f = self.context.connect_output(fd)
		self.xact_dispatch(f)
		self.xact_ctx_connect_input(f)

		return f

	def http_connect_pipeline(self, kpipeline):
		"""
		# Connect the input and output to a &..system.execution.PInvocation.
		# Received data will be sent to the pipeline,
		# and data emitted from the pipeline will be sent to the remote endpoint.
		"""

		sp, i, o, e = xact.pipeline(kpipeline)
		self.xact_ctx_connect_input(fi)
		self.xact_ctx_connect_output(fo)

		return f
