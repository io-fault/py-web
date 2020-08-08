"""
# Client projection dispatch management.

# Provides Contexts for managing a client's sessions.

# [ Engineering ]
# Agents are fairly complicated with respect to preferences. The current
# implementation presumes HTTP/1.1 in most cases where a protocol priority should
# be used to select a desired wire protocol.

# &Navigation and &Session are essentially unimplemented. Finding a generic structure
# that fits all use cases is unlikely; however, the direction of a traditional user agent
# model should be sufficient in most cases.
"""
import typing
import weakref

from ..kernel import core
from ..kernel import flows
from ..kernel import io
from . import http

def _prepare_http_transports_v0(ifctx, ports, Protocol=http.allocate_client_protocol):
	return [(x, (), Protocol()) for x in ports]

def _prepare_http_transports_v1(ifctx, ports, Protocol=http.allocate_client_protocol_v1):
	return [(x, (), Protocol()) for x in ports]

def _prepare_http_transports_v2(ifctx, ports, Protocol=None):
	raise Exception("not implemented")

protocols = {
	'http': _prepare_http_transports_v0, # Adjustable.
	'http-1': _prepare_http_transports_v1, # Strictly 1.0/1.1 only.
	'http-2': _prepare_http_transports_v2, # Not implemented
}

class Controller(object):
	"""
	# Request execution controller for HTTP agents.

	# [ Properties ]
	# /response/
		# The &http.Structures instance representing the response status and headers.
	"""

	@property
	def transport(self) -> io.Transport:
		return self.invocations.sector.xact_context

	def __init__(self, invocations, channel_id, connect_output):
		self.invocations = invocations
		self.response = None
		self.request_headers = []

		self._connect_input = None
		self._connect_output = connect_output
		self._request = None
		self._request_channel_id = channel_id
		self._final = False

	def _correlation(self, channel_id, parameters, connect_input):
		self._connect_input = connect_input
		self._response_channel_id = channel_id
		self.response = http.Structures(parameters[2]).set_status(*parameters[:2])

	def http_add_header(self, key:bytes, value:bytes):
		"""
		# Append a single header to the header sequence that will be supplied by the response.
		"""
		self.request_headers.append((key, value))
	add_header = http_add_header

	def http_extend_headers(self, pairs:http.HeaderSequence):
		"""
		# Add a sequence of headers.
		"""
		self.request_headers.extend(pairs)
	extend_headers = http_extend_headers

	def http_set_request(self, method:bytes, uri:bytes, length:int, cotype:bytes=None, final=False):
		"""
		# Assign the method and URI of the request and designate the transfer encoding.
		# Excepting &length, all parameters *must* be &bytes instances.

		# If &cotype is &None, neither (http/header)`Content-Length` nor
		# (http/header)`Transfer-Encoding` will be appended to the headers.

		# If &cotype is not &None and &length is &None, chunked transfer encoding will be used.
		# If &cotype is not &None and &length is an integer, (http/header)`Content-Length`
		# will be provided.
		"""

		if cotype is not None:
			self._http_content_headers(cotype, length)

		if final:
			self.request_headers.append((b'Connection', b'close'))
			self._final = True
		else:
			self.request_headers.append((b'Connection', b'keep-alive'))

		self._request = (method, uri, self.request_headers, length)

		return self
	set_request = http_set_request

	def connect(self, channel):
		"""
		# Initiate the request causing headers to be sent and connect the &channel as the
		# HTTP request's entity body. If &channel is &None, no entity body will be supplied.
		"""

		self._connect_output(self._request, channel)
		if self._final:
			self.invocations.i_close()

	def accept(self, channel):
		"""
		# Accept the entity-body of the response into &channel.
		# If &channel is &None, any entity body sent will trigger a fault.
		"""
		return self._connect_input(channel)

	def _http_content_headers(self, cotype:bytes, length:int):
		"""
		# Define the type and length of the entity body to be sent.
		"""

		rh = self.request_headers
		rh.append((b'Content-Type', cotype))

		if length is None:
			rh.append((b'Transfer-Encoding', b'chunked'))
		else:
			lstr = str(length).encode('ascii')
			rh.append((b'Content-Length', lstr))

	def http_dispatch_output(self, channel):
		"""
		# Dispatch the given &channel using a new &io.Transfer instance into &invocations'
		# &io.Transport transaction.
		"""
		output_source = flows.Relay(self.invocations.i_catenate, self._request_channel_id)

		xf = io.Transfer()
		ox = core.Transaction.create(xf)
		self.invocations.sector.dispatch(ox)
		xf.io_flow([channel, output_source])

		return self.connect(output_source)

	def http_iterate_output(self, iterator:typing.Iterable):
		"""
		# Construct a Flow consisting of a single &flows.Iterate instance
		# used to stream output to the connection protocol state.

		# The &io.Transfer transaction will be dispatched into the &io.Transport
		# supporting the connection to the remote peer.
		"""

		itc = flows.Iteration(iterator)
		return self.http_dispatch_output(itc)

	def http_put_data(self, uri:bytes, cotype:bytes, data:bytes):
		"""
		# Send the given &data to the remote end with the given content type, &cotype.
		# If other headers are desired, they *must* be configured before running
		# this method.
		"""

		self.set_request(b'PUT', uri, len(data), cotype=cotype)
		return self.http_iterate_output([(data,)])

	def http_read_input_into_buffer(self, callback, *args, limit=None):
		"""
		# Connect the input to a buffer that executes
		# the given callback when the entity body has been transferred.
		"""

		# Service creation.
		reader = io.Transfer()
		rx = core.Transaction.create(reader)
		storage = flows.Collection.extended_list()
		recv = flows.Receiver(self.accept)

		cb = functools.partial(callback, self, storage.c_storage, *args)

		self.invocations.sector.dispatch(rx)
		reader.io_flow([recv, storage], completion=cb)
		reader.io_execute()

	def http_read_input_into_file(self, path, Terminal=io.flows.Terminal):
		"""
		# Connect the input to a buffer that executes
		# the given callback when the entity body has been transferred.
		"""

		reader = io.Transfer()
		rx = core.Transaction.create(reader)

		ko = self.invocations.system.append_file(str(path))
		recv = flows.Receiver(self.accept)

		self.invocations.sector.dispatch(rx)
		t = reader.io_flow([recv, ko], Terminal=Terminal)
		reader.io_execute()
		return t

	def http_ignore_input(self):
		"""
		# Connect the given input to a transfer that discards events.
		"""

		reader = io.Transfer()
		rx = core.Transaction.create(reader)
		recv = flows.Receiver(self.accept)

		self.xact_dispatch(rx)
		reader.io_flow([recv])
		reader.io_execute()

class Session(core.Context):
	"""
	# Session dispatching invocation projections for facilitating a request.
	"""

	def __init__(self):
		self.s_headers = []
		self.s_cookies = {} # Session, per host.
		self.s_connections = collections.defaultdict(weakref.WeakSet)

	def s_correlate(self, inv):
		for x in inv.i_correlate():
			ctl = self.s_controllers.pop((inv, x[0]))
			ctl._correlation(*x)

	def xact_exit(self, xact):
		transport = xact.xact_context

	def actuate(self):
		self.provide('session')

class Navigation(core.Context):
	"""
	# Root agent context managing global headers, connection strategy cache, and host state.
	"""

	def __init__(self):
		self._nav_session_ids = 0
		self.nav_headers = []
		self.nav_cookies = {} # Persistent, per host.
		self.nav_sessions = weakref.WeakValueDictionary()

	def nav_connect(self, endpoint):
		"""
		# Allocate transport communicating with &endpoint with respect to the navigation's
		# perspective.
		"""
		return self.system.connect(endpoint)

	def nav_route(self, io):
		pass

	def nav_open_session(self, session):
		self.sector.dispatch(core.Transaction.create(session))

		sid = self._nav_session_ids + 1
		self._nav_session_ids = sid
		self.nav_sessions[sid] = session

		return sid

	def nav_close_session(self, sid):
		pass

	def actuate(self):
		self.provide('navigation')

	def xact_void(self, final):
		if self.terminating:
			self.finish_termination()

class RInvocation(object):
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
	"""

	projection = True
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

	def __str__(self):
		init = " ".join(str(x) for x in (self.method, self.path))
		headers = self.headers
		if not headers:
			return init

		heads = "\n\t".join(x.decode('ascii') + ': ' + y.decode('ascii') for (x,y) in headers)
		return init + "\n\t" + heads

	@classmethod
	def from_request(Class, rline, headers):
		"""
		# Initialize an Invocation using a parsed request line and headers.
		# Primarily, this is used by &fork in a server context.
		"""

		method, path, version = rline
		return Class(None, method, path, headers)
