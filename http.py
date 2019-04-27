"""
# IETF HTTP tools for &..io based applications.

# &.http provides foundations for clients and servers. The high-level
# interfaces are managed by &..web.

# [ Properties ]
# /HeaderSequence/
	# Type annotation for the header sequence used by &Layer instances,
	# &Layer.header_sequence.
"""
import typing
import functools
import collections
import itertools

from ..time import library as libtime
from ..routes import library as libroutes
from ..system import memory

from ..internet.data import http as protocoldata # On disk (shared) hash for this is preferred.
from ..internet import http as protocolcore

from ..internet import media

from ..kernel import core
from ..kernel import flows

import operator
from ..computation import library as libc
length_string = libc.compose(operator.methodcaller('encode', 'utf-8'), str, len)
length_strings = libc.compose(operator.methodcaller('encode', 'utf-8'), str, sum, functools.partial(map,len))
del libc, operator

HeaderSequence = typing.Sequence[typing.Tuple[bytes, bytes]]

def decode_number(string, int=int):
	ustring = string.decode('ascii')
	return int(ustring, 10)

def ranges(length, range_header):
	"""
	# Generator producing the ranges specified by the given Range header.

	# [ Parameters ]
	# /length/
		# The (http/header)`Content-Length` of the entity body being referenced.
	# /range_header/
		# The (http/header)`Range` to be converted to slices.
	"""
	if range_header is None:
		yield (0, length)
		return

	for x in range_header.split():
		if x.startswith(b'bytes='):
			break
	else:
		yield (0, length)
		return

	label, ranges = x.split(b'=')
	for x in ranges.split(b','):
		start, stop = x.split(b'-')
		if not start:
			# empty start range
			if not stop:
				yield (0, length)
			else:
				# Convert to slice.
				stop = decode_number(stop)
				yield (length - stop, length)
		else:
			if not stop:
				stop = length
			else:
				stop = decode_number(stop) + 1

			yield (decode_number(start), stop)

class Structures(object):
	"""
	# Manages a sequence of HTTP and cached access to specific ones.

	# Primarily used to extract information from received headers, but also useful
	# for preparing headers to be sent.
	"""

	def __init__(self, headers:HeaderSequence, *local:bytes):
		"""
		# Create a cache for a sequence of headers directly stored.

		# [ Parameters ]
		# /headers/
			# The sequence of pairs designating the storage area to use.
		# /local/
			# Additional headers that should have cached access.
		"""
		self.cache = {k.lower():None for k in local}
		self.cookies = []
		self.headers = headers
		self._init_headers(headers)

	def __str__(self):
		return '\n'.join([
			': '.join([x.decode('ascii'), y.decode('ascii')])
			for x, y in self.headers
		])

	def _init_headers(self, headers):
		"""
		# Set the headers to be cached and structured for use by an application.
		"""

		ch = self.cached_headers
		c = self.cache
		for k, v in headers:
			k = k.lower()

			if k in c:
				c[k] = v
			elif k in {b'set-cookie', b'cookie'}:
				self.cookies.append(v)
			elif k in ch:
				# Used to support cached headers local to an instance.
				c[k] = v

		return self

	@property
	def upgrade(self) -> bool:
		"""
		# Whether or not the request looking to perform protocol substitution.
		"""

		return self.connection == b'upgrade'

	@property
	def content(self) -> bool:
		"""
		# Whether the headers indicate an associated body.
		"""
		cl = self.cache.get(b'content-length')
		if cl is not None:
			return True

		return self.cache.get(b'transfer-encoding') == b'chunked'

	@property
	def length(self) -> typing.Optional[int]:
		"""
		# The length of the content; positive if exact, &None if no content, and -1 if arbitrary.
		# For HTTP, arbitrary triggers chunked transfer encoding.
		"""

		cl = self.cache.get(b'content-length')
		if cl is not None:
			return int(cl.decode('ascii'))

		te = self.cache.get(b'transfer-encoding')
		if te is not None and te.lower().strip() == b'chunked':
			return -1

		# no entity body
		return None

	def declare_content_length(self, length:int):
		"""
		# Add a content length header.
		"""

		assert length >= 0

		hs = self.headers
		el = str(length).encode('ascii')

		self.cache[b'content-length'] = el
		hs.append((b'Content-Length', el))

	def declare_variable_content(self):
		"""
		# Add header for chunked transfer encoding.
		"""

		hs = self.headers
		hs.append((b'Transfer-Encoding', b'chunked'))

	def byte_ranges(self, length):
		"""
		# The byte ranges of the request.
		"""

		range_str = self.cache.get(b'range')
		return ranges(length, range_str)

	@property
	def upgrade_insecure(self):
		"""
		# The (http/header-id)`Upgrade-Insecure-Requests` header as a boolean.
		# &None if not the header was not present, &True if the header value was
		# (octets)`1` and &False if (octets)`0`.
		"""

		x = self.cache.get(b'upgrade-insecure-requests')
		if x is None:
			return None
		elif x == b'1':
			return True
		elif x == b'0':
			return False
		else:
			raise ValueError("Upgrade-Insecure-Requests not valid")

	cached_headers = set(
		x.lower() for x in [
			b'Connection',
			b'Upgrade',
			b'Host',
			b'Upgrade-Insecure-Requests',
			b'Range',
			b'Expect',

			b'Transfer-Encoding',
			b'Transfer-Extension',

			b'TE',
			b'Trailer',

			b'Date',
			b'Last-Modified',
			b'Retry-After',

			b'Server',
			b'User-Agent',
			b'From',
			b'P3P',

			b'Accept',
			b'Accept-Encoding',
			b'Accept-Language',
			b'Accept-Ranges',
			b'Accept-Charset',

			b'Content-Type',
			b'Content-Language',
			b'Content-Length',
			b'Content-Range',
			b'Content-Location',
			b'Content-Encoding',

			b'Cache-Control',
			b'ETag',
			b'Expires',
			b'If-Match',
			b'If-Modified-Since',
			b'If-None-Match',
			b'If-Range',
			b'If-Unmodified-Since',

			b'Authorization',
			b'WWW-Authenticate',
			b'Proxy-Authenticate',
			b'Proxy-Authorization',

			b'Location',
			b'Max-Forwards',

			b'Via',
			b'Vary',

			b'X-Forwarded-For',
		]
	)

	@property
	def connection(self) -> bytes:
		"""
		# Return the connection header stripped and lowered or `b''` if no header present.
		"""
		return self.cache.get(b'connection', b'').strip().lower()

	@staticmethod
	@functools.lru_cache(32)
	def media_range_cache(range_data, parse_range=media.Range.from_bytes):
		"""
		# Cached access to a media range header.
		"""

		if range_data is not None:
			return parse_range(range_data)
		else:
			return media.any_range # HTTP default.

	@property
	def media_range(self):
		"""
		# Structured form of the Accept header.
		"""

		accept = self.cache.get(b'accept')
		if accept is None:
			return None
		return self.media_range_cache(accept)

	@property
	def media_type(self) -> media.Type:
		"""
		# The structured media type extracted from the (http/header-id)`Content-Type` header.
		"""

		return media.type_from_bytes(self.headers[b'content-type'])

	@property
	def date(self, parse=libtime.parse_rfc1123) -> libtime.Timestamp:
		"""
		# Date header timestamp.
		"""

		if not b'date' in self.headers:
			return None

		ts = self.headers[b'date'].decode('utf-8')
		return parse(ts)

	@property
	def host(self) -> str:
		"""
		# Decoded host header.
		"""
		return self.cache.get(b'host', b'').decode('idna')

	@property
	def encoding(self) -> str:
		"""
		# Character encoding of entity content. &None if not applicable.
		"""
		pass

	@property
	def final(self) -> bool:
		"""
		# Whether this is suppoed to be the last transaction in the connection.
		"""

		cxn = self.cache.get(b'connection')
		return cxn == b'close' or not cxn

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
	def headers(self) -> HeaderSequence:
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

	def __init__(self, exit_method, method:bytes, path:bytes, headers:HeaderSequence):
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

class RInvocation(Invocation):
	"""
	# An &Invocation created for projecting a remote request.
	# Used by clients to formulate a request and to contain the response status and headers.
	"""

	projection = True

class ProtocolTransaction(core.Executable):
	"""
	# HTTP Transaction Context.

	# Manages &io.Transfer transactions or &io.Transport transaction facilitating a client's request.
	"""

	def io_execute(self):
		"""
		# Entry point for fulfilling a protocol transaction.
		"""

	def io_reflect(self):
		"""
		# Send the input back to the output. Usually, after configuring the response layer.

		# Primarily used for performance testing.
		"""
		pass

	def io_write_null(self):
		"""
		# Used to send a request or a response without a body.
		# Necessary to emit the headers of the transaction.
		"""

	def io_read_null(self):
		"""
		# Used to note that no read will occur.
		# *Must* be used when no body is expected. Usually called by the &Client or &Server.
		"""

	@property
	def http_terminal(self):
		"""
		# Whether the Transaction is the last.
		"""
		return False

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
		raise NotImplementedError()

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
		self.response.add_headers([
			(b'Content-Type', cotype),
			(b'Content-Length', colength),
		])

	def io_iterate_output(self, iterator:typing.Iterable):
		"""
		# Construct a Flow consisting of a single &flows.Iterate instance
		# used to stream output to the connection protocol state.

		# The &flows.Channel will be dispatched into the &Connection for proper
		# fault isolation in cases that the iterator produces an exception.
		"""

		f = flows.Iteration(iterator)
		self.xact_dispatch(f)
		self.response.initiate((self.request.version, b'200', b'OK'))
		self.xact_ctx_connect_output(f)

		return f

	def io_write_output(self, mime:str, data:bytes):
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

	def io_read_file_into_output(self, path:str, str=str):
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

	def io_read_input_into_buffer(self, callback, limit=None):
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

	def io_read_input_into_file(self, route):
		"""
		# Connect the input Flow's entity body to the given file.

		# The file will be truncated and data will be written in append mode.
		"""

		f = self.context.append_file(str(route))
		self.xact_dispatch(f)
		self.xact_ctx_connect_input(f)

		return f

	def io_write_kport_to_output(self, fd, limit=None):
		"""
		# Transfer data from the &kport, file descriptor, to the output
		# constrained by the limit.

		# The file descriptor will be closed after the transfer is complete.
		"""

		f = self.context.connect_input(fd)
		self.xact_dispatch(f)
		self.xact_ctx_connect_output(f)

		return f

	def io_read_input_into_kport(self, fd, limit=None):
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

	def io_connect_pipeline(self, kpipeline):
		"""
		# Connect the input and output to a &..system.execution.PInvocation.
		# Received data will be sent to the pipeline,
		# and data emitted from the pipeline will be sent to the remote endpoint.
		"""

		sp, i, o, e = xact.pipeline(kpipeline)
		self.xact_ctx_connect_input(fi)
		self.xact_ctx_connect_output(fo)

		return f

def join(
		sequence,
		protocol_version,
		status=None,

		rline_ev=protocolcore.Event.rline,
		headers_ev=protocolcore.Event.headers,
		trailers_ev=protocolcore.Event.trailers,
		content=protocolcore.Event.content,
		chunk=protocolcore.Event.chunk,
		EOH=protocolcore.EOH,
		EOM=protocolcore.EOM,

		fc_initiate=flows.fe_initiate,
		fc_terminate=flows.fe_terminate,
		fc_transfer=flows.fe_transfer,
	):
	"""
	# Join flow events into a proper HTTP stream.
	"""

	serializer = protocolcore.assembly()
	serialize = serializer.send
	transfer = ()

	def initiate(event, channel_id, init):
		assert event == fc_initiate
		nonlocal commands

		rline, headers, content_length = sequence(protocol_version, init)
		if content_length is None:
			commands[fc_transfer] = pchunk
		else:
			commands[fc_transfer] = pdata

		return [
			(rline_ev, rline),
			(headers_ev, headers),
			EOH,
		]

	def eom(event, channel_id, param):
		assert event == fc_terminate
		return (EOM,)

	def pdata(event, channel_id, transfer_events):
		assert event == fc_transfer
		return [(content, x) for x in transfer_events]

	def pchunk(event, channel_id, transfer_events):
		assert event == fc_transfer
		return [(chunk, x) for x in transfer_events]

	commands = {
		fc_initiate: initiate,
		fc_terminate: eom,
		fc_transfer: pchunk,
	}
	transformer = commands.__getitem__

	content_ev = None
	while True:
		event = None
		events = (yield transfer)
		transfer = []
		for event in events:
			out_events = transformer(event[0])(*event)
			transfer.extend(serialize(out_events))

def fork(
		allocate, close, overflow,
		rline=protocolcore.Event.rline,
		headers=protocolcore.Event.headers,
		trailers=protocolcore.Event.trailers,
		content=protocolcore.Event.content,
		chunk=protocolcore.Event.chunk,
		violation=protocolcore.Event.violation,
		bypass=protocolcore.Event.bypass,
		EOH=protocolcore.EOH,
		EOM=protocolcore.EOM,
		iter=iter, map=map, len=len,
		chain=itertools.chain.from_iterable,
		fc_initiate=flows.fe_initiate,
		fc_terminate=flows.fe_terminate,
		fc_transfer=flows.fe_transfer,
	):
	"""
	# Split an HTTP stream into flow events for use by &flows.Division.
	"""

	tokenizer = protocolcore.disassembly()
	tokens = tokenizer.send

	close_state = False # header Connection: close
	events = iter(())
	flow_events = []
	layer = None
	internal_overflow = []

	# Pass exception as terminal Layer context.
	def http_protocol_violation(data):
		raise Exception(data)

	http_xact_id = 0

	while not close_state:

		http_xact_id += 1
		lrline = []
		lheaders = []
		local_state = {
			rline: lrline.extend,
			headers: lheaders.extend,
			violation: http_protocol_violation,
			bypass: internal_overflow.extend,
		}

		headers_received = False
		while not headers_received:
			for x in events:
				local_state[x[0]](x[1])
				if x == EOH:
					headers_received = True
					break
			else:
				# need more for headers
				events = []
				y = events.extend
				for x in map(tokens, ((yield flow_events))):
					y(x)
				del y
				flow_events = []
				events = iter(events)

		# got request or status line and headers for this request
		assert len(lrline) == 3

		initiate, rversion = allocate((lrline, lheaders))

		flow_events.append((fc_initiate, http_xact_id, initiate))
		##
		# local_state is used as a catch all
		# if strictness is desired, it should be implemented here.

		body = []
		trailer_sequence = []
		local_state = {
			# handle both chunking and content types
			content: body.append,
			chunk: body.append,
			# extension: handle chunk extension events.
			trailers: trailer_sequence.extend,
			violation: http_protocol_violation,
			bypass: internal_overflow.extend,
		}

		try:
			body_complete = False
			while not body_complete:
				for x in events:
					if x == EOM:
						body_complete = True
						break

					# not an eof event, so extend state and process as needed
					local_state[x[0]](x[1])

					if trailer_sequence:
						layer.trailer(trailer_sequence)
					else:
						if body:
							# send the body to the connected Flow
							# the Distributing instance watches for
							# obstructions on the receiver and sends them
							# upstream, so no buffering need to occur here.
							flow_events.append((fc_transfer, http_xact_id, body))

							# empty body sequence and reconfigure its callback
							body = []
							local_state[content] = local_state[chunk] = body.append

				else:
					# need more for EOM
					events = []
					y = events.extend
					for x in map(tokens, ((yield flow_events))):
						y(x)
					flow_events = []
					events = iter(events)
				# for x in events
			# while not body_complete
		except GeneratorExit:
			raise
		else:
			flow_events.append((fc_terminate, http_xact_id, None))
			layer = None

	# Close state. Signal end.
	close()
	# Store overflow for protocol switches.
	internal_overflow.append(b'')
	for x in internal_overflow:
		overflow(x)
	del internal_overflow[:]

	while True:
		bypassing = map(tokens, ((yield flow_events)))
		flow_events = []
		for x in bypassing:
			assert x[0] == bypass
			if x[1]:
				overflow(x[1])

def initiate_server_request(protocol:bytes, invocation):
	"""
	# Used by clients with &SProtocol.
	"""
	p = invocation.parameters['request']
	l = getattr(invocation, '_output_length', None)
	return (p['method'], p['path'], protocol), p['headers'], l

def initiate_client_response(protocol:bytes, invocation):
	"""
	# Used by servers with &SProtocol.
	"""
	code, description = (str(x).encode('ascii') for x in invocation.status)
	l = getattr(invocation, '_output_length', None)
	return (protocol, code, description), invocation.response_headers, l

def allocate_client_request(pair):
	"""
	# Used by servers with &RProtocol.
	"""
	(method, path, version), headers = pair
	return Invocation(None, method, path, headers), version

def allocate_server_response(pair):
	"""
	# Used by clients with &RProtocol.
	"""
	(version, code, description), headers = pair
	return ((code, description), headers), version

class SProtocol(flows.Protocol):
	"""
	# Protocol class sending HTTP messages.
	"""

	def __init__(self, version:bytes, initiate):
		self.version = version
		self._status = collections.Counter()
		self._state = join(initiate, b'HTTP/1.1', status=self._status)
		self._join = self._state.send
		self._join(None)

	def f_transfer(self, event):
		self.f_emit(self._join(event))

class RProtocol(flows.Protocol):
	"""
	# Protocol class receiving HTTP messages.
	"""

	def p_close(self):
		pass

	def p_correlate(self, send):
		self.p_send = send
		send.p_receive = weakref.ref(self)

	def p_overflowing(self):
		self.start_termination()
		self.p_overflow = []
		return self.p_overflow.append

	def __init__(self, version:bytes, allocate):
		self.version = version
		self._status = collections.Counter()
		self._state = fork(allocate, self.p_close, self.p_overflowing) # XXX: weakmethod
		self._fork = self._state.send
		self._fork(None)

	def f_transfer(self, event):
		self.f_emit(self._fork(event))

class Mitre(flows.Mitre):
	"""
	# Mitre managing HTTP protocol transactions.
	"""

	def __init__(self, router):
		self.m_router = router
		self.m_schannels = {}
		self._protocol_xact_queue = []
		self._protocol_xact_id = 0

	@classmethod
	def client(Class):
		c = Class(None)
		c._m_process = c.m_correlate
		return c

	@classmethod
	def server(Class, router):
		assert router is not None
		s = Class(router)
		s._m_process = s.m_accept
		return s

	def f_transfer(self, events):
		# Synchronized on Logical Process Task Queue
		xq = self._protocol_xact_queue
		already_queued = bool(xq)
		xq.extend(events)
		if not already_queued:
			self.critical(self.m_execute)

	def m_execute(self):
		"""
		# Method enqueued by &f_transfer to flush the protocol transaction queue.
		# Essentially, an internal method.
		"""
		xq = self._protocol_xact_queue
		self._protocol_xact_queue = []
		return self._m_process(xq)

	def m_correlate(self, events):
		"""
		# Received a set of responses. Join with requests, and
		# execute the receiver provided by the enqueueing operation.
		"""

		for channel_id, response, connect in events:
			recv, inv = self.m_schannels.pop(channel_id)
			inv.set_response_status(*response[0]).set_response_headers(response[1])
			inv._connect_input = connect
			inv._channels = (channel_id, channel_id)
			recv(self, inv)

	def m_accept(self, events, partial=functools.partial):
		"""
		# Accept a sequence of requests from a client configured remote endpoint.
		"""

		self._protocol_xact_id += len(events)

		cat = self.f_downstream
		for channel_id, inv, connect in events:
			cat.int_reserve(channel_id)
			inv._connect_input = connect
			inv._output = (cat, channel_id)
			inv._connect_output = partial(cat.int_connect, channel_id)
			self.m_router(self, inv)

	def m_request(self, receiver, invocation:RInvocation, flow:typing.Optional[flows.Relay]):
		"""
		# [ Parameters ]

		# /receiver/
			# Callback performed when a response has been received and is ready to be processed.
		# /invocation/
			# The request line and headers.
		# /flow/
			# The &flows.Relay to connect to input. &None, if there is no entity body.
			# There is no expectation of actuation.
		"""

		self._protocol_xact_id += 1
		channel_id = self._protocol_xact_id
		cat = self.f_downstream

		cat.int_reserve(channel_id)
		self.m_schannels[channel_id] = (receiver, invocation)
		cat.int_connect(channel_id, invocation, flow)

	def m_connect(self, receiver, invocation:RInvocation):
		"""
		# Prepare a transport layer using a request.

		# [ Parameters ]

		# /receiver/
			# Callback performed when a response has been received and is ready to be processed.
		# /invocation/
			# The request line and headers.
		"""

		self._protocol_xact_id += 1
		channel_id = self._protocol_xact_id
		cat = self.f_downstream

		cat.int_reserve(channel_id)
		self.m_schannels[channel_id] = (receiver, invocation)
		p_input = flows.Receiver(None)
		p_output = flows.Relay(cat, channel_id)
		invocation._input = p_input
		invocation._output = p_output
		cat.int_connect(channel_id, invocation, p_output)

		return invocation, (p_input, p_output)

def allocate_client_protocol(version:bytes=b'HTTP/1.1'):
	pi = RProtocol(version, allocate_server_response)
	po = SProtocol(version, initiate_server_request)
	index = ('http', None)
	return (index, (pi, po))

def allocate_server_protocol(version:bytes=b'HTTP/1.1'):
	pi = RProtocol(version, allocate_client_request)
	po = SProtocol(version, initiate_client_response)
	index = ('http', None)
	return (index, (pi, po))
