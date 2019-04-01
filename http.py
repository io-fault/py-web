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

import operator

from ..computation import library as libc
from ..time import library as libtime
from ..routes import library as libroutes

from ..internet import http as protocol
from ..internet import media

from ..system import memory

from ..kernel import library as libkernel
from ..kernel import flows

length_string = libc.compose(operator.methodcaller('encode', 'utf-8'), str, len)
length_strings = libc.compose(operator.methodcaller('encode', 'utf-8'), str, sum, functools.partial(map,len))
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

class Layer(libkernel.Layer):
	"""
	# The HTTP layer of a connection; superclass of &Request and &Response that provide
	# access to the parameters of a &Transaction.

	# [ Properties ]

	# /cached_headers/
		# The HTTP headers that will be available inside a &dict instance
		# as well as the canonical header sequence that preserves order.

	# /(&HeaderSequence)`header_sequence`/
		# The sequence of headers.

	# /(&dict)`headers`/
		# The mapping of headers available in the &header_sequence.

	# /channel/
		# The stream identifier. For HTTP/2.0, this identifies channel
		# being used for facilitating the request or response.
	"""

	protocol = 'http'
	version = 1
	channel = None

	@property
	def content(self):
		"""
		# Whether the Layer Context is associated with content.
		"""
		return self.length is not None

	@property
	def length(self):
		"""
		# The length of the content; positive if exact, &None if no content, and -1 if arbitrary.
		# For HTTP, arbitrary using chunked transfer encoding is used.
		"""

		cl = self.headers.get(b'content-length')
		if cl is not None:
			return int(cl.decode('ascii'))

		te = self.headers.get(b'transfer-encoding')
		if te is not None and te.lower().strip() == b'chunked':
			return -1

		# no entity body
		return None

	def byte_ranges(self, length):
		"""
		# The byte ranges of the request.
		"""

		range_str = self.headers.get(b'range')
		return ranges(length, range_str)

	@property
	def upgrade_insecure(self):
		"""
		# The (http/header-id)`Upgrade-Insecure-Requests` header as a boolean.
		# &None if not the header was not present, &True if the header value was
		# (octets)`1` and &False if (octets)`0`.
		"""

		x = self.headers.get(b'upgrade-insecure-requests')
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

			b'Transfer-Encoding',
			b'Transfer-Extension',

			b'TE',
			b'Trailer',

			b'Date',
			b'Last-Modified',
			b'Retry-After',

			b'Server',
			b'User-Agent',
			b'P3P',

			b'Accept',
			b'Accept-Encoding',
			b'Accept-Language',

			b'Content-Type',
			b'Content-Language',
			b'Content-Length',

			b'Cache-Control',
			b'ETag',
			b'If-Match',
			b'If-Modified-Since',
			b'If-None-Match',
			b'If-Range',
			b'If-Unmodified-Since',

			b'Authorization',
			b'WWW-Authenticate',

			b'Location',
			b'Max-Forwards',

			b'Via',
			b'Vary',
		]
	)

	@property
	def connection(self) -> bytes:
		"""
		# Return the connection header stripped and lowered or `b''` if no header present.
		"""
		return self.headers.get(b'connection', b'').strip().lower()

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

		return self.media_range_cache(self.headers.get(b'accept'))

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
		return self.headers.get(b'host', b'').decode('idna')

	@property
	def encoding(self) -> str:
		"""
		# Character encoding of entity content. &None if not applicable.
		"""
		pass

	@property
	def terminal(self) -> bool:
		"""
		# Whether this is the last request or response in the connection.
		"""

		cxn = self.connection

		if self.version == b'1.0' and cxn != b'keep-alive':
			return True

		return cxn == b'close'

	@property
	def substitution(self) -> bool:
		"""
		# Whether or not the request looking to perform protocol substitution.
		"""

		return self.connection == b'upgrade'

	@property
	def cookies(self) -> typing.Sequence:
		"""
		# Cookie sequence for retrieved Cookie headers or Set-Cookie headers.
		"""

		self.parameters.get('cookies', ())

	def clear(self):
		"""
		# Clear all structures used to make up the Layer Context;
		# &initiate will need to be called again.
		"""

		self.parameters.clear()
		self.headers.clear()
		self.initiation = None
		self.header_sequence.clear()

	def __init__(self, version=b'HTTP/1.1'):
		self.parameters = dict()
		self.headers = dict()
		self.initiation = None
		self.header_sequence = []
		self._version = version

	def __str__(self):
		init = " ".join(x.decode('utf-8') for x in (self.initiation or ()))
		heads = "\n\t".join(x.decode('utf-8') + ': ' + y.decode('utf-8') for (x,y) in self.header_sequence)
		return init + "\n\t" + heads

	def initiate(self, rline:typing.Tuple[bytes,bytes,bytes]):
		"""
		# Define the Request or Response initial line.

		# Called when the request or response was received from a remote endpoint.
		"""
		self.initiation = rline

	def add_headers(self, headers, cookies = False, cache = ()):
		"""
		# Accept a set of headers from the remote end or extend the sequence to
		# be sent to the remote end..
		"""

		self.header_sequence += headers

		for k, v in headers:
			k = k.lower()
			if k in self.cached_headers:
				self.headers[k] = v
			elif k in {b'set-cookie', b'cookie'}:
				cookies = self.parameters.setdefault('cookies', list())
				cookies.append(v)
			elif k in cache:
				self.headers[k] = v

	def add_header(self, header, value):
		"""
		# Add a single header to the sequence.
		# Only for use when building a Request or Response to be sent.
		"""
		self.header_sequence.append((header, value))

	def trailer(self, headers):
		"""
		# Destination of trailer-headers received during chunked transfer encoding.
		"""
		pass

class Request(Layer):
	"""
	# Request portion of an HTTP transaction.
	"""

	@property
	def method(self):
		return self.initiation[0]

	@property
	def path(self):
		return self.initiation[1]

	@property
	def version(self):
		return self.initiation[2]

	def declare_without_content(self, method:bytes, path:str, version:bytes=b'HTTP/1.1'):
		self.initiate((method, path.encode('utf-8'), version))

	def declare_with_content(self, method:bytes, length:int, path:str, version:bytes=b'HTTP/1.1'):
		self.initiate((method, path.encode('utf-8'), version))
		hs = self.header_sequence
		hm = self.headers

		if length is not None:
			if length < 0:
				raise ValueError("content length must be >= 0 or None")

			hs.append((b'Content-Length', str(length).encode('ascii')))
			hm[b'Content-Length'] = length
		else:
			# initialize chunked headers
			hs.append((b'Transfer-Encoding', b'chunked'))
			hm[b'transfer-encoding'] = b'chunked'

	@property
	def GET(self, partial=functools.partial):
		"""
		# Initialize as a GET request.
		"""
		return partial(self.declare_without_content, b'GET')

	@property
	def HEAD(self, partial=functools.partial):
		"""
		# Initialize as a HEAD request.
		"""
		return partial(self.declare_without_content, b'HEAD')

	@property
	def DELETE(self, partial=functools.partial):
		"""
		# Initialize as a DELETE request.
		"""
		return partial(self.declare_without_content, b'DELETE')

	@property
	def TRACE(self, partial=functools.partial):
		"""
		# Initialize as a TRACE request.
		"""
		return partial(self.declare_without_content, b'TRACE')

	@property
	def CONNECT(self, partial=functools.partial):
		"""
		# Initialize as a CONNECT request.
		"""
		return partial(self.declare_without_content, b'CONNECT')

	@property
	def POST(self, partial=functools.partial):
		"""
		# Initialize as a POST request.
		"""
		return partial(self.declare_with_content, b'POST')

	@property
	def PUT(self, partial=functools.partial):
		"""
		# Initialize as a PUT request.
		"""
		return partial(self.declare_with_content, b'PUT')

class Response(Layer):
	"""
	# Response portion of an HTTP transaction.
	"""

	@property
	def version(self):
		return self.initiation[0]

	@property
	def code(self):
		return self.initiation[1]

	@property
	def description(self):
		return self.initiation[2]

	def result(self, code, description, version=b'HTTP/1.1'):
		self.initiate((version, str(code).encode('ascii'), description.encode('utf-8')))

	def OK(self, version=b'HTTP/1.1'):
		self.initiate((version, b'200', b'OK'))

class IO(libkernel.Transport):
	"""
	# HTTP Transaction Context.
	"""
	http_expect_continue = None

	_xc_ci = None
	_xc_co = None

	def __init__(self, request:Request, response:Response, ci, co, host):
		self.host = host
		self.request = request
		self.response = response
		self._xc_ci = ci
		self._xc_co = co

	def actuate(self):
		# Temporary; reference cycle
		self.connection = self.controller.controller

	def terminate(self, by=None):
		self.exit()

	def io_connect_input(self, flow:flows.Channel):
		r = self._xc_ci(flow)
		del self._xc_ci
		if self._xc_co is None:
			self.terminate()
	xact_ctx_connect_input = io_connect_input

	def io_connect_output(self, flow:flows.Channel):
		r = self._xc_co(flow)
		del self._xc_co
		if self._xc_ci is None:
			self.terminate()
	xact_ctx_connect_output = io_connect_output

	def io_reflect(self):
		"""
		# Send the input back to the output. Usually, after configuring the response layer.

		# Primarily used for performance testing.
		"""

		f = flows.Channel()
		self.xact_dispatch(f)
		self.xact_ctx_connect_output(f)
		self.xact_ctx_connect_input(f)

	def io_write_null(self):
		"""
		# Used to send a request or a response without a body.
		# Necessary to emit the headers of the transaction.
		"""
		self.xact_ctx_connect_output(None)

	def io_read_null(self):
		"""
		# Used to note that no read will occur.
		# *Must* be used when no body is expected. Usually called by the &Client or &Server.

		# ! FUTURE:
			# Throws exception or emits error in cases where body is present.
		"""
		self.xact_ctx_connect_input(None)

	@property
	def http_terminal(self):
		"""
		# Whether the Transaction is the last.
		"""
		return self.response.terminal

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
		checksum=None,
		status=None,

		rline=protocol.Event.rline,
		headers=protocol.Event.headers,
		trailers=protocol.Event.trailers,
		content=protocol.Event.content,
		chunk=protocol.Event.chunk,
		EOH=protocol.EOH,
		EOM=protocol.EOM,

		repeat=itertools.repeat,
		zip=zip,

		fc_initiate=flows.Event.initiate,
		fc_terminate=flows.Event.terminate,
		fc_transfer=flows.Event.transfer,
	):
	"""
	# Join &flows.Catenate flow events into a proper HTTP stream.
	"""

	serializer = protocol.assembly()
	serialize = serializer.send
	transfer = ()
	def layer_tokens(event, layer):
		assert event == fc_initiate
		return [
			(rline, layer.initiation),
			(headers, layer.header_sequence),
			EOH,
		], layer

	def eom(event, layer):
		assert event == fc_terminate
		return (EOM,), layer

	def data(event, layer, payload, xchunk=protocol.chunk):
		nonlocal content, chunk
		assert event == fc_transfer

		l = layer.length
		if l is None:
			raise Exception("content without chunked encoding specified or content length")

		if l >= 0:
			btype = content
		else:
			btype = chunk

		return [(btype, x) for x in payload], layer

	commands = {
		fc_initiate: layer_tokens,
		fc_terminate: eom,
		fc_transfer: data,
	}
	transformer = commands.__getitem__

	while 1:
		event = None
		events = (yield transfer)
		transfer = []
		for event in events:
			out_events, layer = transformer(event[0])(*event)
			transfer.extend(serialize(out_events))
			status[event[0]] += 1

def fork(
		Layer, overflow,
		rline=protocol.Event.rline,
		headers=protocol.Event.headers,
		trailers=protocol.Event.trailers,
		content=protocol.Event.content,
		chunk=protocol.Event.chunk,
		violation=protocol.Event.violation,
		bypass=protocol.Event.bypass,
		EOH=protocol.EOH,
		EOM=protocol.EOM,
		iter=iter, map=map, len=len,
		chain=itertools.chain.from_iterable,
		fc_initiate=flows.Event.initiate,
		fc_terminate=flows.Event.terminate,
		fc_transfer=flows.Event.transfer,
		fc_overflow=flows.Event.overflow,
	):
	"""
	# Split an HTTP stream into flow events for use by &flows.Division.
	"""

	tokenizer = protocol.disassembly()
	tokens = tokenizer.send

	close_state = False # header Connection: close
	events = iter(())
	flow_events = []
	layer = None

	# Pass exception as terminal Layer context.
	def http_protocol_violation(data):
		raise Exception(data)

	while not close_state:

		lrline = []
		lheaders = []
		local_state = {
			rline: lrline.extend,
			headers: lheaders.extend,
			violation: http_protocol_violation,
			bypass: overflow.extend,
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

		layer = Layer()
		layer.initiate(lrline[:3])
		layer.add_headers(lheaders)

		if layer.terminal:
			# Connection: close present.
			# generator will exit when the loop completes
			close_state = True

		flow_events.append((fc_initiate, layer))
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
			bypass: overflow.extend,
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
							flow_events.append((fc_transfer, layer, body))

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
			flow_events.append((fc_terminate, layer))
			layer = None

	# Close state.
	# Store overflow for next protocol.
	#flow_events.append((fc_overflow, b''))
	overflow.append(b'')

	while True:
		bypassing = map(tokens, ((yield flow_events)))
		flow_events = []
		for x in bypassing:
			assert x[0] == bypass
			if x[1]:
				overflow.append(x[1])

class Protocol(object):
	"""
	# Stack object for &flows.Transports.

	# [ Properties ]

	# /overflow/
		# Transfers that occurred past protocol boundaries. Used during protocol
		# switching to properly maintain state.
	"""

	@classmethod
	def client(Class) -> 'Protocol':
		return Class(Response)

	@classmethod
	def server(Class) -> 'Protocol':
		return Class(Request)

	@property
	def open_transactions(self):
		return self.status[flows.Event.initiate] - self.status[flows.Event.terminate]

	@property
	def terminated(self):
		return self._output_terminated and self.overflow

	def terminate(self, polarity=0):
		if polarity == 1:
			if not self.overflow:
				# The &fork generator runs forever once outside of the protocol.
				# If this condition is true, it likely means that an interruption
				# is occurring.
				self.overflow.append(b'')
		elif polarity == -1:
			self._output_terminated = True
		else:
			raise ValueError("invalid polarity")

	def __init__(self, Layer:Layer, selected_version=b'HTTP/1.1'):
		self.version = selected_version

		self.overflow = []
		self.input_state = fork(Layer, self.overflow)
		self.fork = self.input_state.send
		self.fork(None)

		self._output_terminated = False
		self.status = collections.Counter()
		self.output_state = join(status=self.status)
		self.join = self.output_state.send
		self.join(None)

	def ht_transport_operations(http):
		f = (False).__bool__
		return ((http.fork, f, f), (http.join, f, f))

flows.Transports.operation_set[Protocol] = Protocol.ht_transport_operations

class Client(flows.Mitre):
	"""
	# Mitre initiating requests for an HTTP Connection.
	"""
	Protocol = Protocol.client

	def __init__(self, router):
		self.m_responses = []
		self.m_requests = []
		self.m_route = router

	def f_transfer(self, events, source=None):
		"""
		# Received a set of response initiations. Join with requests, and
		# execute the receiver provided to &m_request.
		"""

		self.m_responses.extend(events)
		signal_count = min(len(self.m_responses), len(self.m_requests))

		reqs = self.m_requests[:signal_count]
		resp = self.m_responses[:signal_count]
		del self.m_requests[:signal_count]
		del self.m_responses[:signal_count]

		for req, res in zip(reqs, resp):
			rec = req[0]
			rec(self, req[1], *res)

	def m_request(self,
			receiver:libkernel.ProtocolTransactionEndpoint,
			layer:Request,
			flow:flows.Channel=None
		):
		"""
		# Emit an HTTP request. The corresponding response will be joined to form a
		# &ProtocolTransaction instance.

		# [ Parameters ]

		# /receiver/
			# The callback to be performed when a response for the request is received.
		# /layer/
			# The request layer context. &Request.
		# /flow/
			# The request body to be emittted. &None if there is no body to send.
		"""

		layer, connect = self.f_emit((layer,), self)[0]
		self.m_requests.append((receiver, layer))
		connect(flow)

class Server(flows.Mitre):
	"""
	# Mitre managing incoming server connections for HTTP.
	"""
	Protocol = Protocol.server

	def __init__(self, ref, router):
		self.m_reference = ref
		self.m_route = router

	def _init_xacts(self, events):
		"""
		# Reserve respone slots and yield the constructed &IO instances.
		"""

		cxn = self.controller
		px = None

		# Reserve response slot and acquire connect callback.
		responses = self.f_emit([Response() for i in range(len(events))], self)

		for req, res in zip(events, responses):
			ts = libtime.now()
			io = IO(req[0], res[0], req[1], res[1], self.m_reference)
			iox = libkernel.Transaction.create(io)

			datetime = ts.select('rfc').encode('utf-8')
			io.response.add_header(b'Date', datetime)
			if req[0].terminal:
				res[0].add_header(b'Connection', b'close')

			yield iox

	def f_transfer(self, events, source=None):
		"""
		# Accept HTTP &Request's from the remote end and pair them with &Response's.
		"""

		cxn = self.controller
		dispatch = cxn.dispatch
		iox = None

		xacts = list(self._init_xacts(events))
		for iox in xacts:
			dispatch(iox)
			self.m_route(iox, iox.xact_context)

		if iox is not None and iox.xact_context.request.terminal:
			self._f_terminated()
