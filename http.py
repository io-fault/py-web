"""
# IETF HTTP tools for &..kernel based applications.

# &.http provides foundations for clients and servers. &.agent provides client
# transaction contexts &.service provides server transaction contexts.

# [ Properties ]
# /HeaderSequence/
	# Type annotation for the header sequence used by &Structures instances.
"""
import typing
import collections
import itertools

from ..context import tools
from ..time import types as timetypes
from ..system import memory

from ..internet.data import http as protocoldata # On disk (shared) hash for this is preferred.
from ..internet import http as protocolcore

from ..internet import media
from ..internet import ri

from ..kernel import core
from ..kernel import flows

HeaderSequence = typing.Sequence[typing.Tuple[bytes, bytes]]

def ranges(length, range_header, decode_number=int):
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
	# Manages a sequence of HTTP headers and cached access to specific ones.

	# Primarily used to extract information from received client or server headers.
	"""

	_uri_struct = None
	_uri_parts = None

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
		self.has = self.cache.__contains__
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

		if b':uri' in c:
			pair = self.uri.split('?', 1)
			self._uri_path = pair[0]

			if len(pair) > 1:
				self._uri_query = pair[1]
			else:
				self._uri_query = None

		return self

	def _init_uri(self, uri=None):
		self._uri_parts = ri.Parts('authority', 'http', self.host, self._uri_path, self._uri_query, None)
		self._uri_struct = ri.structure(self._uri_parts)

	@property
	def method(self) -> str:
		"""
		# The method as a &str instance.
		"""
		return self.cache[b':method'].decode('utf-8', errors='surrogateescape')

	@property
	def uri(self) -> str:
		"""
		# The request URI as a &str instance.
		"""
		return self.cache[b':uri'].decode('utf-8', errors='surrogateescape')

	@property
	def pathstring(self) -> str:
		"""
		# The path portion of the URI as a string.
		"""
		return self._uri_path

	@property
	def path(self) -> typing.Sequence[str]:
		"""
		# The sequence of path items in pathstring.
		"""

		if self._uri_struct is not None:
			return self._uri_struct['path']
		else:
			self._init_uri()
			return self._uri_struct['path']

	@property
	def query(self) -> typing.Optional[dict]:
		"""
		# The query parameters of the URI.
		"""

		if self._uri_struct is not None:
			return self._uri_struct.get('query')
		else:
			self._init_uri()
			return self._uri_struct.get('query')

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

			b':Method',
			b':URI',
		]
	)

	@property
	def connection(self) -> bytes:
		"""
		# Return the connection header stripped and lowered or `b''` if no header present.
		"""
		return self.cache.get(b'connection', b'').strip().lower()

	@staticmethod
	@tools.cachedcalls(32)
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
	def date(self, parse=(lambda x: timetypes.Timestamp.of(rfc=x))) -> timetypes.Timestamp:
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

class TXProtocol(flows.Protocol):
	"""
	# Protocol class sending HTTP messages.
	"""

	@staticmethod
	def initiate_server_request(protocol:bytes, parameter):
		"""
		# Used by clients to select the proper initiation to send.
		"""
		method, path, headers, length = parameter
		return ((method, path, protocol), headers, length)

	@staticmethod
	def initiate_client_response(protocol:bytes, parameter):
		"""
		# Used by servers to select the proper initiation to send.
		"""
		code, description, headers, length = parameter
		return ((protocol, code, description), headers, length)

	def __init__(self, version:bytes, initiate):
		self.version = version
		self._status = collections.Counter()
		self._state = join(initiate, b'HTTP/1.1', status=self._status)
		self._join = self._state.send
		self._join(None)

	def f_transfer(self, event):
		self.f_emit(self._join(event))

class RXProtocol(flows.Protocol):
	"""
	# Protocol class receiving HTTP messages.
	"""

	@staticmethod
	def allocate_client_request(parameter):
		"""
		# For use by server receiving the client request.
		"""
		(method, path, version), headers = parameter
		return (method, path, headers), version

	@staticmethod
	def allocate_server_response(parameter):
		"""
		# For use by clients receiving the server response.
		"""
		(version, code, description), headers = parameter
		return (code, description, headers), version

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

def allocate_client_protocol(version:bytes=b'HTTP/1.1'):
	pi = RXProtocol(version, RXProtocol.allocate_server_response)
	po = TXProtocol(version, TXProtocol.initiate_server_request)
	index = ('http', None)
	return (index, (pi, po))

def allocate_server_protocol(version:bytes=b'HTTP/1.1'):
	pi = RXProtocol(version, RXProtocol.allocate_client_request)
	po = TXProtocol(version, TXProtocol.initiate_client_response)
	index = ('http', None)
	return (index, (pi, po))
