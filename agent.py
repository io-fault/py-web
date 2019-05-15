"""
# Client projection dispatch management.

# Provides Contexts for managing a client's sessions.

# [ Engineering ]
# Agents are fairly complicated with respect to preferences. The current
# implementation presumes HTTP/1.1 in most cases where a protocol priority should
# be used to select a desired wire protocol.
"""

from ..kernel import core
from ..kernel import flows
from . import http

class Navigation(core.Context):
	"""
	# Root agent context managing headers, connection strategy cache, and host state.
	"""

	def __init__(self):
		self.nav_headers = []
		self.nav_cookies = {} # Per host.

	def nav_connect(self, endpoint):
		"""
		# Allocate transport communicating with &endpoint with respect to the navigation's
		# perspective.
		"""
		return self.system.connect(endpoint)

	def nav_route(self, io):
		pass

	def actuate(self):
		self.provide('navigation')

class Session(core.Context):
	"""
	# Session dispatching invocation projections for facilitating a request.
	"""

	def actuate(self):
		self.provide('session')

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
