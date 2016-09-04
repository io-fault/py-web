"""
High-level HTTP client support.

Provides an &Agent class for managing sets of connections to HTTP servers.
"""

class Agent(libio.Interface):
	"""
	[ Properties ]

	/(&str)`title`
		The default `User-Agent` header.

	/(&dict)`cookies`
		A dictionary of cookies whose keys are either an exact
		string of the domain or a tuple of domain names for pattern
		hosts.
	"""

	def __init__(self, title='fault/0'):
		super().__init__()
		# Per-Host connection dictionary.
		self.connections = weakref.WeakValueDictionary()
		self.contexts = weakref.WeakValueDictionary()
		self.title = title
		self.cookies = {}
		self.headers = []

	@staticmethod
	@functools.lru_cache(64)
	def encoded(self, text):
		"""
		Encoded parts cache.
		"""
		return text.encode('utf-8')

	def request(self,
			host:str,
			method:str,
			path:str="/",
			version:str='HTTP/1.1',
			context:typing.Hashable=None,
			headers:typing.Sequence[typing.Tuple[bytes,bytes]]=(),
			accept:str=None,
			agent:str=None,
			final:bool=True,
		):
		"""
		Build a &http.Request instance inheriting the Agent's configuration.
		Requests can be re-used given identical parameters..

		[ Parameters ]

		/final
			Whether or not the request is the final in the pipeline.
			Causes the (http)`Connection: close` header to be emitted.
		/accept
			The media range to use.
		"""

		if agent is None:
			agent = self.title

		encoded = self.encoded

		req = http.Request()
		if self.headers:
			req.add_headers(self.headers)

		req.initiate((encoded(method), encoded(path), encoded(version)))
		headers = []

		if agent is not None:
			headers.append((b'User-Agent', encoded(agent)))

		if accept is not None:
			headers.append((b'Accept', encoded(str(accept))))

		if host is not None:
			headers.append((b'Host', host.encode('idna')))

		if final is True:
			headers.append((b'Connection', b'close'))

		req.add_headers(headers)

		return req

	def cache(self, target:str,
			request:http.Request,
			endpoint=None,
			security:str='tls',
			replace:bool=False,
		):
		"""
		Download the HTTP resource to the filesystem. If the target file exists, a HEAD
		request will be generated in order to identify if completion is possible.

		[ Parameters ]

		/replace
			Remove the target file if it exists and download the resource again.
		"""

		raise NotImplementedError("unavailable")

	def open(self, context, endpoint, transports=()) -> http.Client:
		"""
		Open a client connection and return the actuated &Client instance.
		"""

		global http
		hc = http.Client.open(self, endpoint, transports=transports)
		self.connections[endpoint] = hc
		self.process(hc)
		return hc
