from ..computation import match
from ..kernel import core
from ..kernel import flows

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

	def __init__(self):
		self.http_hosts = []

	def net_route(self, io):
		"""
		# Route the protocol transactions to the designated host.
		# This only enqueues the invocation for subsequent execution.
		"""

		h = self.http_hosts.get(io.request.host, self.http_default)
		h.h_route(io)

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

	def h_options_request(self, query, px):
		"""
		# Handle a request for (http:initiate)`OPTIONS * HTTP/x.x`.
		# Individual Resources may support an OPTIONS request as well.
		"""
		px.response.initiate((b'HTTP/1.1', b'200', b'OK'))
		px.response.add_header(b'Allow', b','.join(list(self.h_allowed_methods)))
		px.io_write_null()
		px.io_read_null()

	def h_error(self, code, path, query, px, exc, description=None, version=b'HTTP/1.1'):
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

	def h_fallback(self, px, path, query):
		"""
		# Method called when no prefix matches the request.

		# Provided for subclasses in order to override the usual (http/error)`404`.
		"""

		r = self.h_error(404, Path(None, tuple(path)), query, px, None)
		px.io_read_null()
		return r

	def h_route(self, sector, px, dict=dict):
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
