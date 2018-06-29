"""
# Tools for constructing and managing an HTTP daemon.
"""
import typing
import functools
import itertools
import json
import hashlib
import collections

from ..routes import library as libroutes
from ..computation import match
from ..filesystem import library as libfs
from ..system import library as libsys
from ..system import libmemory

from ..internet import media
from ..internet import ri

from ..internet.data import http as data_http
from ..io import http
from ..io import library as libio

from . import xml as libxml

class Path(libroutes.Route):
	"""
	# A Path sequence used to aid in request routing and request path construction.
	"""

	def __str__(self):
		return '/' + '/'.join(self.absolute)

	@property
	def index(self):
		"""
		# Whether the Path is referrring to a directory index. (Ends with a slash)
		"""
		if self.points:
			return self.points[-1] == ""
		else:
			self.absolute[-1] == ""

def init(sector, hostnames, root, *slots):
	"""
	# Initialize an HTTP host in the given sector.
	"""

	h = Host()
	h.h_update_names(*hostnames)
	h.h_update_mounts(root)
	h.h_options = {}

	si = libio.Network(http.Server, h, h.h_route, (), slot='http')

	sector.dispatch(h)
	sector.dispatch(si)

	return h, si

class Network(libio.Context):
	"""
	# System Context for managing a set of &Host instances.
	# Provides grouping for hosts that share the same system network
	# interface.

	# [ Properties ]
	# /http_default
		# The default HTTP Host; the &Host to select in
		# cases where no (http/header)`Host` is designated by
		# a request.
	"""
	http_default = None

	def __init__(self, hosts):
		self.http_hosts = hosts

	def net_route(self, io:http.IO):
		"""
		# Route the HTTP IO Context to the appropriate Host.

		# Normally, this method is only used on the initial request.
		# Subsequent requests should use a cached Host.
		"""

		h = self.http_hosts.get(io.request.host, self.http_default)
		h.h_route(io)

		return h

	def actuate(self):
		sector = self.controller
		f = libio.Funnel()
		self.transport_inlet = f
		sector.dispatch(f)

		for hif, aliases in self.http_interfaces.items():
			h = Host()
			h.h_update_names(hif, *aliases)
			h.h_update_mounts(root)
			h.h_options = {}
			sector.dispatch(h)

		si = libio.Network(http.Server, h, h.h_route, (), slot='http')

		sector.dispatch(si)

		self.http_host = h
		self.http_network = si

def route_headers(route, mtype):
	"""
	# Construct a sequence of headers describing the given &libroutes.File.
	"""

	return (
		(b'Content-Type', mtype.__bytes__()),
		(b'Content-Length', route.size().__str__().encode('ascii')),
		(b'Last-Modified',
			route.get_last_modified().select('rfc').encode('ascii')),
	)

def fs_resolve(cache, root, mime_types, accept):
	"""
	# Given a root &libfs.Dictionary whose keys are mime-types and whose
	# values are &libfs.Dictionary instances, return the &libroutes.Route
	# that best matches the acceptable types and the path.

	# This function should be bound to an LRU cache in order to optimize
	# access to popular files.
	"""

	mtype = accept.query(*mime_types)
	if mtype is None:
		return

	mtype, position, quality = mtype

	if position.pattern:
		# Pattern match; select the set based on it.
		if position != media.any_type:
			# filter dictionaries.
			types = [x for x in mime_types if x in position]
		else:
			# scan all
			types = mime_types
	else:
		types = [mtype]

	for t in types:
		dictpath = root / t.cotype / t.subtype
		if not dictpath.exists():
			continue

		dictionary = cache.get(dictpath)
		if dictionary is None:
			dictionary = libfs.Dictionary.open(str(dictpath))
			cache[dictpath] = dictionary

		yield (t, dictionary)

class Paths(object):
	"""
	# Filesystem mounts based on MIME type. The &Paths handler uses a system
	# directory that contains a set of &..filesystem.library.Dictionary stores
	# organized by media types. The set of available types is checked against
	# the (http:header)`Accept` list provided by a request.

	# directory lists are not handled. The entries must exist with relevant
	# information in order for listings to be retrieved.

	# ! PENDING:
		# - Automatic directory indexing.
		# - `charset` media type parameter.
	"""

	def __init__(self, root):
		self.root = libroutes.File.from_path(root)

		cotypes = self.root.subnodes()[0]
		subtypes = [cotype.subnodes()[0] for cotype in cotypes]
		self.paths = [x.absolute[-2:] for x in itertools.chain(*subtypes)]
		self.types = tuple([media.Type((x[0], x[1], ())) for x in self.paths])
		self.dictionaries = {}

		self.access = functools.partial(fs_resolve, self.dictionaries)

	def __call__(self, path, query, px, str=str):
		p = str('/'.join(path.points)).encode('utf-8')

		for mtype, d in self.access(self.root, self.types, px.request.media_range):
			if not d.has_key(p):
				continue

			r = d.route(p)
			px.io_read_null()
			px.response.result(200, 'OK')
			px.response.add_headers(route_headers(r, mtype))
			px.io_read_file_into_output(str(r))

			# Found existing resource with matching MIME type.
			break
		else:
			px.host.h_error(404, path, query, px, None)

class Host(libio.Interface):
	"""
	# An HTTP Host interface for managing routing of service connections,
	# and handling the representation of error cases.

	# [ Properties ]

	# /h_names
		# The set hostnames that this host can facilitate.
		# The object can be an arbitrary container in order
		# to match patterns as well.

	# /h_canonical
		# The first name given to &update_host_names. &None
		# if no names were given and the name should be
		# inherited from requests.

	# /h_root
		# The root of the host's path as a &..computation.match.SubsequenceScan.
		# This is the initial path of the router in order to allow "mounts"
		# at arbitrary positions. Built from &requisite prefixes.

	# /h_index
		# The handler for the root path. May be &None if &root can resolve it.

	# /h_allowed_methods
		# Option set provided in response to (http/initiate)`OPTIONS * HTTP/1.x`.

	# /h_mount_point
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

	def process(self, xacts):
		"""
		# Process a sequence of protocol transactions by creating a sector
		# for &h_route to be ran within.
		"""

		for px in xacts:
			px.xact_dispatch(libio.Call(self.h_route, px.connection, px))

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

		proc = libio.Iteration([errmsg])
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

# Media Support (Accept header) for Python types.

# Preferences for particular types when no accept header is given or */*
octets = (media.Type.from_string(media.types['data']),)
adaption_preferences = {
	str: (
		media.Type.from_string('text/plain'),
		media.Type.from_string(media.types['data']),
		media.Type.from_string(media.types['json']),
	),
	bytes: octets,
	memoryview: octets,
	bytearray: octets,

	list: (
		media.Type.from_string(media.types['json']),
		media.Type.from_string('text/plain'),
	),
	tuple: (
		media.Type.from_string(media.types['json']),
		media.Type.from_string('text/plain'),
	),
	dict: (
		media.Type.from_string(media.types['json']),
		media.Type.from_string('text/plain'),
	),
	None.__class__: (
		media.Type.from_string(media.types['json']),
	)
}
del octets

conversions = {
	'text/plain': lambda x: str(x).encode('utf-8'),
	media.types['json']: lambda x: json.dumps(x).encode('utf-8'),
	media.types['data']: lambda x: x,
}

def adapt(encoding_range, media_range, obj, iterating = None):
	"""
	# Adapt an arbitrary Python object to the desired request type.
	# Used to interface with Python interfaces.

	# The &iterating parameter instructs &adapt that the &obj is an
	# iterable producing instances of &iterating. For instance,
	# if the iterator produces &bytes, &iterating should be set to &bytes.
	# This allows &adapt to select the conversion method based on the type
	# of objects being produced.

	# Returns &None when there was not an acceptable response.
	"""

	if iterating is not None:
		subject_type = iterating
	else:
		subject_type = type(obj)

	types = adaption_preferences[subject_type]

	result = media_range.query(*types)
	if not result:
		return None

	matched_request, match, quality = result
	if match == media.any_type:
		# determine type from obj type
		match = adaption_preferences[subject_type][0]

	if iterating:
		c = conversion[str(match)]
		adaption = b''.join(map(c, obj))
	else:
		adaption = conversions[str(match)](obj)

	return match, adaption

class Resource(object):
	"""
	# HTTP Resource designating &http.IO processing for the configured MIME types.

	# A Resource is a set of methods that can facilitate an HTTP request; an arbitrary handler
	# for an HTTP method can be bound using the decorator syntax referencing the acceptable
	# MIME type.

	# Parameters are passed to the handler based on the method's signature; json data
	# structures will be parsed and passed as positional and keyword parameters.
	"""

	@classmethod
	def method(Class, **kw):
		"""
		# HTTP Resource Method Decorator for POST operations.

		# Used to identify a method as an HTTP Resource that can
		# be invoked with a &http.IO in order
		# provide a response to a client.

		#!/pl/python
			@libweb.Resource.method(limit=0, ...)
			def method(self, resource, path, query, protoxact):
				"Primary POST implementation"
				pass

			@method.getmethod('text/html')
			def method(self, sector, request, response, input):
				"Resource implementation for text/html requests."
				pass
		"""

		r = Class(**kw)
		return r.__methodwrapper__

	def __methodwrapper__(self, subobj):
		"""
		# Default to POST responding to any Accept.
		"""
		functools.wraps(subobj)(self)
		self.methods[b'POST'][media.any_type] = subobj
		return self

	def __init__(self, limit=None):
		self.methods = collections.defaultdict(dict)
		self.limit = limit

	def getmethod(self, *types, MimeType=media.Type.from_string):
		"""
		# Override the request handler for the resource when the request
		# is preferring one of the given types.
		"""

		def UpdateResourceGET(call, self=self):
			"""
			# Update Resource to handle GET requests for the given resource.
			"""
			GET = self.methods[b'GET']
			for x in types:
				GET[MimeType(x)] = call
			return self

		return UpdateResourceGET

	def transformed(self, context, collection, path, query, px, flow, chain=itertools.chain):
		"""
		# Once the request entity has been buffered into the &libio.Collection,
		# it can be parsed into parameters for the resource method.
		"""

		data_input = b''.join(chain(*collection))
		mtyp = px.request.media_type
		entity_body = json.loads(data_input.decode('utf-8')) # need to adapt based on type

		self.execute(context, entity_body, path, query, px)

	def execute(self, context, content, path, query, px):
		# No input to wait for, invoke the resource handler immediately.
		methods = self.methods[px.request.method]
		media_range = px.request.media_range

		if px.request.method == b'OPTIONS':
			result = self.options(context, self, content)
		else:
			mime_type = media_range.query(*methods.keys())
			if mime_type:
				result = methods[mime_type[0]](context, self, content)
			else:
				return px.host.h_error(500, path, query, px, None)

		# Identify the necessary adaption for output.
		ct, data = adapt(None, media_range, result)

		return px.io_write_output(str(ct), data)

	def options(self, context, content):
		"""
		# Facilitate an OPTIONS request for the &Resource.
		"""
		pass

	def adapt(self,
			context:object, path:Path, query:dict, px:http.IO,
			str=str, len=len
		):
		"""
		# Adapt a single HTTP transaction to the configured resource.
		"""

		if px.request.content:
			if False and self.limit == 0:
				# XXX: zero limit with entity body.
				px.host.h_error(413, path, query, px, None)
				return

			# Buffer and transform the input to the callable adherring to the limit.
			cl = libio.Collection.list()
			collection = cl.c_storage
			px.xact_dispatch(cl)
			cl.atexit(lambda xp: self.transformed(context, collection, path, query, px, xp))
			px.xact_ctx_connect_input(cl)

			return cl
		else:
			px.io_read_null()
			return self.execute(context, None, path, query, px)

	__call__ = adapt

class Index(Resource):
	"""
	# A Resource that represents a set of Resources and the containing resource.
	"""

	@Resource.method()
	def __index__(self, resource, parameters):
		"""
		# List of interfaces for service management.
		"""

		return [
			name for name, method in self.__class__.__dict__.items()
			if isinstance(method, Resource) and not name.startswith('__')
		]

	@__index__.getmethod('text/xml')
	def __index__(self, resource, query):
		"""
		# Generate the index from the &Resource methods.
		"""
		xmlctx = libxml.Serialization()

		resources = [
			name for name, method in self.__class__.__dict__.items()
			if isinstance(method, Resource) and not name.startswith('__')
		]

		xmlgen = xmlctx.root(
			'index', itertools.chain.from_iterable(
				xmlctx.element('resource', None, name=name)
				for name in resources
			),
			namespace='http://fault.io/xml/resources'
		)

		return b''.join(xmlgen)

	@Resource.method()
	def __resource__(self, resource, parameters):
		pass

	def __call__(self, path, query, px,
			partial=functools.partial,
			tuple=tuple, getattr=getattr,
		):
		"""
		# Select the command method from the given path.
		"""
		points = path.points

		if path.index:
			protocol_xact_method = partial(self.__index__)
		elif points:
			protocol_xact_method = getattr(self, points[0], None)
			if protocol_xact_method is None:
				return px.host.h_error(404, path, query, px, None)
		else:
			return px.host.h_error(404, path, query, px, None)

		return protocol_xact_method(self, path, query, px)

class Dictionary(dict):
	"""
	# A set of resources managed as a mapping.

	# Used a means to export factor modules; dictionaries query
	# the factor module for MIME type information and any other
	# available metadata.

	# (http/method)`GET` and (http/method)`HEAD` are the primary methods,
	# but (http/method)`POST` is also supported for factors that are mounted
	# as executable.
	"""
	__slots__ = ()

	def __call__(self, path, query, px):
		if path.points not in self:
			px.host.h_error(404, path, query, px, None)
			return

		mime, data, mode = self[path.points]
		px.io_read_null()
		px.io_write_output(mime, data)

def Factory(cache, selector, method, path, query, px):
	key = self.factory_selector(px)
	try:
		method = self.factory_cache[key]
	except KeyError:
		method = self.factory_method(key)
		self.factory_cache[key] = method

	return method(path, query, px)

class Files(object):
	"""
	# Transaction processor providing access to a set of search paths in order
	# to resolve a resource. &Files only supports GET and HEAD methods.

	# The MIME media type is identified by the file extension.
	"""

	stylesheet = "/lib/if/directory.xsl"

	def __init__(self, *routes):
		self.routes = routes

	def render_directory_listing(self, xml, route):
		"""
		# Iterator producing the XML elements describing the directory's content.
		"""
		get_type = media.types.get

		dl, fl = route.subnodes()
		for f in fl:
			t = get_type(f.extension, 'application/octet-stream')
			try:
				ct, lm, size = f.meta()
				lm = lm.select('iso')
				ct = ct.select('iso')
			except FileNotFoundError:
				continue

			yield from xml.element('resource', None,
				('created', ct),
				('modified', lm),
				('type', t),
				('size', str(size)),
				identifier=f.identifier,
			)

		for d in dl:
			try:
				ct, lm, size = d.meta()
				lm = lm.select('iso')
				ct = ct.select('iso')
			except FileNotFoundError:
				continue

			yield from xml.element('directory', None,
				('created', ct),
				('modified', lm),
				identifier=d.identifier,
			)

	def directory(self, xml, tail):
		for x in self.routes:
			sf = x.extend(tail)
			if sf.exists() and sf.type() == 'directory':
				yield from self.render_directory_listing(xml, sf)

	def context(self, xml, path, query, px):
		yield from xml.element('internet', None,
			('scheme', 'http'),
			('domain', px.request.host),
			('root', str(path.context or '') or None),
		)

	def __call__(self, path, query, px):
		rpath = path.points
		method = px.request.method

		# Resolve relative paths to avoid root escapes.
		rpath = tuple(libroutes.Route._relative_resolution(rpath))
		rpoints = len(rpath)

		for route in self.routes:
			file = route.extend(rpath)

			if not file.exists():
				# first match wins.
				continue

			if method == b'OPTIONS':
				px.response.add_header(b'Allow', b'HEAD, GET')
				px.io_read_null()
				px.io_write_null()
				break

			if file.type() == 'directory':
				if method != b'GET':
					px.host.h_error(500, path, query, px, None)
					break

				suffix = str(path)
				if suffix.endswith('/'):
					xml = libxml.Serialization()
					px.response.add_headers([
						(b'Content-Type', b'text/xml'),
						(b'Transfer-Encoding', b'chunked'),
					])

					px.response.OK()
					px.io_read_null()
					px.io_iterate_output(
						[(b''.join(xml.root('index',
							itertools.chain(
								self.context(xml, path, query, px),
								self.directory(xml, rpath),
							),
							('path', '/'+'/'.join(rpath[:-1]) if rpath[:-1] else None),
							('identifier', rpath[-1] if rpoints else None),
							pi=[
								('xslt-param', 'name="javascript" value="' + \
									'/lib/if/directory/index.js' + \
									'"'
								),
								('xslt-param', 'name="css" value="' + \
									'/lib/if/directory/index.css"'
								),
								('xslt-param', 'name="lib" value="/lib/if/directory"'),
								('xml-stylesheet',
									'type="text/xsl" href="' + \
									'/lib/if/directory/index.xsl"'
								),
							],
							namespace="http://fault.io/xml/resources",
						)),), (b'',)]
					)
				else:
					# Redirect to '/'.
					px.io_read_null()
					px.http_redirect(str(path)+'/')
				break

			if method == b'GET':
				# Only read if the method is GET. HEAD just wants the headers.
				try:
					segments = libmemory.Segments.open(str(file))
				except PermissionError:
					px.host.h_error(403, path, query, px, None)
				else:
					rsize, ranges = self._init_headers(path, query, px, file)
					sc = itertools.chain.from_iterable([
						segments.select(start, stop, 1024*16)
						for start, stop in ranges
					])

					px.io_read_null()
					fi = px.io_iterate_output(((x,) for x in sc))
				break
			elif method == b'HEAD':
				px.response.initiate((b'HTTP/1.1', b'200', b'OK'))
				rsize, ranges = self._init_headers(path, query, px, file)
				px.io_write_null()
				px.io_read_null()
				break
			elif method == b'PUT':
				px.host.h_error(500, path, query, px, None)
				break
			else:
				# Unknown method.
				px.host.h_error(500, path, query, px, None)
				break
		else:
			# [End of loop]

			if method in (b'GET', b'HEAD', b'OPTIONS', b'PATCH'):
				# No such resource.
				px.host.h_error(404, path, query, px, None)
			else:
				px.host.h_error(500, path, query, px, None)

	def _init_headers(self, path, query, px, route):
		try:
			maximum = route.size()
		except PermissionError:
			px.host.h_error(403, path, query, px, None)
		else:
			if b'range' in px.request.headers:
				ranges = list(px.request.byte_ranges(maximum))
				rsize = sum(y-x for x,y in ranges)
			else:
				ranges = [(0, None)]
				rsize = maximum

			t = media.types.get(route.extension, 'application/octet-stream')
			px.response.add_headers([
				(b'Content-Type', t.encode('utf-8')),
				(b'Content-Length', str(rsize).encode('utf-8')),
				(b'Last-Modified', route.get_last_modified().select('rfc').encode('utf-8')),
				(b'Accept-Ranges', b'bytes'),
			])

		return rsize, ranges

class Agent(libio.Interface):
	"""
	# HTTP User Agent interface for client &Network contexts.

	# &Agent provides an interface to client networks. Like server networks,
	# &Host contexts populate the sector and provide targeted handling of
	# transactions. However, &Host instances inside client networks
	# are a projection of a remote host and are used to manage host
	# specific information.

	# [ Properties ]

	# /(&str)`title`
		# The default `User-Agent` header.

	# /(&dict)`cookies`
		# A dictionary of cookies whose keys are either an exact
		# string of the domain or a tuple of domain names for pattern
		# hosts.
	"""

	def __init__(self, title='fault/0'):
		# Per-Host connection dictionary.
		self.title = title
		self.cookies = {}
		self.headers = []

	@staticmethod
	@functools.lru_cache(64)
	def encoded(self, text):
		"""
		# Encoded parts cache.
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
		# Build a &http.Request instance inheriting the Agent's configuration.
		# Requests can be re-used given identical parameters..

		# [ Parameters ]

		# /final
			# Whether or not the request is the final in the pipeline.
			# Causes the (http)`Connection: close` header to be emitted.
		# /accept
			# The media range to use.
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
		# Download the HTTP resource to the filesystem. If the target file exists, a HEAD
		# request will be generated in order to identify if completion is possible.

		# [ Parameters ]

		# /replace
			# Remove the target file if it exists and download the resource again.
		"""

		raise NotImplementedError("unavailable")

	def open(self, context, endpoint, transports=()) -> http.Client:
		"""
		# Open a client connection and return the actuated &Client instance.
		"""

		global http
		hc = http.Client.open(self, endpoint, transports=transports)
		self.connections[endpoint] = hc
		self.process(hc)
		return hc
