"""
# Tools for constructing and managing an HTTP daemon.
"""
import typing
import functools
import itertools
import json
import hashlib
import collections

from ..routes import types as routes
from ..hkp import library as hkp

from ..system import memory
from ..system import files

from ..internet import media

from ..kernel import flows as kflows
from . import http

class Path(routes.Selector):
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

def route_headers(route, mtype):
	"""
	# Construct a sequence of headers describing the given &files.Path.
	"""

	return (
		(b'Content-Type', mtype.__bytes__()),
		(b'Content-Length', route.size().__str__().encode('ascii')),
		(b'Last-Modified',
			route.get_last_modified().select('rfc').encode('ascii')),
	)

def fs_resolve(cache, root, mime_types, accept):
	"""
	# Given a root &hkp.Dictionary whose keys are mime-types and whose
	# values are &hkp.Dictionary instances, return the &routes.Selector
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
			dictionary = hkp.Dictionary.open(str(dictpath))
			cache[dictpath] = dictionary

		yield (t, dictionary)

class Paths(object):
	"""
	# Filesystem mounts based on MIME type. The &Paths handler uses a system
	# directory that contains a set of &..filesystem.library.Dictionary stores
	# organized by media types. The set of available types is checked against
	# the (http/header)`Accept` list provided by a request.

	# directory lists are not handled. The entries must exist with relevant
	# information in order for listings to be retrieved.

	# ! PENDING:
		# - Automatic directory indexing.
		# - `charset` media type parameter.
	"""

	def __init__(self, root):
		self.root = files.Path.from_path(root)

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
		# Once the request entity has been buffered into the &kflows.Collection,
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
			context:object, path:Path, query:dict, px,
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
			cl = kflows.Collection.list()
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
