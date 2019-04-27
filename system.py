from ..internet import media

from . import xml as libxml

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
					segments = memory.Segments.open(str(file))
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
