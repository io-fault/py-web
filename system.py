"""
# System interfaces supporting web services.
"""
import itertools

from ..internet import media
from ..system.files import Path
from ..system import memory
from . import xml as libxml

def render_xml_directory_listing(xml, route):
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

def render_directory_listing(route):
	"""
	# Object directory listing.
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

		yield [f.identifier, ct, lm, t, str(size)]

	for d in dl:
		try:
			ct, lm, size = d.meta()
			lm = lm.select('iso')
			ct = ct.select('iso')
		except FileNotFoundError:
			continue

		yield [f.identifier, ct, lm, None, None]

def join_xml_data(xml, files, ctl, rpath, rpoints):
	ns="http://if.fault.io/xml/resources"
	pi=[
		('xslt-param',
			'name="javascript" value="' \
			'/lib/if/directory/index.js' \
			'"'
		),
		('xslt-param',
			'name="css" value="' \
			'/lib/if/directory/index.css"'
		),
		('xslt-param', 'name="lib" value="/lib/if/directory"'),
		('xml-stylesheet',
			'type="text/xsl" href="' \
			'/lib/if/directory/index.xsl"'
		),
	]

	return b''.join(xml.root('index',
		itertools.chain(
			files.xml_context_element(xml, ctl.request.host, ctl),
			files.xml_list_directory(xml, rpath),
		),
		('path', '/'+'/'.join(rpath[:-1]) if rpath[:-1] else None),
		('identifier', rpath[-1] if rpoints else None),
		pi=pi,
		namespace=ns
	))

class Files(object):
	"""
	# Handler and cache for a union of directories.
	"""

	stylesheet = "/lib/if/directory.xsl"

	def __init__(self, *routes):
		self.routes = routes

	def xml_context_element(self, xml, hostname, root):
		yield from xml.element('internet', None,
			('scheme', 'http'),
			('domain', hostname),
			('root', root or None),
		)

	def xml_list_directory(self, xml, tail):
		for x in self.routes:
			sf = x.extend(tail)
			if sf.exists() and sf.type() == 'directory':
				yield from render_xml_directory_listing(xml, sf)

	def select(self, ctl, host, rpath):
		req = ctl.request
		method = req.method

		# Resolve relative paths to avoid root escapes.
		rpath = Path._relative_resolution(rpath)
		rpoints = len(rpath)

		for route in self.routes:
			file = route.extend(rpath)

			if not file.exists():
				# first match wins.
				continue

			if method == 'OPTIONS':
				ctl.add_header(b'Allow', b'HEAD,GET')
				ctl.set_response(204, b'NO CONTENT', None)
				ctl.accept(None)
				ctl.connect(None)
				break

			if file.type() == 'directory':
				if method != 'GET':
					host.h_error(ctl, 500, None)
					break

				if req.pathstring.endswith('/'):
					xml = libxml.Serialization()
					xmlstr = join_xml_data(xml, self, ctl, rpath, rpoints)
					ctl.http_write_output('text/xml', xmlstr)
					ctl.accept(None)
				else:
					ctl.http_redirect(req.pathstring+'/')
				break

			if method == 'GET':
				# Only read if the method is GET. HEAD just wants the headers.
				try:
					segments = memory.Segments.open(str(file))
				except PermissionError:
					host.h_error(ctl, 403, None)
				else:
					rsize, ranges, cotype = self._init_headers(ctl, host, file)
					sc = itertools.chain.from_iterable([
						segments.select(start, stop, 1024*16)
						for start, stop in ranges
					])

					ctl.set_response(b'200', b'OK', rsize, cotype=cotype.encode('utf-8'))
					ctl.accept(None)
					fi = ctl.http_iterate_output(((x,) for x in sc))
				break
			elif method == 'HEAD':
				rsize, ranges, cotype = self._init_headers(ctl, host, file)
				ctl.set_response(b'204', b'NO CONTENT', rsize, cotype=cotype)
				ctl.connect(None)
				ctl.accept(None)
				break
			elif method == 'PUT':
				host.h_error(ctl, 500, None)
				break
			else:
				# Unknown method.
				host.h_error(ctl, 500, None)
				break
		else:
			# resource does not exist.

			if method in ('GET', 'HEAD', 'OPTIONS', 'PATCH'):
				# No such resource.
				host.h_error(ctl, 404, None)
			else:
				host.h_error(ctl, 500, None)

	def _init_headers(self, ctl, host, route):
		try:
			maximum = route.size()
		except PermissionError:
			host.h_error(ctl, 403, None)
		else:
			if ctl.request.has(b'range'):
				ranges = list(ctl.request.byte_ranges(maximum))
				rsize = sum(y-x for x,y in ranges)
			else:
				ranges = [(0, None)]
				rsize = maximum

			t = media.types.get(route.extension, 'application/octet-stream')
			ctl.extend_headers([
				(b'Last-Modified', route.get_last_modified().select('rfc').encode('utf-8')),
				(b'Accept-Ranges', b'bytes'),
			])

		return rsize, ranges, t
