"""
# System interfaces supporting web services.
"""
import itertools
import typing

from ..routes import types as routetypes
from ..internet import media
from ..system.files import Path
from ..system import memory

from . import xml as libxml

def route_headers(ctl, host, route:routetypes.Selector):
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

		ctl.extend_headers([
			(b'Last-Modified', route.get_last_modified().select('rfc').encode('utf-8')),
			(b'Accept-Ranges', b'bytes'),
		])

	return rsize, ranges

def render_xml_directory_listing(xml, route:routetypes.Selector):
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

def render_directory_listing(directories, files):
	"""
	# Object directory listing.
	"""
	get_type = media.types.get

	for f in files:
		t = get_type(f.extension, 'application/octet-stream')
		try:
			ct, lm, size = f.meta()
			lm = lm.select('iso')
			ct = ct.select('iso')
		except FileNotFoundError:
			continue

		yield [f.identifier, ct, lm, t, size]

	for d in directories:
		try:
			ct, lm, size = d.meta()
			lm = lm.select('iso')
			ct = ct.select('iso')
		except FileNotFoundError:
			continue

		yield [d.identifier, ct, lm, None, None]

def xml_context_element(xml, hostname, root):
	yield from xml.element('internet', None,
		('scheme', 'http'),
		('domain', hostname),
		('root', root or None),
	)

def xml_list_directory(xml, routes, rpath):
	for x in routes:
		sf = x.extend(rpath)

		try:
			yield from render_xml_directory_listing(xml, sf)
		except PermissionError:
			# Ignore directories that can't be read.
			pass

def materialize_xml_index(ctl, root, rpath, rpoints, routes):
	xml = libxml.Serialization()

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
			xml_context_element(xml, ctl.request.host, root),
			xml_list_directory(xml, routes, rpath),
		),
		('path', '/'+'/'.join(rpath[:-1]) if rpath[:-1] else None),
		('identifier', rpath[-1] if rpoints else None),
		pi=pi,
		namespace=ns
	))

def _render_indexes(routes, rpath):
	rows = []
	for r in routes:
		# Skip directories
		r = r.extend(rpath)

		try:
			idx = r.subnodes()
		except PermissionError:
			continue

		rows.append(render_directory_listing(*idx))
	return rows

def materialize_json_index(ctl, root, rpath, rpoints, routes):
	import json
	records = itertools.chain.from_iterable(_render_indexes(routes, rpath))
	return json.dumps(list(records)).encode('utf-8')

def materialize_text_index(ctl, root, rpath, rpoints, routes):
	records = itertools.chain.from_iterable(_render_indexes(routes, rpath))
	return '\n'.join([
		'\t'.join(map(str, row)) for row in records
	]).encode('utf-8')

supported_directory_types = (
	media.type_from_bytes(b'application/json'),
	media.type_from_bytes(b'text/xml'),
	media.type_from_bytes(b'text/plain'),
)

directory_materialization = {
	media.type_from_bytes(b'application/json'): materialize_json_index,
	media.type_from_bytes(b'text/xml'): materialize_xml_index,
	media.type_from_bytes(b'text/plain'): materialize_text_index,
}

def select_filesystem_resource(routes, ctl, host, root, rpath):
	"""
	# Identify a target resource and materialize a response.
	"""

	req = ctl.request

	method = req.method
	if method not in {'GET', 'HEAD', 'OPTIONS'}:
		host.h_error(ctl, 405, None)
		return

	# Resolve relative paths to avoid root escapes.
	rpath = Path._relative_resolution(rpath)
	rpoints = len(rpath)
	mrange = req.media_range or media.any_range

	for route in routes:
		file = route.extend(rpath)

		if not file.exists():
			# first match wins.
			continue

		if method == 'OPTIONS':
			ctl.add_header(b'Allow', b'HEAD,GET')
			ctl.set_response(b'204', b'NO CONTENT', None)
			ctl.connect(None)
			break

		if file.type() == 'directory':
			if method != 'GET':
				host.h_error(ctl, 500, None)
				break

			if req.pathstring.endswith('/'):
				preferred_media_type = mrange.query(*supported_directory_types)

				if preferred_media_type is None:
					host.h_error(ctl, 406, None)
				else:
					selected_type = preferred_media_type[0]
					materialize = directory_materialization[selected_type]

					data = materialize(ctl, root, rpath, rpoints, routes)
					ctl.http_write_output(str(selected_type), data)
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
				cotype = media.types.get(file.extension, 'application/octet-stream')
				acceptable = mrange.query(media.type_from_string(cotype)) is not None

				if not acceptable:
					host.h_error(ctl, 406, None)
				else:
					rsize, ranges = route_headers(ctl, host, file)
					sc = itertools.chain.from_iterable([
						segments.select(start, stop, 1024*16)
						for start, stop in ranges
					])

					ctl.set_response(b'200', b'OK', rsize, cotype=cotype.encode('utf-8'))
					fi = ctl.http_iterate_output(((x,) for x in sc))

			break
		elif method == 'HEAD':
			cotype = media.types.get(file.extension, 'application/octet-stream')
			acceptable = mrange.query(media.type_from_string(cotype)) is not None
			rsize, ranges = route_headers(ctl, host, file)
			ctl.set_response(b'200', b'OK', rsize, cotype=cotype.encode('utf-8'))
			ctl.connect(None)
			break
		else:
			# Unknown method.
			host.h_error(ctl, 405, None)
			break
	else:
		# resource does not exist.
		host.h_error(ctl, 404, None)
