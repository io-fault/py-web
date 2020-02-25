"""
# System interfaces supporting web services.
"""
import itertools
import typing

from ..internet import media
from ..system.files import Path

from . import xml as libxml

def calculate_range(ranges, size, list=list, sum=sum):
	if ranges is not None:
		ranges = list(ranges)
		rsize = sum(y-x for x,y in ranges)
	else:
		ranges = [(0, size)]
		rsize = size

	return (ranges, rsize)

def render_xml_directory_listing(xml, dl, fl):
	"""
	# Iterator producing the XML elements describing the directory's content.
	"""
	get_type = media.types.get

	for f in fl:
		t = get_type(f.extension, 'application/octet-stream')
		try:
			st = f.fs_status()
			ct = st.created
		except FileNotFoundError:
			continue

		yield from xml.element('resource', None,
			('type', t),
			('size', str(st.size)),
			('created', ct.select('iso') if ct is not None else None),
			('modified', st.last_modified.select('iso')),
			identifier=f.identifier,
		)

	for d in dl:
		try:
			st = d.fs_status()
			ct = st.created
		except FileNotFoundError:
			continue

		yield from xml.element('directory', None,
			('created', ct.select('iso') if ct is not None else None),
			('modified', st.last_modified.select('iso')),
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
			st = f.fs_status()
		except FileNotFoundError:
			continue

		yield [f.identifier, t, st.size, st.created, st.last_modified,]

	for d in directories:
		try:
			st = f.fs_status()
		except FileNotFoundError:
			continue

		yield [d.identifier, None, None, st.created, st.last_modified,]

def xml_context_element(xml, hostname, root):
	yield from xml.element('internet', None,
		('scheme', 'http'),
		('domain', hostname),
		('root', root or None),
	)

def _render_index_xml(xml, routes, rpath):
	covered = set()
	dirs = None
	files = None
	dl = ()
	fl = ()

	for x in routes:
		covered.update(x.identifier for x in dl)
		covered.update(x.identifier for x in fl)

		try:
			dl, fl = (x + rpath).fs_list()
		except PermissionError:
			# Ignore directories that can't be read.
			continue

		if covered:
			dirs.extend(x for x in dl if x.identifier not in covered)
			files.extend(x for x in fl if x.identifier not in covered)
		else:
			dirs = dl
			files = fl

	yield from render_xml_directory_listing(xml, dirs, files)

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
			_render_index_xml(xml, routes, rpath),
		),
		('path', '/'+'/'.join(rpath[:-1]) if rpath[:-1] else None),
		('identifier', rpath[-1] if rpoints else None),
		pi=pi,
		namespace=ns
	))

def _render_index(routes, rpath):
	covered = set()
	dirs = None
	files = None
	dl = ()
	fl = ()

	for r in routes:
		covered.update(x.identifier for x in dl)
		covered.update(x.identifier for x in fl)

		try:
			dl, fl = (r + rpath).fs_list()
		except PermissionError:
			# Ignore directories that can't be read.
			continue

		if covered:
			dirs.extend(x for x in dl if x.identifier not in covered)
			files.extend(x for x in fl if x.identifier not in covered)
		else:
			dirs = dl
			files = fl

	return render_directory_listing(dirs, files)

def materialize_json_index(ctl, root, rpath, rpoints, routes):
	import json
	records = _render_index(routes, rpath)
	return json.dumps(list(records)).encode('utf-8')

def materialize_text_index(ctl, root, rpath, rpoints, routes):
	string = (lambda x: str(x) if x is not None else "-")
	records = list(_render_index(routes, rpath))
	records.append(())

	return '\n'.join([
		'\t'.join(map(string, row))
		for row in records
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

def select_filesystem_resource(error, routes, ctl, root, rpath):
	"""
	# Identify a target resource and materialize a response.
	"""
	req = ctl.request

	method = req.method
	if method not in {'GET', 'HEAD', 'OPTIONS'}:
		ctl.add_header(b'Allow', b'GET, HEAD, OPTIONS')
		error(ctl, 405, None)
		return

	# Resolve relative paths to avoid root escapes.
	rpath = Path._relative_resolution(rpath)
	rpoints = len(rpath)
	mrange = req.media_range
	selection_status = None

	# Find file.
	try:
		if rpoints:
			for route in routes:
				if (route/rpath[0]).fs_type() != 'void':
					# first prefix match wins.
					selection = (route + rpath)
					routes = [route]

					selection_status = selection.fs_status()
					break
			else:
				# Resource does not exist.
				error(ctl, 404, None)
				return
		else:
			selection = routes[0]
			selection_status = selection.fs_status()
	except PermissionError:
		error(ctl, 403, None)
		return
	except FileNotFoundError:
		error(ctl, 404, None)
		return

	if method == 'OPTIONS':
		ctl.add_header(b'Allow', b'HEAD,GET')
		ctl.set_response(b'204', b'NO CONTENT', None)
		ctl.connect(None)
		return

	if selection_status.searchable or not rpoints:
		if req.pathstring[-1:] != '/':
			ctl.http_redirect('http://' + req.host + req.pathstring+'/')
			return
		elif (selection/'.index').fs_type() != 'void':
			# Index override.
			selection += ['.index', 'default.html']
			selection_status = selection.fs_status()
		else:
			preferred_media_type = mrange.query(*supported_directory_types)

			if preferred_media_type is None:
				error(ctl, 406, None)
			else:
				selected_type = preferred_media_type[0]
				materialize = directory_materialization[selected_type]

				data = materialize(ctl, root, rpath, rpoints, routes)
				if method == 'GET':
					ctl.http_write_output(str(selected_type), data)
				else:
					cotype = str(selected_type).encode('utf-8')
					ctl.set_response(b'200', b'OK', len(data), cotype)
					ctl.connect(None)
			return

	try:
		cosize = selection_status.size
		cotype = media.types.get(selection.extension, 'application/octet-stream')

		acceptable = mrange.query(media.type_from_string(cotype)) is not None
		if not acceptable:
			error(ctl, 406, None)
			return

		if req.has(b'range'):
			req_ranges = list(ctl.request.byte_ranges(cosize))
			res = b'206'
			descr = b'PARTIAL CONTENT'
			cr = b'bytes %d-%d/%d' %(req_ranges[0][0], req_ranges[0][1], cosize)
			ctl.add_header(b'Content-Range', cr)
		else:
			req_ranges = None
			res = b'200'
			descr = b'OK'
		ranges, rsize = calculate_range(req_ranges, cosize)

		ct = cotype.encode('utf-8')
		lm = selection_status.last_modified

		ctl.extend_headers([
			(b'Last-Modified', lm.select('rfc').encode('utf-8')),
			(b'Accept-Ranges', b'bytes'),
		])

		if method == 'GET':
			start, stop = ranges[0]
			channel = ctl.invocations.system.read_file_range(str(selection), start, stop)
			ctl.set_response(res, descr, rsize, cotype=ct)
			ctl.http_dispatch_output(channel)
			channel.f_transfer(None)
		elif method == 'HEAD':
			ctl.set_response(res, descr, rsize, cotype=ct)
			ctl.connect(None)
	except PermissionError:
		error(ctl, 403, None)
		return
	except FileNotFoundError:
		error(ctl, 404, None)
		return
