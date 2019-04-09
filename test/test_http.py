"""
# Check integrations of internet.http and kernel.http
"""
import itertools
import json
from .. import http as library

from ...kernel import library as libkernel
from ...kernel import flows
from ...kernel.test import library as libtest

def req(*headers, host=b'test.fault.io', version=b'HTTP/1.1', uri=b'/test/fault.io.http', method=b'GET',
		body=b'', ctype=b'text/plain', chunks=()
	):
	init = b'%s %s %s\r\n' % (method, uri, version)
	additional = [
		(b'Host', host),
	]
	if body:
		l = str(len(body))
		additional.extend([
			(b'Content-Length', l.encode('ascii')),
			(b'Content-Type', ctype),
		])
	elif chunks:
		additional.extend([
			(b'Transfer-Encoding', b'chunked'),
			(b'Content-Type', ctype),
		])
		sizes = [hex(x).encode('ascii')[2:] + b'\r\n' for x in map(len, chunks)]
		body = b''.join((x+y+b'\r\n') for x,y in zip(sizes, chunks))
		body += b'0\r\n\r\n'

	if additional:
		headers = itertools.chain(additional, headers)
	header_data = b'\r\n'.join(map(b'%s: %s'.__mod__, headers))

	return (init + header_data + b'\r\n\r\n' + body,)

def test_ranges(test):
	"""
	Check Range header parsing.
	"""
	test/list(library.ranges(0, None)) == [(0, 0)]
	test/list(library.ranges(123, None)) == [(0, 123)]
	test/list(library.ranges(100, None)) == [(0, 100)]

	# HTTP Ranges are inclusive.
	test/list(library.ranges(100, b"bytes=0-0")) == [(0, 1)]
	test/list(library.ranges(100, b"bytes=0-100")) == [(0, 101)]

	# Missing starts means last n-bytes.
	test/list(library.ranges(100, b"bytes=-50")) == [(50, 100)]

def test_fork(test):
	"""
	Validate requests without bodies, sized bodies, and chunked transfers.
	"""
	overflow = []
	g = library.fork(library.Request, overflow)
	g.send(None)
	r_open, r_close = list(g.send(req()))
	layer = r_open[1]
	test/r_open[0] == flows.fe_initiate
	test/r_close[0] == flows.fe_terminate
	test/True == (r_close[1] is layer)

	test.isinstance(layer, library.Request)
	test/layer.method == b'GET'
	test/layer.path == b'/test/fault.io.http'
	test/layer.version == b'HTTP/1.1'
	test/layer.host == 'test.fault.io'

	# Content-Length body.
	r_open, *body, r_close = list(g.send(req(body=b'content')))
	layer = r_open[1]
	test/r_open[0] == flows.fe_initiate
	test/r_close[0] == flows.fe_terminate
	test/True == (r_close[1] is layer)
	test.isinstance(layer, library.Request)

	test.isinstance(layer, library.Request)
	test/layer.method == b'GET'
	test/layer.path == b'/test/fault.io.http'
	test/layer.version == b'HTTP/1.1'
	test/layer.host == 'test.fault.io'

	total_content = b''
	for event in body:
		test/event[1] == layer
		total_content += b''.join(event[2])
	test/total_content == b'content'

	# Chunked body.
	r_open, *body, r_close = list(g.send(req((b'Connection', b'close'), chunks=(b'first\n', b'second\n'))))
	layer = r_open[1]
	test/r_open[0] == flows.fe_initiate
	test/r_close[0] == flows.fe_terminate
	test/True == (r_close[1] is layer)
	test.isinstance(layer, library.Request)

	test.isinstance(layer, library.Request)
	test/layer.method == b'GET'
	test/layer.path == b'/test/fault.io.http'
	test/layer.version == b'HTTP/1.1'
	test/layer.host == 'test.fault.io'
	test/layer.terminal == True

	total_content = b''
	for event in body:
		test/event[1] == layer
		total_content += b''.join(event[2])
	test/total_content == b'first\nsecond\n'

def test_join(test):
	overflow = []
	import collections
	c = collections.Counter()
	j = library.join(status=c)
	g = library.fork(library.Request, overflow)
	g.send(None); j.send(None)

	r = req()
	events = list(g.send(r))
	layer = events[0][1]
	test/b''.join(list(j.send(events))) == r[0]

	r = req(chunks=(b'first\n', b'second\n'))
	events = list(g.send(r))
	layer = events[0][1]
	test/b''.join(list(j.send(events))) == r[0]

	r = req(body=(b'first\n' + b'second\n'))
	events = list(g.send(r))
	layer = events[0][1]
	test/b''.join(list(j.send(events))) == r[0]

def test_Protocol(test):
	"""
	Validate requests without bodies, sized bodies, and chunked transfers.

	More of an integration test as its purpose is to tie &library.fork and
	&library.join together for use with &flows.Transports.
	"""

	ctx = libtest.Executable()
	ctl = libtest.Root()
	S = libkernel.Sector()
	S.context = ctx
	S.controller = ctl
	S.actuate()

	http = library.Protocol.server()
	fi, fo = flows.Transports.create((http.transport_api(),))
	ic = flows.Collection.list()
	oc = flows.Collection.list()

	list(map(S.dispatch, [fi, fo, ic, oc]))
	fi.f_connect(ic)
	fo.f_connect(oc)

	# Replay of test_fork for sanity.
	fi.f_transfer(req())
	r_open, r_close = ic.c_storage[0]
	layer = r_open[1]
	test/r_open[0] == flows.fe_initiate
	test/r_close[0] == flows.fe_terminate
	test/True == (r_close[1] is layer)

	test.isinstance(layer, library.Request)
	test/layer.method == b'GET'
	test/layer.path == b'/test/fault.io.http'
	test/layer.version == b'HTTP/1.1'
	test/layer.host == 'test.fault.io'

if __name__ == '__main__':
	import sys; from ...test import library as libtest
	libtest.execute(sys.modules[__name__])
