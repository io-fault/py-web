"""
# Check integrations of internet.http and kernel.http
"""
import itertools
from .. import service as library

from ...kernel import flows
from ...kernel import io as kio
from ...kernel.test import library as testlib

def test_Invocation_instantiate(test):
	"""
	# - &library.Invocation

	# Instantiation expectations.
	"""
	inv = library.Invocation(None, b'GET', b"/", [])

	test/inv.method == 'GET'
	test/inv.path == "/"
	test/inv.headers == []
	test/str(inv) == "GET /"

	test/inv.status == None
	test/inv.response_headers == None

	inv = library.Invocation(None, b'POST', b"/resource", [])
	test/inv.method == 'POST'
	test/inv.path == "/resource"

def test_Invocation_set_response(test):
	"""
	# - &library.Invocation

	# Assignment methods specifying response status and headers.
	"""
	inv = library.Invocation(None, b'GET', b"/", [])

	inv.set_response_headers([(b'Test', b'Value')])
	inv.set_response_status(200, b'OK')
	test/inv.status == (200, b'OK')
	test/inv.response_headers == [(b'Test', b'Value')]

if __name__ == '__main__':
	import sys; from ...test import library as libtest
	libtest.execute(sys.modules[__name__])
