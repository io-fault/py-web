"""
# Validate Serialization
"""

from .. import xml as library

def test_escapes(test):
	escape = lambda x: list(library.escape_element_string(x))[0]
	test/b'&#38;' == escape("&")
	test/b'&#60;' == escape("<")
	test/b'&#62;' == escape(">")
	test/b'&#62;&#60;&#38;&#38;&#60;' == escape("><&&<")

def test_attribute(test):
	escape = library.escape_attribute_string
	test/'&#38;' == escape("&")
	test/'&#60;' == escape("<")
	test/'>' == escape(">")
	test/'>&#60;&#38;&#38;&#60;' == escape("><&&<")
	test/"'" == escape("'", quote='"')
	test/'"' == escape('"', quote="'")
	test/'&#34;' == escape('"', quote='"')
	test/'&#39;' == escape("'", quote="'")

def test_root_pi(test):
	xml = library.Serialization()
	a = b'<?xml version="1.0" encoding="utf-8"?>'

	g = xml.root('test', None, pi=[('xml-stylesheet', 'type="text/xsl" href="someuri.xsl"')])
	x = b''.join(g)

	test/x == a + b'<?xml-stylesheet type="text/xsl" href="someuri.xsl"?><test/>'

if __name__ == '__main__':
	from ...test import library as libtest; import sys
	libtest.execute(sys.modules[__name__])


