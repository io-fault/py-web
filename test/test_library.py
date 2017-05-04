import itertools
import json
from .. import library

def test_adapt(test):
	plain = library.media.Type.from_string("text/plain")
	jsont = library.media.Type.from_string("application/json")
	octets = library.media.Type.from_string("application/octet-stream")

	mr = library.media.Range.from_string("text/plain, */*")

	output = library.adapt(None, mr, "Text to be encoded")
	test/output == (plain, b'Text to be encoded')

	mr = library.media.Range.from_string("application/json, */*")
	input = {'some': 'dictionary'}
	expect = (json.dumps(input).encode('utf-8'),)
	output = library.adapt(None, mr, input)
	test/output[0] == jsont
	test/output[1] == expect[0]

	mr = library.media.Range.from_string("application/json, */*")
	input = ['some', 'list', 'of', 1, 2, 3]
	expect = (json.dumps(input).encode('utf-8'),)
	output = library.adapt(None, mr, input)
	test/output == (jsont, expect[0])

	mr = library.media.Range.from_string("application/octet-stream")
	input = b'datas'
	expect = (input,)
	output = library.adapt(None, mr, input)
	test/output == (octets, expect[0])