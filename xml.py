"""
# Nested generator based HTML/XML serialization module.

# Provides primitives for generating XML using nested generators.

# [ Properties ]
# /namespaces/
	# Common namespace labels for various XML namespaces.
"""
import functools
import itertools
import typing

namespaces = (
	('xml', "http://www.w3.org/XML/1998/namespace"),
	('xmlns', "http://www.w3.org/2000/xmlns/"),
	('schema', "http://www.w3.org/2001/XMLSchema"),
	('schema-datatypes', "http://www.w3.org/2001/XMLSchema-datatypes"),
	('relaxng', "http://relaxng.org/ns/structure/1.0"),
	('schematron', "http://www.ascc.net/xml/schematron"),
	('rdf', "http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
	('xlink', "http://www.w3.org/1999/xlink"),
	('xinclude', "http://www.w3.org/2001/XInclude"),
	('xslt', "http://www.w3.org/1999/XSL/Transform"),
	('xhtml', "http://www.w3.org/1999/xhtml"),
	('svg', "http://www.w3.org/2000/svg"),
	('mathml', "http://www.w3.org/1998/Math/MathML"),
	('l', "http://if.fault.io/xml/literals"),
)

def escape_element_bytes(data):
	"""
	# Escape bytes instances for storage inside an XML element.
	# &bytes instances are yielded out as there may be a series of
	# CDATA sections, and &element works with iterators when dealing
	# with content.

	# This returns an iterable suitable for use by &element.
	"""

	# VERY inefficient.
	data = data.replace(b'&', b'&#38;')
	data = data.replace(b'<', b'&#60;')
	data = data.replace(b'>', b'&#62;')

	return (data,)

def escape_element_string(string, encoding='utf-8'):
	"""
	# Escape and encode an arbitrary string for storage inside an
	# XML element body. This depends on &escape_element_bytes
	# and has the same limitations with respect to control characters.

	# *This returns an iterable suitable for use by &element*.
	"""

	string = string.replace('&', '&#38;')
	string = string.replace('<', '&#60;')
	string = string.replace('>', '&#62;')

	return (string.encode(encoding, errors='xmlcharrefreplace'),)

def escape_attribute_string(string, quote='"'):
	"""
	# Escape the given string for inclusion in an attribute value.
	# Does *not* encode the result string.

	# ! WARNING:
		# This function only escapes ampersands, less-than comparison
		# characters, and quotes. Low-ASCII will not be escaped and must
		# be processed by a distinct function. This should only be used in cases
		# where the source is known to not produce low-ASCII.
	"""

	string = string.replace('&', '&#38;')

	if quote == '"':
		string = string.replace('"', '&#34;')
	elif quote == "'":
		string = string.replace("'", '&#39;')
	else:
		raise ValueError("invalid quote parameter")

	string = string.replace('<', '&#60;')

	return string

def attribute(identifier, value, quote='"', str=str) -> str:
	"""
	# Construct an XML attribute from the identifier and its value.

	# Does not encode the result string, and attribute values are subjected
	# to the effect of &escape_attribute_string.

	# Returns a &str as they are normally interpolated inside &encode_element.
	"""

	if value is None:
		return ""

	att = ''.join((
		identifier, '=',
		quote,
		escape_attribute_string(str(value)),
		quote,
	))

	return att

def empty(element_identifier, encoding='utf-8'):
	"""
	# Return an iterable to an empty element.
	"""

	return (('<' + element_identifier + '/>').encode(encoding, errors='xmlcharrefreplace'),)

def encode_element(encoding, element_identifier, content, *attribute_sequence, **attributes):
	"""
	# Generate an entire element populating the body by yielding from the given content.
	"""

	att = ""

	attmap = attributes.items()
	for ai in (attribute_sequence, attmap):
		unfiltered_attributes = [x for x in ai if x and x[1] is not None]
		if unfiltered_attributes:
			att += " "
			att += " ".join(x for x in itertools.starmap(attribute, unfiltered_attributes))

	if content is not None:
		element_start = "<%s%s>" %(element_identifier, att)
		element_stop = "</%s>" %(element_identifier,)

		yield element_start.encode(encoding, errors='xmlcharrefreplace')
		yield from content
		yield element_stop.encode(encoding, errors='xmlcharrefreplace')
	else:
		# &None triggers closed element.
		yield ("<%s%s/>" %(element_identifier, att)).encode(
			encoding, errors='xmlcharrefreplace'
		)

element = functools.partial(encode_element, 'utf-8')

class Serialization(object):
	"""
	# Base class for XML serialization instances.
	# Used to localize encoding bindings and default element prefixes.

	# After a Serialization instance is initialized,
	# the &element and &escape attributes will be available for use
	# as they depend on the encoding. Serialization is strictly concerned
	# with the binary emission of a document built for nested iterators.

	# [ Properties ]

	# /xml_prefix
		# The prefix to use when serializing elements with &prefixed.
	# /xml_encoding
		# The encoding to use when serializing &str objects.
	"""

	def __init__(self, xml_prefix:str='', xml_encoding:str='utf-8', xml_version="1.0"):
		"""
		# Initialize the serializer to write XML data in the given encoding.
		"""

		self.xml_version = xml_version
		self.xml_prefix = xml_prefix
		self.xml_encoding = xml_encoding
		self.element = functools.partial(encode_element, xml_encoding)
		self.escape = functools.partial(escape_element_string, encoding=xml_encoding)
		self.text = functools.partial(str.encode, xml_encoding, errors='strict')

	def declaration(self, standalone=None):
		"""
		# Construct and return an ASCII encoded string representing
		# the declaration consistent with the Serialization context.

		# [ Parameters ]

		# /standalone
			# The `standalone` attribute for the declaration.
		"""

		s = '<?xml version="%s" encoding="%s"?>' %(self.xml_version, self.xml_encoding)
		return s.encode('ascii')

	def encode(self, string):
		"""
		# Encode the given string in the configured encoding with `'xmlcharrefreplace'`
		# on errors.

		# Returns the encoded string in a tuple for placement into &element calls.
		"""

		return (string.encode(self.xml_encoding, errors='xmlcharrefreplace'),)

	def empty(self, name, *args, **kw):
		"""
		# Construct an empty XML element with the attributes
		# defined by parameters.
		"""
		return self.element(name, None, *args, **kw)

	def switch(self, xml_prefix=None):
		"""
		# Create another &Serialization instance using a different prefix.
		"""
		dup = self.__class__.__new__(self.__class__)
		dup.__dict__.update(self.__dict__.items())
		if xml_prefix:
			dup.xml_prefix = xml_prefix
		return dup

	def element(self, element_name, subnode_iterator, *attributes, **kwattributes):
		"""
		# Serialize an element with the exact &element_name with the contents of
		# &subnode_iterator as the inner nodes. &subnode_iterator must produce
		# &bytes encoded objects.
		"""

		# Attribute/method is set in __init__.
		pass

	def prefixed(self, element_name, *args, **kw):
		"""
		# Serialize an element using &element, but prefix the element name with
		# prefix configured at &xml_prefix.

		# The configured prefix may or may not be an XML namespace.
		"""

		return self.element(self.xml_prefix + element_name, *args, **kw)

	def pi(self, target, data):
		"""
		# Emit an XML Processing Instruction.

		# Processing Instruction productions are different than &element
		# productions as a single string is returned rather than an iterator.
		"""

		return \
			b'<?' + target.encode(self.xml_encoding) + \
			b' ' + data.encode(self.xml_encoding) + \
			b'?>'

	def root(self, name,
			content, *attributes,
			declaration:bool=True,
			standalone:bool=None,
			prefixed:bool=False,
			namespace:str=None,
			pi:typing.Sequence[typing.Sequence]=(),
		):
		"""
		# Construct the root element of a document.
		"""

		if declaration:
			yield self.declaration(standalone=standalone)

		for pitarget, pichars in pi:
			yield self.pi(pitarget, pichars)

		if prefixed:
			build = self.prefixed
		else:
			build = self.element

		yield from build(name, content, *attributes, xmlns=namespace)

	@functools.lru_cache(24)
	def literal(self, ordinal):
		"""
		# Create a literal element used to represent a disallowed XML character.

		# Strict XML processing implementations may disallow many low-ascii characters,
		# *even when encoded as an entity*. This restriction is problematic as it
		# requires some compensation when working with binary data.

		# &literal provides a way to escape any octet for encoding purposes. The given
		# oridinal will be returned as an element in the `l` namespace. When serializing
		# XML output that exercises &literal, the (xmlns:label)`l` namespace must be defined
		# ahead of time.
		"""

		return b''.join(self.element('l:x%02x' %(ordinal,), None))

	def text(self, *strings):
		"""
		# Emit a text node without escaping contents.
		# Encoding errors will be raised.
		"""
		raise RuntimeError(
			"Serialization.text is initialized and " + \
			"cannot be used as an unbound method"
		)

	def escape(self, string):
		"""
		# Escape the given &string and encode it in the configured encoding.
		"""
		raise RuntimeError(
			"Serialization.escape is initialized and " + \
			"cannot be used as an unbound method"
		)

	def hyperlink(self, href):
		"""
		# Emit the default hyperlink attribute representation.
		"""
		return ('xlink:href', href)
