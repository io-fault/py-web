"""
Loading and management web resources. Manages the construction of Javascript and CSS
resources.
"""
import sys
import subprocess

from ..development import core
from ..development import library as libdev
from ..routes import library as libroutes

def uglify(output, sources, source_map_root=None, module=None):
	"""
	Command constructor for (system/command)`uglifyjs`.

	&<https://www.npmjs.com/package/uglify-js>
	"""
	output = str(output)

	command = ['uglifyjs']
	command.extend(map(str, sources))
	command.extend(('-o', output))
	command.extend(('--source-map', output+'.map'))
	command.extend(('--prefix', 'relative', '-c', '-m'))

	if source_map_root:
		command.extend(('--source-map-root', source_map_root))

	if module:
		command.extend(('--wrap', module, '--export-all'))

	return command

class Javascript(libdev.Sources):
	"""
	Javascript Module managing access and compilation of javascript source using
	node-js minification programs.
	"""
	__type__ = 'javascript'

	def output(self, role=None) -> libroutes.Route:
		"The route file in the (file:directory)`__pycache__` directory."

		return (self.factor.route.cache() / 'output.js')

	@property
	def bytes(self):
		"The contents of the (file:application/javascript)`output.js` file."

		with self.output().open('rb') as f:
			return f.read()

	@property
	def log(self):
		"&libroutes.File referencing the log of the construction process."

		return (self.factor.route.cache() / 'construct.log')

	def compile(self):
		target = self.output()
		dirs, srcs = self.sources.tree()
		srcs.sort(key=lambda x: x.identifier)
		self.factor.route.cache().init('directory')

		command = uglify(
			self.output(), srcs,
			source_map_root=getattr(self, 'source_map_root', None),
			module=None
		)

		with open(str(self.log), 'wb') as lf:
			p = subprocess.Popen(command, stdin=None, stdout=None, stderr=lf.fileno())
			p.wait()

class CSS(libdev.Sources):
	"""
	Factor Module for Cascading Style Sheet targets.

	Provides compilation of CSS from a reasonable set of languages.
	"""
	__type__ = 'css'

	@property
	def bytes(self):
		"The binary contents of the (file:text/css)`output.css` file."

		with self.output().open('rb') as f:
			return f.read()

	def output(self, role=None) -> libroutes.Route:
		"""
		The route to the output file in the
		(file:directory)`__pycache__` directory.
		"""

		return (self.factor.route.cache() / 'output.css')

	def compile(self):
		target = self.output
		dirs, srcs = self.sources.tree()
		srcs.sort(key=lambda x: x.identifier)
		self.factor.route.cache().init('directory')

		with open(str(self.output()), 'wb') as out:
			for x in srcs:
				with x.open('rb') as src:
					out.write(src.read())

mapping = {
	Class.__type__: Class
	for Class in locals().values()
	if (isinstance(Class, type) and issubclass(Class, libdev.Sources))
}

def load(factor_type):
	ctx = core.outerlocals()
	module = sys.modules[ctx['__name__']]
	module.__class__ = mapping[factor_type]
	module._init()
	module.compile()
