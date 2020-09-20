"""
# HTTP host network daemon.
"""
import os
import functools

from ...system.files import Path
from ...system import kernel
from ...system import process
from ...system import network

from ...kernel import system as ksystem
from ...kernel import core as kcore
from ...kernel import io as kio
from ...kernel import dispatch as kdispatch

from ...sectors import daemon
from ...context import tools

from .. import service

optmap = {
	'-L': 'listening-interfaces',
	'-P': 'concurrency',
	'-t': 'trap',
}

def sequence_arguments(igroups, default=None):
	# igroups contains the option argument associated
	# with all non-option arguments following the option
	# This yields out those options associated with the
	# first argument following the option rather than all of them,
	# depending on the type of option.

	for group, contents in igroups:
		if group is None:
			pass
		elif group[:2] == '--':
			if '=' in group:
				yield tuple(group.split('='))
			else:
				yield (group, None)
			group = default
		elif group[:1] == '-':
			if len(group) > 2:
				# Included parameter.
				yield (group[:2], group[2:])
				group = default
			elif not contents:
				yield (group, None)

		if contents:
			yield (group, contents[0])

		for x in contents[1:]:
			yield (default, x)

def parse_arguments(name, args):
	optgroups = tools.group((lambda x: x[:1] == '-'), args)
	cmdgroups = list(tools.group(
		(lambda x: (x is None or x[0] is None)),
		sequence_arguments(optgroups)
	))

	assert cmdgroups[0][0] is None

	# Flatten the arguments following the first set of options.
	remainder = []
	for x in cmdgroups[1:]:
		remainder.append(x[0][1])
		for opt, arg in x[1]:
			remainder.append(opt)
			if arg is not None:
				remainder.append(arg)

	return ((name, cmdgroups[0][1]), remainder)

def rewrite_names(hostname, host):
	selected = True
	default = hostname
	aliases = list(host['names'])
	host['names'].clear()
	host['networks'] = set()

	for name in aliases:
		if name[:1] == '[' and name[-1:] == ']':
			name = name[1:-1]
			selected = True

		if name[-1] == '.':
			name = name[:-1]
		else:
			name = name + '.' + hostname

		if name[:1] == '*':
			# Suffix match
			selected = False
			host['networks'].add(name[1:])
		else:
			host['names'].add(name)
			if selected:
				default = name
				selected = False

	host['subject'] = default

def parse_host_config(indentation, level, section):
	"""
	# Parse the contents of a `@host` section.
	"""
	methods = set()
	partitions = {}
	redirects = {}
	headers = []

	# State fields.
	symbol = target = mount_point = None

	for directive in section.split('\n' + (level * indentation)):
		if directive.lstrip()[:1] in {'#', ''}:
			# Comment or empty line.
			continue

		# The initial split producing the hostsegments made this indentation relative.
		# No indentation multiplication is necessary here.
		if directive.startswith(indentation):
			# Indented continuations.
			# Add line content to the existing set or sequence.
			if symbol is None:
				pass
			if symbol == ':Redirect':
				redirects[target] += directive.split()
			elif symbol == ':Allow':
				methods += directive.split()
			elif symbol == ':Partition':
				part = partitions[mount_point]

				n = len(part)
				if n > 2:
					# Extend argument vector.
					part += directive[1:].strip().split(' ') # Trim the leading tab.
				else:
					part += directive.strip().split(None, 2 - n)
					if len(part) > 2:
						# Initialize the now present argument vector.
						part[2:] = part[2].rstrip('\n').split(' ')
			else:
				# Extend previously declared header.
				h, v = headers[-1]
				if v:
					v += b' '
				v += directive.strip().encode('utf-8')
				headers[-1] = (h, v)

			continue
		else:
			if directive[:1] == ':':
				symbol, parameters = directive.strip('\n').split(None, 1)
			else:
				symbol, parameters = directive.strip('\n').split(':', 1) #* Remove empty lines.
				headers.append((
					symbol.strip().encode('utf-8'),
					parameters.strip().encode('utf-8')
				))
				continue

		# New setting.
		if symbol == ':Redirect':
			target, *endpoints = parameters.split()
			redirects[target] = endpoints
		elif symbol == ':Partition':
			mount_point, *remainder = parameters.strip().split(None, 3) #* Path is required.
			if mount_point[-1] != '/':
				mount_point += '/'

			if len(remainder) < 3:
				partitions[mount_point] = remainder
			else:
				partitions[mount_points] = remainder[2:] + remainder[2].rstrip('\n').split(' ')
		elif symbol == ':Allow':
			methods = set(parameters.split())
		else:
			# Unknown directive.
			pass

	return {
		'allowed-methods': methods,
		'partitions': partitions,
		'redirects': redirects,
		'headers': headers,
	}

def host_inherit_context(target, source):
	# Sets, union.
	for x in ('allowed-methods',):
		target[x].update(source[x])

	# Dictionaries, setdefaults.
	# Arguably, redirects could be merged at the value level,
	# but it doesn't seem useful so just setdefault.
	for x in ('partitions', 'redirects'):
		d = source[x]
		y = target[x]
		for k, v in d.items():
			y.setdefault(k, v)

	# Header sequence, prefix.
	for x in ('headers',):
		target[x][:0] = source[x]

def parse_network_config(string, indentation='\t', level=0):
	# http host network
	cfg = {}

	# (context-host, *http-hosts)
	cfg_segments = string.split('\n' + (level * indentation) + '@')

	# Everything before the first "^@host:...\n"
	ctx = parse_host_config(indentation, level, cfg_segments[0])

	hlevel = level + 1
	hprefix = (indentation * hlevel)
	for section in cfg_segments[1:]: # Host declaration.
		if not section or section[:1] == '#':
			continue

		# Separate the first line containing the host and alias set.
		hostspec, section_content = section.split('\n' + hprefix, 1)

		hc = parse_host_config(indentation, hlevel, section_content)

		host, aliases = hostspec.split(':', 1)
		hc['names'] = set(aliases.split())
		hc['subject'] = host

		host_inherit_context(hc, ctx)
		cfg[host] = hc

	return cfg

def parse_interface_config(string, local=None):
	# interface configuration
	cfg = {}

	for protocolsection in string.split('\n.'):
		if not protocolsection or protocolsection.lstrip()[:1] == '#':
			continue

		proto, *pconfig = protocolsection.split('\n\t')
		proto, stack = proto.split(':', 1)
		stack = stack.strip() or None
		if stack:
			stack = tuple(stack.split('/'))
		else:
			stack = ()

		proto = proto.strip('.') # Handle initial section case.
		parts = {}
		endpoints = cfg[(proto, stack)] = []

		for directive in pconfig:
			directive = directive.strip() # Clean empty lines.
			if directive.startswith('#'):
				continue

			pair = directive.rsplit(':', 1)
			try:
				pair = (pair[0], int(pair[1]))
			except IndexError:
				pair = None

			if directive[:1] == '/' or directive[:2] == './':
				if directive[:1] != '/':
					directive = directive[2:]
				endpoints.append(network.Endpoint.from_local(directive))
				local.add(directive)
			elif pair and pair[0][:1].isdigit():
				endpoints.append(network.Endpoint.from_ip4(pair))
			elif pair and pair[0][:1] == '[' and pair[0][-1:] == ']':
				endpoints.append(network.Endpoint.from_ip6((pair[0][1:-1], pair[1])))
			else:
				if pair:
					hostname = pair[0]
				else:
					hostname = directive

				cname, ifaddrs = network.select_interfaces(proto, 'octets', hostname)
				if pair:
					endpoints.extend(
						x.replace(port=pair[1], transport=0, type='octets')
						for x in ifaddrs
					)
				else:
					endpoints.extend(ifaddrs)

	return cfg

def load_partitions(items):
	from importlib import import_module

	prefixes = {}

	for mnt, router in items:
		module_name, router_name, *argv = router # Insufficient Partition parameters?
		module = import_module(module_name)
		prefixes[mnt] = getattr(module, router_name), argv

	return prefixes

def create_host(name, config):
	parts = load_partitions(config['partitions'].items())
	h = service.Host(parts)

	rewrite_names(name, config)
	h.h_update_names(name, *config['names'])
	if config['headers']:
		h.h_set_headers(config['headers'])

	if 'allowed-methods' in config:
		h.h_allowed_methods = frozenset(x.encode('utf-8') for x in config['allowed-methods'])

	if config['redirects']:
		for target, origins in config['redirects'].items():
			h.h_set_redirects(target, origins)

	return h

def allocate_network(optdata, kports):
	# Interface -> Connections -> (http) Network
	netcfg = {}
	for configpath in optdata['host-networks']:
		net = parse_network_config(open(configpath).read())
		netcfg.update(net)

	hostset = {
		host: create_host(host, hcfg)
		for host, hcfg in netcfg.items()
	}

	network = service.Network(list(hostset.values()))
	network.http_default_host = optdata['trap']

	cxns = kio.Connections(network.net_accept)
	ifs = []
	for p, ep in kports.items():
		i = kio.Interface(cxns.cxn_accept, service.protocols[p[0]])
		i.if_install(ep)
		ifs.append(i)

	ifseq = kcore.Sequenced(ifs) # Does not require sequenced shutdown.
	coif = kdispatch.Coprocess('system-interfaces', ifseq)
	cocx = kdispatch.Coprocess('service-connections', cxns)

	# Terminated in reverse order.
	return kcore.Sequenced([network, cocx, coif])

def integrate(name, args):
	optdata = {
		'listening-interfaces': [],
		'host-networks': [],
		'concurrency': os.environ.get('SERVICE_CONCURRENCY', '1'),
		'trap': None,
	}

	optset, arguments = parse_arguments(name, args)
	for opt, param  in optset[1]:
		opt = optmap[opt]
		dv = optdata[opt]

		if isinstance(dv, list):
			dv.append(param)
		else:
			optdata[opt] = param

	return optdata, arguments

def main(inv:process.Invocation) -> process.Exit:
	optdata, arguments = integrate(inv.parameters['system']['name'], inv.args)
	optdata['host-networks'] = arguments

	ifcfg = {}
	lset = set()

	for configpath in optdata['listening-interfaces']:
		for k, v in (parse_interface_config(open(configpath).read(), local=lset)).items():
			if k not in ifcfg:
				ifcfg[k] = []

			ifcfg[k].extend(v) # KeyError: Protocol not recognized.

	for socket in lset:
		try:
			os.unlink(socket)
		except FileNotFoundError:
			pass

	workers = max(int(optdata.get('concurrency', 1)), 1)

	kports = {
		p: kernel.Ports([network.service(x) for x in ep])
		for p, ep in ifcfg.items()
	}

	alloc = functools.partial(allocate_network, optdata, kports)
	net = alloc()
	dpm = daemon.ProcessManager(net, alloc, concurrency=workers)

	process = ksystem.dispatch(inv, dpm, identifier='http-network-daemon')
	ksystem.set_root_process(process)
	ksystem.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
