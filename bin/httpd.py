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

from .. import service, http

optmap = {
	'-L': 'listening-interfaces',
	'-N': 'host-networks',
	'-P': 'concurrency',
	'-t': 'trap',
}

def sequence_arguments(igroups, default=None):
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
	cmdgroups[0] = (name, cmdgroups[0][1])

	return cmdgroups

def merge(target, source):
	for x in ('names', 'partitions', 'allowed-methods'):
		target[x].update(source[x])

	for x in ('headers',):
		target[x].extend(source[x])

	src = source['redirects']
	dst = target['redirects']
	for k, values in src.items():
		if k not in dst:
			dst[k] = []
		dst[k].extend(values)

def rewrite_names(hostname, host):
	selected = True
	default = hostname
	aliases = list(host['names'])
	host['names'].clear()

	for name in aliases:
		if name[:1] == '[' and name[-1:] == ']':
			name = name[1:-1]
			selected = True

		if name[-1] == '.':
			name = name[:-1]
			if name == '*':
				host['trap'] = name
				continue
		else:
			name = name + '.' + hostname

		host['names'].add(name)
		if selected:
			default = name
			selected = False

	host['subject'] = default

def parse_network_config(string):
	# http host network
	cfg = {}

	for hostsection in string.split('\n@'): # Host declaration.
		if not hostsection or hostsection.lstrip()[:1] == '#':
			continue

		hostspec, *hconfig = hostsection.split('\n\t')
		host, aliases = hostspec.split(':', 1)

		host = host.strip('@') # Handle initial section case.
		parts = {}
		hc = cfg[host] = {
			'names': set(aliases.split()),
			'allowed-methods': set(),
			'partitions': parts,
			'subject': host,
			'redirects': {},
			'headers': [],
		}

		symbol = target = mount_point = None
		for directive in hconfig:
			if directive.lstrip().startswith('#'):
				continue

			if directive.startswith('\t'):
				# Indented continuations.
				if symbol is None:
					pass
				if symbol == ':Redirect':
					hc['redirects'][target] += directive.split()
				elif symbol == ':Allow':
					hc['allowed-methods'] += directive.split()
				elif symbol == ':Partition':
					part = parts[mount_point]

					n = len(part)
					if n == 3:
						# Extend option string.

						v = part[-1]
						v += '\n'
						v += directive[1:] # Trim the leading tab.

						parts[mount_point] = part[:3] + (v,)
					else:
						parts[mount_point] += tuple(directive.strip().split(None, 2 - n))
				else:
					# Extend previously declared header.
					h, v = hc['headers'][-1]
					if v:
						v += b' '
					v += directive.strip().encode('utf-8')
					hc['headers'][-1] = (h, v)

				continue
			else:
				if directive[:1] == ':':
					symbol, parameters = directive.strip('\n').split(None, 1)
				else:
					symbol, parameters = directive.strip('\n').split(':', 1) # Clean empty lines.
					hc['headers'].append((
						symbol.strip().encode('utf-8'),
						parameters.strip().encode('utf-8')
					))
					continue

			# New setting.
			if symbol == ':Redirect':
				target, *endpoints = parameters.split()
				hc['redirects'][target] = endpoints
			elif symbol == ':Partition':
				mount_point, *remainder = parameters.split(None, 3) # Path is required.
				if mount_point[-1] != '/':
					mount_point += '/'

				parts[mount_point] = tuple(remainder)
			elif symbol == ':Allow':
				methods = parameters.split()
				hc['allowed-methods'] = methods
			elif symbol == ':Inherit':
				for template_host in parameters.split():
					merge(hc, cfg[template_host])
			else:
				# Unknown directive.
				pass

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
			stack = stack.split('/')

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
		module_name, router_name, *options = router # Insufficient Partition parameters?
		if not options:
			options = None
		else:
			options = options[0]

		module = import_module(module_name)
		prefixes[mnt] = getattr(module, router_name), options

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

def allocate(optdata, kports):
	# Interface -> Connections -> (http) Network
	netcfg = {}
	for configpath in optdata['host-networks']:
		netcfg.update(parse_network_config(open(configpath).read()))

	hostset = {
		host: create_host(host, hcfg)
		for host, hcfg in netcfg.items()
		if (host[:1] + host[-1:]) != '<>' # Ignore templates.
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

	for ev in parse_arguments(name, args):
		parameter, options = ev
		for opt, param  in options:
			opt = optmap[opt]
			dv = optdata[opt]

			if isinstance(dv, list):
				dv.append(param)
			else:
				optdata[opt] = param

	return optdata

def main(inv:process.Invocation) -> process.Exit:
	optdata = integrate(inv.parameters['system']['name'], inv.args)

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

	alloc = functools.partial(allocate, optdata, kports)
	dpm = daemon.ProcessManager(alloc(), alloc, concurrency=workers)

	process = ksystem.dispatch(inv, dpm, identifier='http-network-daemon')
	ksystem.set_root_process(process)
	ksystem.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
