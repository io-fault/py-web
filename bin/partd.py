"""
# HTTP application daemon.
"""
import os
import functools

from ...system import kernel
from ...system import process
from ...system import network

from ...kernel import system as ksystem
from ...kernel import core as kcore
from ...kernel import io as kio
from ...kernel import dispatch as kdispatch

from ...sectors import daemon

from .. import service, http

def load_partition(module_name, router_name):
	from importlib import import_module
	module = import_module(module_name)
	return getattr(module, router_name)

def allocate(application, protocol, interface):
	# Interface -> Connections -> Partition
	cxns = kio.Connections(application.part_accept)

	i = kio.Interface(cxns.cxn_accept, protocol)
	i.if_install(interface)

	coif = kdispatch.Coprocess('system-interfaces', i)
	cocx = kdispatch.Coprocess('service-connections', cxns)

	# Terminated in reverse order.
	return kcore.Sequenced([application, cocx, coif])

def main(inv:process.Invocation) -> process.Exit:
	socket_path, module_name, router_name, *argv = inv.args
	call = load_partition(module_name, router_name)
	application = call('/', argv)

	try:
		os.unlink(socket_path)
	except FileNotFoundError:
		pass

	workers = max(int(os.environ.get('SERVICE_CONCURRENCY', 1)), 1)
	kp = kernel.Ports([network.service(network.Endpoint.from_local(socket_path))])

	alloc = functools.partial(allocate, application, service.protocols['http'], kp)
	app = alloc()
	dpm = daemon.ProcessManager(app, alloc, concurrency=workers)

	process = ksystem.dispatch(inv, dpm, identifier='http-application-daemon')
	ksystem.set_root_process(process)
	ksystem.control()

if __name__ == '__main__':
	process.control(main, process.Invocation.system())
