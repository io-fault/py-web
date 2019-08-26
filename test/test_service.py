"""
# Check integrations of internet.http and kernel.http
"""
import itertools
from .. import service as module

from ...kernel import flows
from ...kernel import io as kio
from ...kernel.test import library as testlib

if __name__ == '__main__':
	import sys; from ...test import library as libtest
	libtest.execute(sys.modules[__name__])
