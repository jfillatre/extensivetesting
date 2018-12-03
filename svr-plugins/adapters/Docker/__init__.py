#!/usr/bin/env python
# -*- coding: utf-8 -*-

from container import *
from client import *
from templates import *

__DESCRIPTION__ = """Allow to manage docker container.
                     Adapter based on docker library
				"""

__HELPER__ =    [

		("DockerContainer", ["__init__", "run", "create", "get", "list", "prune"])
		]
