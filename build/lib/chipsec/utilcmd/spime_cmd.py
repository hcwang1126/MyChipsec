#!/usr/bin/env python
#
# *********************************************************
# 
#                   PRE-RELEASE NOTICE
#
#        This file contains pre-release functionality
#        Please do not distribute this file publicly
#
# *********************************************************
#
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#
#
# Authors:
#  Yuriy Bulygin
#



import os
import sys
import time

from chipsec.file import *
from chipsec.command import BaseCommand

from chipsec.hal.spi_me import *

class MECommand(BaseCommand):
    """
    >>> chipsec_util me [rom]

    Examples:

    >>> chipsec_util me spi.bin
    """
    def requires_driver(self):
        return False

    def run(self):
        if 3 > len(self.argv):
            print MECommand.__doc__
            return

        rom_file = self.argv[2]
        self.logger.log( "[CHIPSEC] Parsing SPI ME Region from file '%s'\n" % rom_file )

        t = time.time()
        parse_me_region_from_file( rom_file )
        self.logger.log( "\n[CHIPSEC] (me) time elapsed %.3f" % (time.time()-t) )


commands = { 'me': MECommand }
