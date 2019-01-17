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



"""
Access to Uncore CSRs on certain Intel CPUs (Nehalem/Lynnfield family architecture)

usage:
    >>> read_csr( 0x1050 )
    >>> write_csr( 0x1050, 0xE0000001 )
"""

__version__ = '1.0'

import struct
import sys
import os.path

from chipsec.logger import logger
from chipsec.hal.pci import *

class CsrRuntimeError (RuntimeError):
    pass

class Csr:

    def __init__( self, helper ):
        self.helper = helper

    def read_csr( self, address ):
        bus = 0xFF # should be 0xFF or 0xFE
        dev = 0
        fun = (address & 0xFF00) >> 12
        off = (address & 0xFF)
        value = self.helper.read_pci_reg( bus, dev, fun, off, 4 )
        if logger().VERBOSE:
            logger().log( "[csr] reading Uncore CSR: 0x%02X, value: 0x%08X (B/D/F/off = %d/%d/%d/%x)" % (address, value, bus, dev, fun, off) )
        return value

    def write_csr( self, address, dword_value ):
        bus = 0xFF # should be 0xFF or 0xFE
        dev = 0
        fun = (address & 0xFF00) >> 12
        off = (address & 0xFF)
        old_value = self.helper.write_pci_reg( bus, dev, fun, off, 4, dword_value )
        if logger().VERBOSE:
            logger().log( "[csr] writing Uncore CSR: 0x%02X, value: 0x%08X (B/D/F/off = %d/%d/%d/%x)" % (address, dword_value, bus, dev, fun, off) )
        return old_value
