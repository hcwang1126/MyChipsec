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
# Authors:
#  HC Wang
#


"""
Check and dump ACPI HPET

"""

from chipsec.module_common import *
from chipsec.hal.acpi   import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'perf'

TAGS = [MTAG_HWCONFIG]


class hpet(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

        try:
            self._acpi = ACPI(self.cs)
        except AcpiRuntimeError, msg:
            print msg
            return

    def is_supported(self):
        return True

    def _dump_acpi_table(self, name):
        if self._acpi.is_ACPI_table_present( name ):
            self.logger.log( "[CHIPSEC] reading ACPI table '%s'" % name )
            self._acpi.dump_ACPI_table( name )
        else:
            self.logger.log( "[CHIPSEC] ACPI table '%s' wasn't found" % name )

    def check_and_dump_hpet(self):
        
        self._dump_acpi_table("HPET")

        return ModuleResult.PASSED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_and_dump_hpet()