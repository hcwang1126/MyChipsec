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
Checks for SPI Controller Vendor Components Locks
"""

from chipsec.module_common import *
TAGS = [MTAG_BIOS]

class spi_vcl(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_vendor_component_lock(self):
        self.logger.start_test( "SPI Vendor Component Lock" )

        if not self.cs.is_register_defined( 'LVSCC' ):
            self.logger.error( "Couldn't find definition of required registers (LVSCC)" )
            return ModuleResult.ERROR

        lvscc_reg = self.cs.read_register( 'LVSCC' )
        self.cs.print_register( 'LVSCC', lvscc_reg )
        vcl = self.cs.get_register_field( 'LVSCC', lvscc_reg, 'VCL')

        if 1 == vcl: self.logger.log_passed_check( "Vendor Specific Component Capabilities is locked" )
        else:        self.logger.log_failed_check( "Vendor Specific Component Capabilities can be modified" )

        res = ModuleResult.PASSED if (1 == vcl) else ModuleResult.FAILED
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_vendor_component_lock()
