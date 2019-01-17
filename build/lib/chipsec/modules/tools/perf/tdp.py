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
Checks if performance registers are correct.

"""

from chipsec.module_common import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'perf'

TAGS = [MTAG_HWCONFIG]


class tdp(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True


    def read_and_print_reg ( self, reg_name ):
        reg_val = self.cs.read_register ( reg_name )
        self.cs.print_register( reg_name, reg_val )
        return reg_val


    def dump_tdp_cfg( self ):
        self.logger.start_test( "TDP Settings Dump" )

        pkg_power_limit = self.read_and_print_reg( 'MSR_PKG_POWER_LIMIT' )

        power_unit = 2 ** self.cs.read_register_field( 'MSR_RAPL_POWER_UNIT', 'POWER_UNITS', True )
        pl1_set_tdp = self.cs.read_register_field( 'MSR_PKG_POWER_LIMIT', 'PL1', False ) / power_unit
        pl2_set_tdp = self.cs.read_register_field( 'MSR_PKG_POWER_LIMIT', 'PL2', False ) / power_unit

        self.logger.log_information_check( "PL1 is %dW" % (int(pl1_set_tdp)))
        self.logger.log_information_check( "PL2 is %dW" % (int(pl2_set_tdp)))

        return ModuleResult.PASSED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.dump_tdp_cfg()
		
