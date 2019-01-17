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
Common checks for DIMM SPD protections
"""

from chipsec.module_common import *

from chipsec.hal.smbus import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'spd'

TAGS = [MTAG_HWCONFIG]

class spd(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.smbus = SMBus( self.cs )

    def is_supported(self):
        if self.cs.get_chipset_id() in chipsec.chipset.CHIPSET_FAMILY_CORE:
            return True
        return False

    def check_SPD_write_protection( self ):
        self.smbus.display_SMBus_info()
        hcfg = self.smbus.get_SMBus_HCFG()
        if self.cs.get_register_field( 'SMBUS_HCFG', hcfg, 'SPD_WD'):
            self.logger.log_passed_check( "DIMM SPD writes are blocked by SMBus Controller\n" )
            return ModuleResult.PASSED
        else:
            self.logger.log_failed_check( "DIMM SPD writes are allowed by SMBus Controller\n" )
            return ModuleResult.FAILED


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "SMBus Write Protection of DIMM Serial Presence Detect (SPD) ROM" )
        if not self.smbus.is_SMBus_enabled():
            self.logger.log_skipped_check( "SMBus Controller is disabled" )
            return ModuleResult.SKIPPED
        if self.smbus.is_SMBus_supported():
            return self.check_SPD_write_protection()
        else:
            raise Exception, 'SMBus Controller is enabled but not recognized'
