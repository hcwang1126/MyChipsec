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
Check Memory Controller Configuration
"""

from chipsec.module_common import *

from chipsec.hal.mmio import *
from chipsec.hal.pci import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'mclock'

TAGS = [MTAG_HWCONFIG]


MCHBAR_MCLOCK_OFFSET = 0x50FC

class mclock(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        if self.cs.get_chipset_id() in chipsec.chipset.CHIPSET_FAMILY_CORE:
            return True
        return False

    def check_mclock(self):
        self.logger.start_test( "Memory Controller Lock" )

        mchbar_addr = self.cs.mmio.get_MCHBAR_base_address()
        self.logger.log("[*] MC_LOCK address: 0x%08X" % (mchbar_addr + MCHBAR_MCLOCK_OFFSET))
        mclock = self.cs.mmio.read_MMIO_reg_dword(mchbar_addr, MCHBAR_MCLOCK_OFFSET) & 0xFF
        self.logger.log( "[*] MC_LOCK register = 0x%02X" % mclock )

        mclock_ok = 0
        if ( 0x87 == (mclock & 0x87) ):
            self.logger.log_passed_check( "Memory controller configuration is locked\n" )
            mclock_ok = 1
        else:
            self.logger.log_failed_check( "Memory controller configuration is NOT locked\n" )

        return mclock_ok == 1

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self,  module_argv ):
        return self.check_mclock()
