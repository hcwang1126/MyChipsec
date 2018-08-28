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
#  Yuriy Bulygin
#


"""
Checks if Power Management Controller (PMC) in PCH is configured securely

 SKL PSCS Reference: table 7-8 test #4 
 BDW PSCS Reference: table 3-10 test #4
 HSW PSCS Reference: 2.2.9 test #4
"""

from chipsec.module_common import *

from chipsec.hal.mmio import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'pmc'

TAGS = [MTAG_HWCONFIG]


class pmc(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        did = self.cs.get_chipset_id()
        excluded_cores = [chipsec.chipset.CHIPSET_ID_SNB,chipsec.chipset.CHIPSET_ID_IVB,chipsec.chipset.CHIPSET_ID_LFD,chipsec.chipset.CHIPSET_ID_WSM]
        _cores = [d for d in chipsec.chipset.CHIPSET_FAMILY_CORE if d not in excluded_cores]
        _xeons = chipsec.chipset.CHIPSET_FAMILY_XEON
        return ((did in _cores) or (did in _xeons))

    def check_pm_cfg( self ):
        self.logger.start_test( "Power Management Controller (PMC) Config" )

        pm_cfg = self.cs.read_register( 'PM_CFG' )
        self.cs.print_register( 'PM_CFG', pm_cfg )

        if ((pm_cfg >> 27) & 0x1) == 1:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All required bits are set in PM_CFG" )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "Production systems should disable PMC debug mode by setting bit 27 in PM_CFG" )

        return res


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_pm_cfg()
