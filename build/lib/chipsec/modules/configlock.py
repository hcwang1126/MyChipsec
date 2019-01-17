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
Checks CPU Configuration Lock
"""

from chipsec.module_common import *

from chipsec.hal.msr import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'configlock'

TAGS = [MTAG_HWCONFIG]

class configlock (BaseModule):

    def is_supported(self):
        # MS HyperV workaround. HyperV reports SMRR support but throws and exception on access to SMRR msrs.
        # Not a problem for chipsec driver but crashes RwDrv.'
        from chipsec.hal.cpu import VMM_HYPER_V
        if self.cs.cpu.check_vmm() == VMM_HYPER_V: 
            self.logger.log("Not supported under Hyper-V")
            return False
        return (self.cs.is_core() or self.cs.is_server())

    ## check_configlock
    # checks the CPU configuration lock
    def check_configlock(self):
        self.logger.start_test( "CPU Configuration Lock Check" )

        self.logger.log( "[*] checking that the CPU configuration is locked down by the firmware.." )
        configlock = self.cs.get_control( 'ConfigLock', with_print=True)

        if 1 == configlock:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "CPU configuration is locked down\n" )
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed_check( "CPU configuration is NOT locked down\n" )

        return res


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv ):
        self.res = self.check_configlock()
        return self.res 
