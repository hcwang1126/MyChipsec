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
#  Erik Bjorge
#


"""
Checks CPU Configuration Lock
"""

from chipsec.module_common import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'debug_interface'

TAGS = [MTAG_HWCONFIG]

class debug_interface(BaseModule):

    def is_supported(self):
        # Use CPUID Function 1 to determine if the IA32_DEBUG_INTERFACE MSR is supported.
        # See IA32 SDM CPUID Instruction for details.  (SDBG ECX bit 11)
        (eax, ebx, ecx, edx) = self.cs.cpu.cpuid(1, 0)
        return (ecx & (1 << 11)) != 0

    ## check_debug
    # checks the CPU debug interface configuration
    def check_debug(self):
        self.logger.start_test( "CPU Debug Interface MSR Check" )

        self.logger.log( "[*] checking if CPU debug interface is disabled and locked down..")
        dbgiface        = self.cs.read_register('IA32_DEBUG_INTERFACE')
        dbgiface_enable = self.cs.get_register_field('IA32_DEBUG_INTERFACE', dbgiface, 'ENABLE')
        dbgiface_lock   = self.cs.get_register_field('IA32_DEBUG_INTERFACE', dbgiface, 'LOCK')

        self.cs.print_register('IA32_DEBUG_INTERFACE', dbgiface)

        if 1 == dbgiface_enable or 0 == dbgiface_lock:
            if 1 == dbgiface_enable:
                self.logger.log_important("CPU debug enable requested by software.")
            if 0 == dbgiface_lock:
                self.logger.log_important("CPU debug interface is not locked.")
            res = ModuleResult.FAILED
            self.logger.log_failed_check("CPU debug interface state is incorrect.")
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed_check("CPU debug interface state is correct.")

        return res


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run(self, module_argv ):
        self.res = self.check_debug()
        return self.res 
