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
#Copyright (c) 2010-2017, Intel Corporation
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
#  Aaron Frinzell
#  Erik Bjorge
#

""" Direct Connect Interface Tests
Reference: Platform Secure Configuration Spec

"""

from chipsec.module_common import *
import chipsec.chipset
import chipsec.logger


TAGS = [MTAG_HWCONFIG]

class dci(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.res = ModuleResult.PASSED

    def is_supported(self):
        return self.cs.is_register_defined('ECTRL')

    def check_ectrl(self):
        self.logger.start_test( "Direct Connect Interface check" )
        self.logger.log( "[*] Verifying DCI is disabled and locked.." )

        # Read register and decode the values
        ectrl = self.cs.read_register('ECTRL')
        ectrl_lock = self.cs.get_register_field('ECTRL', ectrl, 'LOCK')
        ectrl_enable = self.cs.get_register_field('ECTRL', ectrl, 'ENABLE')
        ectrl_avail = self.cs.get_register_field('ECTRL', ectrl, 'AVAILABLE')
        self.cs.print_register('ECTRL', ectrl)

        res = ModuleResult.PASSED
        if ectrl_enable == 1:
            res = ModuleResult.FAILED
            self.logger.log_bad("DCI enable bit set on this platform.")
        if ectrl_lock == 0:
            res = ModuleResult.FAILED
            self.logger.log_bad("DCI lock bit not set on this platform." )
        if ectrl_avail == 1:
            res = ModuleResult.FAILED
            self.logger.log_bad("DCI available on this boot.")

        if (res == ModuleResult.FAILED):
            self.logger.log_failed_check('DCI is configured incorrectly.')
        elif (res == ModuleResult.PASSED):
            self.logger.log_passed_check('DCI is locked and configured correctly.')

        return res

    def run(self, module_argv):
        return self.check_ectrl()

