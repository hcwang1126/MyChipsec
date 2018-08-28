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
Check BIOS Guard related configuration
"""

from chipsec.module_common import *

from chipsec.hal.msr import *

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'biosguard'

TAGS = [MTAG_BIOS]


class biosguard(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)


    def is_supported(self):
        # MS HyperV workaround. HyperV reports SMRR support but throws and exception on access to SMRR msrs.
        # Not a problem for chipsec driver but crashes RwDrv.'
        from chipsec.hal.cpu import VMM_HYPER_V
        if self.cs.cpu.check_vmm() == VMM_HYPER_V:
            self.logger.log("Not supported under Hyper-V")
            return False
        return self.cs.is_register_defined('MSR_PLATFORM_INFO')

    ## check_BIOS_Guard_supported
    # Checks that CPU supports BIOS Guard
    def check_BIOS_Guard_supported( self ):
        self.logger.log( "[*] Checking CPU BIOS Guard support (bit 35) in PLATFORM_INFO MSR.." )

        platform_info_msr_reg = self.cs.read_register( 'MSR_PLATFORM_INFO')
        biosguard = self.cs.get_register_field( 'MSR_PLATFORM_INFO', platform_info_msr_reg, 'BIOSGuard' )
        self.cs.print_register( 'MSR_PLATFORM_INFO', platform_info_msr_reg )

        if ( 1 == biosguard ): self.logger.log_good( "CPU supports BIOS Guard feature" )
        else:                  self.logger.log_skipped_check( "CPU does not support BIOS Guard feature" )

        return biosguard

    ## check_BIOS_Guard_config
    # Checks that BIOS Guard protection is enabled and locked
    def check_BIOS_Guard_config( self ):
        self.logger.log( "[*] Checking if CPU BIOS Guard is enabled and locked in PLAT_FRMW_PROT_CTRL MSR.." )

        pfpc_msr_reg = self.cs.read_register( 'PLAT_FRMW_PROT_CTRL_MSR' )
        self.cs.print_register( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg )
        biosguard_lock = self.cs.get_register_field( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg, 'Lock' )
        biosguard_en   = self.cs.get_register_field( 'PLAT_FRMW_PROT_CTRL_MSR', pfpc_msr_reg, 'Enable' )

        if 1 == biosguard_en:
            self.logger.log_good( "CPU BIOS Guard is used. BIOS Update is protected by the CPU\n" )
            if 1 == biosguard_lock:
                res = ModuleResult.PASSED
                self.logger.log_passed_check( "CPU BIOS Guard configuration is locked" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "CPU BIOS Guard configuration is not locked" )
        else:
            self.logger.log('')
            if 1 == biosguard_lock:
                res = ModuleResult.WARNING
                self.logger.log_warn_check( "CPU BIOS Guard is not used. BIOS Update is done via legacy update mechanisms" )
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed_check( "BIOS Guard configuration is not locked" )
        return res

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test( "Intel BIOS Guard Configuration" )

        # Nothing we can do if BIOS Guard is not supported by the CPU
        if not self.check_BIOS_Guard_supported():
            return ModuleResult.SKIPPED

        return self.check_BIOS_Guard_config()
