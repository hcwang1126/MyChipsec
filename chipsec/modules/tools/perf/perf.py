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
from chipsec.hal.pci    import *

IOUT_SLOPE_DEFAULT = 0x200
IOUT_SLOPE_OK = 0
IOUT_SLOPE_WARN = 1

PACKAGE_POWER_LIMIT_OK = 0
PACKAGE_POWER_LIMIT_FAILED = 1

PREFETCHERS_DISABLED = 0
PREFETCHERS_ENABLED = 1

PCU_CR1_DID_VID = 0x20818086
PCU_CR1_PCI_DEV = 30
PCU_CR1_PCI_FUN = 1
CSR_DESIRED_CORES_CFG2_OFFSET = 0xA0

UPI0_DID_VID = 0x20588086
UPI0_DEV = 14
UPI0_FUN = 0
KTILK_SNC_CONFIG_OFFSET = 0x180
KTI_AG_CTRL = 0xF0

CHA_UTIL_DID_VID = 0x208D8086
CHA_UTIL_DEV = 0x08
CHA_UTIL_FUN = 0x00
HA_COH_CFG_OFFSET = 0x11C

CHA_SAD_ALL_DID_VID = 0x20548086
CHA_SAD_ALL_DEV = 29
CHA_SAD_ALL_FUN = 0x00
DBP_CFG_OFFSET = 0x28C

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'perf'

TAGS = [MTAG_HWCONFIG]


class perf(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def check_iout_slope(self):
        vr_misc_config = self.cs.read_register( 'VR_MISC_CONFIG' )
        self.cs.print_register( 'VR_MISC_CONFIG', vr_misc_config )
        
        iout_slope = self.cs.read_register_field( 'VR_MISC_CONFIG', 'IOUT_SLOPE', False )
        if iout_slope > IOUT_SLOPE_DEFAULT:
            self.logger.log_warn_check( "IOUT_SLOPE could be not equal to default for better performance." )
            return IOUT_SLOPE_WARN
        else:
            return IOUT_SLOPE_OK

    def check_prefetchers(self):
        prefetchers = self.cs.read_register( 'Prefetchers' )
        self.cs.print_register( 'Prefetchers', prefetchers )

        prefetchers_en = PREFETCHERS_ENABLED
        
        hw_prefetchers = self.cs.read_register_field( 'Prefetchers', 'HardwarePrefetcher', True )
        acl_prefetchers = self.cs.read_register_field( 'Prefetchers', 'AdjacentCacheLinePrefetch', True )
        dcu_streamer_prefetchers = self.cs.read_register_field( 'Prefetchers', 'DCUStreamerPrefetcher', True )
        dcu_ip_prefetchers = self.cs.read_register_field( 'Prefetchers', 'DCUIpPrefetcher', True )
        
        if hw_prefetchers != 0:
            self.logger.log_failed_check( "Hardware prefetcher is disabled!" )
            prefetchers_en = PREFETCHERS_DISABLED
        elif acl_prefetchers != 0:
            self.logger.log_failed_check( "Adjacent cache line prefetch is disabled!" )
            prefetchers_en = PREFETCHERS_DISABLED
        elif dcu_streamer_prefetchers != 0:
            self.logger.log_failed_check( "DCU streamer prefetcher is disabled!" )
            prefetchers_en = PREFETCHERS_DISABLED
        elif dcu_ip_prefetchers != 0:
            self.logger.log_failed_check( "DCU IP prefetcher is disabled!" )
            prefetchers_en = PREFETCHERS_DISABLED
        else:
            self.logger.log_passed_check( "All prefetchers are enabled." )

        return prefetchers_en

    def check_p_state_cfg( self ):
        misc_pwr_mgmt = self.cs.read_register( 'MSR_MISC_PWR_MGMT' )
        self.cs.print_register( 'MSR_MISC_PWR_MGMT', misc_pwr_mgmt )

        ia32_pm_en = self.cs.read_register( 'IA32_PM_ENABLE' )
        self.cs.print_register( 'IA32_PM_ENABLE', ia32_pm_en )
        return

    def check_perf_bias_cfg( self ):
        msr_pwr_ctl = self.cs.read_register( 'MSR_POWER_CTL' )
        self.cs.print_register( 'MSR_POWER_CTL', msr_pwr_ctl )

        config_mode = self.cs.read_register_field( 'MSR_POWER_CTL', 'PWR_PERF_TUNING_CFG_MODE', False )

        if config_mode:
            energy_policy = self.cs.read_register( 'ENERGY_PERF_BIAS_CONFIG' )
            self.cs.print_register( 'ENERGY_PERF_BIAS_CONFIG', energy_policy )
        else:
            energy_policy = self.cs.read_register( 'IA32_ENERGY_PERF_BIAS' )
            self.cs.print_register( 'IA32_ENERGY_PERF_BIAS', energy_policy )

        return

    def _find_pci_bus ( self, did_vid, pci_dev, pci_fun ):
        bus = None

        for i in range(0xff):
            if self.cs.pci.read_dword(i, pci_dev, pci_fun, 0) == did_vid:
                bus = i
                break;

        return bus

    def check_ht_enable ( self ):
        pcu_cr1_bus = self._find_pci_bus( PCU_CR1_DID_VID, PCU_CR1_PCI_DEV, PCU_CR1_PCI_FUN )
        if pcu_cr1_bus != None:
            csr_desired_cores_cfg2 = self.cs.pci.read_dword(pcu_cr1_bus, PCU_CR1_PCI_DEV, PCU_CR1_PCI_FUN, CSR_DESIRED_CORES_CFG2_OFFSET)
            self.cs.print_register( 'CSR_DESIRED_CORES_CFG2', csr_desired_cores_cfg2 )
        return

    def _get_csr_value ( self, pci_did_vid, pci_dev, pci_fun, pci_offset):
        pci_bus = self._find_pci_bus( pci_did_vid, pci_dev, pci_fun )
        csr_value = None
        if pci_bus != None:
            if pci_offset <= 0xff:
                csr_value = self.cs.pci.read_dword(pci_bus, pci_dev, pci_fun, pci_offset)
            else:
                csr_value = self.cs.mmio.read_mmcfg_reg(pci_bus, pci_dev, pci_fun, pci_offset, 4)

        return csr_value
         

    def check_AtoS_enable ( self ):
        ha_coh_cfg_1 = self._get_csr_value(CHA_UTIL_DID_VID, CHA_UTIL_DEV, CHA_UTIL_FUN, HA_COH_CFG_OFFSET)
        if ha_coh_cfg_1 != None:
            self.cs.print_register( 'HA_COH_CONFIG_1',  ha_coh_cfg_1 )
        return

    def check_llc_dead_line ( self ):
        dbp_cfg = self._get_csr_value(CHA_SAD_ALL_DID_VID, CHA_SAD_ALL_DEV, CHA_SAD_ALL_FUN, DBP_CFG_OFFSET)
        if dbp_cfg != None:
            self.cs.print_register( 'DBP_CONFIG',  dbp_cfg )
        return

    def check_snc_enable ( self ):
        snc_config = self.cs.read_register( 'SNC_CONFIG' )
        self.cs.print_register( 'SNC_CONFIG', snc_config )
        return

    def check_upi_prefetch_enable ( self ):
        upi0_kti_ag_ctrl = self._get_csr_value(UPI0_DID_VID, UPI0_DEV, UPI0_FUN, KTI_AG_CTRL)
        if upi0_kti_ag_ctrl != None:
            self.cs.print_register( 'UPI0_KTI_AG_CTRL',  upi0_kti_ag_ctrl)
        return

    def check_turbo_enable ( self ):
        ia32_misc_enable = self.cs.read_register( 'IA32_MISC_ENABLE' )
        self.cs.print_register( 'IA32_MISC_ENABLE', ia32_misc_enable )
        return

    def check_llc_prefetch ( self ):
        ia32_bios_sign_id = self.cs.read_register( 'IA32_BIOS_SIGN_ID' )
        self.cs.print_register( 'IA32_BIOS_SIGN_ID', ia32_bios_sign_id )
        ucode_revision = self.cs.read_register_field( 'IA32_BIOS_SIGN_ID', 'Microcode', False )
        if (ucode_revision & 0x0FF) >= 0x05:
            self.logger.log_information_check("Support LLC prefetch.")
            #msr_llc_prefetch = self.cs.read_register( 'MSR_VIRTUAL_MSR_LLC_PREFETCH' )
            #self.cs.print_register( 'MSR_VIRTUAL_MSR_LLC_PREFETCH', msr_llc_prefetch )
        else:
            self.logger.log_information_check("Not support LLC prefetch.")
        return

    def check_perf_cfg( self ):
        self.logger.start_test( "Performance Registers Check" )

        #prefetchers_res = self.check_prefetchers()
        self.check_perf_bias_cfg()
        #self.check_p_state_cfg()
        self.check_ht_enable()
        self.check_turbo_enable()
        #self.check_snc_enable()
        self.check_upi_prefetch_enable()
        self.check_AtoS_enable()
        self.check_llc_dead_line()
        self.check_llc_prefetch()
        iout_slope_res = self.check_iout_slope()

        res = ModuleResult.PASSED
        """
        if prefetchers_res != PREFETCHERS_ENABLED:
            res = ModuleResult.FAILED
        elif iout_slope_res != IOUT_SLOPE_OK:
            res = ModuleResult.WARNING
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All registers are set in performance spec" )
        """
        return res

    def read_and_print_reg ( self, reg_name ):
        reg_val = self.cs.read_register ( reg_name )
        self.cs.print_register( reg_name, reg_val )
        return reg_val

    def check_pkg_power_limit( self, pl1_tdp, pl2_tdp):
        pkg_power_limit = self.read_and_print_reg( 'MSR_PKG_POWER_LIMIT' )
        
        power_unit = 2 ** self.cs.read_register_field( 'MSR_RAPL_POWER_UNIT', 'POWER_UNITS', True )
        pl1_set_tdp = self.cs.read_register_field( 'MSR_PKG_POWER_LIMIT', 'PL1', False ) / power_unit
        pl2_set_tdp = self.cs.read_register_field( 'MSR_PKG_POWER_LIMIT', 'PL2', False ) / power_unit
        
        result = PACKAGE_POWER_LIMIT_OK
        if pl1_set_tdp != pl1_tdp:
            self.logger.log_failed_check( "PL1 is %dW, not assigned to %dW" % (int(pl1_set_tdp), int(pl1_tdp)))
            result = PACKAGE_POWER_LIMIT_FAILED

        if pl2_set_tdp != pl2_tdp:
            self.logger.log_failed_check( "PL2 is %dW, not assigned to %dW" % (int(pl2_set_tdp), int(pl2_tdp)))
            result = PACKAGE_POWER_LIMIT_FAILED

        if result == PACKAGE_POWER_LIMIT_OK:
            self.logger.log_passed_check( "All package power limit settings are correct." )

        return result

    def check_tdp_cfg( self, pl1_tdp=205, pl2_tdp=240):
        self.logger.start_test( "TDP settings check" )

        pkg_power_limit_res = self.check_pkg_power_limit(pl1_tdp, pl2_tdp)

        if pkg_power_limit_res != PACKAGE_POWER_LIMIT_OK:
            res = ModuleResult.FAILED
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed_check( "All registers are set in performance spec." )

        return res

    def dump_turbo_settings( self ):
        self.read_and_print_reg( 'MSR_TURBO_RATIO_LIMIT' )

        try:
          self.read_and_print_reg( 'MSR_TURBO_GROUP_CORE_CNT' )
        except:
          self.logger.log_warn_check( "MSR_TURBO_GROUP_CORE_CNT is not support.." )
        
        return

    def dump_flex_ratio_settings( self ):
        try:
          self.read_and_print_reg( 'MSR_FLEX_RATIO' )
        except:
          self.logger.log_warn_check( "MSR_FLEX_RATIO is not support.." )
        
        return

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        if len(module_argv) > 0:
            test_mode = module_argv[0].lower()
            if 'tdp' == test_mode:
                if len(module_argv) == 3:
                    pl1_tdp = module_argv[1]
                    pl2_tdp = module_argv[2]
                    return self.check_tdp_cfg(pl1_tdp, pl2_tdp)

            if 'turbo' == test_mode:
                return self.dump_turbo_settings ()
            
            if 'flex_ratio' == test_mode:
                return self.dump_flex_ratio_settings ()

        return self.check_perf_cfg()
