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
Verifies if MAC/pTRR mitigations for DRAM row hammer are supported, verifies DRAM supports ECC
"""

from chipsec.module_common import *

import chipsec.hal.smbus
import chipsec.hal.spd

# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'rowhammer'
TAGS = [MTAG_HWCONFIG]

_SPD_OFFSET_PTRR_TMAW_MAC = 41

_SPD_OFFSET_PTRR_TMAW_MAC_pTRR_BIT  = 7
_SPD_OFFSET_PTRR_TMAW_MAC_pTRR_MASK = (1 << _SPD_OFFSET_PTRR_TMAW_MAC_pTRR_BIT)
_SPD_OFFSET_PTRR_TMAW_MAC_UMAC_BIT  = 3
_SPD_OFFSET_PTRR_TMAW_MAC_UMAC_MASK = (1 << _SPD_OFFSET_PTRR_TMAW_MAC_UMAC_BIT)
_SPD_OFFSET_PTRR_TMAW_MAC_MAW_BIT   = 4
_SPD_OFFSET_PTRR_TMAW_MAC_MAW_MASK  = (3 << _SPD_OFFSET_PTRR_TMAW_MAC_MAW_BIT)
_SPD_OFFSET_PTRR_TMAW_MAC_MAC_BIT   = 0
_SPD_OFFSET_PTRR_TMAW_MAC_MAC_MASK  = (7 << _SPD_OFFSET_PTRR_TMAW_MAC_MAC_BIT)

MAC = {
  0x0: 'Unknown',
  0x1: '700K',
  0x2: '600K',
  0x3: '500K',
  0x4: '400K',
  0x5: '300K',
  0x6: '200K?',
  0x7: 'Reserved'
}

MAW = {
  0x0: '64 ms',
  0x1: '48 ms',
  0x2: '32 ms',
  0x3: 'Reserved'
}

MAC_PASS = 0
MAC_FAIL = 1
MAC_WARN = 2


class rowhammer(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.smbus = chipsec.hal.smbus.SMBus( self.cs )
        self.spd   = chipsec.hal.spd.SPD( self.smbus )

    def is_supported(self):
        p = self.cs.get_chipset_id()
        return (p not in chipsec.chipset.CHIPSET_FAMILY_ATOM) and (p not in chipsec.chipset.CHIPSET_FAMILY_XEON)


    def check_antiRH_pTRR( self, device, ptrr_mac ):
        # check DIMM is pTRR compliant
        pTRR = (ptrr_mac & _SPD_OFFSET_PTRR_TMAW_MAC_pTRR_MASK) >> _SPD_OFFSET_PTRR_TMAW_MAC_pTRR_BIT
        self.logger.log( "      Pseudo TRR (pTRR)            : 0x%01X" % pTRR )
        return (pTRR == 1)

    def check_antiRH_MAC( self, device, ptrr_mac ):
        # check DIMM supports Unlimited MAC and MAC level
        umac = (ptrr_mac & _SPD_OFFSET_PTRR_TMAW_MAC_UMAC_MASK) >> _SPD_OFFSET_PTRR_TMAW_MAC_UMAC_BIT
        self.logger.log( "      Unlimited MAC                : 0x%01X" % umac )
        mac = (ptrr_mac & _SPD_OFFSET_PTRR_TMAW_MAC_MAC_MASK) >> _SPD_OFFSET_PTRR_TMAW_MAC_MAC_BIT
        self.logger.log( "      Maximum Activate Count (MAC) : 0x%01X (%s)" % (mac,MAC[mac]) )
        maw = (ptrr_mac & _SPD_OFFSET_PTRR_TMAW_MAC_MAW_MASK) >> _SPD_OFFSET_PTRR_TMAW_MAC_MAW_BIT
        self.logger.log( "      Maximum Active Window (MAW)  : 0x%01X (%s)" % (maw,MAW[maw]) )
        if 1 == umac: mac_sts = MAC_PASS
        elif mac > 0: mac_sts = MAC_WARN
        else:         mac_sts = MAC_FAIL
        return mac_sts

    def check_ECC( self, device ):
        ecc_ok = self.spd.isECC( device )
        self.logger.log( '    %s %s ECC' % (chipsec.hal.spd.SPD_DIMMS[device],'supports' if ecc_ok else 'does not support')  )
        return ecc_ok

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        #self.logger.HAL = True

        self.logger.start_test( "DRAM Row Hammer Mitigations" )

        if not self.smbus.is_SMBus_enabled():
            self.logger.log_skipped_check( "SMBus Controller is disabled" )
            return ModuleResult.SKIPPED
        if not self.smbus.is_SMBus_supported():
            self.logger.log_skipped_check( "SMBus Controller is enabled but not recognized" )
            return ModuleResult.SKIPPED

        self.smbus.enable_SMBus_host_controller()

        _dimms = self.spd.detect()
        self.logger.log( "[*] Found %d DIMM(s) with SPD EEPROM" % len(_dimms))
        if 0 == len(_dimms):
            self.logger.log_warn_check( "Didn't find SPD on DIMMs. Cannot verify row hammer susceptibility" )
            return ModuleResult.WARNING

        res = ModuleResult.PASSED

        for _dimm in _dimms:
            _dimm_n = chipsec.hal.spd.SPD_DIMMS[_dimm]
            self.logger.log( "[*] reading %s SPD information.." % _dimm_n)
            #self.spd.decode( _dimm )
            dram_type   = self.spd.getDRAMDeviceType( _dimm )
            module_type = self.spd.getModuleType( _dimm )
            self.logger.log( "    %s DRAM device type (byte 2): 0x%01X (%s)" % (_dimm_n, dram_type, chipsec.hal.spd.dram_device_type_name(dram_type)) )
            self.logger.log( "    %s module type (byte 3)     : 0x%01X (%s)" % (_dimm_n, module_type, chipsec.hal.spd.module_type_name(module_type)) )

            self.logger.log( "[*] checking %s for row hammer mitigations.." % _dimm_n )

            ecc = self.check_ECC( _dimm )

            if (chipsec.hal.spd.DRAM_DEVICE_TYPE_DDR3 != dram_type):
                self.logger.log_good( '%s is not DDR3' % _dimm_n )
                continue

            ptrr_mac = self.spd.read_byte( _SPD_OFFSET_PTRR_TMAW_MAC, _dimm )
            self.logger.log( "    PTRR/TMAW/MAC (byte 0x%02X)      : 0x%02X" % (_SPD_OFFSET_PTRR_TMAW_MAC, ptrr_mac) )
            ptrr_ok = self.check_antiRH_pTRR( _dimm, ptrr_mac )
            mac_sts = self.check_antiRH_MAC( _dimm, ptrr_mac )

            if ptrr_ok:
                self.logger.log_good( "%s has row hammer mitigation (pTRR compliant)" % _dimm_n )
            elif MAC_PASS == mac_sts:
                self.logger.log_good( "%s has row hammer mitigation (supports Unlimited MAC)" % _dimm_n )
            elif MAC_WARN == mac_sts:
                if ModuleResult.FAILED != res: res = ModuleResult.WARNING
                self.logger.log_important( "%s supports MAC but needs to be tested" % _dimm_n )
            elif ecc:
                if ModuleResult.FAILED != res: res = ModuleResult.WARNING
                self.logger.log_important( "%s supports ECC but needs to be tested" % _dimm_n )
            else:
                res = ModuleResult.FAILED
                self.logger.log_bad( "%s does not seem to have any row hammer mitigation" % _dimm_n )

        self.logger.log( '' )
        if ModuleResult.PASSED == res:              
            self.logger.log_passed_check( "All DIMM modules appear to support row hammer mitigations" )
        elif ModuleResult.FAILED == res:
            self.logger.log_failed_check( "Some DIMM modules may be susceptible to row hammer" )
        elif ModuleResult.WARNING == res:
            self.logger.log_warn_check( "Some DIMM modules support MAC or ECC but need to be tested" )
        return res
        