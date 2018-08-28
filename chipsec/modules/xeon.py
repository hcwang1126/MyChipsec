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
#  Aaron Frinzell
#



""" Haswell Server and Broadwell Server (Grantley) Secure Configuration Tests

These tests are derived from the BIOS Writers Guide for this platform.
"""

from chipsec.module_common import *
import chipsec.chipset
import chipsec.logger
from chipsec.hal import mmio

_MODULE_NAME = 'xeon'


TAGS = [MTAG_SMM,MTAG_HWCONFIG]

# Modify MICROCODE_REV 
MICROCODE_REV = 0x0000

_64k_ALIGNED = 0xFFFF
RCBA_LIMIT  = 0x4000


class xeon(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.mmio = mmio.MMIO(self.cs)

    def is_supported(self):
        return self.cs.get_chipset_id() in [chipsec.chipset.CHIPSET_ID_HSX, chipsec.chipset.CHIPSET_ID_BDX]

    def check_xeon(self):
        self.logger.start_test( "Secured configuration for Xeon processor" )

        xeon_ok = True

        vtd = self.cs.read_register( 'VTBAR' )
        if (self.cs.get_register_field( 'VTBAR', vtd, 'Enable' )):
            self.logger.log('')
            if self.logger.VERBOSE: self.logger.log_important('VT-d is enabled.')
            self.logger.log( "[*] Verifying VTGENCTRL.lockvtd bit is set.." )
            self.logger.log_important( "Only applies if VT-d is enabled. " )
            vtgen = self.cs.read_register( 'VTGENCTRL' )
            self.logger.log( "[*]   VTGENCTRL       : 0x%08X" % vtgen )
            ok = True
            lockvtd = (self.cs.get_register_field( 'VTGENCTRL', vtgen, 'lockvtd' ))
            ok = lockvtd
            self.logger.log( "[*]     lockvtd       : %u" % lockvtd )
            xeon_ok = xeon_ok and ok
            if ok: self.logger.log_passed_check( "VTBAR[0] is read-only (RO)" )
            else: self.logger.log_failed_check( "VTBAR[0] is writeable (RW-LB)" )
        else:
            self.logger.log('')
            if self.logger.VERBOSE: self.logger.log_skipped_check('VT-d not enabled. Bypassing VTGENCTRL check.') 

        self.logger.log('')
        self.logger.log( "[*] Verifying MISCCTRLSTS_0.inbound_configuration_enable bit is not set on every PCI port.." )
        miscctrlsts000 = self.cs.read_register( 'MISCCTRLSTS0_0.0.0' )
        miscctrlsts010 = self.cs.read_register( 'MISCCTRLSTS0_0.1.0' )
        miscctrlsts011 = self.cs.read_register( 'MISCCTRLSTS0_0.1.1' )
        miscctrlsts020 = self.cs.read_register( 'MISCCTRLSTS0_0.2.0' )
        miscctrlsts021 = self.cs.read_register( 'MISCCTRLSTS0_0.2.1' )
        miscctrlsts022 = self.cs.read_register( 'MISCCTRLSTS0_0.2.2' )
        miscctrlsts023 = self.cs.read_register( 'MISCCTRLSTS0_0.2.3' )
        miscctrlsts030 = self.cs.read_register( 'MISCCTRLSTS0_0.3.0' )
        miscctrlsts031 = self.cs.read_register( 'MISCCTRLSTS0_0.3.1' )
        miscctrlsts032 = self.cs.read_register( 'MISCCTRLSTS0_0.3.2' )
        miscctrlsts033 = self.cs.read_register( 'MISCCTRLSTS0_0.3.3' )
        ok = True
        self.logger.log( "[*] MISCCTRLSTS0 [0.0.0]           : 0x%08X" % miscctrlsts000 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.0.0' ):
            inbound000 = self.cs.get_register_field( 'MISCCTRLSTS0_0.0.0', miscctrlsts000, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound000 )
            if inbound000: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.1.0]           : 0x%08X" % miscctrlsts010 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.1.0' ):
            inbound010 = self.cs.get_register_field( 'MISCCTRLSTS0_0.1.0', miscctrlsts010, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound010 )
            if inbound010: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.1.1]           : 0x%08X" % miscctrlsts011 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.1.1' ):
            inbound011 = self.cs.get_register_field( 'MISCCTRLSTS0_0.1.1', miscctrlsts011, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound011 )
            if inbound011: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.2.0]           : 0x%08X" % miscctrlsts020 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.2.0' ):
            inbound020 = self.cs.get_register_field( 'MISCCTRLSTS0_0.2.0', miscctrlsts020, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound020 )
            if inbound020: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.2.1]           : 0x%08X" % miscctrlsts021 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.2.1' ):
            inbound021 = self.cs.get_register_field( 'MISCCTRLSTS0_0.2.1', miscctrlsts021, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound021 )
            if inbound021: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.2.2]           : 0x%08X" % miscctrlsts022 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.2.2' ):
            inbound022 = self.cs.get_register_field( 'MISCCTRLSTS0_0.2.2', miscctrlsts022, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound022 )
            if inbound022: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.2.3]           : 0x%08X" % miscctrlsts023 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.2.3' ):
            inbound023 = self.cs.get_register_field( 'MISCCTRLSTS0_0.2.3', miscctrlsts023, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound023 )
            if inbound023: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.3.0]           : 0x%08X" % miscctrlsts030 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.3.0' ):
            inbound030 = self.cs.get_register_field( 'MISCCTRLSTS0_0.3.0', miscctrlsts030, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound030 )
            if inbound030: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.3.1]           : 0x%08X" % miscctrlsts031 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.3.1' ):
            inbound031 = self.cs.get_register_field( 'MISCCTRLSTS0_0.3.1', miscctrlsts031, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound031 )
            if inbound031: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.3.2]           : 0x%08X" % miscctrlsts032 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.3.2' ):
            inbound032 = self.cs.get_register_field( 'MISCCTRLSTS0_0.3.2', miscctrlsts032, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound032 )
            if inbound032: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] MISCCTRLSTS0 [0.3.3]           : 0x%08X" % miscctrlsts033 )
        if self.cs.is_device_enabled( '_MISCCTRLSTS0_0.3.3' ):
            inbound033 = self.cs.get_register_field( 'MISCCTRLSTS0_0.3.3', miscctrlsts033, 'inbound_configuration_enable' )
            self.logger.log( "[*]   inbound_configuration_enable : %u" % inbound033 )
            if inbound033: ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Inbound Configuration Requests are disabled on all PCI ports." )
        else: self.logger.log_failed_check( "Inbound Configuration Requests are not disabled on all PCI ports." )


        self.logger.log('')
        self.logger.log( "[*] checking ERRINJCON.errinjdis bit is set correctly.." )
        errinj = self.cs.read_register( 'ERRINJCON' )
        self.logger.log( "[*]   ERRINJCON       : 0x%016X" % errinj )
        errinjdis = (self.cs.get_register_field( 'ERRINJCON', errinj, 'errinjdis' ))
        self.logger.log( "[*]     errinjdis     : %u" % errinjdis )
        ok = errinjdis
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "PCIe error injection bits are disabled" )
        else:  self.logger.log_failed_check( "PCIe error injection bits are not disabled" )


        self.logger.log('')
        self.logger.log( "[*] checking SPD Configuration.." )
        smbcntl_0_19  = self.cs.read_register( 'SMBCNTL_0_19' )
        smbcntl_0_22  = self.cs.read_register( 'SMBCNTL_0_22' )
        smbcntl_1_19  = self.cs.read_register( 'SMBCNTL_1_19' )
        smbcntl_1_22  = self.cs.read_register( 'SMBCNTL_1_22' )
        ok = True
        self.logger.log( "[*] SMBCNTL_0_19     : 0x%08X" % smbcntl_0_19 )
        if self.cs.is_device_enabled( '_SMBCNTL_0_19' ):
            smb_dis_wrt_0_19 = self.cs.get_register_field( 'SMBCNTL_0_19', smbcntl_0_19, 'smb_dis_wrt' )
            self.logger.log( "[*]   smb_dis_wrt    : %u" % smb_dis_wrt_0_19 )
            if smb_dis_wrt_0_19: self.logger.log_passed_check( "SMBCNTL_0_19 SMBUS write disabled" )
            else: 
                self.logger.log_failed_check( "SMBCNTL_0_19 SMBUS write not disabled" )
                ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] SMBCNTL_0_22     : 0x%08X" % smbcntl_0_22 )
        if self.cs.is_device_enabled( '_SMBCNTL_0_22' ):
            smb_dis_wrt_0_22 = self.cs.get_register_field( 'SMBCNTL_0_22', smbcntl_0_22, 'smb_dis_wrt' )
            self.logger.log( "[*]   smb_dis_wrt    : %u" % smb_dis_wrt_0_22 )
            if smb_dis_wrt_0_22: self.logger.log_passed_check( "SMBCNTL_0_22 SMBUS write disabled" )
            else:
                self.logger.log_failed_check( "SMBCNTL_0_22 SMBUS write not disabled" )
                ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] SMBCNTL_1_19     : 0x%08X" % smbcntl_1_19 )
        if self.cs.is_device_enabled( '_SMBCNTL_1_19' ):
            smb_dis_wrt_1_19 = self.cs.get_register_field( 'SMBCNTL_1_19', smbcntl_1_19, 'smb_dis_wrt' )
            self.logger.log( "[*]   smb_dis_wrt    : %u" % smb_dis_wrt_1_19 )
            if smb_dis_wrt_1_19: self.logger.log_passed_check( "SMBCNTL_1_19 SMBUS write disabled" )
            else:  
                self.logger.log_failed_check( "SMBCNTL_1_19 SMBUS write not disabled" )
                ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log( "[*] SMBCNTL_1_22     : 0x%08X" % smbcntl_1_22 )
        if self.cs.is_device_enabled( '_SMBCNTL_1_22' ):
            smb_dis_wrt_1_22 = self.cs.get_register_field( 'SMBCNTL_1_22', smbcntl_1_22, 'smb_dis_wrt' )
            self.logger.log( "[*]   smb_dis_wrt    : %u" % smb_dis_wrt_1_22 )
            if smb_dis_wrt_1_22: self.logger.log_passed_check( "SMBCNTL_1_22 SMBUS write disabled" )
            else:
                self.logger.log_failed_check( "SMBCNTL_1_22 SMBUS write not disabled" )
                ok = False
        else: self.logger.log_skipped_check( "Device may be disabled. Bypassing check." )

        self.logger.log('')  
        self.logger.log( "[*] checking if GENPROTRANGE_BASE/LIMIT pair overlaps with RCBA.." )
        genprot0_base       = self.cs.read_register( 'GENPROTRANGE0_BASE' )
        genprot0_base_addr  = self.cs.get_register_field( 'GENPROTRANGE0_BASE', genprot0_base, 'base_address', True )
        genprot0_limit      = self.cs.read_register( 'GENPROTRANGE0_LIMIT' )
        genprot0_limit_addr = self.cs.get_register_field( 'GENPROTRANGE0_LIMIT', genprot0_limit, 'limit_address', True ) + _64k_ALIGNED
        genprot1_base       = self.cs.read_register( 'GENPROTRANGE1_BASE' )
        genprot1_base_addr  = self.cs.get_register_field( 'GENPROTRANGE1_BASE', genprot1_base, 'base_address', True )
        genprot1_limit      = self.cs.read_register( 'GENPROTRANGE1_LIMIT' )
        genprot1_limit_addr = self.cs.get_register_field( 'GENPROTRANGE1_LIMIT', genprot1_limit, 'limit_address', True ) + _64k_ALIGNED
        genprot2_base       = self.cs.read_register( 'GENPROTRANGE2_BASE' )
        genprot2_base_addr  = self.cs.get_register_field( 'GENPROTRANGE2_BASE', genprot2_base, 'base_address', True )
        genprot2_limit      = self.cs.read_register( 'GENPROTRANGE2_LIMIT' )
        genprot2_limit_addr = self.cs.get_register_field( 'GENPROTRANGE2_LIMIT', genprot2_limit, 'limit_address', True ) + _64k_ALIGNED
        (rcba, rcba_size) = self.mmio.get_MMIO_BAR_base_address( 'RCBA' )
        rcba_limit  = rcba + RCBA_LIMIT - 1
        self.logger.log( "[*]   GENPROTRANGE0 [BASE-LIMIT] : 0x%016X-0x%016X" % (genprot0_base_addr, genprot0_limit_addr) )
        self.logger.log( "[*]   GENPROTRANGE1 [BASE-LIMIT] : 0x%016X-0x%016X" % (genprot1_base_addr, genprot1_limit_addr) )
        self.logger.log( "[*]   GENPROTRANGE2 [BASE-LIMIT] : 0x%016X-0x%016X" % (genprot2_base_addr, genprot2_limit_addr) )
        self.logger.log( "[*]   RCBA                       : 0x%016X-0x%016X" % (rcba, rcba_limit) )
        ok = False
        if (genprot0_base_addr <= rcba) and (genprot0_limit_addr >= rcba_limit): ok = True
        if (genprot1_base_addr <= rcba) and (genprot1_limit_addr >= rcba_limit): ok = True
        if (genprot2_base_addr <= rcba) and (genprot2_limit_addr >= rcba_limit): ok = True
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "A GENPROTRANGE_BASE/LIMIT does contain RCBA" )
        else:  self.logger.log_failed_check( "A GENPROTRANGE_BASE/LIMIT does not completely contain RCBA" )


        self.logger.log('')         
        self.logger.log( "[*] checking SMI from PCH sources are globally enabled.." )
        smi_en     = self.cs.read_register( 'SMI_EN' )
        self.logger.log( "[*]   SMI_EN               : 0x%08X" % smi_en )
        smi_en_gbl   = self.cs.get_register_field( 'SMI_EN', smi_en, 'GBL_SMI_EN' )
        self.logger.log( "[*]     GBL_SMI_EN         : %u" % smi_en_gbl )       
        smi_en_gpio  = self.cs.get_register_field( 'SMI_EN', smi_en, 'GPIO_UNLOCK_SMI_EN' )
        self.logger.log( "[*]     GPIO_UNLOCK_SMI_EN : %u" % smi_en_gpio )
        smi_en_tco   = self.cs.get_register_field( 'SMI_EN', smi_en, 'TCO_EN' )
        self.logger.log( "[*]     TCO_EN             : %u" % smi_en_tco )
        ok = (0 != smi_en_gbl)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "SMI from PCH sources is globally enabled" )
        else:  self.logger.log_failed_check( "SMI from PCH sources is not globally enabled" )
        ok = (0 != smi_en_gpio)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "SMI Config of GPIOs are locked down" )
        else:  self.logger.log_warn_check( "SMI Config of GPIOs are not locked down" )
        ok = (0 != smi_en_tco)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "TCO logic to generate SMI is enabled" )
        else:  self.logger.log_failed_check( "TCO logic to generate SMI is not enabled" )


        self.logger.log('')  
        self.logger.log( "[*] checking General PM Configuration 1 Register.." )
        gen_pmcon  = self.cs.read_register( 'GEN_PMCON_1' )
        self.logger.log( "[*]   GEN_PMCON_1        : 0x%08X" % gen_pmcon )
        smi_lock     = self.cs.get_register_field( 'GEN_PMCON_1', gen_pmcon, 'SMI_LOCK' )
        self.logger.log( "[*]     SMI_LOCK         : %u" % smi_lock )
        ok = (0 != smi_lock)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Writes to GBL_SMI_EN are disabled" )
        else:  self.logger.log_failed_check( "Writes to GBL_SMI_EN are not disabled" ) 


        self.logger.log('')  
        self.logger.log( "[*] checking SMI_EN[TCO_EN] locked.." )
        tco1_cnt   = self.cs.read_register( 'TCO1_CNT' )
        self.logger.log( "[*]   TCO1_CNT           : 0x%08X" % tco1_cnt )
        tco_lock     = self.cs.get_register_field( 'TCO1_CNT', tco1_cnt, 'TCO_LOCK' )
        self.logger.log( "[*]     TCO_LOCK         : %u" % tco_lock )
        ok = (0 != tco_lock)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Writes to TCO_EN are disabled" )
        else:  self.logger.log_failed_check( "Writes to TCO_EN are not disabled" )        

        self.logger.log('') 
        self.logger.log( "[*] checking TC Lock-Down is set (TCLOCKDN).." )
        tclockdn       = self.cs.read_register( 'TCLOCKDN' )
        self.logger.log( "[*]   TCLOCKDN           : 0x%08X" % tclockdn )
        TC_LockDown    = self.cs.get_register_field( 'TCLOCKDN', tclockdn, 'TC_LockDown' )
        self.logger.log( "[*]     TC_LockDown      : %u" % TC_LockDown )
        ok = (1 == TC_LockDown)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Virtual Resource control registers [V0CTL, V1CTL] are locked" )
        else:  self.logger.log_failed_check( "Virtual Resource control registers [V0CTL, V1CTL] are not locked" )


        self.logger.log('')
        self.logger.log( "[*] checking Soft Reset Data Lock Register (SRDL).." )
        srdl           = self.cs.read_register( 'SRDL' )
        self.logger.log( "[*]   SRDL               : 0x%08X" % srdl )
        ssl            = self.cs.get_register_field( 'SRDL', srdl, 'SSL' )
        self.logger.log( "[*]     SSL              : %u" % ssl )
        ok = (1 == ssl)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "SRDL, SRDC, & SRD registers are locked" )
        else:  self.logger.log_failed_check( "SRDL, SRDC, & SRD registers are not locked" )


        self.logger.log('')
        self.logger.log( "[*] checking ACPI Base Address Register is locked at offset 0x40.." )
        gen_pmcon_lock = self.cs.read_register( 'GEN_PMCON_LOCK' )
        self.logger.log( "[*]   GEN_PMCON_LOCK     : 0x%02X" % gen_pmcon_lock )
        acpi_base_lock = self.cs.get_register_field( 'GEN_PMCON_LOCK', gen_pmcon_lock, 'ACPI_BASE_LOCK' )
        self.logger.log( "[*]     ACPI_BASE_LOCK   : %u" % acpi_base_lock )
        ok = (1 == acpi_base_lock)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "ACPI Base Address Register (ABASE) is locked down" )
        else:  self.logger.log_failed_check( "ACPI Base Address Register (ABASE) is not locked down" )


        self.logger.log('')
        self.logger.log( "[*] checking RCBA is locked.." )
        ulkmc          = self.cs.read_register( 'ULKMC' )
        self.logger.log( "[*]   ULKMC              : 0x%08X" % ulkmc )
        rcbalk         = self.cs.get_register_field( 'ULKMC', ulkmc, 'RCBALK' )
        self.logger.log( "[*]     RCBALK           : %u" % rcbalk )
        ok = (1 == rcbalk)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "RCBA is locked" )
        else:  self.logger.log_failed_check( "RCBA is not locked" )        


        self.logger.log('')
        self.logger.log( "[*] checking Personality Lock Key Control Register Capability Lock.." )
        plkctl         = self.cs.read_register( 'PLKCTL' )
        self.logger.log( "[*]   PLKCTL             : 0x%04X" % plkctl )
        plkctl_cl      = self.cs.get_register_field( 'PLKCTL', plkctl, 'CL' )
        self.logger.log( "[*]     CL               : %u" % plkctl_cl )
        ok = (1 == plkctl_cl)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Capability Lock set" )
        else:  self.logger.log_failed_check( "Capability Lock is not set" )          


        self.logger.log('')
        self.logger.log( "[*] checking MS Unit Device Function Hide lock.." )
        msdavfunchide  = self.cs.read_register( 'MSDEVFUNCHIDE' )
        self.logger.log( "[*]   MSDEVFUNCHIDE      : 0x%08X" % msdavfunchide )
        hide_lock      = self.cs.get_register_field( 'MSDEVFUNCHIDE', msdavfunchide, 'LOCK' )
        self.logger.log( "[*]     Lock             : %u" % hide_lock )
        ok = (1 == hide_lock)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Device Function Hide Register is locked" )
        else:  self.logger.log_failed_check( "Device Function Hide Register is not locked" )

        
        self.logger.log('')
        self.logger.log( "[*] checking Core-Thread lock-down.." )
        desired_cores = self.cs.read_register( 'CSR_DESIRED_CORES' )
        self.logger.log( "[*]   CSR_DESIRED_CORES  : 0x%08X" % desired_cores )
        if self.cs.is_device_enabled( '_CSR_DESIRED_CORES' ):
            desired_cores_lck = self.cs.get_register_field( 'CSR_DESIRED_CORES', desired_cores, 'LOCK' )
            self.logger.log( "[*]     Lock             : %u" % desired_cores_lck )
            ok = (1 == desired_cores_lck)
            xeon_ok = xeon_ok and ok
            if ok: self.logger.log_passed_check( "Number of cores/threads BIOS wants to exist is locked down" )
            else:  self.logger.log_failed_check( "Number of cores/threads BIOS wants to exist is not locked down" )
        else: self.logger.log_skipped( "Device may be disabled. Bypassing check." )


        self.logger.log('')
        self.logger.log( "[*] checking C-State Configuration Register configuration.." )
        cst_config = self.cs.read_register( 'MSR_PKG_CST_CONFIG_CONTROL' )
        self.logger.log( "[*]   MSR_PKG_CST_CONFIG_CONTROL : 0x%016X" % cst_config )
        cst_config_lck = self.cs.get_register_field( 'MSR_PKG_CST_CONFIG_CONTROL', cst_config, 'LOCK' )
        self.logger.log( "[*]     Lock                     : %u" % cst_config_lck )
        ok = (1 == cst_config_lck)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "C-State Configuration Control Register is locked" )
        else:  self.logger.log_failed_check( "C-State Configuration Control Register is not locked" ) #Warning        


        self.logger.log('')
        self.logger.log( "[*] checking Silicon debug feature settings.." )
        debug_interface = self.cs.read_register( 'IA32_DEBUG_INTERFACE' )
        self.logger.log( "[*]   IA32_DEBUG_INTERFACE : 0x%08X" % debug_interface )
        debug_enable = self.cs.get_register_field( 'IA32_DEBUG_INTERFACE', debug_interface, 'ENABLE' )
        debug_lock   = self.cs.get_register_field( 'IA32_DEBUG_INTERFACE', debug_interface, 'LOCK' )
        self.logger.log( "[*]     Enable             : %u" % debug_enable )
        self.logger.log( "[*]     Lock               : %u" % debug_lock )
        ok = (0 == debug_enable)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Silicon debug features are disabled" )
        else:  self.logger.log_failed_check( "Silicon debug features are not disabled" )
        ok = debug_lock
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Silicon Debug Feature Control register is locked" )
        else:  self.logger.log_failed_check( "Silicon Debug Feature Control register is not locked" )


        self.logger.log('')
        self.logger.log( "[*] checking Intel TXT DMA protected range settings.." )
        debug_interface = self.cs.read_register( 'LTDPR' )
        self.logger.log( "[*]   LTDPR              : 0x%08X" % debug_interface )
        ltdpr_lck = self.cs.get_register_field( 'LTDPR', debug_interface, 'lock' )
        self.logger.log( "[*]     Lock             : %u" % ltdpr_lck )
        ok = ltdpr_lck
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "Intel TXT DMA Protected Range register is locked" )
        else:  self.logger.log_failed_check( "Intel TXT DMA Protected Range register is not locked" )


        self.logger.log('')
        self.logger.log( "[*] checking DMI Root Complex BAR settings.." )
        dmircbar = self.cs.read_register( 'DMIRCBAR' )
        self.logger.log( "[*]   DMIRCBAR           : 0x%08X" % dmircbar )
        dmircbar_en = self.cs.get_register_field( 'DMIRCBAR', dmircbar, 'dmircbaren' )
        self.logger.log( "[*]     dmircbaren       : %u" % dmircbar_en )
        ok = (0 == dmircbar_en)
        xeon_ok = xeon_ok and ok
        if ok: self.logger.log_passed_check( "DMIRCBAR is disabled" )
        else:  self.logger.log_failed_check( "DMIRCBAR is not disabled" )


        return xeon_ok

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.check_xeon()
