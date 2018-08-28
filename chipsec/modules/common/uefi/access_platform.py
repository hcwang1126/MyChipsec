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
#  John Loucaides
#



"""
UEFI Variables Access Control Test for Platform Specific Variables
Checks protection of UEFI variables of concern. This Proprietary test module checks against a list of variable names that have previously required protection on some platforms. When using this test, BIOS developers can add/substitute their own list of "variables of concern"
"""

from chipsec.module_common import *
from chipsec.file          import *
from chipsec.hal.uefi      import *
import chipsec.chipset

TAGS = [MTAG_BIOS,MTAG_SECUREBOOT]

# add/substitute a list of "variables of concern" here:
VARIABLES_TO_CHECK = (   "VendorKeys", "SignatureSupport", "SetupDefault", "Setup", "RevocationList", "PlatformInfo", "PlatformCpuInfo", "OsInicationsSupported", "MfgDefault", "MemoryTypeInformation", "MemoryConfig", "FirmwarePerformance", "dbtDefault", "db", "AuthVarKeyDatabase", "AcpiGlobalVariable", "PciBusSetup", "MeBiosExtensionSetup", "SmbiosType1SystemUuid", "AttemptUSBFirst", "ColdReset",  "PlatformFviSetupDataVar", "SaPegData", "SetupCpuFeatures", "TcgSetup", "FwEntry", "InitSetupVariable", "spddata", "1GPageTable", "CpuSmmMsrSaveStateEnable", "CpuSmmUseBlockIndication", "CpuSmmUseDelayIndication", "CpuSmmUseSmmEnableIndication", "DefSetup", "EfiNicIp4ConfigVariable", "FeData", "HiiDB", "IP6_CONFIG_IFR_NVDATA", "ISCSI_CONFIG_IFR_NVDATA", "KeyOrder", "PchInit", "SdrEraseTimeStamp", "SdrVersion", "SECUREBOOT_CONFIGURATION", "ServerMgmt", "TCG_CONFIGURATION", "TREE_CONFIGURATION", "UefiOptimizedBoot", "StdDefaults", "SmramCpuNvs" )


class access_platform(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._uefi = UEFI(self.cs)
        self.concern_vars = VARIABLES_TO_CHECK

    def is_supported(self):
        supported = self.cs.helper.EFI_supported()
        if not supported: self.logger.log_skipped_check( "OS does not support UEFI Runtime API" )
        return supported

    def diff_var( self, data1, data2):
        if data1 is None or data2 is None:
            return data1 != data2

        oldstr = ":".join("{:02x}".format(ord(c)) for c in data1)
        newstr = ":".join("{:02x}".format(ord(c)) for c in data2)

        if oldstr != newstr:
            print oldstr
            print newstr
            return True
        else:
            return False

    def can_modify(self, name, guid, data):
        ret    = False
        status = False

        origdata = data
        datalen = len(bytearray(data))
        baddata = 'Z'*datalen #0x5A is ASCII 'Z'
        if baddata == origdata: baddata = 'A'*datalen #in case we failed to restore previously

        status = self._uefi.set_EFI_variable(name, guid, baddata)
        #if not status: self.logger.log_good('Writing EFI variable %s did not succeed.' % name)
        newdata  = self._uefi.get_EFI_variable(name, guid)
        if self.diff_var(newdata, origdata):
            ret = True
            self.logger.log_bad('EFI variable %s has been corrupted. Recovering..' % name)
            self._uefi.set_EFI_variable(name, guid, origdata)
            if self.diff_var(self._uefi.get_EFI_variable(name, guid), origdata):
                nameguid = name+' {'+guid+'}'
                self.logger.log_error('RECOVERY FAILED. Variable %s remains corrupted. Original data value: %s' % (nameguid, origdata))
        return ret

    def modify_variables( self, variables ):
        modified_concern = []
        res = False
        self.logger.log('[*] Attempting to modify variables of concern ..')
        for (name, guid, data) in variables:
            if self.can_modify( name, guid, data ):
                modified_concern.append( name )
                self.logger.log_bad( '  %-26s: HAS BEEN MODIFIED' % name )
            else:
                self.logger.log_good( '  %-26s: could not modify' % name )
        if len(modified_concern) > 0:
            res = True
            self.logger.log_bad('The following variables of concern can be modified:')
            for name in modified_concern: self.logger.log('    %s' % name)
        return res


    def check_vars(self, do_modify):
        res = ModuleResult.PASSED
        error = False
        vars = self._uefi.list_EFI_variables()
        if vars is None:
            self.logger.log_error_check( 'Could not enumerate UEFI Variables from runtime (Legacy OS?)' )
            self.logger.log_important( "Note that UEFI variables may still exist, OS just did not expose runtime UEFI Variable API to read them.\nYou can extract variables directly from ROM file via 'chipsec_util.py uefi nvram bios.bin' command and verify their attributes manually." )
            return ModuleResult.ERROR

        vars_to_verify = []

        self.logger.log('')
        self.logger.log('[*] Enumerating all accessible EFI variables ..')
        self.logger.log('')
        self.logger.log( " Variable                       | Storage      | Access         | Protection       | Sensitive | Concern?" )
        self.logger.log( "---------------------------------------------------------------------------------------------------------" )

        for name in vars.keys():

            if name is None or vars[name] is None: pass
            if len(vars[name]) > 1: self.logger.log_important( 'Found two instances of the variable %s.' % name )

            is_concern_var = (name in self.concern_vars)
            str_concern_var = 'yes' if is_concern_var else ''

            for (off, buf, hdr, data, guid, attrs) in vars[name]:
                is_auth = IS_EFI_VARIABLE_AUTHENTICATED(attrs)
                is_bs   = IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_BOOTSERVICE_ACCESS )
                is_rt   = IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_RUNTIME_ACCESS )
                is_nv   = IS_VARIABLE_ATTRIBUTE( attrs, EFI_VARIABLE_NON_VOLATILE )

                str_nv = 'non-volatile' if is_nv else 'volatile'
                str_access = 'runtime' if is_rt else ''
                if is_bs: str_access += ' & boot'
                str_auth = ('auth (%s)' % get_auth_attr_string(attrs)) if is_auth else ''

                is_concern = (is_concern_var and is_nv and not is_auth)
                if is_concern:
                    vars_to_verify.append( (name,guid,data) )
                str_is_concern = 'YES' if is_concern else ''

                self.logger.log( " %-30s | %-12s | %-14s | %-16s | %-9s | %s" % (name, str_nv, str_access, str_auth, str_concern_var, str_is_concern) )

        if len(vars_to_verify) > 0:
            self.logger.log('')
            res = ModuleResult.FAILED if (do_modify and self.modify_variables( vars_to_verify )) else ModuleResult.WARNING

        self.logger.log('')
        if error: return ModuleResult.ERROR
        if   ModuleResult.PASSED  == res: self.logger.log_passed_check( 'All checked EFI variables are protected' )
        elif ModuleResult.WARNING == res: self.logger.log_warn_check  ( 'Not all checked EFI variables are protected. Evaluate accessible variables manually.' )
        elif ModuleResult.FAILED  == res: self.logger.log_failed_check('Checked EFI variables were modified.')
        return res


    def run( self,  module_argv ):
        self.logger.start_test( "Access Control of EFI Variables" )
        do_modify = (len(module_argv) > 0 and module_argv[0] == OPT_MODIFY)
        return self.check_vars( do_modify )
