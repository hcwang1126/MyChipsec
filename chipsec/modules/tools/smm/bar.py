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
This module monitors changes in [named] MMIO ranges done by SMI handlers

Usage:
    ``chipsec_main -m tools.smm.bar [-a <bar_names>,smi,<smi_code_start:smi_code_end>]`` 
  
- ``bar_names``: names of MMIO ranges separated with ``:`` (see ``chipsec_util mmio list``)
- ``smi``: generate SMI events (will only compare MMIO ranges without SMI event if omitted)
- ``smi_code_start:smi_code_end``: range of SMI codes (values written to IO port 0xB2)

Example:

>>> ``chipsec_main.py -m tools.smm.bar -a RCBA:MCHBAR,smi,0:0xFF``
"""


import time

from chipsec.module_common import *

from chipsec import defines
from chipsec import file
from chipsec.hal import pci
from chipsec.hal.interrupts import Interrupts

_FILL_VALUE_QWORD   = 0x0000000000000000
_FILL_VALUE_BYTE    = 0x00

SMI_CODE_LIMIT      = 0x0
SMI_DATA_LIMIT      = 0x1
SMI_FUNC_LIMIT      = 0x7

MAX_MMIO_BAR_SIZE   = 0x400000

NO_DIFFS            = 10

EXCLUDE_SMI         = []

REPEAT_SMI_ON_NEW_CHANGED_REGS = True

def DIFF( s, t, sz ):
    return [ pos for pos in range( sz ) if s[pos] != t[pos] ]

class bar(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self._interrupts  = Interrupts( self.cs )

        self.generate_smi = False
        self.bar_names    = []
        self.bars         = {}
        self.bars_diff    = {}

        # SMI code to be written to I/O port 0xB2
        self.smic_start   = 0x00
        self.smic_end     = SMI_CODE_LIMIT
        # SMI data to be written to I/O port 0xB3
        self.smid_start   = 0x00
        self.smid_end     = SMI_DATA_LIMIT
        # SMI handler "function" often supplied in ECX register
        self.smif_start   = 0x00
        self.smif_end     = SMI_FUNC_LIMIT
        # SMM communication buffer often supplied in EBX register
        self.comm         = 0x00
       

    def mmio_diff(self, bar_name, _regs=None):
        regs = _regs if _regs else self.bars[bar_name]
        n = len(regs)
        new_regs = self.cs.mmio.read_MMIO_BAR(bar_name)
        diff = DIFF(new_regs, regs, n)
        return (len(diff) > 0), diff

    def check_mmio_noSMI(self):
        for bar_name in self.bars.keys():
            self.logger.log("[*] '%s' normal difference (%d diffs):" % (bar_name,3*NO_DIFFS))
            self.logger.flush()
            diff = []
            for i in range(3*NO_DIFFS):
                if i > 0 and (i % NO_DIFFS) == 0:
                    self.logger.log("sleeping 1 sec..")
                    time.sleep(1)
                regs = self.cs.mmio.read_MMIO_BAR(bar_name)
                _,d = self.mmio_diff(bar_name, regs)
                self.logger.log("    diff%d: %d regs %s" % (i,len(d),d))
                diff = list(set(diff)|set(d))
            self.bars_diff[bar_name] = diff
            self.logger.log("    %d regs changed: %s" % (len(diff),sorted(diff)))

    def read_BARs(self):
        bars = {}
        for bar_name in self.bar_names:
            self.logger.log("    reading '%s'" % bar_name)
            bars[bar_name] = self.cs.mmio.read_MMIO_BAR(bar_name)
        return bars

    def check_BARs(self, bars, bars1):
        changed = False
        for bar_name in bars.keys():
            n = len(bars[bar_name])
            self.logger.log("    diffing '%s' (%d regs)" % (bar_name,n))
            diff = DIFF(bars1[bar_name], bars[bar_name], n)
            if len(diff) > 0:
                self.logger.log("    %d regs changed: %s" % (len(diff),sorted(diff)))
                normal_diff = self.bars_diff[bar_name]
                new = [r for r in diff if r not in normal_diff]
                self.logger.log("    new regs: %s" % sorted(new))
                if len(new) > 0: changed = True
            else:
                self.logger.log("    no changes")
        return changed

    def smi_mmio_check(self, thread_id):

        for smi_code in xrange(self.smic_start,self.smic_end+1):
            if smi_code in EXCLUDE_SMI: continue
            for smi_data in xrange(self.smid_start,self.smid_end+1):
                for ecx in xrange(self.smif_start,self.smif_end+1):
                    self.logger.log("[*] SMI# %02X: data %02X, func (ECX) 0x%08X" % (smi_code,smi_data,ecx) )
                    bars = self.read_BARs()
                    self.logger.log("    generating SMI" )
                    self.logger.flush()
                    self._interrupts.send_SW_SMI(thread_id, smi_code, smi_data, _FILL_VALUE_QWORD, self.comm, ecx, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD)
                    bars_after = self.read_BARs()
                    if self.check_BARs(bars, bars_after):
                        self.logger.log_important( "New changes found!" )
                        if REPEAT_SMI_ON_NEW_CHANGED_REGS:
                            self.logger.log("    repeating SMI")
                            self._interrupts.send_SW_SMI(thread_id, smi_code, smi_data, _FILL_VALUE_QWORD, self.comm, ecx, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD, _FILL_VALUE_QWORD)
                            bars1 = self.read_BARs()
                            self.check_BARs(bars_after,bars1)

        return ModuleResult.PASSED

    def run( self, module_argv ):
        self.logger.start_test( "Monitors changes in MMIO ranges done by SMI handlers" )

        if len(module_argv) > 0:
            self.bar_names = module_argv[0].split(':')

        if len(self.bar_names) == 0:
            self.logger.error("MMIO BAR names were not specified")
            self.logger.log("Example: chipsec_main.py -m tools.smm.bar -a RCBA:MCHBAR,smi,0:1")
            return ModuleResult.SKIPPED

        if len(module_argv) > 1 and module_argv[1] == 'smi':
            self.generate_smi = True
            if len(module_argv) > 2:
                smic_arr        = module_argv[2].split(':')
                self.smic_start = int(smic_arr[0],16)
                self.smic_end   = int(smic_arr[1],16)

        self.logger.log("[*] Configuration:")
        self.logger.log("    MMIO BAR names: %s" % self.bar_names)
        self.logger.log("    Generate SMI: %s" % ('True' if self.generate_smi else 'False'))
        self.logger.log("    SMI codes: [0x%02x:0x%02x]" % (self.smic_start,self.smic_end))

        # allocate a page or SMM communication buffer (often supplied in EBX register)
        (va, self.comm) = self.cs.mem.alloc_physical_mem( 0x1000, defines.BOUNDARY_4GB-1 )
        self.logger.log( "[*] SMM comm buffer (EBX)  : 0x%016X" % self.comm )
        self.cs.mem.write_physical_mem( self.comm, 0x1000, chr(0)*0x1000 )

        for bar_name in self.bar_names:
            if self.cs.mmio.is_MMIO_BAR_defined(bar_name):
                (base,size) = self.cs.mmio.get_MMIO_BAR_base_address(bar_name)
                self.logger.log("[*] MMIO BAR '%s': base = 0x%016X, size = 0x%08X" % (bar_name,base,size))
            else:
                self.bar_names.remove(bar_name)
                self.logger.warn("'%s' BAR is not defined. ignoring.." % bar_name)

        self.logger.log("[*] reading contents of MMIO BARs %s" % self.bar_names)
        self.bars = self.read_BARs()

        self.logger.flush()
        self.logger.log("[*] calculating normal MMIO BAR differences..")
        self.check_mmio_noSMI()

        self.logger.flush()
        if self.generate_smi:
            self.logger.log("[*] fuzzing SMIs..")
            self.res = self.smi_mmio_check(0)

        return self.res