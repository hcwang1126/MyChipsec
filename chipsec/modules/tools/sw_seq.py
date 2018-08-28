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
#Copyright (c) 2017, Intel Corporation
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

"""

SW Sequencing SPI Configuration checks

usage:
    ``chipsec_main -m tools.sw_seq [-l <log.txt>] [-v] [-i -a <ICHx>]``

    - ``-l`` : <log.txt> = log file to create
    - ``-v`` : Verbose mode
    - ``-a`` :<ICHx> ICH on platform = ICH7 | ICH8 | ICH9 | ICH10
    
Where:
    - ``[]``: optional line
    
Examples:
    chipsec_main.py -m tools.sw_seq -l log.txt
    chipsec_main.py -m tools.sw_seq -l log.txt -i -a ICH8

"""

from chipsec.module_common import *
import chipsec.chipset
import chipsec.logger

TAGS = [MTAG_HWCONFIG]

#OPCODE:OPTYPE
OPCODES    = { 0x03:0x2, 0x05:0x0, 0x02:0x3, 0xD8:0x3, 0x20:0x3, 0x9F:0x0, 0x0B:0x2, 0x04:0x1 }
BADCODES   = [ 0xC7, 0x01 ]
PREFIX     = [ 0x06 ]
SIZE_64K   = 0x3
SIZE_8K    = 0x2
SIZE_4K    = 0x1
SIZE_256B  = 0x0

ICH = ['ICH7','ICH8','ICH9','ICH10']
ich = ''
RES = []


class sw_seq(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
    
    def is_supported(self):
        return True

    def display_OPCODES(self, _opmenu_reg, _optype_reg):
        self.logger.log( '' )
        self.logger.log( '============================' )
        self.logger.log( 'SPI Opcode Info' )
        self.logger.log( '----------------------------' )
        self.logger.log( '' )
        self.logger.log( 'OPMENU: 0x%016X' % _opmenu_reg )
        self.logger.log( 'OPTYPE: 0x%08X' % _optype_reg )
        self.logger.log( '' )
        self.logger.log( '-------------------------' )
        self.logger.log( 'Opcode #  | Opcode | Type' )
        self.logger.log( '-------------------------' )
        for index in range(8):
            self.logger.log( ' Opcode%d  :  0x%02X  -  %u ' % (index,((_opmenu_reg >> index*8) & 0xFF), ((_optype_reg >> index*2) & 0x3)) )
        self.logger.log( '' )

    def find_max_size(self, _lvscc_reg, _uvscc_reg):
        max_size = SIZE_4K
        lsize = usize = 0
        
        if not (_lvscc_reg or _uvscc_reg):
            return max_size
        if _lvscc_reg:
            lvscc  = self.cs.read_register( _lvscc_reg )
            if self.cs.register_has_field( _lvscc_reg, 'EO_64k_VALID' ):
                if self.cs.get_register_field( _lvscc_reg, lvscc, 'EO_64k_VALID' ): 
                    lsize = SIZE_64K
            else:
                lsize = self.cs.get_register_field( _lvscc_reg, lvscc, 'LBES' )
        if _uvscc_reg:
            uvscc  = self.cs.read_register( _uvscc_reg )
            if self.cs.register_has_field( _uvscc_reg, 'EO_64k_VALID' ):
                if self.cs.get_register_field( _lvscc_reg, lvscc, 'EO_64k_VALID' ):
                    usize = SIZE_64K
            else:
                usize = self.cs.get_register_field( _uvscc_reg, uvscc, 'UBES' )
        if (lsize < usize): 
            max_size = usize
        elif (lsize > usize):
            max_size = lsize
        else: max_size = lsize
        
        return max_size

    def update_OPCODES(self, _lvscc_reg, _uvscc_reg, size):
        lop = uop = 0
        if _lvscc_reg:
            lvscc = self.cs.read_register( _lvscc_reg )
            if self.cs.register_has_field( _lvscc_reg, 'EO_64k_VALID' ):
                if self.cs.get_register_field( _lvscc_reg, lvscc, 'EO_64k_VALID' ):
                    lop = self.cs.get_register_field( _lvscc_reg, lvscc, 'EO_64k' )
        if _uvscc_reg:
            uvscc = self.cs.read_register( _uvscc_reg )
            if self.cs.register_has_field( _uvscc_reg, 'EO_64k_VALID' ):
                if self.cs.get_register_field( _uvscc_reg, uvscc, 'EO_64k_VALID' ):
                    uop = self.cs.get_register_field( _uvscc_reg, uvscc, 'EO_64k' )

        if size != SIZE_64K:
            BADCODES.append(0xD8)
            if lop: BADCODES.append(lop)
            if uop: BADCODES.append(uop)
        if size == SIZE_256B:
            BADCODES.append(0x20)

    def region_size(self, base, limit ):
        return ( (limit << 12) + 0xFFF ) - ( base << 12 ) + 1

    def check_module_size(self, size, base, limit):
        result = False
        _region_size = self.region_size( base, limit )
        if ( size == SIZE_64K ):
            if ( _region_size & 0xFFFF ):
                result = True
        elif ( size == SIZE_8K ):
            if ( _region_size & 0x1FFF ):
                result = True
        elif ( size == SIZE_4K ):
            if ( _region_size & 0xFFF ):
                result = True
        else:
            if ( _region_size & 0xFF ):
                result = True
        return result
        
    def check_module_alignment(self, size, base):
        if ( size == SIZE_64K ):
            if (( base << 12 ) & 0xFFFF):
                return True
        elif (size == SIZE_8K):
            if (( base << 12 ) & 0x1FFF):
                return True
        else:
            return False

    def is_FPR_enabled(self, pr_reg):
        for pr in range(len(pr_reg)):
            pr_val = self.cs.read_register( pr_reg[pr] )
            if self.cs.register_has_field( pr_reg[pr], 'RPE' ):
                if ( self.cs.get_register_field( pr_reg[pr], pr_val, 'RPE' ) or self.cs.get_register_field( pr_reg[pr], pr_val, 'WPE' ) ):
                    return True
            else:
                if ( self.cs.get_register_field( pr_reg[pr], pr_val, 'WPE' ) ):
                    return True
        return False
            
    def check_sw_seq(self):
        self.logger.start_test( 'SW Sequencing SPI Configuration checks' )
        
        opmenu_hi_reg = 'OPMENU_HI'
        opmenu_lo_reg = 'OPMENU_LO'
        optype_reg    = 'OPTYPE'
        preop_reg     = 'PREOP'
        lvscc_reg     = 'LVSCC'
        uvscc_reg     = 'UVSCC'
        PR_REG        = ['PR0', 'PR1', 'PR2', 'PR3', 'PR4']

        if ich == 'ICH7':
            opmenu_hi_reg = 'OPMENU_HI_7'
            opmenu_lo_reg = 'OPMENU_LO_7'
            optype_reg    = 'OPTYPE_7'
            preop_reg     = 'PREOP_7'
            lvscc_reg     = None
            uvscc_reg     = None
            PR_REG        = ['PR0_7', 'PR1_7', 'PR2_7']
        elif ich == 'ICH8':
            opmenu_hi_reg = 'OPMENU_HI_8'
            opmenu_lo_reg = 'OPMENU_LO_8'
            lvscc_reg     = 'LVSCC_8'
            uvscc_reg     = None
        
        opmenu_lo = self.cs.read_register( opmenu_lo_reg )
        opmenu_hi = self.cs.read_register( opmenu_hi_reg )
        opmenu = ( opmenu_hi << 32) + opmenu_lo
        OPMENU_OPS = []
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_lo_reg, opmenu_lo, 'OPCODE0' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_lo_reg, opmenu_lo, 'OPCODE1' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_lo_reg, opmenu_lo, 'OPCODE2' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_lo_reg, opmenu_lo, 'OPCODE3' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_hi_reg, opmenu_hi, 'OPCODE4' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_hi_reg, opmenu_hi, 'OPCODE5' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_hi_reg, opmenu_hi, 'OPCODE6' ) )
        OPMENU_OPS.append( self.cs.get_register_field( opmenu_hi_reg, opmenu_hi, 'OPCODE7' ) )

        optype = self.cs.read_register( optype_reg )
        OPTYPES = []
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE0' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE1' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE2' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE3' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE4' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE5' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE6' ) )
        OPTYPES.append( self.cs.get_register_field( optype_reg, optype, 'OPTYPE7' ) )
        
        preop  = self.cs.read_register( preop_reg )
        preop0 = self.cs.get_register_field( preop_reg, preop, 'PREOP0' )
        preop1 = self.cs.get_register_field( preop_reg, preop, 'PREOP1' )
        
        self.display_OPCODES( opmenu, optype )
        
        max_erase_size = self.find_max_size( lvscc_reg, uvscc_reg )
        if self.logger.VERBOSE:
            self.logger.log_important( 'Detected Max erase size: 0x%X' % max_erase_size )
            self.logger.log( '' )
        
        fpr_enabled = self.is_FPR_enabled( PR_REG )
        if fpr_enabled:
            self.update_OPCODES( lvscc_reg, uvscc_reg, max_erase_size )

        self.logger.log( '[*] Check for presence of certain OPCODEs..' )
        warning = False
        badopcode = False
        if opmenu:
            for op in range(len(OPMENU_OPS)):
                if OPMENU_OPS[op] in BADCODES:
                    badopcode = True
                    self.logger.log_important( 'Unsafe OPCODE : OPCODE'+str(op)+' = 0x%02X' % OPMENU_OPS[op] )
                elif OPMENU_OPS[op] not in OPCODES:
                    warning = True
                    self.logger.log_important( 'Unknown OPCODE: OPCODE'+str(op)+' = 0x%02X' % OPMENU_OPS[op] )
                    self.logger.log( '    INFORMATION: CHIPSEC does not understand this OPCODE. Developer must ensure its proper operation from security point-of-view.' )
            if badopcode:
                self.logger.log_failed( 'Unsafe OPCODEs found' )
                RES.append( 'FAILED' )
            elif warning:
                RES.append( 'WARNING' )
            else:
                self.logger.log_passed( 'No unsafe OPCODEs found' )
            if self.logger.VERBOSE:
                codes = ''.join('0x%02X ' % x for x in OPCODES.keys())
                self.logger.log( '    INFORMATION: Known OPCODEs  - '+codes )
                codes = ''.join('0x%02X ' % x for x in BADCODES)
                self.logger.log( '    INFORMATION: Unsafe OPCODEs - '+codes )
        else:
            self.logger.log_warning( 'OPMENU contains all 0x00 OPCODES' )
            self.logger.log( '    INFORMATION: This is an undefined configuration for SW Sequencing' )
            RES.append( 'WARNING' )


        self.logger.log( '' )
        self.logger.log( '[*] Check OPCODE Types..' )
        res = ModuleResult.PASSED
        if opmenu:
            for op in range(len(OPMENU_OPS)):
                if (OPCODES.get(OPMENU_OPS[op], OPTYPES[op]) != OPTYPES[op]):
                    msg = 'Incorrect OPTYPE detected for OPCODE'+str(op)+' (0x%02X): OPTYPE'+str(op)+' = 0x%X'
                    self.logger.log_important( msg % (OPMENU_OPS[op], OPTYPES[op]) )
                    res = ModuleResult.FAILED
            if ( res == ModuleResult.PASSED ):
                self.logger.log_passed( 'OPTYPES matched OPCODEs' )
            else:
                self.logger.log_failed( 'OPTYPES did not match OPCODEs' )
                RES.append( 'FAILED' )
        else:
            self.logger.log_important( 'OPMENU contains all 0x00 OPCODES.' )
            self.logger.log_skipped( 'OPTYPE tests skipped' )


        self.logger.log( '' )
        self.logger.log( '[*] Check PREFIX..' )
        if opmenu:
            res_fail = False
            if preop0 and (preop0 not in PREFIX):
                self.logger.log_important( 'PREFIX detected: PREFIX0 = 0x%02X' % preop0 )
                res_fail = True      
            if preop1 and (preop1 not in PREFIX):
                self.logger.log_important( 'PREFIX detected: PREFIX1 = 0x%02X' % preop1 )
                res_fail = True
            if res_fail:
                self.logger.log_failed( 'Found non-whitelisted PREFIX' )
                RES.append( 'FAILED' )
            elif not preop0 or not preop1:
                self.logger.log( '    PREFIX1 = 0x%02X' % preop1 )
                self.logger.log( '    PREFIX2 = 0x%02X' % preop2 )
                self.logger.log( '    INFORMATION: CHIPSEC does not understand this PREFIX 0x00. Developer must ensure its proper operation from security point-of-view.' )
                RES.append( 'WARNING' )
            else:
                self.logger.log_passed( 'Only whitelisted PREFIXs found' )
            if self.logger.VERBOSE:
                codes = ''.join('0x%02X ' % x for x in PREFIX)
                self.logger.log( '    INFORMATION: Known PREFIXs - '+codes )
        else:
            self.logger.log_important( 'OPMENU contains all 0x00 OPCODES.' )
            self.logger.log_skipped( 'PREFIX tests skipped' )


        self.logger.log( '' )
        self.logger.log( '[*] Check Region Base size and alignment..' )
        if fpr_enabled:
            res = ModuleResult.PASSED
            for pr in range(len(PR_REG)):
                pr_val = self.cs.read_register( PR_REG[pr] )
                if self.cs.register_has_field( PR_REG[pr], 'RPE' ):
                    pr_enabled = self.cs.get_register_field( PR_REG[pr], pr_val, 'RPE' ) or self.cs.get_register_field( PR_REG[pr], pr_val, 'WPE' )
                else:
                    pr_enabled = self.cs.get_register_field( PR_REG[pr], pr_val, 'WPE' )  
                if pr_enabled:
                    base  = self.cs.get_register_field( PR_REG[pr], pr_val, 'PRB' )
                    limit = self.cs.get_register_field( PR_REG[pr], pr_val, 'PRL' )
                    self.logger.log( '[*] PR'+str(pr)+' region enabled.' )
                    if self.check_module_size( max_erase_size, base, limit ):
                        self.logger.log_important( 'PR'+str(pr)+' region size not multiple of maximum write operation' )
                        self.logger.log( '    Reported region Base  : 0x%08X' % (base << 12) )
                        self.logger.log( '    Reported region Limit : 0x%08X' % ((limit << 12) + 0xFFF) )
                        self.logger.log( '    Region size           : 0x%08X' % self.region_size( base, limit ) )
                        res = ModuleResult.FAILED
                    if self.check_module_alignment( max_erase_size, base ):
                        self.logger.log_important( 'PR'+str(pr)+' base address not multiple of maximum write operation' )
                        self.logger.log( '    Reported region Base : 0x%08X' % (base << 12) )
                        res = ModuleResult.FAILED
                else: self.logger.log( '[*] PR'+str(pr)+' region disabled.  Skipping region.' )
            if res == ModuleResult.PASSED: 
                self.logger.log_passed( 'All PR region size and alignment tests passed' )
            else:
                self.logger.log_important( 'Detected Max erase size: 0x%X' % max_erase_size )
                self.logger.log_failed( 'One or more PR region size and alignment tests failed' )
                RES.append( 'FAILED' )
        else:
            self.logger.log_important( 'No PR regions enabled' )
            self.logger.log_skipped( 'Region size and alignment tests skipped' )


        if 'FAILED' in RES:
            return ModuleResult.FAILED
        elif 'WARNING' in RES:
            return ModuleResult.WARNING
        else:
            return ModuleResult.PASSED

        
    def run(self, module_argv):
    
        if len(module_argv) > 0:
            ich = module_argv[0].upper()
            if ich not in ICH:
                self.logger.log_important( 'Unknown mode: %s' % module_argv[0] )
                self.logger.log(__doc__)
                return ModuleResult.ERROR
            else:
                self.logger.log_important( 'Bypassing configuration files and using predefined ICH settings: %s' % ich )

        return self.check_sw_seq()
        