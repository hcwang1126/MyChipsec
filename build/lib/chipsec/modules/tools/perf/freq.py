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
Dump Intel CPU frequency

"""

from chipsec.module_common import *

MAX_NON_TURBO_LIM_RATIO_BIT = 8
MAX_NON_TURBO_LIM_RATIO_SIZE = 8


# ############################################################
# SPECIFY PLATFORMS THIS MODULE IS APPLICABLE TO
# ############################################################
_MODULE_NAME = 'perf'

TAGS = [MTAG_HWCONFIG]


class freq(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return True

    def _get_register_field(self, reg_value, field_bit, size):

        field_mask  = (1 << size) - 1

        return (reg_value >> field_bit) & field_mask

    def dump_freq_settings( self ):
        try:
          reg_val = self.cs.read_register ( 'MSR_PLATFORM_INFO' )
          self.logger.log_information_check( "MSR_PLATFORM_INFO = 0x%016X" % reg_val)

          max_ratio = self._get_register_field (reg_val, MAX_NON_TURBO_LIM_RATIO_BIT, MAX_NON_TURBO_LIM_RATIO_SIZE)
          self.logger.log_information_check( "  MAX_NON_TURBO_RATIO[%d] = 0x%X, %d MHz" % (MAX_NON_TURBO_LIM_RATIO_BIT, max_ratio, max_ratio * 100))
        except:
          self.logger.log_warn_check( "MSR_PLATFORM_INFO is not support.." )

        
        return ModuleResult.PASSED

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        return self.dump_freq_settings()
