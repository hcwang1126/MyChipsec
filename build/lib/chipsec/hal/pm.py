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
HAL component encapsulating platform/SoC power management functionality

usage:
    >>> pm_status()
    >>> sleep_state( sleep_type )
    >>> platform_reset( reset_type )
"""

__version__ = '1.0'

import struct
import sys
import time

from chipsec.logger import *
import chipsec.chipset

SLEEP_TYPE_S0 = 0
SLEEP_TYPE_S1 = 1
SLEEP_TYPE_S3 = 3
SLEEP_TYPE_S4 = 4
SLEEP_TYPE_S5 = 5

RESET_TYPE_INIT = 0x4
RESET_TYPE_WARM = 0x6
RESET_TYPE_COLD = 0xE

class PM:
    def __init__( self, cs ):
        self.cs = cs

    def pm_status( self ):
        pm1_sts = self.cs.read_register( 'PM1_STS' )
        self.cs.print_register( 'PM1_STS', pm1_sts )
        #pm1_cnt = self.cs.read_register( 'PM1_CNT' )
        #self.cs.print_register( 'PM1_CNT', pm1_cnt )
        slp_typ = self.cs.read_register_field( 'PM1_CNT', 'SLP_TYP' )
        logger().log( '[pm] Sleep Type: 0x%X' % slp_typ )
        

    def sleep_state( self, sleep_type ):
        self.cs.write_register_field( 'PM1_CNT', 'SLP_TYP', sleep_type )
        self.cs.write_register_field( 'PM1_CNT', 'SLP_EN', 1 )
        time.sleep(1)

    def goto_s3( self ):
        return self.sleep_state( SLEEP_TYPE_S3 )
    def goto_s4( self ):
        return self.sleep_state( SLEEP_TYPE_S4 )
    def goto_s5( self ):
        return self.sleep_state( SLEEP_TYPE_S5 )

    def platform_reset( self, reset_type ):
        self.cs.write_register( 'RST_CNT', reset_type )
