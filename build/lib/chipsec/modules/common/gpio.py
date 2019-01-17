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
Common checks for PCH GPIO protections
"""

from chipsec.module_common import *

TAGS = [MTAG_HWCONFIG]

class gpio (BaseModule):

    def __init__(self):
        BaseModule.__init__(self)

    def is_supported(self):
        return self.cs.is_core()

    def check_gpio_lock(self):
        self.logger.start_test( "GPIO Configuration Lock" )
        
        if not self.cs.is_register_defined( 'GC' ):
            self.logger.error( "Couldn't find definition of required registers (GC)" )
            return ModuleResult.ERROR

        gpiocontrol = self.cs.read_register( 'GC' )
        self.cs.print_register( 'GC', gpiocontrol)

        gle = self.cs.get_register_field( 'GC', gpiocontrol, 'GLE' )

        if gle == 1:
            self.logger.log_passed_check( "GPIO Configuration is locked" )
            return ModuleResult.PASSED
        else:
            self.logger.log_warn_check( "GPIO Configuration is not locked. It is strongly recommended to lock down GPIO configuration." )
            return ModuleResult.WARNING

    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self,module_argv ):
        return self.check_gpio_lock()
