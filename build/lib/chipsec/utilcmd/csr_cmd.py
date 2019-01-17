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


from chipsec.logger import  logger
from chipsec.hal.csr import Csr
from chipsec.command import BaseCommand


# ###################################################################
#
# CPU CSR access utility
#
# ###################################################################
class CSRCommand(BaseCommand):
    """
    >>> chipsec_util csr <csr> [value]

    Examples:

    >>> chipsec_util csr 0x1050
    >>> chipsec_util csr 0x1050 0xE0000001
    """

    def requires_driver(self):
        # No driver required when printing the util documentation
        if len(self.argv) < 2:
            return False
        return True

    def run(self):

        if 2 > len(self.argv):
            print CSRCommand.__doc__
            return

        _csr = Csr( self.cs.helper )
        
        try:
            csr_address = int(self.argv[2],16)
        except:
            print CSRCommand.__doc__
            return

        if 4 == len(self.argv):
            value = int(self.argv[3], 16)
            old_value = _csr.write_csr( csr_address, value )
            self.logger.log( "[CHIPSEC] writing Uncore CSR 0x%08X <- 0x%08X (old value = 0x%08X)" % (csr_address, value, old_value) )
        else:
            csr_value = _csr.read_csr( csr_address )
            self.logger.log( "[CHIPSEC] reading Uncore CSR 0x%08X = 0x%08X" % (csr_address, csr_value) )

commands = { 'csr': CSRCommand }
