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
#  Andrew Furtak
#  Yuriy Bulygin
#



import os
import sys
import time

from chipsec.command import BaseCommand
from chipsec.file import *
from chipsec.hal.bitlocker import *

# ###################################################################
#
# Microsoft Windows Bitlocker utility
#
# ###################################################################

class BitlockerCommand(BaseCommand):
    """
    >>> chipsec_util bitlocker volume|fve <filename>
    >>> chipsec_util bitlocker rkey <recovery_password>
    >>> chipsec_util bitlocker rpwd <recovery_key>

    Examples:

    >>> chipsec_util bitlocker fve bitlocker.meta0.bin
    >>> chipsec_util bitlocker rkey XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
    >>> chipsec_util bitlocker rpwd XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    """
    def requires_driver(self):
        return False


    def run(self):
        if len(self.argv) < 3:
            print BitlockerCommand.__doc__
            return

        op = self.argv[2]
        t = time.time()

        if ( 'volume' == op ):
            filename = self.argv[ 3 ]
            buf = read_file( filename )
            self.logger.log( "[CHIPSEC] Bitlocker volume header:" )
            parse_bitlocker_volume_header( buf )
        elif ( 'fve' == op ):
            filename = self.argv[ 3 ]
            buf = read_file( filename )
            self.logger.log( "[CHIPSEC] Bitlocker FVE metadata block header:" )
            parse_bitlocker_metadata_block( buf )
        elif ( 'rkey' == op ):
            pwd = self.argv[ 3 ]
            self.logger.log( "[CHIPSEC] Bitlocker recovery password: %s" % pwd )
            self.logger.log( "[CHIPSEC] Distilled recovery key: %s" % get_recovery_key( pwd ) )
        elif ( 'rpwd' == op ):
            rkey = self.argv[ 3 ]
            import binascii
            b_rkey = binascii.unhexlify( rkey )
            self.logger.log( "[CHIPSEC] Bitlocker recovery key ( %s ):" % rkey )
            print_buffer( b_rkey )
            self.logger.log( "[CHIPSEC] Recovery password: %s" % get_rk_password( b_rkey ) )
        elif ( 'dec_aesccm' == op ):
            blob = read_file( self.argv[ 3 ] )
            key  = read_file( self.argv[ 4 ] )
            cleartext_f = self.argv[ 5 ]
            self.logger.log( "[CHIPSEC] Decrypting AES-CCM encrypted blob to file '%s'" % cleartext_f )
            write_file( cleartext_f, decrypt_rkey( blob, key ) )
        else:
            self.logger.error( "unknown command-line option '%.32s'" % op )
            print BitlockerCommand.__doc__
            return

        self.logger.log( "[CHIPSEC] (bitlocker) time elapsed %.3f" % (time.time()-t) )


commands = { 'bitlocker': BitlockerCommand }
