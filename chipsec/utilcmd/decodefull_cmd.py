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


import os
import sys
import time

from  chipsec.logger import *
import  chipsec.file
from chipsec.command import BaseCommand

import chipsec.hal.spi            as spi
import chipsec.hal.spi_descriptor as spi_descriptor
import chipsec.hal.spi_me         as spi_me
import chipsec.hal.spi_uefi       as spi_uefi
import chipsec.hal.uefi           as uefi


# ###################################################################
#
# Complete decode of SPI flash memory image including ME region
#
# ###################################################################

class FullDecodeCommand(BaseCommand):
    """
    >>> chipsec_util decodefull <rom> [fw_type]\n

    For a list of fw types run:

    >>> chipsec_util decodefull types

    Examples:

    >>> chipsec_util decodefull spi.bin vss
    """
    def requires_driver(self):
        return False

    def run(self):
        
        if 3 > len(self.argv):
            print FullDecodeCommand.__doc__
            return
        
        _uefi = uefi.UEFI( self.cs )
        if self.argv[2] == "types":
            print "\n<fw_type> should be in [ %s ]\n" % ( " | ".join( ["%s" % t for t in uefi.fw_types] ) )
            return
        
        rom_file = self.argv[2]

        fwtype = ''
        if 4 == len(self.argv):
            fwtype = self.argv[3]

        self.logger.log( "[CHIPSEC] Decoding SPI ROM image from a file '%s'" % rom_file )
        t = time.time()

        f = chipsec.file.read_file( rom_file )
        (fd_off, fd) = spi_descriptor.get_spi_flash_descriptor( f )
        if (-1 == fd_off) or (fd is None):
            self.logger.error( "Could not find SPI Flash descriptor in the binary '%s'" % rom_file )
            return False

        self.logger.log( "[CHIPSEC] Found SPI Flash descriptor at offset 0x%x in the binary '%s'" % (fd_off, rom_file) )
        rom = f[fd_off:]

        # Decoding SPI Flash Regions
        # flregs[r] = (r,SPI_REGION_NAMES[r],flreg,base,limit,notused)
        flregs = spi_descriptor.get_spi_regions( fd )
        if flregs is None:
            self.logger.error( "SPI Flash descriptor region is not valid" )
            return False

        _orig_logname = self.logger.LOG_FILE_NAME

        pth = os.path.join( self.cs.helper.getcwd(), rom_file + ".dir" )
        if not os.path.exists( pth ):
            os.makedirs( pth )

        for r in flregs:
            idx     = r[0]
            name    = r[1]
            base    = r[3]
            limit   = r[4]
            notused = r[5]
            if not notused:
                region_data = rom[base:limit+1]
                fname = os.path.join( pth, '%d_%04X-%04X_%s.bin' % (idx, base, limit, name) )
                chipsec.file.write_file( fname, region_data )
                if spi.FLASH_DESCRIPTOR == idx:
                    # Decoding Flash Descriptor
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    spi_descriptor.parse_spi_flash_descriptor( region_data )
                elif spi.ME == idx:
                    # Decoding ME Region
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    spi_me.parse_me_region_from_file( fname )
                elif spi.BIOS == idx:
                    # Decoding EFI Firmware Volumes
                    self.logger.set_log_file( os.path.join( pth, fname + '.log' ) )
                    spi_uefi.decode_uefi_region(_uefi, pth, fname, fwtype)

        self.logger.set_log_file( _orig_logname )
        self.logger.log( "[CHIPSEC] (decode) time elapsed %.3f" % (time.time()-t) )


commands = { 'decodefull': FullDecodeCommand }
