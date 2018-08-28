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
SPI Flash ME Region binary parsing functionality

usage:
    >>> parse_me_region_from_file( filename )
    >>> parse_me_region( merom )
"""

__version__ = '1.0'

import os
import struct
import sys
import time
import collections

from chipsec.helper.oshelper import helper
from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *


FPT_HDR_VERSION1                = 0x10 #< FPT Version 1 Header Value
FPT_HDR_VERSION2                = 0x20 #< FPT Version 2 Header Value

FPT_HDR_MARKER                  = 0x54504624 #< Structure Marker $FPT
FPT_ENTRY_VERSION               = 0x10       #< FPT Entry Structure Version
FPT_PARTITION_NAME_CODE         = 0x45444F43 #< "CODE" Partition Name
FPT_PARTITION_NAME_NFTP         = 0x5054464E #< "NFTP" Partition Name
FPT_PARTITION_NAME_RECOVERY     = 0x59564352 #< "RCVY" Partition Name
FPT_PARTITION_NAME_KERNELDATA   = 0x5441444B #< "KDAT" Partition Name
FPT_PARTITION_NAME_3RDPARTYDATA = 0x53445033 #< "3PDS" Partition Name
FPT_PARTITION_NAME_ROM          = 0x424D4F52 #< "ROMB" Partition Name
FPT_PARTITION_NAME_EFFS         = 0x53464645 #< "EFFS" Partition Name
FPT_PARTITION_NAME_GEN          = 0x504E4547 #< "GENP" Partition Name

PARTITION_ACCESS_READ_ENABLE    = (1 << 0) #< Read Access bit in Permissions field of FPT Entry
PARTITION_ACCESS_WRITE_ENABLE   = (1 << 1) #< Write Access bit in Permissions field of FPT Entry
PARTITION_ACCESS_EXECUTE_ENABLE = (1 << 2) #< Execute Access bit in Permissions field of FPT Entry

PARTITION_EXTEND_TILL_REGION_END  = 0xFFFFFFFF #< Length value that extends partition to end of Region

FPTHeaderVer2 = "<4IIIBBBBIII2I"
FPTHeaderVer2_size = struct.calcsize(FPTHeaderVer2)

FPTEntry = "<8I"
FPTEntry_size = struct.calcsize(FPTEntry)

def u32tostr(u32):
    s = ''.join([(chr(u32 & 0xff)), (chr((u32 >> 8) & 0xff)), (chr((u32 >> 0x10) & 0xff)), (chr((u32 >> 0x18) & 0xff))])
    if (s.isalnum()): return s
    return ("%08X" % u32)


def parse_me_region( data ):
    fof = 0
    fptof = 0
    while (fof + FPTHeaderVer2_size) < len(data):
        fof = data.find("$FPT", fof)
        if fof == -1: break
        if fof < 0x10: continue
        fof = fof - 0x10
        RomBypassVector0, RomBypassVector1, RomBypassVector2, RomBypassVector3, HeaderMarker, NumFptEntries, HeaderVersion, EntryVersion, \
        HeaderLength, HeaderChecksum, FileSysData, UmaSize, Flags, RSVD0, RSVD1 = struct.unpack_from( FPTHeaderVer2, data[fof:fof + FPTHeaderVer2_size] )

        logger().log( 'ME Flash Partition Table:' )
        logger().log( '---------------------------------------------------------------------------------------------------' )
        logger().log( 'HeaderMarker  : 0x%08X (%s)' % (HeaderMarker, struct.pack('I',HeaderMarker) ) )
        logger().log( 'NumFptEntries : %d' % NumFptEntries )
        logger().log( 'HeaderVersion : 0x%02X' % HeaderVersion )
        logger().log( 'EntryVersion  : 0x%02X' % EntryVersion )
        logger().log( 'HeaderLength  : 0x%02X' % HeaderLength )
        logger().log( 'HeaderChecksum: 0x%02X' % HeaderChecksum )
        logger().log( 'FileSysData   : 0x%08X' % FileSysData )
        logger().log( 'UmaSize       : 0x%08X' % UmaSize )
        logger().log( 'Flags         : 0x%08X' % Flags )
        fptof = fof
        fof = fof + HeaderLength
        if (HeaderMarker == FPT_HDR_MARKER):
            break

    if (-1 == fof):
        logger().log( '[spi_me] ME Flash Partition Table (FPT) was not found' )
        return None

    logger().log( '\nPartitions    :' )
    logger().log( '---------------------------------------------------------------------------------------------------' )
    logger().log( ' Name        | Owner | Offset   | Length   | TokensOnStart | MaxTokens | ScratchSectors | Attr     ' )
    logger().log( '---------------------------------------------------------------------------------------------------' )
    c = 0
    partitions = {}
    while ((fof + FPTEntry_size) < len(data)) and (c < NumFptEntries):
        name, owner, offset, length, TokensOnStart, MaxTokens, ScratchSectors, attribs = struct.unpack_from( FPTEntry, data[fof:fof + FPTEntry_size] )
        fof = fof + FPTEntry_size
        c = c + 1
        pof = fptof + offset
        part_name = u32tostr(name)
        if (0 == offset):
            part_name += ' (EFFS)'
        part_owner = ''
        if not (0xFFFFFFFF == owner):
            part_owner = u32tostr(owner)
        logger().log( ' %-11s | %-5s | %08X | %08X | %08X      | %08X  | %08X       | %08X' % (part_name,part_owner,offset,length,TokensOnStart,MaxTokens,ScratchSectors,attribs) )
        partitions[u32tostr(name)] = (data[pof:pof + length], owner, offset, TokensOnStart, MaxTokens, ScratchSectors, attribs)

    return partitions

def parse_me_region_from_file( filename, outpath=None ):
    rom = read_file( filename )

    if outpath is None:
        outpath = os.path.join( helper().getcwd(), filename + ".dir" )
    if not os.path.exists( outpath ):
        os.makedirs( outpath )

    partitions = parse_me_region( rom )
    if (partitions is None) or (0 == len(partitions)):
        return

    for pk in partitions.keys():
        p = partitions[pk]
        pd = p[0]
        off = p[2]
        if (off > 0):
            write_file( os.path.join( outpath, "%08X-%08X-%s.bin" % (off, len(pd), pk) ), pd )
