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



"""
Bitlocker volume extraction functionality
"""

__version__ = '1.0'

import struct
import sys
import time
from collections import namedtuple
from chipsec.logger import *
from chipsec.file import *

BL_FS_SIG = '-FVE-FS-'

BITLOCKER_VOLUME_HEADER_PART1_FMT  = '=BBB8sHBHBHHBHHHIIIHHIHHQIBBBI11s8s'
BITLOCKER_VOLUME_HEADER_PART1_SIZE = struct.calcsize( BITLOCKER_VOLUME_HEADER_PART1_FMT )
class BITLOCKER_VOLUME_HEADER_PART1( namedtuple('BITLOCKER_VOLUME_HEADER_PART1', 'BootEntryPoint0 BootEntryPoint1 BootEntryPoint2 Signature BytesPerSector SectorsPerClusterBlock ReservedSectors NumOfFATs RootDirEntries TotalNumOfSectors16 MediaDesc SectorsPerFAT16 SectorsPerTrack NumOfHeads NumOfHiddenSectors TotalNumOfSectors32 SectorsPerFAT32 FATFlags Version ClusterNumOfDirStart FSInfoSectorNum CopyOfThisBootSectorNum Reserved0 Reserved1 PhysDriveNum Reserved2 ExtendedBootSig VolumeSN VolumeLabel FSSig') ):
    __slots__ = ()
    def __str__(self):
        return """
BITLOCKER VOLUME HEADER
---------------------------------------------------------
0    BootEntryPoint          : %02X %02X %02X
3    Signature               : %s
11   BytesPerSector          : %04X
13   SectorsPerClusterBlock  : %02X
14   ReservedSectors         : %04X
16   NumOfFATs               : %02X
17   RootDirEntries          : %04X
19   TotalNumOfSectors16     : %04X
21   MediaDesc               : %02X
22   SectorsPerFAT16         : %04X
24   SectorsPerTrack         : %04X
26   NumOfHeads              : %04X
28   NumOfHiddenSectors      : %08X
32   TotalNumOfSectors32     : %08X
36   SectorsPerFAT32         : %08X
40   FATFlags                : %04X
42   Version                 : %04X
44   ClusterNumOfDirStart    : %08X
48   FSInfoSectorNum         : %04X
50   CopyOfThisBootSectorNum : %04X
52   Reserved                : %016X %08X
64   PhysDriveNum            : %02X
65   Reserved2               : %02X
66   ExtendedBootSig         : %02X
67   VolumeSN                : %08X
71   VolumeLabel             : %s
82   FSSig                   : %s
""" % ( self.BootEntryPoint0, self.BootEntryPoint1, self.BootEntryPoint2, self.Signature, self.BytesPerSector, self.SectorsPerClusterBlock, self.ReservedSectors, self.NumOfFATs, self.RootDirEntries, self.TotalNumOfSectors16, self.MediaDesc, self.SectorsPerFAT16, self.SectorsPerTrack, self.NumOfHeads, self.NumOfHiddenSectors, self.TotalNumOfSectors32, self.SectorsPerFAT32, self.FATFlags, self.Version, self.ClusterNumOfDirStart, self.FSInfoSectorNum, self.CopyOfThisBootSectorNum, self.Reserved0, self.Reserved1, self.PhysDriveNum, self.Reserved2, self.ExtendedBootSig, self.VolumeSN, self.VolumeLabel, self.FSSig )

BITLOCKER_VOLUME_HEADER_PART2_FMT  = '=IHH8sQQQ'
BITLOCKER_VOLUME_HEADER_PART2_SIZE = struct.calcsize( BITLOCKER_VOLUME_HEADER_PART2_FMT )
class BITLOCKER_VOLUME_HEADER_PART2( namedtuple('BITLOCKER_VOLUME_HEADER_PART2', 'BitLockerGUID0 BitLockerGUID1 BitLockerGUID2 BitLockerGUID3 FVEMetadataBlock1Offset FVEMetadataBlock2Offset FVEMetadataBlock3Offset') ):
    __slots__ = ()
    def __str__(self):
        return """
BITLOCKER VOLUME HEADER (part 2)
---------------------------------------------------------------------
160  BitLockerGUID           : {%08X-%04X-%04X-%04s-%06s}
176  FVEMetadataBlock1Offset : %016X
184  FVEMetadataBlock2Offset : %016X
192  FVEMetadataBlock3Offset : %016X
""" % ( self.BitLockerGUID0, self.BitLockerGUID1, self.BitLockerGUID2, self.BitLockerGUID3[:2].encode('hex').upper(), self.BitLockerGUID3[-6::].encode('hex').upper(), self.FVEMetadataBlock1Offset, self.FVEMetadataBlock2Offset, self.FVEMetadataBlock3Offset )

BITLOCKER_METADATA_BLOCK_HEADER_FMT  = '=8sHHHHQIIQQQQIIIIIHH8sIIQ'
BITLOCKER_METADATA_BLOCK_HEADER_SIZE = struct.calcsize( BITLOCKER_METADATA_BLOCK_HEADER_FMT )
class BITLOCKER_METADATA_BLOCK_HEADER( namedtuple('BITLOCKER_METADATA_BLOCK_HEADER', 'Signature Size Version Unknown1 Unknown2 EncryptedVolumeSize Unknown3 VolumeHeaderSectorsNum FVEMetadataBlock1Offset FVEMetadataBlock2Offset FVEMetadataBlock3Offset VolumeHeaderOffset SizeMinusHeader Unknown4 Unknown5 SizeMinusHeader2 VolumeGUID0 VolumeGUID1 VolumeGUID2 VolumeGUID3 NextCounter Algorithm Timestamp') ):
    __slots__ = ()
    def __str__(self):
        return """
BITLOCKER FVE METADATA BLOCK HEADER
---------------------------------------------------------------------
0    Signature               : %s
8    Size                    : %04X
10   Version                 : %04X
12   Unknown1                : %04X
14   Unknown2                : %04X
16   EncryptedVolumeSize     : %016X
24   Unknown3                : %08X
28   VolumeHeaderSectorsNum  : %08X
32   FVEMetadataBlock1Offset : %016X
40   FVEMetadataBlock2Offset : %016X
48   FVEMetadataBlock3Offset : %016X
56   VolumeHeaderOffset      : %016X
64   SizeMinusHeader         : %08X
68   Unknown (=1)            : %08X
72   Unknown (=0x30)         : %08X
76   SizeMinusHeader2        : %08X
80   VolumeGUID              : {%08X-%04X-%04X-%04s-%06s}
96   NextCounter             : %08X
100  Algorithm               : %08X
104  Timestamp               : %016X""" % ( self.Signature, self.Size, self.Version, self.Unknown1, self.Unknown2, self.EncryptedVolumeSize, self.Unknown3, self.VolumeHeaderSectorsNum, self.FVEMetadataBlock1Offset, self.FVEMetadataBlock2Offset, self.FVEMetadataBlock3Offset, self.VolumeHeaderOffset, self.SizeMinusHeader, self.Unknown4, self.Unknown5, self.SizeMinusHeader2, self.VolumeGUID0, self.VolumeGUID1, self.VolumeGUID2, self.VolumeGUID3[:2].encode('hex').upper(), self.VolumeGUID3[-6::].encode('hex').upper(), self.NextCounter, self.Algorithm, self.Timestamp )


BITLOCKER_FVE_METADATA_ENTRY_FMT  = '=HHHH'
BITLOCKER_FVE_METADATA_ENTRY_SIZE = struct.calcsize( BITLOCKER_FVE_METADATA_ENTRY_FMT )
class BITLOCKER_FVE_METADATA_ENTRY( namedtuple('BITLOCKER_FVE_METADATA_ENTRY', 'EntrySize EntryType ValueType Version') ):
    __slots__ = ()
    def __str__(self):
        try:    entry_type = FVE_METADATA_ENTRY_TYPE[self.EntryType]
        except: entry_type = ''
        try:    value_type = FVE_METADATA_ENTRY_VALUE_TYPE[self.ValueType]
        except: value_type = ''
        return """FVE Metadata Entry
0x0  EntrySize    : %04X
0x2  EntryType    : %04X (%s)
0x4  ValueType    : %04X (%s)
0x6  Version (=1) : %04X
0x8  Data         :""" % ( self.EntrySize, self.EntryType, entry_type, self.ValueType, value_type, self.Version )

VMK_FMT  = '=IHH8sQHH'
VMK_SIZE = struct.calcsize( VMK_FMT )
class VMK( namedtuple('VMK', 'KeyGUID0 KeyGUID1 KeyGUID2 KeyGUID3 LastModified Unknown ProtectionType') ):
    __slots__ = ()
    def __str__(self):
        try:    protection_type = KEY_PROTECTION_TYPE[self.ProtectionType]
        except: protection_type = ''
        return """
  VMK
  -----------------------------------------------------------------
  0   KeyGUID        : {%08X-%04X-%04X-%04s-%06s}
  16  LastModified   : %016X
  24  Unknown        : %04X
  26  ProtectionType : %04X (%s)
  28  VMK Data       :
""" % ( self.KeyGUID0, self.KeyGUID1, self.KeyGUID2, self.KeyGUID3[:2].encode('hex').upper(), self.KeyGUID3[-6::].encode('hex').upper(), self.LastModified, self.Unknown, self.ProtectionType, protection_type )

FVE_METADATA_ENTRY_TYPE_NONE        = 0x0
FVE_METADATA_ENTRY_TYPE_VMK         = 0x2
FVE_METADATA_ENTRY_TYPE_FVEK        = 0x3
FVE_METADATA_ENTRY_TYPE_VALIDATION  = 0x4
FVE_METADATA_ENTRY_TYPE_STARTUPKEY  = 0x6
FVE_METADATA_ENTRY_TYPE_DESCRIPTION = 0x7
FVE_METADATA_ENTRY_TYPE_FVEK_BACKUP = 0xB
FVE_METADATA_ENTRY_TYPE_VOLHDRBLOCK = 0xF

FVE_METADATA_ENTRY_VALUE_TYPE_ERASED        = 0x0
FVE_METADATA_ENTRY_VALUE_TYPE_KEY           = 0x1
FVE_METADATA_ENTRY_VALUE_TYPE_UNICODESTR    = 0x2
FVE_METADATA_ENTRY_VALUE_TYPE_STRETCHKEY    = 0x3
FVE_METADATA_ENTRY_VALUE_TYPE_USEKEY        = 0x4
FVE_METADATA_ENTRY_VALUE_TYPE_AESCCM_ENCKEY = 0x5
FVE_METADATA_ENTRY_VALUE_TYPE_TPM_ENCKEY    = 0x6
FVE_METADATA_ENTRY_VALUE_TYPE_VALIDATION    = 0x7
FVE_METADATA_ENTRY_VALUE_TYPE_VMK           = 0x8
FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNALKEY   = 0x9
FVE_METADATA_ENTRY_VALUE_TYPE_UPDATE        = 0xA
FVE_METADATA_ENTRY_VALUE_TYPE_ERROR         = 0xB
FVE_METADATA_ENTRY_VALUE_TYPE_OFFSETSIZE    = 0xF

FVE_METADATA_ENTRY_TYPE = {
FVE_METADATA_ENTRY_TYPE_NONE        : 'None',
FVE_METADATA_ENTRY_TYPE_VMK         : 'Volume Master Key',
FVE_METADATA_ENTRY_TYPE_FVEK        : 'Full Volume Encryption Key',
FVE_METADATA_ENTRY_TYPE_VALIDATION  : 'Validation',
FVE_METADATA_ENTRY_TYPE_STARTUPKEY  : 'Startup Key',
FVE_METADATA_ENTRY_TYPE_DESCRIPTION : 'Description',
FVE_METADATA_ENTRY_TYPE_FVEK_BACKUP : 'FVEK BACKUP',
FVE_METADATA_ENTRY_TYPE_VOLHDRBLOCK : 'Volume Header Block'
}

FVE_METADATA_ENTRY_VALUE_TYPE = {
FVE_METADATA_ENTRY_VALUE_TYPE_ERASED        : 'Erased',
FVE_METADATA_ENTRY_VALUE_TYPE_KEY           : 'Key',
FVE_METADATA_ENTRY_VALUE_TYPE_UNICODESTR    : 'Unicode String',
FVE_METADATA_ENTRY_VALUE_TYPE_STRETCHKEY    : 'Stretch Key',
FVE_METADATA_ENTRY_VALUE_TYPE_USEKEY        : 'Use Key',
FVE_METADATA_ENTRY_VALUE_TYPE_AESCCM_ENCKEY : 'AES-CCM Encrypted Key',
FVE_METADATA_ENTRY_VALUE_TYPE_TPM_ENCKEY    : 'TPM Encoded Key',
FVE_METADATA_ENTRY_VALUE_TYPE_VALIDATION    : 'Validation',
FVE_METADATA_ENTRY_VALUE_TYPE_VMK           : 'VMK',
FVE_METADATA_ENTRY_VALUE_TYPE_EXTERNALKEY   : 'External Key',
FVE_METADATA_ENTRY_VALUE_TYPE_UPDATE        : 'Update',
FVE_METADATA_ENTRY_VALUE_TYPE_ERROR         : 'Error',
FVE_METADATA_ENTRY_VALUE_TYPE_OFFSETSIZE    : 'Offset and Size'
}

KEY_PROTECTION_TYPE_CLEARKEY    = 0x0000
KEY_PROTECTION_TYPE_TPM         = 0x0100
KEY_PROTECTION_TYPE_STARTUPKEY  = 0x0200
KEY_PROTECTION_TYPE_RECOVERYPWD = 0x0800
KEY_PROTECTION_TYPE_PWD         = 0x2000

KEY_PROTECTION_TYPE = {
KEY_PROTECTION_TYPE_CLEARKEY    : 'VMK protected with Clear Key',
KEY_PROTECTION_TYPE_TPM         : 'VMK protected with TPM',
KEY_PROTECTION_TYPE_STARTUPKEY  : 'VMK protected with Startup Key',
KEY_PROTECTION_TYPE_RECOVERYPWD : 'VMK protected with Recovery Password',
KEY_PROTECTION_TYPE_PWD         : 'VMK protected with Password'
}

def parse_bitlocker_volume_header( buf ):
    if not (type(buf) == str):
        logger().error('Invalid object type %s'%type(buf))
        return

    pos = buf.find( BL_FS_SIG )
    if (-1 == pos or pos < 3):
        logger().error( "Valid BitLocker Volume is not found(should have signature '%s' at offset 3): offset = %x" % (BL_FS_SIG,pos) )
        return None

    vol_off = pos - 3
    vol = buf[ vol_off : ]
    logger().log( '[bitlocker] Valid BitLocker Volume found at offset 0x%08X' % vol_off )

    vol_hdr1 = BITLOCKER_VOLUME_HEADER_PART1( *struct.unpack_from( BITLOCKER_VOLUME_HEADER_PART1_FMT, vol ) )
    logger().log( vol_hdr1 )

    logger().log( '\n# BITLOCKER VOLUME HEADER BOOT CODE (1)' )
    off = BITLOCKER_VOLUME_HEADER_PART1_SIZE
    bootcode1 = vol[ off: off + 70 ]
    print_buffer( bootcode1 )

    logger().log( '\n# BITLOCKER VOLUME HEADER CONTINUED' )
    off = BITLOCKER_VOLUME_HEADER_PART1_SIZE + 70
    vol_hdr2 = BITLOCKER_VOLUME_HEADER_PART2( *struct.unpack_from( BITLOCKER_VOLUME_HEADER_PART2_FMT, vol[off:] ) )
    logger().log( vol_hdr2 )

    logger().log( '\n# BITLOCKER VOLUME HEADER BOOT CODE (2)' )
    off = BITLOCKER_VOLUME_HEADER_PART1_SIZE + 70 + BITLOCKER_VOLUME_HEADER_PART2_SIZE
    bootcode2 = vol[ off: off + 307 ]
    print_buffer( bootcode2 )


def parse_fve_metadata_entires( fve_metadata_entires, size, bLast ):

    logger().log( "Total size of FVE entries: 0x%X" % size )
    off = 0
    while off < size:
        fve_metadata_entry = BITLOCKER_FVE_METADATA_ENTRY( *struct.unpack_from( BITLOCKER_FVE_METADATA_ENTRY_FMT, fve_metadata_entires[off:] ) )
        entry_data = fve_metadata_entires[ off + BITLOCKER_FVE_METADATA_ENTRY_SIZE : off + fve_metadata_entry.EntrySize ]
        logger().log( "\nOffset: 0x%X" % off )
        logger().log( fve_metadata_entry )

        if 0 == fve_metadata_entry.EntrySize:
            logger().warn( "Entry size is 0. Stopping.." )
            logger().log( "---------------------------------------------------------------------" )
            break
        if 0x1 != fve_metadata_entry.Version:
            logger().warn( "Entry version != 0x1. Stopping.." )
            logger().log( "---------------------------------------------------------------------" )
            break

        print_buffer( entry_data )

        if FVE_METADATA_ENTRY_TYPE_VMK == fve_metadata_entry.EntryType:
            vmk = VMK( *struct.unpack_from( VMK_FMT, entry_data ) )
            logger().log( vmk )
            if not bLast:
                logger().log( ">> Begin VMK entry properties >>" )
                parse_fve_metadata_entires( entry_data[VMK_SIZE:], (fve_metadata_entry.EntrySize - BITLOCKER_FVE_METADATA_ENTRY_SIZE - VMK_SIZE), True )
                logger().log( "<< End VMK entry properties <<" )
        elif FVE_METADATA_ENTRY_TYPE_DESCRIPTION == fve_metadata_entry.EntryType:
            desc_size = fve_metadata_entry.EntrySize - 8
            str_fmt = "%ds" % desc_size
            if FVE_METADATA_ENTRY_VALUE_TYPE_UNICODESTR == fve_metadata_entry.ValueType:
                s, = struct.unpack( str_fmt, entry_data[ : desc_size ] )
                desc = unicode(s, "utf-16-le", errors="replace").split(u'\u0000')[0]
            else:
                desc = "".join( entry_data[ : desc_size ] )
            logger().log( "Description: %s" % desc )
        elif FVE_METADATA_ENTRY_TYPE_VOLHDRBLOCK == fve_metadata_entry.EntryType and FVE_METADATA_ENTRY_VALUE_TYPE_OFFSETSIZE == fve_metadata_entry.ValueType:
            logger().log( "---------------------------------------------------------------------" )
            logger().log( "Is 'Volume Hader Block' entry always the last one ??" )
            break

        off += fve_metadata_entry.EntrySize

def parse_bitlocker_metadata_block( buf ):
    if not (type(buf) == str):
        logger().error('Invalid object type %s'%type(buf))
        return

    pos = buf.find( BL_FS_SIG )
    if (-1 == pos):
        logger().error( "Valid BitLocker Volume is not found(should have signature '%s' at offset 3): offset = %x" % (BL_FS_SIG,pos) )
        return None
    #
    # Parsing FVE metadata block header
    #
    fve_off = pos
    fve = buf[ fve_off : ]
    logger().log( '[bitlocker] Valid BitLocker FVE metadata block found at offset 0x%08X' % fve_off )

    fve_metadata_block_hdr = BITLOCKER_METADATA_BLOCK_HEADER( *struct.unpack_from( BITLOCKER_METADATA_BLOCK_HEADER_FMT, fve ) )
    logger().log( fve_metadata_block_hdr )

    #
    # Extracting FVE metadata entries array
    #
    entires = fve[ BITLOCKER_METADATA_BLOCK_HEADER_SIZE : ]
    logger().log( "---------------------------------------------------------------------" )
    parse_fve_metadata_entires( entires, len(entires), False )

def get_fve_metadata_entries( buf ):
    if not (type(buf) == str):
        logger().error('Invalid object type %s'%type(buf))
        return

    pos = buf.find( BL_FS_SIG )
    if (-1 == pos):
        logger().error( "Valid BitLocker Volume is not found(should have signature '%s' at offset 3): offset = %x" % (BL_FS_SIG,pos) )
        return None

    fve_off = pos
    fve = buf[ fve_off : ]
    logger().log( '[bitlocker] Valid BitLocker FVE metadata block found at offset 0x%08X' % fve_off )

    fve_metadata_block_hdr = BITLOCKER_METADATA_BLOCK_HEADER( *struct.unpack_from( BITLOCKER_METADATA_BLOCK_HEADER_FMT, fve ) )
    logger().log( fve_metadata_block_hdr )

#
# Calculates Bitlocker recovery key from recovery password
# Format of the password: 8 '-' delimited 6-digit groups (e.g. XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX)
#
def get_recovery_key( recovery_pwd ):
    distilled_rkey = ''
    rpwd_groups = recovery_pwd.split('-')
    if len(rpwd_groups) != 8: logger().warn( "Invalid recovery password: password must contain 8 6-digit groups" )
    for gr in rpwd_groups:
        g = int(gr)
        if g%11: logger().warn( "Invalid recovery password: each 6-digit group must be divisible by 11" )
        k = g/11
        distilled_rkey += ( "%02X%02X" % (k&0xFF, (k>>8)&0xFF) )
    return distilled_rkey

#
# Extracts recovery password from Bitlocker recovery key
# Format of the key: string of 16 bytes
#
def get_rk_password( rkey ):
    g0, g1, g2, g3, g4, g5, g6, g7 = struct.unpack("<HHHHHHHH", rkey)
    pwd = "%06d-%06d-%06d-%06d-%06d-%06d-%06d-%06d" % (g0 * 11, g1 * 11, g2 * 11, g3 * 11, g4 * 11, g5 * 11, g6 * 11, g7 * 11)
    return pwd

gCounter = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

def initcounter(nonce):
    global gCounter
    gCounter = "\x02" + nonce + "\x00\x00\x00"

# the function uses only the last byte of the counter
def getcounter():
    global gCounter
    oldCounter = gCounter
    newCounter = (gCounter[:-1] + chr(ord(gCounter[-1]) + 1))
    gCounter = newCounter
    return oldCounter

def decrypt_rkey(blob, key):
    from Crypto.Cipher import AES
    blen = len(blob)
    if blen != 0x38:
        print " *** Invalid blob length: %d ***" % blen
        return ""
    nonce = blob[:12]
    initcounter(nonce)
    ct = blob[12:]
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=getcounter)
    clear = cipher.decrypt(ct)
    return clear
