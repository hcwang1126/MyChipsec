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



from chipsec.cfg.common import Cfg
class avn (Cfg):
    def __init__(self):
        Cfg.__init__(self)

    # ----------------------------------------------------------------------------
    # PCI 0/31/0: PCH LPC Root Complex
    # ----------------------------------------------------------------------------
    LPC_BC_REG_OFF        = 0xFC #  BIOS Control (BC)
    GEN_PMCON = 0x24
    CFG_REG_PCH_LPC_ACTL   = 0x44 # ACPI Control  (ACTL)
    CFG_REG_PCH_LPC_GBA    = 0x48 # GPIO I/O Base (GBA)
    CFG_REG_PCH_LPC_GC     = 0x48 # GPIO Control  (GC)

    # ----------------------------------------------------------------------------
    # SPI Controller MMIO
    # ----------------------------------------------------------------------------
    SPI_MMIO_REG_OFFSET   = 0x54
    SPI_BASE_ADDR_SHIFT   = 2
    SPI_MMIO_BASE_OFFSET  = 0x0
    SPI_BIOS_CONTROL_OFFSET = 0xFC # BIOS Control Register

    # ----------------------------------------------------------------------------
    # PCI B0:D31:F3 SMBus Controller
    # ----------------------------------------------------------------------------
    PCI_B0D31F3_SMBUS_CTRLR_DID = 0x1F12

    CFG_REG_PCH_SMB_SBA  = 0x10                    # SMBus Base Address
    CFG_REG_PCH_SMB_SBA_BASE_ADDRESS_MASK = 0xFFFFFFE0 # Base Address


    # ----------------------------------------------------------------------------
    # PCH RCBA
    # ----------------------------------------------------------------------------
    RCBA_GENERAL_CONFIG_OFFSET = 0x0
    RCBA_GC_GCS_REG_OFFSET     = 0x0    # General Control and Status (GCS) register
