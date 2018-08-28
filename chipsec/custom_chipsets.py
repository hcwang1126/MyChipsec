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
#Copyright (c) 2010-2018, Intel Corporation
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



"""
Contains support of pre-release platforms
"""

import chipset

CHIPSET_ID_BLK  = 1000 + 1
CHIPSET_ID_CNTG = 1000 + 2
CHIPSET_ID_EGLK = 1000 + 3
CHIPSET_ID_TBG  = 1000 + 4
CHIPSET_ID_LFD  = 1000 + 5
CHIPSET_ID_JSP  = 1000 + 6
CHIPSET_ID_WSM  = 1000 + 7

CHIPSET_ID_SKX  = 1000 + 12
CHIPSET_ID_KNL  = 1000 + 13
CHIPSET_ID_WHL  = 1000 + 18

CHIPSET_ID_GLK  = 2000 + 4

chipset.CHIPSET_FAMILY_XEON.extend([CHIPSET_ID_TBG,CHIPSET_ID_SKX,CHIPSET_ID_KNL])
chipset.CHIPSET_FAMILY_CORE.extend([CHIPSET_ID_LFD,CHIPSET_ID_WSM,CHIPSET_ID_WHL])
chipset.CHIPSET_FAMILY_ATOM.extend([CHIPSET_ID_GLK])
chipset.CHIPSET_FAMILY_QUARK.extend([])

custom_proc_dict = {

# 3 Series Desktop Chipset (Broadwater and Bearlake) = 29xx
0x2970 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH / ICH9' },
0x2980 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - Woodriver / ICH9' },
0x2990 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - Aledo / ICH9' },
0x29B0 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - Q35 Host Controller / ICH9' },
0x29C0 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - G33/P35 Host Controller / ICH9' },
0x29D0 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - Q33 Host Controller / ICH9' },
0x29E0 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - X38 Host Controller / ICH9' },
0x29F0 : {'name' : 'Bearlake',       'id' : CHIPSET_ID_BLK , 'code' : 'BLK',  'longname' : 'BearLake MCH - Bigby / ICH9' },

# 4 Series Mobile Chipset (Cantiga) = 2A4x - 2AF0
0x2A40 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2A50 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2A60 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2A70 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2A80 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2A90 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AA0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AB0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AC0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AD0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AE0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },
0x2AF0 : {'name' : 'Cantiga',        'id' : CHIPSET_ID_CNTG, 'code' : 'CNTG',  'longname' : 'Cantiga MCH / ICH9m' },

# 4 Series Desktop Chipset (Eaglelake) = 2E0x,2E1x,2E2x,2E3x,2E4
0x2E00 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH / ICH10' },
0x2E10 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH - Q45/Q43 Host Controller / ICH10' },
0x2E20 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH - G45/G43/P45 Host Controller / ICH10'    },
0x2E30 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH - G41 Host Controller / ICH10'            },
0x2E40 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH - B43 Host Controller / ICH10'            },
0x2E90 : {'name' : 'Eaglelake',      'id' : CHIPSET_ID_EGLK, 'code' : 'EGLK',  'longname' : 'EagleLake MCH - B43 (Upgraded) Host Controller / ICH10' },

# Core Processor Family (Westmere)
# 0x004x
# 0x0061 ??
0x0040 : {'name' : 'Westmere',       'id' : CHIPSET_ID_WSM , 'code' : 'WSM',  'longname' : 'Westmere Desktop (Ironlake GMCH) / Ibex Peak PCH' },
0x0044 : {'name' : 'Westmere',       'id' : CHIPSET_ID_WSM , 'code' : 'WSM',  'longname' : 'Westmere Mobile (Ironlake GMCH) / Ibex Peak PCH' },
0x0048 : {'name' : 'Westmere',       'id' : CHIPSET_ID_WSM , 'code' : 'WSM',  'longname' : 'Westmere Workstation/Server (Ironlake GMCH) / Ibex Peak PCH' },

# Tylersburg IOH
# 0x340x
0x3400 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3401 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3402 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3403 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3404 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3405 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3406 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },
0x3407 : {'name' : 'Tylersburg',     'id' : CHIPSET_ID_TBG , 'code' : 'TBG',  'longname' : 'Nehalem CPU / Tylersburg IOH' },

# Lynnfield based CPUs
0xD130 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Foxhollow' },
0xD131 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD132 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD133 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD134 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD135 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD136 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },
0xD137 : {'name' : 'Lynnfield',      'id' : CHIPSET_ID_LFD , 'code' : 'LFD',  'longname' : 'Intel Core i7-800 and i5-700 Desktop (Lynnfield DT)' },

# Jasper Forest
# 0x371x - 0x372x ??
0x3710 : {'name' : 'Jasper Forest',  'id' : CHIPSET_ID_JSP , 'code' : 'JSP',  'longname' : 'Jasper Forest' },

# Sandy Bridge
0x010C : {'name' : 'Sandy Bridge',   'id' : chipset.CHIPSET_ID_SNB , 'code' : 'SNB',  'longname' : 'Sandy Bridge' },

# Knights Landing Server
0x7801 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7802 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7803 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7804 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7805 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7806 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7818 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x7819 : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},
0x783D : {'name' : 'Knights Landing Server', 'id' : CHIPSET_ID_KNL,  'code' : 'KNL',  'longname' : 'Intel Xeon Phi Processor (Knights Landing Server CPU / Wellsburg PCH)'},

# Broadwell
0x1608 : {'name' : 'Broadwell',      'id' : chipset.CHIPSET_ID_BDW , 'code' : 'BDW',  'longname' : 'Intel Xeon Processor E3 (Broadwell CPU)' },

# Skylake Server
0x2020 : {'name' : 'Skylake',        'id' : CHIPSET_ID_SKX , 'code' : 'SKX',  'longname' : 'Intel Xeon Processor E5/E7 v5 (Skylake CPU)' },

# Coffee Lake
0x3ECC : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake U (2 Cores)' },
0x3ED0 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake U (4 Cores)' },
0x3E10 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake H (4 Cores)' },
0x3EC4 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake H (6 Cores)' },
0x3E0F : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake S (2 Cores)' },
0x3E30 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake S (8 Cores)' },
0x3E18 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Workstation (4 Cores)' },
0x3EC6 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Workstation (6 Cores)' },
0x3E31 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Workstation (8 Cores)' },
0x3E33 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Server (4 Cores)' },
0x3ECA : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Server (6 Cores)' },
0x3E32 : {'name' : 'CoffeeLake','id' : chipset.CHIPSET_ID_CFL , 'code' : 'CFL',  'longname' : 'CoffeeLake Server (8 Cores)' },

# Whiskey Lake
0x3E34 : {'name' : 'WhiskeyLake','id' : CHIPSET_ID_WHL , 'code' : 'WHL',  'longname' : 'WhiskeyLake U (4 Cores)'},

#
# Atom based SoC platforms
#

# Braswell
0x22B0 : {'name' : 'Braswell','id' : chipset.CHIPSET_ID_BSW , 'code' : 'BSW',  'longname' : 'Braswell SoC' },

# Gemini Lake
0x3180 : {'name' : 'Gemini Lake','id' : CHIPSET_ID_GLK , 'code' : 'GLK',  'longname' : 'Gemini Lake' },
0x31F0 : {'name' : 'Gemini Lake','id' : CHIPSET_ID_GLK , 'code' : 'GLK',  'longname' : 'Gemini Lake' },

}

PCH_ID_3xx      = 80000 + 10002

PCH_CODE_3xx    = 'PCH_3XX'

custom_pch_dict = {

0xA2D3 : {'name' : 'C422',   'id' : chipset.PCH_ID_2xx, 'code' : chipset.PCH_CODE_2xx, 'longname' : 'Intel C422 (200 series) PCH'},

0xA306 : {'name' : 'Q370',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel Q370 (CNL) PCH'},
0xA304 : {'name' : 'H370',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel H370 (CNL) PCH'},
0xA305 : {'name' : 'Z390',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel Z390 (CNL) PCH'},
0xA308 : {'name' : 'B360',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel B360 (CNL) PCH'},
0xA303 : {'name' : 'H310',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel H310 (CNL) PCH'},
0xA30A : {'name' : 'C242',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel C242 (CNL) PCH'},
0xA309 : {'name' : 'C246',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel C246 (CNL) PCH'},
0xA30D : {'name' : 'HM370',  'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel HM370 (CNL) PCH'},
0xA30C : {'name' : 'QM370',  'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel QM370 (CNL) PCH'},
0xA30E : {'name' : 'CM246',  'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel CM246 (CNL) PCH'},
0x9D81 : {'name' : 'LP-U',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel LP U Full Sample (CNL) PCH'},
0x9D83 : {'name' : 'LP-Y',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel LP Prem-Y (CNL) PCH'},
0x9D84 : {'name' : 'LP-U',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel LP Prem-U (CNL) PCH'},
0x9D85 : {'name' : 'LP-U',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel LP Base-U (CNL) PCH'},
0x9D86 : {'name' : 'LP-Y',   'id' : PCH_ID_3xx, 'code' : PCH_CODE_3xx, 'longname' : 'Intel LP Y Full Sample (CNL) PCH'},

}

chipset.Chipset_Dictionary.update(custom_proc_dict)
chipset.pch_dictionary.update(custom_pch_dict)
