CHIPSEC: Platform Security Assessment Framework
===============================================

[![Build Status](https://travis-ci.org/chipsec/chipsec.svg?branch=master)](https://travis-ci.org/chipsec/chipsec)

CHIPSEC is a framework for analyzing the security of PC platforms including hardware, system firmware (BIOS/UEFI), and platform components. It includes a security test suite, tools for accessing various low level interfaces, and forensic capabilities. It can be run on Windows, Linux, Mac OS X and UEFI shell. Instructions for installing and using CHIPSEC can be found in the [manual](chipsec-manual.pdf).

NOTE: This software is for security testing purposes. Use at your own risk. Read [WARNING.txt](chipsec/WARNING.txt) before using.

First version of CHIPSEC was released in March 2014:
[Announcement at CanSecWest 2014](https://cansecwest.com/slides/2014/Platform%20Firmware%20Security%20Assessment%20wCHIPSEC-csw14-final.pdf)

Recent presentation on how to use CHIPSEC to find vulnerabilities in firmware, hypervisors and hardware configuration, explore low level system assets and even detect firmware implants:
[Exploring Your System Deeper](https://www.slideshare.net/CanSecWest/csw2017-bazhaniuk-exploringyoursystemdeeperupdated)

Projects That Include CHIPSEC
-----------------------------

 * [Linux UEFI Validation (LUV)](https://01.org/linux-uefi-validation)

Contact Us
----------

Mailing lists:

 * CHIPSEC users: [chipsec-users](https://groups.google.com/forum/#!forum/chipsec-users)
 * [CHIPSEC discussion list on 01.org](https://lists.01.org/mailman/listinfo/chipsec)

Follow us on [twitter](https://twitter.com/CHIPSEC)
# Pre-Release CHIPSEC

******************************************************************
 
*PRE-RELEASE NOTICE*

This private repository contains pre-release CHIPSEC functionality

Please do not distribute contents of this repository publicly

******************************************************************

# Building and Using Pre-Release CHIPSEC

* Download/clone CHIPSEC framework from https://github.com/chipsec/chipsec to \<CHIPSEC_PATH\>

* Merge contents of chipsec-prerelease repository into downloaded CHIPSEC located in \<CHIPSEC_PATH\>. This is a simple directory merge. chipsec-prerelease repository has the same directory structure as public CHIPSEC framework. All files from chipsec-prerelease should be moved to corresponding sub-directories in \<CHIPSEC_PATH\>

* Follow CHIPSEC install instructions in [chipsec-manual.pdf](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf) to install and run CHIPSEC in your environment

******************************************************************

### Using CHIPSEC through DAL/ITP2

- Modify `chipsec/helper/helpers.py` and add the line `from chipsec.helper.dal import *`
- Load `itpii` module, then run from command line as usual. Operations will go through DAL to target platform.
  **NOTE:** all actions which do not specify a thread explicitly use Core 0 Thread 0, this cannot be reconfigured currently.
  **WARNING:** using chipsec over DAL at a command prompt is excruciatingly slow, as the DAL stack must be initialized and torn down for every command. Importing chipsec in a DAL CLI session will give much better performance. 
- Alternatively, launch the DAL CLI and enter `import chipsec_util` or `import chipsec_main` to load desired chipsec functions.
  See `chipsec_util.py` for examples of how to use the chipsec utilities from inside the Python CLI.