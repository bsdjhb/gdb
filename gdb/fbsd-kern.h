/* Target-dependent code for FreeBSD kernels, architecture-independent.

   Copyright (C) 2023 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef FBSD_KERN_H
#define FBSD_KERN_H

/* An osabi sniffer for FreeBSD kernels.

   This function assumes that an ABFD's flavor is ELF.  */

extern enum gdb_osabi fbsd_kernel_osabi_sniffer (bfd *abfd);

#endif /* fbsd-kern.h */
