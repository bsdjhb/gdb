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

#include "defs.h"
#include "elf-bfd.h"
#include "gdbarch.h"
#include "gdb_bfd.h"
#include "osabi.h"

#include "fbsd-kern.h"
#include "solib-fbsd-kld.h"

#define KERNEL_INTERP		"/red/herring"

/* See fbsd-kern.h.  */

enum gdb_osabi
fbsd_kernel_osabi_sniffer (bfd *abfd)
{
  gdb_assert (bfd_get_flavour (abfd) == bfd_target_elf_flavour);

  /* First, determine if this is a FreeBSD/ELF binary.  */
  switch (elf_elfheader(abfd)->e_ident[EI_OSABI]) {
  case ELFOSABI_FREEBSD:
    break;
  case ELFOSABI_NONE:
    {
      enum gdb_osabi osabi = GDB_OSABI_UNKNOWN;

      for (asection *sect : gdb_bfd_sections (abfd))
	generic_elf_osabi_sniff_abi_tag_sections (abfd, sect, &osabi);

      /* aarch64 and RISC-V kernels don't have the right note tag for
	 kernels so just look for /red/herring anyway.  */
      if (osabi == GDB_OSABI_UNKNOWN
	  && (elf_elfheader(abfd)->e_machine == EM_AARCH64
	      || elf_elfheader(abfd)->e_machine == EM_RISCV))
	break;
      if (osabi != GDB_OSABI_FREEBSD)
	return (GDB_OSABI_UNKNOWN);
      break;
    }
  default:
    return (GDB_OSABI_UNKNOWN);
  }

  /* FreeBSD ELF kernels have an interpreter path of "/red/herring". */
  bfd_byte buf[sizeof(KERNEL_INTERP)];
  bfd_byte *bufp = buf;
  asection *s = bfd_get_section_by_name(abfd, ".interp");
  if (s != nullptr && bfd_section_size(s) == sizeof(buf)
      && bfd_get_full_section_contents(abfd, s, &bufp)
      && memcmp(buf, KERNEL_INTERP, sizeof(buf)) == 0)
    return (GDB_OSABI_FREEBSD_KERNEL);

  return (GDB_OSABI_UNKNOWN);
}

/* See fbsd-kern.h. */

void
fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  set_gdbarch_so_ops (gdbarch, &fbsd_kld_so_ops);
}
