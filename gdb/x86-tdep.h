/* Target-dependent code for X86-based targets.

   Copyright (C) 2018-2023 Free Software Foundation, Inc.

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

#ifndef X86_TDEP_H
#define X86_TDEP_H

/* Checks whether PC lies in an indirect branch thunk using registers
   REGISTER_NAMES[LO] (inclusive) to REGISTER_NAMES[HI] (exclusive).  */

extern bool x86_in_indirect_branch_thunk (CORE_ADDR pc,
					  const char * const *register_names,
					  int lo, int hi);

/* Add content to *NOTE_DATA (and update *NOTE_SIZE) to include a note
   containing CPUID leaves for the current target.  The core file is
   being written to OBFD.  If something goes wrong then *NOTE_DATA can
   be set to nullptr.  */

extern void x86_elf_make_cpuid_note (bfd *obfd,
				     gdb::unique_xmalloc_ptr<char> *note_data,
				     int *note_size);

#endif /* x86-tdep.h */
