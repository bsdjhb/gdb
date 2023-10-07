/* x86 CPUID functions.

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

#include "gdbsupport/common-defs.h"
#include "nat/x86-cpuid.h"

/* Data stored in the note for a single CPUID leaf.  */

struct cpuid_leaf
{
  uint32_t leaf;
  uint32_t subleaf;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

/* Append a single CPUID leaf.  */

static void
append_cpuid_note (gdb::unique_xmalloc_ptr<gdb_byte> &buf, size_t &len,
		   uint32_t leaf, uint32_t subleaf)
{
  struct cpuid_leaf data;
  if (!x86_cpuid_count (leaf, subleaf, &data.eax, &data.ebx, &data.ecx,
			&data.edx))
    return;

  data.leaf = leaf;
  data.subleaf = subleaf;

  buf.reset ((gdb_byte *) xrealloc (buf.release (), len + sizeof (data)));
  memcpy (buf.get() + len, &data, sizeof (data));
  len += sizeof (data);
}

/* See x86-cpuid.h.  */

void
x86_cpuid_note (gdb::unique_xmalloc_ptr<gdb_byte> &buf, size_t &len)
{
  buf.reset (nullptr);
  len = 0;

  /* Include 0xd sub-leaves that describe the XSAVE extended state.  */
  uint32_t eax, edx;
  if (x86_cpuid_count (0xd, 0, &eax, nullptr, nullptr, &edx)
      && (eax != 0 || edx != 0))
    {
      /* Main leaf and sub-leaf 1. */
      append_cpuid_note (buf, len, 0xd, 0);
      append_cpuid_note (buf, len, 0xd, 1);

      /* Sub-leaves for each enabled feature.  */
      eax >>= 2;
      uint32_t i = 2;
      while (eax != 0)
	{
	  if ((eax & 1) == 1)
	    append_cpuid_note (buf, len, 0xd, i);
	  eax >>= 1;
	  i++;
	}

      i = 0;
      while (edx != 0)
	{
	  if ((edx & 1) == 1)
	    append_cpuid_note (buf, len, 0xd, i + 32);
	  edx >>= 1;
	  i++;
	}
    }
}
