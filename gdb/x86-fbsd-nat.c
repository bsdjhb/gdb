/* Native-dependent code for FreeBSD x86.

   Copyright (C) 2022-2023 Free Software Foundation, Inc.

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
#include "x86-fbsd-nat.h"
#ifdef PT_GETXSTATE_INFO
#include "nat/x86-cpuid.h"
#include "nat/x86-xstate.h"
#endif

/* Implement the virtual fbsd_nat_target::low_new_fork method.  */

void
x86_fbsd_nat_target::low_new_fork (ptid_t parent, pid_t child)
{
  struct x86_debug_reg_state *parent_state, *child_state;

  /* If there is no parent state, no watchpoints nor breakpoints have
     been set, so there is nothing to do.  */
  parent_state = x86_lookup_debug_reg_state (parent.pid ());
  if (parent_state == nullptr)
    return;

  /* The kernel clears debug registers in the new child process after
     fork, but GDB core assumes the child inherits the watchpoints/hw
     breakpoints of the parent, and will remove them all from the
     forked off process.  Copy the debug registers mirrors into the
     new process so that all breakpoints and watchpoints can be
     removed together.  */

  child_state = x86_debug_reg_state (child);
  *child_state = *parent_state;
}

#ifdef PT_GETXSTATE_INFO
enum target_xfer_status
x86_fbsd_nat_target::xfer_partial (enum target_object object,
				   const char *annex, gdb_byte *readbuf,
				   const gdb_byte *writebuf,
				   ULONGEST offset, ULONGEST len,
				   ULONGEST *xfered_len)
{
  switch (object)
    {
    case TARGET_OBJECT_X86_CPUID:
      if (readbuf)
	{
	  size_t size = m_cpuid_note_len;
	  if (offset >= size)
	    return TARGET_XFER_EOF;
	  size -= offset;
	  if (size > len)
	    size = len;

	  if (size == 0)
	    return TARGET_XFER_EOF;

	  memcpy (readbuf, m_cpuid_note.get () + offset, size);
	  *xfered_len = size;
	  return TARGET_XFER_OK;
	}
      return TARGET_XFER_E_IO;
    default:
      return fbsd_nat_target::xfer_partial (object, annex, readbuf,
					    writebuf, offset, len,
					    xfered_len);
    }
}

void
x86_fbsd_nat_target::probe_xsave_layout (pid_t pid)
{
  if (m_xsave_probed)
    return;

  m_xsave_probed = true;

  x86_cpuid_note (m_cpuid_note, m_cpuid_note_len);

  if (ptrace (PT_GETXSTATE_INFO, pid, (PTRACE_TYPE_ARG3) &m_xsave_info,
	      sizeof (m_xsave_info)) != 0)
    return;
  if (m_xsave_info.xsave_len != 0)
    m_xsave_layout = x86_fetch_xsave_layout (m_xsave_info.xsave_mask,
					     m_xsave_info.xsave_len);
}
#endif
