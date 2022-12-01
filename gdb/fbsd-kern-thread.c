/* FreeBSD kernel thread support

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
#include "gdbarch.h"
#include "gdbcore.h"
#include "progspace.h"

#include "fbsd-kern-thread.h"
#include "fbsd-tdep.h"

/* Length of p_comm[] and td_name[] arrays.  */
#define	KTHREAD_NAME_MAX	20

struct fbsd_kthread_lookup_info
{
  /* Address of various globals.  */
  CORE_ADDR zombproc = 0;
  CORE_ADDR allproc = 0;
  CORE_ADDR pidhash = 0;
  CORE_ADDR pidhashtbl = 0;

  /* Offsets of fields in struct proc.  */
  LONGEST off_p_pid = -1;
  LONGEST off_p_comm = -1;
  LONGEST off_p_hash = -1;
  LONGEST off_p_list = -1;
  LONGEST off_p_threads = -1;

  /* Offsets of fields in struct thread.  */
  LONGEST off_td_tid = -1;
  LONGEST off_td_oncpu = -1;
  LONGEST off_td_pcb = -1;
  LONGEST off_td_name = -1;
  LONGEST off_td_plist = -1;

  /* Size of td_oncpu (char in older kernels).  */
  LONGEST size_td_oncpu = -1;

  bool initialized = false;
  bool valid = false;
};

/* Per-program-space data key.  */
static const registry<program_space>::key<fbsd_kthread_lookup_info>
fbsd_kthread_pspace_data;

/* Get the current kthread lookup info.  If none is found yet, add it
   now.  This function always returns a valid object.  */

static struct fbsd_kthread_lookup_info *
get_fbsd_kthread_info (void)
{
  struct fbsd_kthread_lookup_info *info;

  info = fbsd_kthread_pspace_data.get (current_program_space);
  if (info == nullptr)
    info = fbsd_kthread_pspace_data.emplace (current_program_space);

  return info;
}

/* Lookup needed offsets and addresses.  */

static void
fbsd_kthread_resolve_info (gdbarch *gdbarch,
			   struct fbsd_kthread_lookup_info *info)
{
  gdb_assert (!info->initialized);

  info->initialized = true;

  /* FreeBSD kernels 10.3 and later include the offset of relevant
     members in struct proc and struct thread as global constants.  If
     those constants don't exist, fall back to using debug
     symbols.  */
  try
    {
      info->off_p_pid = fbsd_read_integer_by_name (gdbarch, "proc_off_p_pid");
      info->off_p_comm = fbsd_read_integer_by_name (gdbarch, "proc_off_p_comm");
      info->off_p_list = fbsd_read_integer_by_name (gdbarch, "proc_off_p_list");
      info->off_p_threads = fbsd_read_integer_by_name (gdbarch,
						       "proc_off_p_threads");
      info->off_td_tid = fbsd_read_integer_by_name (gdbarch,
						    "thread_off_td_tid");
      info->off_td_name = fbsd_read_integer_by_name (gdbarch,
						     "thread_off_td_name");
      info->off_td_oncpu = fbsd_read_integer_by_name (gdbarch,
						      "thread_off_td_oncpu");
      info->off_td_pcb = fbsd_read_integer_by_name (gdbarch,
						    "thread_off_td_pcb");
      info->off_td_plist = fbsd_read_integer_by_name (gdbarch,
						      "thread_off_td_plist");
    }
  catch (const gdb_exception_error &e)
    {
      try
	{
	  struct symbol *proc_sym
	    = lookup_symbol_in_language ("struct proc", nullptr, STRUCT_DOMAIN,
					 language_c, nullptr).symbol;
	  if (proc_sym == nullptr)
	    error (_("Unable to find struct proc symbol"));

	  info->off_p_pid = lookup_struct_elt (proc_sym->type (), "p_pid",
					       0).offset / 8;
	  info->off_p_comm = lookup_struct_elt (proc_sym->type (), "p_comm",
						0).offset / 8;
	  info->off_p_list = lookup_struct_elt (proc_sym->type (), "p_list",
						0).offset / 8;
	  info->off_p_threads = lookup_struct_elt (proc_sym->type (),
						   "p_threads", 0).offset / 8;

	  struct symbol *thread_sym
	    = lookup_symbol_in_language ("struct thread", nullptr,
					 STRUCT_DOMAIN, language_c,
					 nullptr).symbol;
	  if (thread_sym == nullptr)
	    error (_("Unable to find struct thread symbol"));

	  info->off_td_tid = lookup_struct_elt (thread_sym->type (), "td_tid",
						0).offset / 8;
	  info->off_td_name = lookup_struct_elt (thread_sym->type (), "td_name",
						 0).offset / 8;
	  info->off_td_pcb = lookup_struct_elt (thread_sym->type (), "td_pcb",
						0).offset / 8;
	  info->off_td_plist = lookup_struct_elt (thread_sym->type (),
						  "td_plist", 0).offset / 8;
	  info->off_td_oncpu = lookup_struct_elt (thread_sym->type (),
						  "td_oncpu", 0).offset / 8;
	}
      catch (const gdb_exception_error &e2)
	{
	  return;
	}
    }

  /* td_oncpu is an int in 11.0 and later.  There is no global
     constant for this value so try debug info first.  If there is no
     debug info, assume the size from 11.0 and later.  */
  try
    {
      struct symbol *thread_sym
	= lookup_symbol_in_language ("struct thread", nullptr, STRUCT_DOMAIN,
				     language_c, nullptr).symbol;
      if (thread_sym == nullptr)
	error (_("Unable to find struct thread symbol"));

      struct_elt td_oncpu = lookup_struct_elt (thread_sym->type (), "td_oncpu",
					       0);
      info->size_td_oncpu = FIELD_BITSIZE (*td_oncpu.field) / 8;
    }
  catch (const gdb_exception_error &e)
    {
      info->size_td_oncpu = 4;
    }

  /* In 13.0 and later, the zombproc list was removed and processes must
     be enumerated via the pid hash table instead.  */
  try
    {
      info->off_p_hash = fbsd_read_integer_by_name (gdbarch, "proc_off_p_hash");
    }
  catch (const gdb_exception_error &e)
    {
      try
	{
	  struct symbol *proc_sym
	    = lookup_symbol_in_language ("struct proc", nullptr, STRUCT_DOMAIN,
					 language_c, nullptr).symbol;
	  if (proc_sym == nullptr)
	    error (_("Unable to find struct proc symbol"));

	  info->off_p_hash = lookup_struct_elt (proc_sym->type (), "p_hash",
					       0).offset / 8;
	}
      catch (const gdb_exception_error &e2)
	{
	}
    }

  /* Lookup addresses of relevant global variables.  */
  struct bound_minimal_symbol msymbol
    = lookup_minimal_symbol ("zombproc", nullptr,
			     current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    info->zombproc = msymbol.value_address ();

  msymbol = lookup_minimal_symbol ("allproc", nullptr,
				   current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    info->allproc = msymbol.value_address ();

  msymbol = lookup_minimal_symbol ("pidhash", nullptr,
				   current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    info->pidhash = msymbol.value_address ();

  msymbol = lookup_minimal_symbol ("pidhashtbl", nullptr,
				   current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    info->pidhashtbl = msymbol.value_address ();

  if (info->zombproc != 0)
    {
      /* allproc is required in kernels older than 13.0.  */
      if (info->allproc == 0)
	return;
    }
  else
    {
      /* p_hash and the pid hash able are required in 13.0 and later.  */
      if (info->off_p_hash == -1 || info->pidhash == 0 || info->pidhashtbl == 0)
	return;
    }

  info->valid = true;
}

/* Enumerate threads from a process.  If an exception is thrown while
   reading state from an individual thread, only the threads examined
   previously are added to THREADS.  */

static void
fbsd_kthread_add_process (std::list<fbsd_kthread_info> &threads,
			  gdbarch *gdbarch,
			  const struct fbsd_kthread_lookup_info *info,
			  CORE_ADDR proc_address)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  struct fbsd_kthread_info ki;

  ki.proc_address = proc_address;
  ki.pid = read_memory_integer (proc_address + info->off_p_pid, 4, byte_order);

  CORE_ADDR td_address = read_memory_typed_address (proc_address
						    + info->off_p_threads,
						    ptr_type);
  while (td_address != 0)
    {
      ki.thread_address = td_address;
      ki.pcb_address = read_memory_typed_address (td_address + info->off_td_pcb,
						  ptr_type);
      ki.tid = read_memory_integer (td_address + info->off_td_tid, 4,
				    byte_order);
      ki.cpu = read_memory_integer (td_address + info->off_td_oncpu,
				    info->size_td_oncpu, byte_order);
      threads.push_back (ki);

      td_address = read_memory_typed_address (td_address + info->off_td_plist,
					      ptr_type);
    }
}

/* Walk a linked list of processes linked via the p_list field
   enumerating kernel threads.  If an exception is thrown while
   enumerating threads from a process, the function returns with
   whatever threads were added to THREADS before the exception was
   thrown.  */

static void
fbsd_kthread_add_procs_list (std::list<fbsd_kthread_info> &threads,
			     gdbarch *gdbarch,
			     const struct fbsd_kthread_lookup_info *info,
			     CORE_ADDR list_head)
{
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  CORE_ADDR proc_address;

  try
    {
      CORE_ADDR proc_address = read_memory_typed_address (list_head, ptr_type);
      while (proc_address != 0)
	{
	  fbsd_kthread_add_process (threads, gdbarch, info, proc_address);
	  proc_address = read_memory_typed_address (proc_address
						    + info->off_p_list,
						    ptr_type);
	}
    }
  catch (const gdb_exception_error &e)
    {
    }
}

/* Walk processes in PID hash table enumerating kernel threads.  If an
   exception is thrown while enumerating processes and threads within
   a given hash table bucket, the rest of the bucket is ignored.  */

static void
fbsd_kthread_add_procs_hash (std::list<fbsd_kthread_info> &threads,
			     gdbarch *gdbarch,
			     const struct fbsd_kthread_lookup_info *info)
{
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  LONGEST pidhash;
  CORE_ADDR pidhashtbl;

  try
    {
      pidhash = read_memory_integer (info->pidhash, 4,
				     gdbarch_byte_order (gdbarch));
      pidhashtbl = read_memory_typed_address (info->pidhashtbl, ptr_type);
    }
  catch (const gdb_exception_error &e)
    {
      return;
    }

  for (LONGEST i = 0; i < pidhash; i++)
    {
      try
	{
	  CORE_ADDR bucket_address = pidhashtbl + i * ptr_type->length ();
	  CORE_ADDR proc_address = read_memory_typed_address (bucket_address,
							      ptr_type);
	  while (proc_address != 0)
	    {
	      fbsd_kthread_add_process (threads, gdbarch, info, proc_address);
	      proc_address = read_memory_typed_address (proc_address
							+ info->off_p_hash,
							ptr_type);
	    }
	}
      catch (const gdb_exception_error &e)
	{
	}
    }
}

/* See fbsd-kern-thread.h.  */

std::list<fbsd_kthread_info>
fbsd_kthread_list_threads (gdbarch *gdbarch)
{
  struct fbsd_kthread_lookup_info *info = get_fbsd_kthread_info();

  if (!info->initialized)
    fbsd_kthread_resolve_info (gdbarch, info);
  if (!info->valid)
    return {};

  std::list<fbsd_kthread_info> threads;

  if (info->zombproc != 0)
    {
      fbsd_kthread_add_procs_list (threads, gdbarch, info, info->allproc);
      fbsd_kthread_add_procs_list (threads, gdbarch, info, info->zombproc);
    }
  else
    fbsd_kthread_add_procs_hash (threads, gdbarch, info);
  return threads;
}

/* See fbsd-kern-thread.h.  */

const char *
fbsd_kthread_name (const struct fbsd_kthread_info *ki)
{
  struct fbsd_kthread_lookup_info *info = get_fbsd_kthread_info();
  static char buf[KTHREAD_NAME_MAX * 2 + 3];

  gdb::unique_xmalloc_ptr<char> p_comm
    = target_read_string (ki->proc_address + info->off_p_comm,
			  KTHREAD_NAME_MAX);
  if (p_comm == nullptr)
    return nullptr;

  gdb::unique_xmalloc_ptr<char> td_name
    = target_read_string (ki->thread_address + info->off_td_name,
			  KTHREAD_NAME_MAX);

  /* Ignore the thread name if it is a duplicate of the process command.  */
  if (td_name != nullptr && strcmp (p_comm.get (), td_name.get ()) != 0)
    snprintf (buf, sizeof (buf), "%s/%s", p_comm.get (), td_name.get ());
  else
    snprintf (buf, sizeof (buf), "%s", p_comm.get ());
  return buf;
}

/* See fbsd-kern-thread.h.  */

const char *
fbsd_kthread_extra_info (const struct fbsd_kthread_info *ki)
{
  static char buf[64];

  snprintf (buf, sizeof (buf), "PID=%s", plongest (ki->pid));
  return buf;
}
