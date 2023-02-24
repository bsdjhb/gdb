/* FreeBSD Kernel Data Access Library (libkvm) target.

   Copyright (C) 2004-2023 Free Software Foundation, Inc.

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
#include "command.h"
#include "elf-bfd.h"
#include "filenames.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "inferior.h"
#include "objfiles.h"
#include "osabi.h"
#include "process-stratum-target.h"
#include "target.h"
#include "value.h"
#include "readline/tilde.h"
#include "gdbsupport/buildargv.h"
#include "gdbsupport/pathstuff.h"
#include "gdbsupport/gdb_tilde_expand.h"

#include <sys/user.h>
#include <fcntl.h>
#include <kvm.h>
#include <paths.h>

#include "fbsd-kern-thread.h"
#include "fbsd-tdep.h"

#include <unordered_map>

/* Size of struct pcb.  */
static LONGEST pcb_size;

/* Kernel memory device file.  */
static std::string vmcore;

/* Kernel memory interface descriptor.  */
static kvm_t *kvm;

/* Maps process IDs to kernel thread IDs.  */
static std::unordered_map<LONGEST, LONGEST> pid_to_tid;

/* Maps process structure addresses to kernel thread IDs.  */
static std::unordered_map<CORE_ADDR, LONGEST> paddr_to_tid;

/* Maps thread structure addresses to kernel thread IDs.  */
static std::unordered_map<CORE_ADDR, LONGEST> tdaddr_to_tid;

struct fbsd_kvm_kthread_info : public private_thread_info
{
  fbsd_kthread_info ki;
};

/* Return the fbsd_kthread_info attached to THREAD.  */

static fbsd_kthread_info *
get_fbsd_kthread_info (thread_info *thread)
{
  fbsd_kvm_kthread_info *priv =
    gdb::checked_static_cast<fbsd_kvm_kthread_info *> (thread->priv.get ());
  return &priv->ki;
}

static ptid_t
fbsd_kvm_ptid (int tid)
{
  /* This follows the model described in bsd-kvm.c except that kernel
     tids are used as the tid of the ptid instead of a process ID.  */
  return ptid_t (1, 1, tid);
}

/* The FreeBSD libkvm target.  */

static const target_info fbsd_kvm_target_info = {
  "kvm",
  N_("Kernel core dump file"),
  N_("Use a vmcore file as a target.\n\
If no filename is specified, /dev/mem is used to examine the running kernel.\n\
target vmcore [-w] [filename]")
};

class fbsd_kvm_target final : public process_stratum_target
{
public:
  fbsd_kvm_target () = default;

  const target_info &info () const override
  { return fbsd_kvm_target_info; }

  void close () override;
  void detach (inferior *, int) override;
  void fetch_registers (struct regcache *, int) override;
  enum target_xfer_status xfer_partial (enum target_object object,
					const char *annex,
					gdb_byte *readbuf,
					const gdb_byte *writebuf,
					ULONGEST offset, ULONGEST len,
					ULONGEST *xfered_len) override;

  void files_info () override;
  bool thread_alive (ptid_t ptid) override;
  std::string pid_to_str (ptid_t) override;
  const char *thread_name (struct thread_info *) override;
  const char *extra_thread_info (thread_info *) override;

  bool has_memory () override;
  bool has_stack () override;
  bool has_registers () override;
  bool has_execution (inferior *inf) override { return false; }
};

/* Target ops for libkvm interface.  */
static fbsd_kvm_target fbsd_kvm_ops;

#ifdef HAVE_KVM_OPEN2
static int
fbsd_kvm_resolve_symbol (const char *name, kvaddr_t *kva)
{
  struct bound_minimal_symbol ms;

  ms = lookup_minimal_symbol (name, nullptr, nullptr);
  if (ms.minsym == nullptr)
    return (1);
  *kva = ms.value_address ();
  return (0);
}
#endif

static void
fbsd_kvm_target_open (const char *args, int from_tty)
{
  target_preopen (from_tty);
  const char *kernel = get_exec_file (0);
  if (kernel == nullptr)
    error (_("Can't open a vmcore without a kernel"));

  gdbarch *gdbarch = target_gdbarch ();
  if (!gdbarch_supply_fbsd_pcb_p (gdbarch))
    error (_("ABI doesn't support a vmcore target"));

  std::string filename;
  bool writeable = false;
  if (args != NULL)
    {
      gdb_argv built_argv (args);

      for (char **argv = built_argv.get (); *argv != nullptr; argv++)
	{
	  if (**argv == '-')
	    {
	      if (strcmp (*argv, "-w") == 0)
		writeable = true;
	      else
		error (_("Invalid argument"));
	    }
	  else
	    {
	      if (!filename.empty ())
		error (_("Invalid argument"));

	      filename = gdb_tilde_expand (*argv);
	      if (!IS_ABSOLUTE_PATH (filename))
		filename = gdb_abspath (filename.c_str ());
	    }
	}
    }

  LONGEST new_pcb_size;
  try
    {
      new_pcb_size = fbsd_read_integer_by_name (gdbarch, "pcb_size");
    }
  catch (const gdb_exception_error &e)
    {
      try
	{
	  struct symbol *pcb_sym
	    = lookup_symbol_in_language ("struct pcb", nullptr, STRUCT_DOMAIN,
					 language_c, nullptr).symbol;
	  if (pcb_sym == nullptr)
	    error (_("Unable to find struct pcb symbol"));

	  new_pcb_size = pcb_sym->type ()->length ();
	}
      catch (const gdb_exception_error &e)
	{
	  error (_("Can't determine PCB size"));
	}
    }

  char kvm_err[_POSIX2_LINE_MAX];
#ifdef HAVE_KVM_OPEN2
  kvm_t *nkvm = kvm_open2(kernel, filename.c_str (),
			  writeable ? O_RDWR : O_RDONLY, kvm_err,
			  fbsd_kvm_resolve_symbol);
#else
  kvm_t *nkvm = kvm_openfiles(kernel, filename.c_str (), nullptr,
			      writeable ? O_RDWR : O_RDONLY, kvm_err);
#endif
  if (nkvm == nullptr)
    error (_("Failed to open vmcore: %s"), kvm_err);

  /* Don't free the filename now and close any previous vmcore. */
  current_inferior ()->unpush_target (&fbsd_kvm_ops);

#ifdef HAVE_KVM_DISP
  /* Relocate kernel objfile if needed. */
  struct objfile *symfile_objfile = current_program_space->symfile_object_file;
  if (symfile_objfile != nullptr
      && ((bfd_get_file_flags(symfile_objfile->obfd.get ()) & (EXEC_P | DYNAMIC))
	  != 0))
    {
      CORE_ADDR displacement = kvm_kerndisp (nkvm);
      if (displacement != 0)
	{
	  section_offsets new_offsets (symfile_objfile->section_offsets.size (),
				       displacement);
	  objfile_relocate (symfile_objfile, new_offsets);
	}
    }
#endif

  kvm = nkvm;
  vmcore = std::move (filename);
  target_unpush_up unpusher;
  inferior *inf = current_inferior();
  inf->push_target (&fbsd_kvm_ops);
  pcb_size = new_pcb_size;

  if (inf->pid == 0) {
    inferior_appeared(inf, 1);
    inf->fake_pid_p = 1;
  }

  /* Lookup symbols needed for stoppcbs[] handling, but don't fail if
     they aren't present.  */
  CORE_ADDR stoppcbs = 0;
  struct bound_minimal_symbol msymbol
    = lookup_minimal_symbol ("stoppcbs", nullptr,
			     current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    stoppcbs = msymbol.value_address ();

  CORE_ADDR dumppcb = 0;
  msymbol = lookup_minimal_symbol ("dumppcb", nullptr,
				   current_program_space->symfile_object_file);
  if (msymbol.minsym != nullptr)
    dumppcb = msymbol.value_address ();

  LONGEST dumptid, mp_maxid;
  try
    {
      dumptid = fbsd_read_integer_by_name (gdbarch, "dumptid");
    }
  catch (const gdb_exception_error &e)
    {
      dumptid = -1;
    }
  try
    {
      mp_maxid = fbsd_read_integer_by_name (gdbarch, "mp_maxid");
    }
  catch (const gdb_exception_error &e)
    {
      mp_maxid = 0;
    }

  std::list<fbsd_kthread_info> threads = fbsd_kthread_list_threads (gdbarch);
  if (threads.empty ())
    error (_("Failed to enumerate any threads"));

  pid_to_tid.clear ();
  paddr_to_tid.clear ();
  tdaddr_to_tid.clear ();

  LONGEST lastpid = -1;
  thread_info *curthr = nullptr;
  for (const fbsd_kthread_info &ki : threads)
    {
      fbsd_kvm_kthread_info *priv = new fbsd_kvm_kthread_info;

      priv->ki = ki;
      if (ki.tid == dumptid)
	priv->ki.pcb_address = dumppcb;
      else if (ki.cpu >= 0 && ki.cpu <= mp_maxid && stoppcbs != 0)
	priv->ki.pcb_address = stoppcbs + ki.cpu * pcb_size;

      thread_info *thr = add_thread_silent (&fbsd_kvm_ops,
					    fbsd_kvm_ptid (ki.tid));
      thr->priv.reset (priv);

      if (ki.tid == dumptid || curthr == nullptr)
	curthr = thr;

      if (ki.pid != lastpid)
	{
	  pid_to_tid[ki.pid] = ki.tid;
	  paddr_to_tid[ki.proc_address] = ki.tid;
	}
      tdaddr_to_tid[ki.thread_address] = ki.tid;
    }

  switch_to_thread (curthr);

  unpusher.release ();

  post_create_inferior (from_tty);

  target_fetch_registers (get_current_regcache (), -1);

  reinit_frame_cache ();
  print_stack_frame (get_selected_frame (NULL), 0, SRC_AND_LOC, 1);
}

static void
fbsd_kvm_clear ()
{
  if (kvm != nullptr)
    {
      switch_to_no_thread ();
      exit_inferior_silent (current_inferior ());

      clear_solib ();
      if (kvm_close (kvm) != 0)
	warning (("%s"), kvm_geterr (kvm));
      kvm = nullptr;
      vmcore.clear ();

      pid_to_tid.clear ();
      paddr_to_tid.clear ();
      tdaddr_to_tid.clear ();
    }
}

void
fbsd_kvm_target::close ()
{
  fbsd_kvm_clear ();
}

void
fbsd_kvm_target::detach (inferior *inf, int from_tty)
{
  /* See comment in core_target::detach.  */
  fbsd_kvm_clear ();

  inf->unpush_target (this);

  /* Clear the register cache and the frame cache.  */
  registers_changed ();
  reinit_frame_cache ();

  if (from_tty)
    gdb_printf (_("No vmcore file now.\n"));
}

const char *
fbsd_kvm_target::thread_name (thread_info *thread)
{
  fbsd_kthread_info *priv = get_fbsd_kthread_info (thread);
  return fbsd_kthread_name (priv);
}

const char *
fbsd_kvm_target::extra_thread_info (thread_info *thread)
{
  fbsd_kthread_info *priv = get_fbsd_kthread_info (thread);
  return fbsd_kthread_extra_info (priv);
}

bool
fbsd_kvm_target::has_memory ()
{
  return kvm != NULL;
}

bool
fbsd_kvm_target::has_stack ()
{
  return kvm != NULL;
}

bool
fbsd_kvm_target::has_registers ()
{
  return kvm != NULL;
}

void
fbsd_kvm_target::files_info()
{
  if (vmcore != _PATH_MEM)
    gdb_printf (_("\tUsing the kernel crash dump %s.\n"),
		vmcore.c_str ());
  else
    gdb_printf (_("\tUsing the currently running kernel.\n"));
}

std::string
fbsd_kvm_target::pid_to_str (ptid_t ptid)
{
  return string_printf (_("Thread %ld"), ptid.tid ());
}

bool
fbsd_kvm_target::thread_alive (ptid_t ptid)
{
  return true;
}

void
fbsd_kvm_target::fetch_registers (struct regcache *regcache, int regnum)
{
  gdbarch *gdbarch = regcache->arch ();
  struct thread_info *thread = find_thread_ptid (current_inferior (),
						 regcache->ptid ());
  fbsd_kthread_info *priv = get_fbsd_kthread_info (thread);

  if (!gdbarch_supply_fbsd_pcb_p (gdbarch))
    return;

  gdb_byte buf[pcb_size];
  if (target_read_memory (priv->pcb_address, buf, sizeof (buf)) != 0)
    return;
  gdbarch_supply_fbsd_pcb (gdbarch, regcache, buf, sizeof (buf));
}

enum target_xfer_status
fbsd_kvm_target::xfer_partial (enum target_object object, const char *annex,
			       gdb_byte *readbuf, const gdb_byte *writebuf,
			       ULONGEST offset, ULONGEST len,
			       ULONGEST *xfered_len)
{
  ssize_t nbytes;

  gdb_assert(kvm != NULL);
  switch (object)
    {
    case TARGET_OBJECT_MEMORY:
      nbytes = len;
      if (readbuf != NULL)
#ifdef HAVE_KVM_OPEN2
	nbytes = kvm_read2 (kvm, offset, readbuf, len);
#else
	nbytes = kvm_read (kvm, offset, readbuf, len);
#endif
      if (writebuf != NULL && len > 0)
	nbytes = kvm_write (kvm, offset, writebuf, len);
      if (nbytes < 0)
	return TARGET_XFER_E_IO;
      if (nbytes == 0)
	return TARGET_XFER_EOF;
      *xfered_len = nbytes;
      return TARGET_XFER_OK;
    default:
      return TARGET_XFER_E_IO;
    }
}

static void
fbsd_kvm_switch_to_thread (const char *arg, int tid)
{
  struct thread_info *tp;

  tp = find_thread_ptid (&fbsd_kvm_ops, fbsd_kvm_ptid (tid));
  if (tp == nullptr)
    error ("invalid tid");
  thread_select (arg, tp);
}

static void
fbsd_kvm_set_proc_cmd (const char *arg, int from_tty)
{
  if (!arg)
    error_no_arg ("proc address for the new context");

  if (kvm == nullptr)
    error ("only supported for vmcore target");

  CORE_ADDR addr = parse_and_eval_address (arg);
  LONGEST tid;

  auto paddr_it = paddr_to_tid.find (addr);
  if (paddr_it != paddr_to_tid.end ())
    tid = paddr_it->second;
  else
    {
      auto pid_it = pid_to_tid.find (addr);
      if (pid_it != pid_to_tid.end ())
	tid = pid_it->second;
      else
	error ("invalid pid or proc address");
    }
  fbsd_kvm_switch_to_thread (arg, tid);
}

static void
fbsd_kvm_set_tid_cmd (const char *arg, int from_tty)
{
  if (!arg)
    error_no_arg ("TID or thread address for the new context");

  if (kvm == nullptr)
    error ("only supported for vmcore target");

  CORE_ADDR addr = parse_and_eval_address (arg);
  LONGEST tid;

  auto it = tdaddr_to_tid.find (addr);
  if (it != tdaddr_to_tid.end ())
    tid = it->second;
  else
    tid = addr;
  fbsd_kvm_switch_to_thread (arg, tid);
}

void _initialize_fbsd_kvm_target ();
void
_initialize_fbsd_kvm_target ()
{
  add_target (fbsd_kvm_target_info, fbsd_kvm_target_open, filename_completer);

  add_com ("proc", class_obscure, fbsd_kvm_set_proc_cmd,
	   _("Set current kernel process context"));
  add_com ("tid", class_obscure, fbsd_kvm_set_tid_cmd,
	   _("Set current kernel thread context"));
}
