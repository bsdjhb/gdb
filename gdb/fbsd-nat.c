/* Native-dependent code for FreeBSD.

   Copyright (C) 2002-2017 Free Software Foundation, Inc.

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
#include "gdbcore.h"
#include "inferior.h"
#include "regcache.h"
#include "regset.h"
#include "gdbcmd.h"
#include "gdbthread.h"
#include "gdb_wait.h"
#include <sys/types.h>
#include <sys/procfs.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#ifdef HAVE_KINFO_GETVMMAP
#include <sys/user.h>
#include <libutil.h>
#endif

#include <unordered_map>

#include "elf-bfd.h"
#include "fbsd-nat.h"

/* Return the name of a file that can be opened to get the symbols for
   the child process identified by PID.  */

static char *
fbsd_pid_to_exec_file (struct target_ops *self, int pid)
{
  ssize_t len;
  static char buf[PATH_MAX];
  char name[PATH_MAX];

#ifdef KERN_PROC_PATHNAME
  size_t buflen;
  int mib[4];

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = pid;
  buflen = sizeof buf;
  if (sysctl (mib, 4, buf, &buflen, NULL, 0) == 0)
    return buf;
#endif

  xsnprintf (name, PATH_MAX, "/proc/%d/exe", pid);
  len = readlink (name, buf, PATH_MAX - 1);
  if (len != -1)
    {
      buf[len] = '\0';
      return buf;
    }

  return NULL;
}

#ifdef HAVE_KINFO_GETVMMAP
/* Iterate over all the memory regions in the current inferior,
   calling FUNC for each memory region.  OBFD is passed as the last
   argument to FUNC.  */

static int
fbsd_find_memory_regions (struct target_ops *self,
			  find_memory_region_ftype func, void *obfd)
{
  pid_t pid = ptid_get_pid (inferior_ptid);
  struct kinfo_vmentry *vmentl, *kve;
  uint64_t size;
  struct cleanup *cleanup;
  int i, nitems;

  vmentl = kinfo_getvmmap (pid, &nitems);
  if (vmentl == NULL)
    perror_with_name (_("Couldn't fetch VM map entries."));
  cleanup = make_cleanup (free, vmentl);

  for (i = 0; i < nitems; i++)
    {
      kve = &vmentl[i];

      /* Skip unreadable segments and those where MAP_NOCORE has been set.  */
      if (!(kve->kve_protection & KVME_PROT_READ)
	  || kve->kve_flags & KVME_FLAG_NOCOREDUMP)
	continue;

      /* Skip segments with an invalid type.  */
      if (kve->kve_type != KVME_TYPE_DEFAULT
	  && kve->kve_type != KVME_TYPE_VNODE
	  && kve->kve_type != KVME_TYPE_SWAP
	  && kve->kve_type != KVME_TYPE_PHYS)
	continue;

      size = kve->kve_end - kve->kve_start;
      if (info_verbose)
	{
	  fprintf_filtered (gdb_stdout, 
			    "Save segment, %ld bytes at %s (%c%c%c)\n",
			    (long) size,
			    paddress (target_gdbarch (), kve->kve_start),
			    kve->kve_protection & KVME_PROT_READ ? 'r' : '-',
			    kve->kve_protection & KVME_PROT_WRITE ? 'w' : '-',
			    kve->kve_protection & KVME_PROT_EXEC ? 'x' : '-');
	}

      /* Invoke the callback function to create the corefile segment.
	 Pass MODIFIED as true, we do not know the real modification state.  */
      func (kve->kve_start, size, kve->kve_protection & KVME_PROT_READ,
	    kve->kve_protection & KVME_PROT_WRITE,
	    kve->kve_protection & KVME_PROT_EXEC, 1, obfd);
    }
  do_cleanups (cleanup);
  return 0;
}
#else
static int
fbsd_read_mapping (FILE *mapfile, unsigned long *start, unsigned long *end,
		   char *protection)
{
  /* FreeBSD 5.1-RELEASE uses a 256-byte buffer.  */
  char buf[256];
  int resident, privateresident;
  unsigned long obj;
  int ret = EOF;

  /* As of FreeBSD 5.0-RELEASE, the layout is described in
     /usr/src/sys/fs/procfs/procfs_map.c.  Somewhere in 5.1-CURRENT a
     new column was added to the procfs map.  Therefore we can't use
     fscanf since we need to support older releases too.  */
  if (fgets (buf, sizeof buf, mapfile) != NULL)
    ret = sscanf (buf, "%lx %lx %d %d %lx %s", start, end,
		  &resident, &privateresident, &obj, protection);

  return (ret != 0 && ret != EOF);
}

/* Iterate over all the memory regions in the current inferior,
   calling FUNC for each memory region.  OBFD is passed as the last
   argument to FUNC.  */

static int
fbsd_find_memory_regions (struct target_ops *self,
			  find_memory_region_ftype func, void *obfd)
{
  pid_t pid = ptid_get_pid (inferior_ptid);
  char *mapfilename;
  FILE *mapfile;
  unsigned long start, end, size;
  char protection[4];
  int read, write, exec;
  struct cleanup *cleanup;

  mapfilename = xstrprintf ("/proc/%ld/map", (long) pid);
  cleanup = make_cleanup (xfree, mapfilename);
  mapfile = fopen (mapfilename, "r");
  if (mapfile == NULL)
    error (_("Couldn't open %s."), mapfilename);
  make_cleanup_fclose (mapfile);

  if (info_verbose)
    fprintf_filtered (gdb_stdout, 
		      "Reading memory regions from %s\n", mapfilename);

  /* Now iterate until end-of-file.  */
  while (fbsd_read_mapping (mapfile, &start, &end, &protection[0]))
    {
      size = end - start;

      read = (strchr (protection, 'r') != 0);
      write = (strchr (protection, 'w') != 0);
      exec = (strchr (protection, 'x') != 0);

      if (info_verbose)
	{
	  fprintf_filtered (gdb_stdout, 
			    "Save segment, %ld bytes at %s (%c%c%c)\n",
			    size, paddress (target_gdbarch (), start),
			    read ? 'r' : '-',
			    write ? 'w' : '-',
			    exec ? 'x' : '-');
	}

      /* Invoke the callback function to create the corefile segment.
	 Pass MODIFIED as true, we do not know the real modification state.  */
      func (start, size, read, write, exec, 1, obfd);
    }

  do_cleanups (cleanup);
  return 0;
}
#endif

#ifdef KERN_PROC_AUXV
static enum target_xfer_status (*super_xfer_partial) (struct target_ops *ops,
						      enum target_object object,
						      const char *annex,
						      gdb_byte *readbuf,
						      const gdb_byte *writebuf,
						      ULONGEST offset,
						      ULONGEST len,
						      ULONGEST *xfered_len);

/* Implement the "to_xfer_partial target_ops" method.  */

static enum target_xfer_status
fbsd_xfer_partial (struct target_ops *ops, enum target_object object,
		   const char *annex, gdb_byte *readbuf,
		   const gdb_byte *writebuf,
		   ULONGEST offset, ULONGEST len, ULONGEST *xfered_len)
{
  pid_t pid = ptid_get_pid (inferior_ptid);

  switch (object)
    {
    case TARGET_OBJECT_AUXV:
      {
	struct cleanup *cleanup = make_cleanup (null_cleanup, NULL);
	unsigned char *buf;
	size_t buflen;
	int mib[4];

	if (writebuf != NULL)
	  return TARGET_XFER_E_IO;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_AUXV;
	mib[3] = pid;
	if (offset == 0)
	  {
	    buf = readbuf;
	    buflen = len;
	  }
	else
	  {
	    buflen = offset + len;
	    buf = XCNEWVEC (unsigned char, buflen);
	    cleanup = make_cleanup (xfree, buf);
	  }
	if (sysctl (mib, 4, buf, &buflen, NULL, 0) == 0)
	  {
	    if (offset != 0)
	      {
		if (buflen > offset)
		  {
		    buflen -= offset;
		    memcpy (readbuf, buf + offset, buflen);
		  }
		else
		  buflen = 0;
	      }
	    do_cleanups (cleanup);
	    *xfered_len = buflen;
	    return (buflen == 0) ? TARGET_XFER_EOF : TARGET_XFER_OK;
	  }
	do_cleanups (cleanup);
	return TARGET_XFER_E_IO;
      }
    default:
      return super_xfer_partial (ops, object, annex, readbuf, writebuf, offset,
				 len, xfered_len);
    }
}
#endif

#ifdef PT_LWPINFO
static int debug_fbsd_lwp;

static void (*super_resume) (struct target_ops *,
			     ptid_t,
			     int,
			     enum gdb_signal);
static ptid_t (*super_wait) (struct target_ops *,
			     ptid_t,
			     struct target_waitstatus *,
			     int);

static void
show_fbsd_lwp_debug (struct ui_file *file, int from_tty,
		     struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("Debugging of FreeBSD lwp module is %s.\n"), value);
}

#if defined(TDP_RFPPWAIT) || defined(HAVE_STRUCT_PTRACE_LWPINFO_PL_TDNAME)
/* Fetch the external variant of the kernel's internal process
   structure for the process PID into KP.  */

static void
fbsd_fetch_kinfo_proc (pid_t pid, struct kinfo_proc *kp)
{
  size_t len;
  int mib[4];

  len = sizeof *kp;
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = pid;
  if (sysctl (mib, 4, kp, &len, NULL, 0) == -1)
    perror_with_name (("sysctl"));
}
#endif

/*
  FreeBSD's first thread support was via a "reentrant" version of libc
  (libc_r) that first shipped in 2.2.7.  This library multiplexed all
  of the threads in a process onto a single kernel thread.  This
  library was supported via the bsd-uthread target.

  FreeBSD 5.1 introduced two new threading libraries that made use of
  multiple kernel threads.  The first (libkse) scheduled M user
  threads onto N (<= M) kernel threads (LWPs).  The second (libthr)
  bound each user thread to a dedicated kernel thread.  libkse shipped
  as the default threading library (libpthread).

  FreeBSD 5.3 added a libthread_db to abstract the interface across
  the various thread libraries (libc_r, libkse, and libthr).

  FreeBSD 7.0 switched the default threading library from from libkse
  to libpthread and removed libc_r.

  FreeBSD 8.0 removed libkse and the in-kernel support for it.  The
  only threading library supported by 8.0 and later is libthr which
  ties each user thread directly to an LWP.  To simplify the
  implementation, this target only supports LWP-backed threads using
  ptrace directly rather than libthread_db.

  FreeBSD 11.0 introduced LWP event reporting via PT_LWP_EVENTS.
*/

/* Return true if PTID is still active in the inferior.  */

static int
fbsd_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  if (ptid_lwp_p (ptid))
    {
      struct ptrace_lwpinfo pl;

      if (ptrace (PT_LWPINFO, ptid_get_lwp (ptid), (caddr_t) &pl, sizeof pl)
	  == -1)
	return 0;
#ifdef PL_FLAG_EXITED
      if (pl.pl_flags & PL_FLAG_EXITED)
	return 0;
#endif
    }

  return 1;
}

/* Convert PTID to a string.  Returns the string in a static
   buffer.  */

static const char *
fbsd_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  lwpid_t lwp;

  lwp = ptid_get_lwp (ptid);
  if (lwp != 0)
    {
      static char buf[64];
      int pid = ptid_get_pid (ptid);

      xsnprintf (buf, sizeof buf, "LWP %d of process %d", lwp, pid);
      return buf;
    }

  return normal_pid_to_str (ptid);
}

#ifdef HAVE_STRUCT_PTRACE_LWPINFO_PL_TDNAME
/* Return the name assigned to a thread by an application.  Returns
   the string in a static buffer.  */

static const char *
fbsd_thread_name (struct target_ops *self, struct thread_info *thr)
{
  struct ptrace_lwpinfo pl;
  struct kinfo_proc kp;
  int pid = ptid_get_pid (thr->ptid);
  long lwp = ptid_get_lwp (thr->ptid);
  static char buf[sizeof pl.pl_tdname + 1];

  /* Note that ptrace_lwpinfo returns the process command in pl_tdname
     if a name has not been set explicitly.  Return a NULL name in
     that case.  */
  fbsd_fetch_kinfo_proc (pid, &kp);
  if (ptrace (PT_LWPINFO, lwp, (caddr_t) &pl, sizeof pl) == -1)
    perror_with_name (("ptrace"));
  if (strcmp (kp.ki_comm, pl.pl_tdname) == 0)
    return NULL;
  xsnprintf (buf, sizeof buf, "%s", pl.pl_tdname);
  return buf;
}
#endif

/* Enable additional event reporting on new processes.

   To catch fork events, PTRACE_FORK is set on every traced process
   to enable stops on returns from fork or vfork.  Note that both the
   parent and child will always stop, even if system call stops are
   not enabled.

   To catch LWP events, PTRACE_EVENTS is set on every traced process.
   This enables stops on the birth for new LWPs (excluding the "main" LWP)
   and the death of LWPs (excluding the last LWP in a process).  Note
   that unlike fork events, the LWP that creates a new LWP does not
   report an event.  */

static void
fbsd_enable_proc_events (pid_t pid)
{
#ifdef PT_GET_EVENT_MASK
  int events;

  if (ptrace (PT_GET_EVENT_MASK, pid, (PTRACE_TYPE_ARG3)&events,
	      sizeof (events)) == -1)
    perror_with_name (("ptrace"));
  events |= PTRACE_FORK | PTRACE_LWP;
#ifdef PTRACE_VFORK
  events |= PTRACE_VFORK;
#endif
  if (ptrace (PT_SET_EVENT_MASK, pid, (PTRACE_TYPE_ARG3)&events,
	      sizeof (events)) == -1)
    perror_with_name (("ptrace"));
#else
#ifdef TDP_RFPPWAIT
  if (ptrace (PT_FOLLOW_FORK, pid, (PTRACE_TYPE_ARG3)0, 1) == -1)
    perror_with_name (("ptrace"));
#endif
#ifdef PT_LWP_EVENTS
  if (ptrace (PT_LWP_EVENTS, pid, (PTRACE_TYPE_ARG3)0, 1) == -1)
    perror_with_name (("ptrace"));
#endif
#endif
}

/* Add threads for any new LWPs in a process.

   When LWP events are used, this function is only used to detect existing
   threads when attaching to a process.  On older systems, this function is
   called to discover new threads each time the thread list is updated.  */

static void
fbsd_add_threads (pid_t pid)
{
  struct cleanup *cleanup;
  lwpid_t *lwps;
  int i, nlwps;

  gdb_assert (!in_thread_list (pid_to_ptid (pid)));
  nlwps = ptrace (PT_GETNUMLWPS, pid, NULL, 0);
  if (nlwps == -1)
    perror_with_name (("ptrace"));

  lwps = XCNEWVEC (lwpid_t, nlwps);
  cleanup = make_cleanup (xfree, lwps);

  nlwps = ptrace (PT_GETLWPLIST, pid, (caddr_t) lwps, nlwps);
  if (nlwps == -1)
    perror_with_name (("ptrace"));

  for (i = 0; i < nlwps; i++)
    {
      ptid_t ptid = ptid_build (pid, lwps[i], 0);

      if (!in_thread_list (ptid))
	{
#ifdef PT_LWP_EVENTS
	  struct ptrace_lwpinfo pl;

	  /* Don't add exited threads.  Note that this is only called
	     when attaching to a multi-threaded process.  */
	  if (ptrace (PT_LWPINFO, lwps[i], (caddr_t) &pl, sizeof pl) == -1)
	    perror_with_name (("ptrace"));
	  if (pl.pl_flags & PL_FLAG_EXITED)
	    continue;
#endif
	  if (debug_fbsd_lwp)
	    fprintf_unfiltered (gdb_stdlog,
				"FLWP: adding thread for LWP %u\n",
				lwps[i]);
	  add_thread (ptid);
	}
    }
  do_cleanups (cleanup);
}

/* Implement the "to_update_thread_list" target_ops method.  */

static void
fbsd_update_thread_list (struct target_ops *ops)
{
#ifdef PT_LWP_EVENTS
  /* With support for thread events, threads are added/deleted from the
     list as events are reported, so just try deleting exited threads.  */
  delete_exited_threads ();
#else
  prune_threads ();

  fbsd_add_threads (ptid_get_pid (inferior_ptid));
#endif
}

#ifdef TDP_RFPPWAIT
/*
  To catch fork events, PT_FOLLOW_FORK is set on every traced process
  to enable stops on returns from fork or vfork.  Note that both the
  parent and child will always stop, even if system call stops are not
  enabled.

  After a fork, both the child and parent process will stop and report
  an event.  However, there is no guarantee of order.  If the parent
  reports its stop first, then fbsd_wait explicitly waits for the new
  child before returning.  If the child reports its stop first, then
  the event is saved on a list and ignored until the parent's stop is
  reported.  fbsd_wait could have been changed to fetch the parent PID
  of the new child and used that to wait for the parent explicitly.
  However, if two threads in the parent fork at the same time, then
  the wait on the parent might return the "wrong" fork event.

  The initial version of PT_FOLLOW_FORK did not set PL_FLAG_CHILD for
  the new child process.  This flag could be inferred by treating any
  events for an unknown pid as a new child.

  In addition, the initial version of PT_FOLLOW_FORK did not report a
  stop event for the parent process of a vfork until after the child
  process executed a new program or exited.  The kernel was changed to
  defer the wait for exit or exec of the child until after posting the
  stop event shortly after the change to introduce PL_FLAG_CHILD.
  This could be worked around by reporting a vfork event when the
  child event posted and ignoring the subsequent event from the
  parent.

  This implementation requires both of these fixes for simplicity's
  sake.  FreeBSD versions newer than 9.1 contain both fixes.
*/

struct fbsd_fork_info
{
  struct fbsd_fork_info *next;
  ptid_t ptid;
};

static struct fbsd_fork_info *fbsd_pending_children;

/* Record a new child process event that is reported before the
   corresponding fork event in the parent.  */

static void
fbsd_remember_child (ptid_t pid)
{
  struct fbsd_fork_info *info = XCNEW (struct fbsd_fork_info);

  info->ptid = pid;
  info->next = fbsd_pending_children;
  fbsd_pending_children = info;
}

/* Check for a previously-recorded new child process event for PID.
   If one is found, remove it from the list and return the PTID.  */

static ptid_t
fbsd_is_child_pending (pid_t pid)
{
  struct fbsd_fork_info *info, *prev;
  ptid_t ptid;

  prev = NULL;
  for (info = fbsd_pending_children; info; prev = info, info = info->next)
    {
      if (ptid_get_pid (info->ptid) == pid)
	{
	  if (prev == NULL)
	    fbsd_pending_children = info->next;
	  else
	    prev->next = info->next;
	  ptid = info->ptid;
	  xfree (info);
	  return ptid;
	}
    }
  return null_ptid;
}

#ifndef PTRACE_VFORK
static struct fbsd_fork_info *fbsd_pending_vfork_done;

/* Record a pending vfork done event.  */

static void
fbsd_add_vfork_done (ptid_t pid)
{
  struct fbsd_fork_info *info = XCNEW (struct fbsd_fork_info);

  info->ptid = pid;
  info->next = fbsd_pending_vfork_done;
  fbsd_pending_vfork_done = info;
}

/* Check for a pending vfork done event for a specific PID.  */

static int
fbsd_is_vfork_done_pending (pid_t pid)
{
  struct fbsd_fork_info *info;

  for (info = fbsd_pending_vfork_done; info != NULL; info = info->next)
    {
      if (ptid_get_pid (info->ptid) == pid)
	return 1;
    }
  return 0;
}

/* Check for a pending vfork done event.  If one is found, remove it
   from the list and return the PTID.  */

static ptid_t
fbsd_next_vfork_done (void)
{
  struct fbsd_fork_info *info;
  ptid_t ptid;

  if (fbsd_pending_vfork_done != NULL)
    {
      info = fbsd_pending_vfork_done;
      fbsd_pending_vfork_done = info->next;
      ptid = info->ptid;
      xfree (info);
      return ptid;
    }
  return null_ptid;
}
#endif
#endif

/*
 * A new thread might report an event while single-stepping an
 * existing thread.  With LWP events, the new thread should always
 * report a born event (PL_FLAG_BORN) before any other events.
 * Without LWP events, a new thread can report some other event (such
 * as a breakpoint).  To detect this case, remember the last PTID
 * passed to resume.  In fbsd_wait(), fbsd_resume_ptid is used to
 * determine if a such an event occurred.  If it does, the new thread
 * is suspended via PT_SUSPEND and the process is continued via
 * PT_CONTINUE to wait for an event from the stepping thread.
 *
 * If the event reported for the new thread is a born event, the event
 * can be handled when it occurs by adding the new thread GDB's thread
 * list.  For systems without LWP events, the thread event needs to be
 * remembered so it can be reported later when the process is resumed
 * without single-stepping.
 */
static ptid_t fbsd_resume_ptid;
#ifndef PT_LWP_EVENTS
static int fbsd_resume_step;
static std::unordered_map<ptid_t, struct target_waitstatus> fbsd_suspended_lwps;

/* Return the ptid of a suspended thread that matches the ptid of the last
   resume request.  If no such thread is suspended, return null_ptid.  */

static ptid_t
fbsd_find_suspended_thread ()
{
  for (const auto &kv : fbsd_suspended_lwps)
    if (kv.first.matches (fbsd_resume_ptid))
      return kv.first;
  return null_ptid;
}
#endif

/* Implement the "to_resume" target_ops method.  */

static void
fbsd_resume (struct target_ops *ops,
	     ptid_t ptid, int step, enum gdb_signal signo)
{
#if defined(TDP_RFPPWAIT) && !defined(PTRACE_VFORK)
  pid_t pid;

  /* Don't PT_CONTINUE a process which has a pending vfork done event.  */
  if (ptid_equal (minus_one_ptid, ptid))
    pid = ptid_get_pid (inferior_ptid);
  else
    pid = ptid_get_pid (ptid);
  if (fbsd_is_vfork_done_pending (pid))
    return;
#endif

  if (debug_fbsd_lwp)
    fprintf_unfiltered (gdb_stdlog,
			"FLWP: fbsd_resume for ptid (%d, %ld, %ld)\n",
			ptid_get_pid (ptid), ptid_get_lwp (ptid),
			ptid_get_tid (ptid));
  fbsd_resume_ptid = ptid;
#ifndef PT_LWP_EVENTS
  fbsd_resume_step = step;
  /* If there are suspended threads that can now be resumed, don't
     resume any threads and don't call super_resume.  Instead, leave
     the process suspended and let fbsd_wait report one of the
     existing events.  This assumes that ptid passed to fbsd_wait is
     always a superset of the ptid passed to this function.  */
  if (fbsd_find_suspended_thread () != null_ptid)
    return;
#endif
  if (ptid_lwp_p (ptid))
    {
      /* If ptid is a specific LWP, suspend all other LWPs in the process.  */
      struct thread_info *tp;
      int request;

      ALL_NON_EXITED_THREADS (tp)
        {
	  if (ptid_get_pid (tp->ptid) != ptid_get_pid (ptid))
	    continue;

#ifndef PT_LWP_EVENTS
	  /* If a new thread has been suspended while single-stepping
	     another thread, leave it suspended until its existing
	     event has been reported.  */
	  if (fbsd_suspended_lwps.find (ptid) != fbsd_suspended_lwps.end ())
	    continue;
#endif

	  if (ptid_get_lwp (tp->ptid) == ptid_get_lwp (ptid))
	    request = PT_RESUME;
	  else
	    request = PT_SUSPEND;

	  if (ptrace (request, ptid_get_lwp (tp->ptid), NULL, 0) == -1)
	    perror_with_name (("ptrace"));
	}
    }
  else
    {
      /* If ptid is a wildcard, resume all matching threads (they won't run
	 until the process is continued however).  */
      struct thread_info *tp;

      ALL_NON_EXITED_THREADS (tp)
        {
	  if (!ptid_match (tp->ptid, ptid))
	    continue;

	  if (ptrace (PT_RESUME, ptid_get_lwp (tp->ptid), NULL, 0) == -1)
	    perror_with_name (("ptrace"));
	}
      ptid = inferior_ptid;
    }
  super_resume (ops, ptid, step, signo);
}

/* Wait for the child specified by PTID to do something.  Return the
   process ID of the child, or MINUS_ONE_PTID in case of error; store
   the status in *OURSTATUS.  */

static ptid_t
fbsd_wait (struct target_ops *ops,
	   ptid_t ptid, struct target_waitstatus *ourstatus,
	   int target_options)
{
  ptid_t wptid;

  while (1)
    {
#ifndef PTRACE_VFORK
      wptid = fbsd_next_vfork_done ();
      if (!ptid_equal (wptid, null_ptid))
	{
	  ourstatus->kind = TARGET_WAITKIND_VFORK_DONE;
	  return wptid;
	}
#endif
#ifndef PT_LWP_EVENTS
      /* Check for any new threads that were previously suspended that
	 can now be reported.  */
      wptid = fbsd_find_suspended_thread ();
      if (wptid != null_ptid)
	{
	  auto it = fbsd_suspended_lwps.find (wptid);
	  *ourstatus = it->second;
	  if (debug_fbsd_lwp)
	    fprintf_unfiltered (gdb_stdlog, "FLWP: resuming new LWP %lu\n",
				wptid.lwp ());
	  fbsd_suspended_lwps.erase (it);
	}
      else
#endif
      wptid = super_wait (ops, ptid, ourstatus, target_options);
      if (ourstatus->kind == TARGET_WAITKIND_STOPPED)
	{
	  struct ptrace_lwpinfo pl;
	  pid_t pid;
	  int status;

	  pid = ptid_get_pid (wptid);

#ifndef PT_LWP_EVENTS
	  /* If wptid contains an LWP, it is a new thread that was
	     previously suspended.  In that case, the LWP ID must be
	     used with PT_LWPINFO.  Otherwise, the pid reported by
	     wait from super_wait should be used.  */
	  if (wptid.lwp_p ())
	    {
	      if (ptrace (PT_LWPINFO, wptid.lwp (), (caddr_t) &pl, sizeof pl)
		  == -1)
		perror_with_name (("ptrace"));
	    }
	  else
#endif
	    {
	      if (ptrace (PT_LWPINFO, pid, (caddr_t) &pl, sizeof pl) == -1)
		perror_with_name (("ptrace"));

	      wptid = ptid_build (pid, pl.pl_lwpid, 0);
	    }

#ifdef PT_LWP_EVENTS
	  if (pl.pl_flags & PL_FLAG_EXITED)
	    {
	      /* If GDB attaches to a multi-threaded process, exiting
		 threads might be skipped during fbsd_post_attach that
		 have not yet reported their PL_FLAG_EXITED event.
		 Ignore EXITED events for an unknown LWP.  */
	      if (in_thread_list (wptid))
		{
		  if (debug_fbsd_lwp)
		    fprintf_unfiltered (gdb_stdlog,
					"FLWP: deleting thread for LWP %u\n",
					pl.pl_lwpid);
		  if (print_thread_events)
		    printf_unfiltered (_("[%s exited]\n"), target_pid_to_str
				       (wptid));
		  delete_thread (wptid);
		}
	      if (ptrace (PT_CONTINUE, pid, (caddr_t) 1, 0) == -1)
		perror_with_name (("ptrace"));
	      continue;
	    }
#endif

	  /* Switch to an LWP PTID on the first stop in a new process.
	     This is done after handling PL_FLAG_EXITED to avoid
	     switching to an exited LWP.  It is done before checking
	     PL_FLAG_BORN in case the first stop reported after
	     attaching to an existing process is a PL_FLAG_BORN
	     event.  */
	  if (in_thread_list (pid_to_ptid (pid)))
	    {
	      if (debug_fbsd_lwp)
		fprintf_unfiltered (gdb_stdlog,
				    "FLWP: using LWP %u for first thread\n",
				    pl.pl_lwpid);
	      thread_change_ptid (pid_to_ptid (pid), wptid);
	    }

#ifdef PT_LWP_EVENTS
	  if (pl.pl_flags & PL_FLAG_BORN)
	    {
	      /* If GDB attaches to a multi-threaded process, newborn
		 threads might be added by fbsd_add_threads that have
		 not yet reported their PL_FLAG_BORN event.  Ignore
		 BORN events for an already-known LWP.  */
	      if (!in_thread_list (wptid))
		{
		  if (debug_fbsd_lwp)
		    fprintf_unfiltered (gdb_stdlog,
					"FLWP: adding thread for LWP %u\n",
					pl.pl_lwpid);
		  add_thread (wptid);
		}
	      if (fbsd_resume_ptid.lwp_p () && fbsd_resume_ptid != wptid)
		{
		  if (debug_fbsd_lwp)
		    fprintf_unfiltered (gdb_stdlog,
					"FLWP: suspending thread for LWP %u\n",
					pl.pl_lwpid);
		  if (ptrace (PT_SUSPEND, wptid.lwp (), NULL, 0) == -1)
		    perror_with_name (("ptrace"));
		}
	      if (ptrace (PT_CONTINUE, pid, (caddr_t) 1, 0) == -1)
		perror_with_name (("ptrace"));
	      continue;
	    }
#else
	  /*
	   * A new thread might have been created while
	   * single-stepping an existing thread.  If so, add the new
	   * thread to GDB's thread list and suspend it.  It will be
	   * resumed once it has been reported to GDB by a future
	   * wait.
	   */
	  if (fbsd_resume_ptid.lwp_p () && fbsd_resume_ptid != wptid)
	    {
	      if (!in_thread_list (wptid))
		{
		  if (debug_fbsd_lwp)
		    fprintf_unfiltered (gdb_stdlog,
					"FLWP: adding thread for LWP %u\n",
					pl.pl_lwpid);
		  add_thread (wptid);
		}
	      if (debug_fbsd_lwp)
		fprintf_unfiltered (gdb_stdlog,
				    "FLWP: suspending thread for LWP %u\n",
				    pl.pl_lwpid);
	      gdb_assert (fbsd_suspended_lwps.find (wptid)
			  == fbsd_suspended_lwps.end ());
	      fbsd_suspended_lwps.emplace (wptid, *ourstatus);
	      if (ptrace (PT_SUSPEND, wptid.lwp (), NULL, 0) == -1)
		perror_with_name (("ptrace"));
	      if (ptrace (PT_CONTINUE, pid, (caddr_t) 1, 0) == -1)
		perror_with_name (("ptrace"));
	      continue;
	    }
#endif

#ifdef TDP_RFPPWAIT
	  if (pl.pl_flags & PL_FLAG_FORKED)
	    {
#ifndef PTRACE_VFORK
	      struct kinfo_proc kp;
#endif
	      ptid_t child_ptid;
	      pid_t child;

	      child = pl.pl_child_pid;
	      ourstatus->kind = TARGET_WAITKIND_FORKED;
#ifdef PTRACE_VFORK
	      if (pl.pl_flags & PL_FLAG_VFORKED)
		ourstatus->kind = TARGET_WAITKIND_VFORKED;
#endif

	      /* Make sure the other end of the fork is stopped too.  */
	      child_ptid = fbsd_is_child_pending (child);
	      if (ptid_equal (child_ptid, null_ptid))
		{
		  pid = waitpid (child, &status, 0);
		  if (pid == -1)
		    perror_with_name (("waitpid"));

		  gdb_assert (pid == child);

		  if (ptrace (PT_LWPINFO, child, (caddr_t)&pl, sizeof pl) == -1)
		    perror_with_name (("ptrace"));

		  gdb_assert (pl.pl_flags & PL_FLAG_CHILD);
		  child_ptid = ptid_build (child, pl.pl_lwpid, 0);
		}

	      /* Enable additional events on the child process.  */
	      fbsd_enable_proc_events (ptid_get_pid (child_ptid));

#ifndef PTRACE_VFORK
	      /* For vfork, the child process will have the P_PPWAIT
		 flag set.  */
	      fbsd_fetch_kinfo_proc (child, &kp);
	      if (kp.ki_flag & P_PPWAIT)
		ourstatus->kind = TARGET_WAITKIND_VFORKED;
#endif
	      ourstatus->value.related_pid = child_ptid;

	      return wptid;
	    }

	  if (pl.pl_flags & PL_FLAG_CHILD)
	    {
	      /* Remember that this child forked, but do not report it
		 until the parent reports its corresponding fork
		 event.  */
	      fbsd_remember_child (wptid);
	      continue;
	    }

#ifdef PTRACE_VFORK
	  if (pl.pl_flags & PL_FLAG_VFORK_DONE)
	    {
	      ourstatus->kind = TARGET_WAITKIND_VFORK_DONE;
	      return wptid;
	    }
#endif
#endif

#ifdef PL_FLAG_EXEC
	  if (pl.pl_flags & PL_FLAG_EXEC)
	    {
	      ourstatus->kind = TARGET_WAITKIND_EXECD;
	      ourstatus->value.execd_pathname
		= xstrdup (fbsd_pid_to_exec_file (NULL, pid));
	      return wptid;
	    }
#endif

	  /* Note that PL_FLAG_SCE is set for any event reported while
	     a thread is executing a system call in the kernel.  In
	     particular, signals that interrupt a sleep in a system
	     call will report this flag as part of their event.  Stops
	     explicitly for system call entry and exit always use
	     SIGTRAP, so only treat SIGTRAP events as system call
	     entry/exit events.  */
	  if (pl.pl_flags & (PL_FLAG_SCE | PL_FLAG_SCX)
	      && ourstatus->value.sig == SIGTRAP)
	    {
#ifdef HAVE_STRUCT_PTRACE_LWPINFO_PL_SYSCALL_CODE
	      if (catch_syscall_enabled ())
		{
		  if (catching_syscall_number (pl.pl_syscall_code))
		    {
		      if (pl.pl_flags & PL_FLAG_SCE)
			ourstatus->kind = TARGET_WAITKIND_SYSCALL_ENTRY;
		      else
			ourstatus->kind = TARGET_WAITKIND_SYSCALL_RETURN;
		      ourstatus->value.syscall_number = pl.pl_syscall_code;
		      return wptid;
		    }
		}
#endif
	      /* If the core isn't interested in this event, just
		 continue the process explicitly and wait for another
		 event.  Note that PT_SYSCALL is "sticky" on FreeBSD
		 and once system call stops are enabled on a process
		 it stops for all system call entries and exits.  */
#ifdef PT_LWP_EVENTS
	      if (ptrace (PT_CONTINUE, pid, (caddr_t) 1, 0) == -1)
		perror_with_name (("ptrace"));
#else
	      /* If this event was from a suspended thread, the full
		 logic in fbsd_resume (suspending and resuming threads
		 and whether or not to actually resume the process)
		 needs to be run.  */
	      fbsd_resume (ops, fbsd_resume_ptid, fbsd_resume_step,
			   GDB_SIGNAL_0);
#endif
	      continue;
	    }
	}
      return wptid;
    }
}

#ifdef TDP_RFPPWAIT
/* Target hook for follow_fork.  On entry and at return inferior_ptid is
   the ptid of the followed inferior.  */

static int
fbsd_follow_fork (struct target_ops *ops, int follow_child,
			int detach_fork)
{
  if (!follow_child && detach_fork)
    {
      struct thread_info *tp = inferior_thread ();
      pid_t child_pid = ptid_get_pid (tp->pending_follow.value.related_pid);

      /* Breakpoints have already been detached from the child by
	 infrun.c.  */

      if (ptrace (PT_DETACH, child_pid, (PTRACE_TYPE_ARG3)1, 0) == -1)
	perror_with_name (("ptrace"));

#ifndef PTRACE_VFORK
      if (tp->pending_follow.kind == TARGET_WAITKIND_VFORKED)
	{
	  /* We can't insert breakpoints until the child process has
	     finished with the shared memory region.  The parent
	     process doesn't wait for the child process to exit or
	     exec until after it has been resumed from the ptrace stop
	     to report the fork.  Once it has been resumed it doesn't
	     stop again before returning to userland, so there is no
	     reliable way to wait on the parent.

	     We can't stay attached to the child to wait for an exec
	     or exit because it may invoke ptrace(PT_TRACE_ME)
	     (e.g. if the parent process is a debugger forking a new
	     child process).

	     In the end, the best we can do is to make sure it runs
	     for a little while.  Hopefully it will be out of range of
	     any breakpoints we reinsert.  Usually this is only the
	     single-step breakpoint at vfork's return point.  */

	  usleep (10000);

	  /* Schedule a fake VFORK_DONE event to report on the next
	     wait.  */
	  fbsd_add_vfork_done (inferior_ptid);
	}
#endif
    }

  return 0;
}

static int
fbsd_insert_fork_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}

static int
fbsd_remove_fork_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}

static int
fbsd_insert_vfork_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}

static int
fbsd_remove_vfork_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}
#endif

/* Implement the "to_post_startup_inferior" target_ops method.  */

static void
fbsd_post_startup_inferior (struct target_ops *self, ptid_t pid)
{
  fbsd_resume_ptid = null_ptid;
  fbsd_enable_proc_events (ptid_get_pid (pid));
}

/* Implement the "to_post_attach" target_ops method.  */

static void
fbsd_post_attach (struct target_ops *self, int pid)
{
  fbsd_resume_ptid = null_ptid;
  fbsd_enable_proc_events (pid);
  fbsd_add_threads (pid);
}

#ifdef PL_FLAG_EXEC
/* If the FreeBSD kernel supports PL_FLAG_EXEC, then traced processes
   will always stop after exec.  */

static int
fbsd_insert_exec_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}

static int
fbsd_remove_exec_catchpoint (struct target_ops *self, int pid)
{
  return 0;
}
#endif

#ifdef HAVE_STRUCT_PTRACE_LWPINFO_PL_SYSCALL_CODE
static int
fbsd_set_syscall_catchpoint (struct target_ops *self, int pid, int needed,
			     int any_count, int table_size, int *table)
{

  /* Ignore the arguments.  inf-ptrace.c will use PT_SYSCALL which
     will catch all system call entries and exits.  The system calls
     are filtered by GDB rather than the kernel.  */
  return 0;
}
#endif
#endif

void
fbsd_nat_add_target (struct target_ops *t)
{
  t->to_pid_to_exec_file = fbsd_pid_to_exec_file;
  t->to_find_memory_regions = fbsd_find_memory_regions;
#ifdef KERN_PROC_AUXV
  super_xfer_partial = t->to_xfer_partial;
  t->to_xfer_partial = fbsd_xfer_partial;
#endif
#ifdef PT_LWPINFO
  t->to_thread_alive = fbsd_thread_alive;
  t->to_pid_to_str = fbsd_pid_to_str;
#ifdef HAVE_STRUCT_PTRACE_LWPINFO_PL_TDNAME
  t->to_thread_name = fbsd_thread_name;
#endif
  t->to_update_thread_list = fbsd_update_thread_list;
  t->to_has_thread_control = tc_schedlock;
  super_resume = t->to_resume;
  t->to_resume = fbsd_resume;
  super_wait = t->to_wait;
  t->to_wait = fbsd_wait;
  t->to_post_startup_inferior = fbsd_post_startup_inferior;
  t->to_post_attach = fbsd_post_attach;
#ifdef TDP_RFPPWAIT
  t->to_follow_fork = fbsd_follow_fork;
  t->to_insert_fork_catchpoint = fbsd_insert_fork_catchpoint;
  t->to_remove_fork_catchpoint = fbsd_remove_fork_catchpoint;
  t->to_insert_vfork_catchpoint = fbsd_insert_vfork_catchpoint;
  t->to_remove_vfork_catchpoint = fbsd_remove_vfork_catchpoint;
#endif
#ifdef PL_FLAG_EXEC
  t->to_insert_exec_catchpoint = fbsd_insert_exec_catchpoint;
  t->to_remove_exec_catchpoint = fbsd_remove_exec_catchpoint;
#endif
#ifdef HAVE_STRUCT_PTRACE_LWPINFO_PL_SYSCALL_CODE
  t->to_set_syscall_catchpoint = fbsd_set_syscall_catchpoint;
#endif
#endif
  add_target (t);
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_fbsd_nat;

void
_initialize_fbsd_nat (void)
{
#ifdef PT_LWPINFO
  add_setshow_boolean_cmd ("fbsd-lwp", class_maintenance,
			   &debug_fbsd_lwp, _("\
Set debugging of FreeBSD lwp module."), _("\
Show debugging of FreeBSD lwp module."), _("\
Enables printf debugging output."),
			   NULL,
			   &show_fbsd_lwp_debug,
			   &setdebuglist, &showdebuglist);
#endif
}
