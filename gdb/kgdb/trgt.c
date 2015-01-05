/*
 * Copyright (c) 2004 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/gnu/usr.bin/gdb/kgdb/trgt.c 260601 2014-01-13 19:08:25Z marcel $");

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>

#include <defs.h>
#include <readline/readline.h>
#include <readline/tilde.h>
#include <command.h>
#include <exec.h>
#include <frame-unwind.h>
#include <gdb.h>
#include <gdbcore.h>
#include <gdbthread.h>
#include "gdb_obstack.h"
#include <inferior.h>
#include <language.h>
#include "objfiles.h"
#include <regcache.h>
#include <solib.h>
#include <target.h>
#include <ui-out.h>

#include "kgdb.h"

static CORE_ADDR stoppcbs;

static void	kgdb_core_cleanup(void *);

static char *vmcore;
static struct target_ops kgdb_trgt_ops;

/* Per-architecture data key.  */
static struct gdbarch_data *fbsd_vmcore_data;

struct fbsd_vmcore_ops
{
  /* Supply registers for a pcb to a register cache.  */
  void (*supply_pcb)(struct regcache *, CORE_ADDR);

  /* Return address of pcb for thread running on a CPU. */
  CORE_ADDR (*cpu_pcb_addr)(u_int);
};

static void *
fbsd_vmcore_init (struct obstack *obstack)
{
  struct fbsd_vmcore_ops *ops;

  ops = OBSTACK_ZALLOC (obstack, struct fbsd_vmcore_ops);
  return ops;
}

/* Set the function that supplies registers from a pcb
   for architecture GDBARCH to SUPPLY_PCB.  */

void
fbsd_vmcore_set_supply_pcb (struct gdbarch *gdbarch,
			    void (*supply_pcb) (struct regcache *,
						CORE_ADDR))
{
  struct fbsd_vmcore_ops *ops = gdbarch_data (gdbarch, fbsd_vmcore_data);
  ops->supply_pcb = supply_pcb;
}

/* Set the function that returns the address of the pcb for a thread
   running on a CPU for
   architecture GDBARCH to CPU_PCB_ADDR.  */

void
fbsd_vmcore_set_cpu_pcb_addr (struct gdbarch *gdbarch,
			      CORE_ADDR (*cpu_pcb_addr) (u_int))
{
  struct fbsd_vmcore_ops *ops = gdbarch_data (gdbarch, fbsd_vmcore_data);
  ops->cpu_pcb_addr = cpu_pcb_addr;
}

kvm_t *kvm;
static char kvm_err[_POSIX2_LINE_MAX];

#define	KERNOFF		(kgdb_kernbase ())
#define	INKERNEL(x)	((x) >= KERNOFF)

static CORE_ADDR
kgdb_kernbase (void)
{
	static CORE_ADDR kernbase;
	struct bound_minimal_symbol msym;

	if (kernbase == 0) {
		msym = lookup_minimal_symbol ("kernbase", NULL, NULL);
		if (msym.minsym == NULL) {
			kernbase = KERNBASE;
		} else {
			kernbase = BMSYMBOL_VALUE_ADDRESS (msym);
		}
	}
	return kernbase;
}

static void
kgdb_trgt_open(char *filename, int from_tty)
{
	struct fbsd_vmcore_ops *ops = gdbarch_data (target_gdbarch(),
	    fbsd_vmcore_data);
	struct cleanup *old_chain;
	struct thread_info *ti;
	struct kthr *kt;
	kvm_t *nkvm;
	char *temp, *kernel;
	int ontop;

	if (ops == NULL || ops->supply_pcb == NULL || ops->cpu_pcb_addr == NULL)
		error ("ABI doesn't support a vmcore target");

	target_preopen (from_tty);
	kernel = get_exec_file (1);
	if (kernel == NULL)
		error ("Can't open a vmcore without a kernel");

	if (filename) {
		filename = tilde_expand (filename);
		if (filename[0] != '/') {
			temp = concat (current_directory, "/", filename, NULL);
			xfree(filename);
			filename = temp;
		}
	}

	old_chain = make_cleanup (xfree, filename);

	nkvm = kvm_openfiles(kernel, filename, NULL,
	    write_files ? O_RDWR : O_RDONLY, kvm_err);
	if (nkvm == NULL)
		error ("Failed to open vmcore: %s", kvm_err);

	/* Don't free the filename now and close any previous vmcore. */
	discard_cleanups(old_chain);
	unpush_target(&kgdb_trgt_ops);

	kvm = nkvm;
	vmcore = filename;
	old_chain = make_cleanup(kgdb_core_cleanup, NULL);

	push_target (&kgdb_trgt_ops);
	discard_cleanups (old_chain);

	kgdb_dmesg();

	init_thread_list();
	kt = kgdb_thr_init(ops->cpu_pcb_addr);
	while (kt != NULL) {
		ti = add_thread(pid_to_ptid(kt->tid));
		kt = kgdb_thr_next(kt);
	}
	if (curkthr != 0)
		inferior_ptid = pid_to_ptid(curkthr->tid);

#if 1
	target_fetch_registers (get_current_regcache (), -1);

	reinit_frame_cache ();
	print_stack_frame (get_selected_frame (NULL), 0, SRC_AND_LOC, 1);
#else	
	flush_cached_frames();
	select_frame (get_current_frame());
	print_stack_frame(get_selected_frame(),
	    frame_relative_level(get_selected_frame()), 1);
#endif
}

static void
kgdb_trgt_close(struct target_ops *self)
{

	if (kvm != NULL) {
		clear_solib();
		if (kvm_close(kvm) != 0)
			warning("cannot close \"%s\": %s", vmcore,
			    kvm_geterr(kvm));
		kvm = NULL;
		xfree(vmcore);
		vmcore = NULL;
	}

	inferior_ptid = null_ptid;
}

static void
kgdb_core_cleanup(void *arg)
{

	kgdb_trgt_close(0);
}

static void
kgdb_trgt_detach(struct target_ops *ops, const char *args, int from_tty)
{

	if (args)
		error ("Too many arguments");
	unpush_target(&kgdb_trgt_ops);
	reinit_frame_cache();
	if (from_tty)
		printf_filtered("No vmcore file now.\n");
}

static char *
kgdb_trgt_extra_thread_info(struct target_ops *ops, struct thread_info *ti)
{

	return (kgdb_thr_extra_thread_info(ptid_get_pid(ti->ptid)));
}

static void
kgdb_trgt_files_info(struct target_ops *target)
{

	printf_filtered ("\t`%s', ", vmcore);
	wrap_here ("        ");
	printf_filtered ("file type %s.\n", "FreeBSD kernel vmcore");
}

static void
kgdb_trgt_find_new_threads(struct target_ops *ops)
{
	/*
	 * XXX: We should probably rescan the thread list here and update
	 * it if there are any changes.  One nit though is that we'd have
	 * to detect exited threads.
	 */
	gdb_assert(kvm != NULL);
#if 0
	struct target_ops *tb;
	
	if (kvm != NULL)
		return;

	tb = find_target_beneath(ops);
	if (tb->to_find_new_threads != NULL)
		tb->to_find_new_threads(tb);
#endif
}

static char *
kgdb_trgt_pid_to_str(struct target_ops *ops, ptid_t ptid)
{
	static char buf[33];

	snprintf(buf, sizeof(buf), "Thread %d", ptid_get_pid(ptid));
	return (buf);
}

static int
kgdb_trgt_thread_alive(struct target_ops *ops, ptid_t ptid)
{
	return (kgdb_thr_lookup_tid(ptid_get_pid(ptid)) != NULL);
}

static void
kgdb_trgt_fetch_registers(struct target_ops *tops,
			  struct regcache *regcache, int regnum)
{
	struct fbsd_vmcore_ops *ops = gdbarch_data (target_gdbarch(),
	    fbsd_vmcore_data);
	struct kthr *kt;

	if (ops->supply_pcb == NULL)
		return;
	kt = kgdb_thr_lookup_tid(ptid_get_pid(inferior_ptid));
	if (kt == NULL)
		return;
	ops->supply_pcb(regcache, kt->pcb);
}

static enum target_xfer_status
kgdb_trgt_xfer_partial(struct target_ops *ops, enum target_object object,
		       const char *annex, gdb_byte *readbuf,
		       const gdb_byte *writebuf,
		       ULONGEST offset, ULONGEST len, ULONGEST *xfered_len)
{
	ssize_t nbytes;

	gdb_assert(kvm != NULL);
	switch (object) {
	case TARGET_OBJECT_MEMORY:
		nbytes = len;
		if (readbuf != NULL)
			nbytes = kvm_read(kvm, offset, readbuf, len);
		if (writebuf != NULL && len > 0)
			nbytes = kvm_write(kvm, offset, writebuf, len);
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

static int
kgdb_trgt_ignore_breakpoints(struct target_ops *ops, struct gdbarch *gdbarch,
    struct bp_target_info *bp_tgt)
{

	return 0;
}

static void
kgdb_switch_to_thread(int tid)
{
	char buf[16];
	int thread_id;

	thread_id = pid_to_thread_id(pid_to_ptid(tid));
	if (thread_id == 0)
		error ("invalid tid");
	snprintf(buf, sizeof(buf), "%d", thread_id);
	gdb_thread_select(current_uiout, buf, NULL);
}

static void
kgdb_set_proc_cmd (char *arg, int from_tty)
{
	CORE_ADDR addr;
	struct kthr *thr;

	if (!arg)
		error_no_arg ("proc address for the new context");

	if (kvm == NULL)
		error ("only supported for core file target");

	addr = parse_and_eval_address (arg);

	if (!INKERNEL (addr)) {
		thr = kgdb_thr_lookup_pid((int)addr);
		if (thr == NULL)
			error ("invalid pid");
	} else {
		thr = kgdb_thr_lookup_paddr(addr);
		if (thr == NULL)
			error("invalid proc address");
	}
	kgdb_switch_to_thread(thr->tid);
}

static void
kgdb_set_tid_cmd (char *arg, int from_tty)
{
	CORE_ADDR addr;
	struct kthr *thr;

	if (!arg)
		error_no_arg ("TID or thread address for the new context");

	addr = (CORE_ADDR) parse_and_eval_address (arg);

	if (kvm != NULL && INKERNEL (addr)) {
		thr = kgdb_thr_lookup_taddr(addr);
		if (thr == NULL)
			error("invalid thread address");
		addr = thr->tid;
	}
	kgdb_switch_to_thread(addr);
}

static int
kgdb_trgt_return_one(struct target_ops *ops)
{

	return 1;
}

void
initialize_kgdb_target(void)
{

	kgdb_trgt_ops.to_magic = OPS_MAGIC;
	kgdb_trgt_ops.to_shortname = "vmcore";
	kgdb_trgt_ops.to_longname = "kernel core dump file";
	kgdb_trgt_ops.to_doc = 
    "Use a vmcore file as a target.  Specify the filename of the vmcore file.";
	kgdb_trgt_ops.to_stratum = process_stratum;
	kgdb_trgt_ops.to_has_memory = kgdb_trgt_return_one;
	kgdb_trgt_ops.to_has_registers = kgdb_trgt_return_one;
	kgdb_trgt_ops.to_has_stack = kgdb_trgt_return_one;

	kgdb_trgt_ops.to_open = kgdb_trgt_open;
	kgdb_trgt_ops.to_close = kgdb_trgt_close;
	kgdb_trgt_ops.to_attach = find_default_attach;
	kgdb_trgt_ops.to_detach = kgdb_trgt_detach;
	kgdb_trgt_ops.to_extra_thread_info = kgdb_trgt_extra_thread_info;
	kgdb_trgt_ops.to_fetch_registers = kgdb_trgt_fetch_registers;
	kgdb_trgt_ops.to_files_info = kgdb_trgt_files_info;
	kgdb_trgt_ops.to_find_new_threads = kgdb_trgt_find_new_threads;
	kgdb_trgt_ops.to_pid_to_str = kgdb_trgt_pid_to_str;
	kgdb_trgt_ops.to_thread_alive = kgdb_trgt_thread_alive;
	kgdb_trgt_ops.to_xfer_partial = kgdb_trgt_xfer_partial;
	kgdb_trgt_ops.to_insert_breakpoint = kgdb_trgt_ignore_breakpoints;
	kgdb_trgt_ops.to_remove_breakpoint = kgdb_trgt_ignore_breakpoints;

	add_target(&kgdb_trgt_ops);

	add_com ("proc", class_obscure, kgdb_set_proc_cmd,
	   "Set current process context");
	add_com ("tid", class_obscure, kgdb_set_tid_cmd,
	   "Set current thread context");
}

CORE_ADDR
kgdb_trgt_stop_pcb(u_int cpuid, u_int pcbsz)
{
	static int once = 0;

	if (stoppcbs == 0 && !once) {
		once = 1;
		stoppcbs = kgdb_lookup("stoppcbs");
	}
	if (stoppcbs == 0)
		return 0;

	return (stoppcbs + pcbsz * cpuid);
}
