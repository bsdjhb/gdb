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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/gnu/usr.bin/gdb/kgdb/trgt_i386.c 274391 2014-11-11 18:54:57Z dim $");

#include <sys/param.h>
#include <sys/proc.h>
#include <machine/pcb.h>
#include <machine/frame.h>
#include <machine/segments.h>
#include <machine/tss.h>
#include <err.h>
#include <kvm.h>
#include <string.h>

#include <defs.h>
#include "osabi.h"
#include <target.h>
#include "gdbcore.h"
#include <gdbthread.h>
#include <inferior.h>
#include <regcache.h>
#include <frame-unwind.h>
#include <i386-tdep.h>
#include "solib.h"
#include "trad-frame.h"

#include "kgdb.h"

struct i386fbsd_info {
	int ofs_fix;
};

/* Per-program-space data key.  */
static const struct program_space_data *i386fbsd_pspace_data;

static void
i386fbsd_pspace_data_cleanup (struct program_space *pspace, void *arg)
{
  struct i386fbsd_info *info = arg;

  xfree (info);
}

/* Get the current i386fbsd data.  If none is found yet, add it now.  This
   function always returns a valid object.  */

static struct i386fbsd_info *
get_i386fbsd_info (void)
{
  struct i386fbsd_info *info;

  info = program_space_data (current_program_space, i386fbsd_pspace_data);
  if (info != NULL)
    return info;

  info = XCNEW (struct i386fbsd_info);
  set_program_space_data (current_program_space, i386fbsd_pspace_data, info);

  /*
   * In revision 1.117 of i386/i386/exception.S trap handlers
   * were changed to pass trapframes by reference rather than
   * by value.  Detect this by seeing if the first instruction
   * at the 'calltrap' label is a "push %esp" which has the
   * opcode 0x54.
   */
  if (kgdb_parse("((char *)calltrap)[0]") == 0x54)
    info->ofs_fix = 4;
  else
    info->ofs_fix = 0;
  return info;
}

static CORE_ADDR
i386fbsd_cpu_pcb_addr(u_int cpuid)
{
	return (kgdb_trgt_stop_pcb(cpuid, sizeof(struct pcb)));
}

static void
i386fbsd_supply_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
	struct pcb pcb;

	if (kvm_read(kvm, pcb_addr, &pcb, sizeof(pcb)) != sizeof(pcb)) {
		warnx("kvm_read: %s", kvm_geterr(kvm));
		memset(&pcb, 0, sizeof(pcb));
	}
	regcache_raw_supply(regcache, I386_EBX_REGNUM, (char *)&pcb.pcb_ebx);
	regcache_raw_supply(regcache, I386_ESP_REGNUM, (char *)&pcb.pcb_esp);
	regcache_raw_supply(regcache, I386_EBP_REGNUM, (char *)&pcb.pcb_ebp);
	regcache_raw_supply(regcache, I386_ESI_REGNUM, (char *)&pcb.pcb_esi);
	regcache_raw_supply(regcache, I386_EDI_REGNUM, (char *)&pcb.pcb_edi);
	regcache_raw_supply(regcache, I386_EIP_REGNUM, (char *)&pcb.pcb_eip);
	regcache_raw_supply_unsigned(regcache, I386_CS_REGNUM,
	    GSEL(GCODE_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, I386_DS_REGNUM,
	    GSEL(GDATA_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, I386_ES_REGNUM,
	    GSEL(GDATA_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, I386_FS_REGNUM,
	    GSEL(GPRIV_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, I386_GS_REGNUM,
	    GSEL(GDATA_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, I386_SS_REGNUM,
	    GSEL(GDATA_SEL, SEL_KPL));
}

static int i386fbsd_tss_offset[15] = {
	offsetof(struct i386tss, tss_eax),
	offsetof(struct i386tss, tss_ecx),
	offsetof(struct i386tss, tss_edx),
	offsetof(struct i386tss, tss_ebx),
	offsetof(struct i386tss, tss_esp),
	offsetof(struct i386tss, tss_ebp),
	offsetof(struct i386tss, tss_esi),
	offsetof(struct i386tss, tss_edi),
	offsetof(struct i386tss, tss_eip),
	offsetof(struct i386tss, tss_eflags),
	offsetof(struct i386tss, tss_cs),
	offsetof(struct i386tss, tss_ss),
	offsetof(struct i386tss, tss_ds),
	offsetof(struct i386tss, tss_es),
	offsetof(struct i386tss, tss_fs)
};

/*
 * If the current thread is executing on a CPU, fetch the common_tss
 * for that CPU.
 *
 * This is painful because 'struct pcpu' is variant sized, so we can't
 * use it.  Instead, we lookup the GDT selector for this CPU and
 * extract the base of the TSS from there.
 */
static CORE_ADDR
i386fbsd_fetch_tss(void)
{
	struct kthr *kt;
	struct segment_descriptor sd;
	uintptr_t addr, cpu0prvpage, tss;

	kt = kgdb_thr_lookup_tid(ptid_get_tid(inferior_ptid));
	if (kt == NULL || kt->cpu == NOCPU || kt->cpu < 0)
		return (0);

	addr = kgdb_lookup("gdt");
	if (addr == 0)
		return (0);
	addr += (kt->cpu * NGDT + GPROC0_SEL) * sizeof(sd);
	if (kvm_read(kvm, addr, &sd, sizeof(sd)) != sizeof(sd)) {
		warnx("kvm_read: %s", kvm_geterr(kvm));
		return (0);
	}
	if (sd.sd_type != SDT_SYS386BSY) {
		warnx("descriptor is not a busy TSS");
		return (0);
	}
	tss = sd.sd_hibase << 24 | sd.sd_lobase;

	/*
	 * In SMP kernels, the TSS is stored as part of the per-CPU
	 * data.  On older kernels, the CPU0's private page
	 * is stored at an address that isn't mapped in minidumps.
	 * However, the data is mapped at the alternate cpu0prvpage
	 * address.  Thus, if the TSS is at the invalid address,
	 * change it to be relative to cpu0prvpage instead.
	 */ 
	if (trunc_page(tss) == 0xffc00000) {
		addr = kgdb_lookup("cpu0prvpage");
		if (addr == 0)
			return (0);
		if (kvm_read(kvm, addr, &cpu0prvpage, sizeof(cpu0prvpage)) !=
		    sizeof(cpu0prvpage)) {
			warnx("kvm_read: %s", kvm_geterr(kvm));
			return (0);
		}
		tss = cpu0prvpage + (tss & PAGE_MASK);
	}
	return ((CORE_ADDR)tss);
}

static struct trad_frame_cache *
i386fbsd_dblfault_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct trad_frame_cache *cache;
  CORE_ADDR addr, func, tss;
  int i;

  if (*this_cache != NULL)
    return (*this_cache);

  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);
  tss = i386fbsd_fetch_tss ();

  for (i = 0; i < ARRAY_SIZE (i386fbsd_tss_offset); i++)
    if (i386fbsd_tss_offset[i] != -1)
      trad_frame_set_reg_addr (cache, i, tss + i386fbsd_tss_offset[i]);

  /* Construct the frame ID using the function start.  */
  /* XXX: Stack address should be dbfault_stack + PAGE_SIZE. */
  trad_frame_set_id (cache, frame_id_build (tss + sizeof(struct i386tss),
					    func));

  return cache;
}

static void
i386fbsd_dblfault_this_id (struct frame_info *this_frame,
			     void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    i386fbsd_dblfault_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
i386fbsd_dblfault_prev_register (struct frame_info *this_frame,
				   void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    i386fbsd_dblfault_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
i386fbsd_dblfault_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && strcmp (name, "dblfault_handler") == 0);
}

static const struct frame_unwind i386fbsd_dblfault_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  i386fbsd_dblfault_this_id,
  i386fbsd_dblfault_prev_register,
  NULL,
  i386fbsd_dblfault_sniffer
};

static int i386fbsd_trapframe_offset[15] = {
	offsetof(struct trapframe, tf_eax),
	offsetof(struct trapframe, tf_ecx),
	offsetof(struct trapframe, tf_edx),
	offsetof(struct trapframe, tf_ebx),
	offsetof(struct trapframe, tf_esp),
	offsetof(struct trapframe, tf_ebp),
	offsetof(struct trapframe, tf_esi),
	offsetof(struct trapframe, tf_edi),
	offsetof(struct trapframe, tf_eip),
	offsetof(struct trapframe, tf_eflags),
	offsetof(struct trapframe, tf_cs),
	offsetof(struct trapframe, tf_ss),
	offsetof(struct trapframe, tf_ds),
	offsetof(struct trapframe, tf_es),
	offsetof(struct trapframe, tf_fs)
};

static struct trad_frame_cache *
i386fbsd_trapframe_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct trad_frame_cache *cache;
  struct i386fbsd_info *info;
  CORE_ADDR addr, func, pc, sp;
  const char *name;
  int i;

  if (*this_cache != NULL)
    return (*this_cache);

  info = get_i386fbsd_info();
  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);
  sp = get_frame_register_unsigned (this_frame, I386_ESP_REGNUM);

  find_pc_partial_function (func, &name, NULL, NULL);
  if (strcmp(name, "calltrap") == 0 ||
      strcmp(name, "Xlcall_syscall") == 0 ||
      strcmp(name, "Xint0x80_syscall") == 0)
    /* Traps in later kernels pass the trap frame by reference. */
    sp += info->ofs_fix;
  else if (strcmp(name, "Xtimerint") == 0)
    /* Timer interrupts also pass the trap frame by reference. */
    sp += info->ofs_fix;
  else if (strcmp(name, "Xcpustop") == 0 ||
	   strcmp(name, "Xrendezvous") == 0 ||
	   strcmp(name, "Xipi_intr_bitmap_handler") == 0 ||
	   strcmp(name, "Xlazypmap") == 0)
    /* These handlers push a trap frame only. */
    ;
  else if (strcmp(name, "fork_trampoline") == 0)
    if (get_frame_pc (this_frame) == func)
      {
	/* fork_exit hasn't been called (kthread has never run), so
	   %esp in the pcb points to the word above the trapframe.  */
	sp += 4;
      }
    else
      {
	/* fork_exit has been called, so %esp in fork_exit's
	   frame is &tf - 12.  */
	sp += 12;
      }
  else {
    /* Interrupt frames pass the IDT vector in addition to the trap frame. */
    sp += info->ofs_fix + 4;
  }

  for (i = 0; i < ARRAY_SIZE (i386fbsd_trapframe_offset); i++)
    if (i386fbsd_trapframe_offset[i] != -1)
      trad_frame_set_reg_addr (cache, i, sp + i386fbsd_trapframe_offset[i]);

  /* Read %eip from trap frame.  */
  addr = sp + i386fbsd_trapframe_offset[I386_EIP_REGNUM];
  pc = read_memory_unsigned_integer (addr, 4, byte_order);

  if (pc == 0 && strcmp(name, "fork_trampoline") == 0)
    {
      /* Initial frame of a kthread; terminate backtrace.  */
      trad_frame_set_id (cache, outer_frame_id);
    }
  else
    {
      /* Construct the frame ID using the function start.  */
      trad_frame_set_id (cache, frame_id_build (sp + sizeof(struct trapframe),
						func));
    }

  return cache;
}

static void
i386fbsd_trapframe_this_id (struct frame_info *this_frame,
			     void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    i386fbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
i386fbsd_trapframe_prev_register (struct frame_info *this_frame,
				   void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    i386fbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
i386fbsd_trapframe_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && ((strcmp (name, "calltrap") == 0)
		   || (strcmp (name, "fork_trampoline") == 0)
		   || (name[0] == 'X' && name[1] != '_')));
}

static const struct frame_unwind i386fbsd_trapframe_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  i386fbsd_trapframe_this_id,
  i386fbsd_trapframe_prev_register,
  NULL,
  i386fbsd_trapframe_sniffer
};

static void
i386fbsd_kernel_init_abi(struct gdbarch_info info, struct gdbarch *gdbarch)
{

	i386_elf_init_abi(info, gdbarch);

	frame_unwind_prepend_unwinder(gdbarch, &i386fbsd_dblfault_unwind);
	frame_unwind_prepend_unwinder(gdbarch, &i386fbsd_trapframe_unwind);

	set_solib_ops(gdbarch, &kld_so_ops);

	fbsd_vmcore_set_supply_pcb(gdbarch, i386fbsd_supply_pcb);
	fbsd_vmcore_set_cpu_pcb_addr(gdbarch, i386fbsd_cpu_pcb_addr);
}

void _initialize_i386_kgdb_tdep(void);

void
_initialize_i386_kgdb_tdep(void)
{
	/* XXX: amd64 needs this as well, but we only need one. */
	gdbarch_register_osabi_sniffer(bfd_arch_i386,
				       bfd_target_elf_flavour,
				       fbsd_kernel_osabi_sniffer);
	gdbarch_register_osabi (bfd_arch_i386, 0,
	    GDB_OSABI_FREEBSD_ELF_KERNEL, i386fbsd_kernel_init_abi);

	i386fbsd_pspace_data = register_program_space_data_with_cleanup (NULL,
	    i386fbsd_pspace_data_cleanup);
}
