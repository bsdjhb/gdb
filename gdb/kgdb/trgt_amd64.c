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
__FBSDID("$FreeBSD: head/gnu/usr.bin/gdb/kgdb/trgt_amd64.c 246893 2013-02-17 02:15:19Z marcel $");

#include <sys/types.h>
#ifdef __amd64__
#include <machine/pcb.h>
#include <machine/frame.h>
#endif
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
#include <amd64-tdep.h>
#include "solib.h"
#include "stack.h"
#include "trad-frame.h"

#include "kgdb.h"

#ifdef __amd64__
static CORE_ADDR
amd64fbsd_cpu_pcb_addr(u_int cpuid)
{
	return (kgdb_trgt_stop_pcb(cpuid, sizeof(struct pcb)));
}

static void
amd64fbsd_supply_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
	struct pcb pcb;

	if (kvm_read(kvm, pcb_addr, &pcb, sizeof(pcb)) != sizeof(pcb)) {
		warnx("kvm_read: %s", kvm_geterr(kvm));
		memset(&pcb, 0, sizeof(pcb));
	}

	regcache_raw_supply(regcache, AMD64_RBX_REGNUM, (char *)&pcb.pcb_rbx);
	regcache_raw_supply(regcache, AMD64_RBP_REGNUM, (char *)&pcb.pcb_rbp);
	regcache_raw_supply(regcache, AMD64_RSP_REGNUM, (char *)&pcb.pcb_rsp);
	regcache_raw_supply(regcache, 12, (char *)&pcb.pcb_r12);
	regcache_raw_supply(regcache, 13, (char *)&pcb.pcb_r13);
	regcache_raw_supply(regcache, 14, (char *)&pcb.pcb_r14);
	regcache_raw_supply(regcache, 15, (char *)&pcb.pcb_r15);
	regcache_raw_supply(regcache, AMD64_RIP_REGNUM, (char *)&pcb.pcb_rip);
	regcache_raw_supply_unsigned(regcache, AMD64_CS_REGNUM,
	    GSEL(GCODE_SEL, SEL_KPL));
	regcache_raw_supply_unsigned(regcache, AMD64_SS_REGNUM,
	    GSEL(GDATA_SEL, SEL_KPL));
	
#if 0
	/*
	 * XXX: This is reading stack garbage and can't be correct for
	 * a pcb in stoppcbs[].
	 */
	amd64_supply_fxsave(regcache, -1, (struct fpusave *)(&pcb + 1));
#endif
}
#endif

static const int amd64fbsd_trapframe_offset[] = {
  6 * 8,			/* %rax */
  7 * 8,			/* %rbx */
  3 * 8,			/* %rcx */
  2 * 8,			/* %rdx */
  1 * 8,			/* %rsi */
  0 * 8,			/* %rdi */
  8 * 8,			/* %rbp */
  22 * 8,			/* %rsp */
  4 * 8,			/* %r8 ...  */
  5 * 8,
  9 * 8,
  10 * 8,
  11 * 8,
  12 * 8,
  13 * 8,
  14 * 8,			/* ... %r15 */
  19 * 8,			/* %rip */
  21 * 8,			/* %eflags */
  20 * 8,			/* %cs */
  23 * 8,			/* %ss */
  -1,				/* %ds */
  -1,				/* %es */
  -1,				/* %fs */
  -1				/* %gs */
};

#define TRAPFRAME_SIZE	192

static struct trad_frame_cache *
amd64fbsd_trapframe_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct trad_frame_cache *cache;
  CORE_ADDR addr, func, sp;
  ULONGEST cs;
  int i;

  if (*this_cache != NULL)
    return (*this_cache);

  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);
  sp = get_frame_register_unsigned (this_frame, AMD64_RSP_REGNUM);

  for (i = 0; i < ARRAY_SIZE (amd64fbsd_trapframe_offset); i++)
    if (amd64fbsd_trapframe_offset[i] != -1)
      trad_frame_set_reg_addr (cache, i, sp + amd64fbsd_trapframe_offset[i]);

  /* Read %cs from trap frame.  */
  addr = sp + amd64fbsd_trapframe_offset[AMD64_CS_REGNUM];
  cs = read_memory_unsigned_integer (addr, 8, byte_order);

  if ((cs & I386_SEL_RPL) == I386_SEL_UPL)
    {
      /* Trap from user space; terminate backtrace.  */
      trad_frame_set_id (cache, outer_frame_id);
    }
  else
    {
      /* Construct the frame ID using the function start.  */
      trad_frame_set_id (cache, frame_id_build (sp + TRAPFRAME_SIZE, func));
    }

  return cache;
}

static void
amd64fbsd_trapframe_this_id (struct frame_info *this_frame,
			     void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    amd64fbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
amd64fbsd_trapframe_prev_register (struct frame_info *this_frame,
				   void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    amd64fbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
amd64fbsd_trapframe_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && ((strcmp (name, "calltrap") == 0)
		   || (strcmp (name, "nmi_calltrap") == 0)
		   || (name[0] == 'X' && name[1] != '_')));
}

static const struct frame_unwind amd64fbsd_trapframe_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  amd64fbsd_trapframe_this_id,
  amd64fbsd_trapframe_prev_register,
  NULL,
  amd64fbsd_trapframe_sniffer
};

static void
amd64fbsd_kernel_init_abi(struct gdbarch_info info, struct gdbarch *gdbarch)
{

	amd64_init_abi(info, gdbarch);

	frame_unwind_prepend_unwinder(gdbarch, &amd64fbsd_trapframe_unwind);

	set_solib_ops(gdbarch, &kld_so_ops);

#ifdef __amd64__
	fbsd_vmcore_set_supply_pcb(gdbarch, amd64fbsd_supply_pcb);
	fbsd_vmcore_set_cpu_pcb_addr(gdbarch, amd64fbsd_cpu_pcb_addr);
#endif
}

void _initialize_amd64_kgdb_tdep(void);

void
_initialize_amd64_kgdb_tdep(void)
{
#ifdef __amd64__
	/* XXX: i386 needs this as well, but we only need one. */
	gdbarch_register_osabi_sniffer(bfd_arch_i386,
				       bfd_target_elf_flavour,
				       fbsd_kernel_osabi_sniffer);
#endif
	gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64,
	    GDB_OSABI_FREEBSD_ELF_KERNEL, amd64fbsd_kernel_init_abi);

#ifdef __amd64__
	gdb_assert(sizeof(struct trapframe) == TRAPFRAME_SIZE);
	gdb_assert(offsetof(struct trapframe, tf_rax)
		   == amd64fbsd_trapframe_offset[AMD64_RAX_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rbx)
		   == amd64fbsd_trapframe_offset[AMD64_RBX_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rcx)
		   == amd64fbsd_trapframe_offset[AMD64_RCX_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rdx)
		   == amd64fbsd_trapframe_offset[AMD64_RDX_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rsi)
		   == amd64fbsd_trapframe_offset[AMD64_RSI_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rdi)
		   == amd64fbsd_trapframe_offset[AMD64_RDI_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rbp)
		   == amd64fbsd_trapframe_offset[AMD64_RBP_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rsp)
		   == amd64fbsd_trapframe_offset[AMD64_RSP_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r8)
		   == amd64fbsd_trapframe_offset[AMD64_R8_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r9)
		   == amd64fbsd_trapframe_offset[AMD64_R9_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r10)
		   == amd64fbsd_trapframe_offset[AMD64_R10_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r11)
		   == amd64fbsd_trapframe_offset[AMD64_R11_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r12)
		   == amd64fbsd_trapframe_offset[AMD64_R12_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r13)
		   == amd64fbsd_trapframe_offset[AMD64_R13_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r14)
		   == amd64fbsd_trapframe_offset[AMD64_R14_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_r15)
		   == amd64fbsd_trapframe_offset[AMD64_R15_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rip)
		   == amd64fbsd_trapframe_offset[AMD64_RIP_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_rflags)
		   == amd64fbsd_trapframe_offset[AMD64_EFLAGS_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_cs)
		   == amd64fbsd_trapframe_offset[AMD64_CS_REGNUM]);
	gdb_assert(offsetof(struct trapframe, tf_ss)
		   == amd64fbsd_trapframe_offset[AMD64_SS_REGNUM]);
#endif
}
