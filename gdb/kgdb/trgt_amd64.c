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
#include <machine/pcb.h>
#include <machine/frame.h>
#include <err.h>
#include <kvm.h>
#include <string.h>

#include <defs.h>
#include "osabi.h"
#include <target.h>
#include <gdbthread.h>
#include <inferior.h>
#include <regcache.h>
#include <frame-unwind.h>
#include <amd64-tdep.h>
#include "solib.h"
#include "stack.h"

#include "kgdb.h"

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
#if 0
	/*
	 * XXX: This is reading stack garbage and can't be correct for
	 * a pcb in stoppcbs[].
	 */
	amd64_supply_fxsave(regcache, -1, (struct fpusave *)(&pcb + 1));
#endif
}

struct amd64fbsd_trapframe_cache {
	CORE_ADDR	pc;
	CORE_ADDR	sp;
};

static int amd64fbsd_trapframe_offset[20] = {
	offsetof(struct trapframe, tf_rax),
	offsetof(struct trapframe, tf_rbx),
	offsetof(struct trapframe, tf_rcx),
	offsetof(struct trapframe, tf_rdx),
	offsetof(struct trapframe, tf_rsi),
	offsetof(struct trapframe, tf_rdi),
	offsetof(struct trapframe, tf_rbp),
	offsetof(struct trapframe, tf_rsp),
	offsetof(struct trapframe, tf_r8),
	offsetof(struct trapframe, tf_r9),
	offsetof(struct trapframe, tf_r10),
	offsetof(struct trapframe, tf_r11),
	offsetof(struct trapframe, tf_r12),
	offsetof(struct trapframe, tf_r13),
	offsetof(struct trapframe, tf_r14),
	offsetof(struct trapframe, tf_r15),
	offsetof(struct trapframe, tf_rip),
	offsetof(struct trapframe, tf_rflags),
	offsetof(struct trapframe, tf_cs),
	offsetof(struct trapframe, tf_ss)
};

static struct amd64fbsd_trapframe_cache *
amd64fbsd_trapframe_cache(struct frame_info *this_frame, void **this_cache)
{
	struct gdbarch *gdbarch = get_frame_arch(this_frame);
	enum bfd_endian byte_order = gdbarch_byte_order(gdbarch);
	gdb_byte buf[8];
	struct amd64fbsd_trapframe_cache *cache;

	if (*this_cache != NULL)
		return (*this_cache);

	cache = FRAME_OBSTACK_ZALLOC(struct amd64fbsd_trapframe_cache);
	cache->pc = get_frame_func(this_frame);
	get_frame_register(this_frame, AMD64_RSP_REGNUM, buf);
	cache->sp = extract_unsigned_integer (buf, 8, byte_order);
	*this_cache = cache;
	return (cache);
}

static enum unwind_stop_reason
amd64fbsd_trapframe_unwind_stop_reason(struct frame_info *this_frame,
    void **this_cache)
{
	struct amd64fbsd_trapframe_cache *cache;

	cache = amd64fbsd_trapframe_cache(this_frame, this_cache);
	if (cache->sp == 0)
		return UNWIND_UNAVAILABLE;

	return UNWIND_NO_REASON;
}

static void
amd64fbsd_trapframe_this_id(struct frame_info *this_frame, void **this_cache,
    struct frame_id *this_id)
{
	struct amd64fbsd_trapframe_cache *cache;

	cache = amd64fbsd_trapframe_cache(this_frame, this_cache);
	if (cache->sp == 0)
		*this_id = frame_id_build_unavailable_stack(cache->pc);
	else
		*this_id = frame_id_build(cache->sp, cache->pc);
}

static struct value *
amd64fbsd_trapframe_prev_register(struct frame_info *this_frame,
    void **this_cache, int regnum)
{
	struct amd64fbsd_trapframe_cache *cache;
	int ofs;

	ofs = (regnum >= AMD64_RAX_REGNUM && regnum <= AMD64_EFLAGS_REGNUM + 2)
	    ? amd64fbsd_trapframe_offset[regnum] : -1;
	if (ofs == -1)
		return frame_unwind_got_optimized(this_frame, regnum);

	cache = amd64fbsd_trapframe_cache(this_frame, this_cache);
	return frame_unwind_got_memory(this_frame, regnum, cache->sp + ofs);
}

static int
amd64fbsd_trapframe_sniffer(const struct frame_unwind *self,
    struct frame_info *this_frame, void **this_prologue_cache)
{
	struct cleanup *old_chain;
	char *funname;
	enum language funlang;
	int is_trapframe;

	find_frame_funname(this_frame, &funname, &funlang, NULL);
	if (funname == NULL)
		return (0);
	old_chain = make_cleanup(xfree, funname);
	is_trapframe = 0;
	if (strcmp(funname, "calltrap") == 0 ||
	    strcmp(funname, "nmi_calltrap") == 0 ||
	    (funname[0] == 'X' && funname[1] != '_'))
		is_trapframe = 1;
	do_cleanups(old_chain);
	return (is_trapframe);
}
    
static const struct frame_unwind amd64fbsd_trapframe_unwind = {
        NORMAL_FRAME,
	amd64fbsd_trapframe_unwind_stop_reason,
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

	fbsd_vmcore_set_supply_pcb(gdbarch, amd64fbsd_supply_pcb);
	fbsd_vmcore_set_cpu_pcb_addr(gdbarch, amd64fbsd_cpu_pcb_addr);
}

void _initialize_amd64_kgdb_tdep(void);

void
_initialize_amd64_kgdb_tdep(void)
{
	/* XXX: i386 needs this as well, but we only need one. */
	gdbarch_register_osabi_sniffer(bfd_arch_i386,
				       bfd_target_elf_flavour,
				       fbsd_kernel_osabi_sniffer);
	gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64,
	    GDB_OSABI_FREEBSD_ELF_KERNEL, amd64fbsd_kernel_init_abi);
}
