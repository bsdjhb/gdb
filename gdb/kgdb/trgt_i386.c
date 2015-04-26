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
#include <target.h>
#include <gdbthread.h>
#include <inferior.h>
#include <regcache.h>
#include <frame-unwind.h>
#include <i386-tdep.h>

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
  set_program_space_data (current_program_space, i386fbsd_pspace_data, info);
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

#if 0
struct kgdb_tss_cache {
	CORE_ADDR	pc;
	CORE_ADDR	sp;
	CORE_ADDR	tss;
};
#endif

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

#if 1
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
  ULONGEST cs;
  const char *name;

  cs = get_frame_register_unsigned (this_frame, I386_CS_REGNUM);
  if ((cs & I386_SEL_RPL) == I386_SEL_UPL)
    return 0;

  find_pc_partial_function (get_frame_pc (this_frame), &name, NULL, NULL);
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
#else
static struct kgdb_tss_cache *
i386fbsd_tss_cache(struct frame_info *next_frame, void **this_cache)
{
	char buf[MAX_REGISTER_SIZE];
	struct kgdb_tss_cache *cache;

	cache = *this_cache;
	if (cache == NULL) {
		cache = FRAME_OBSTACK_ZALLOC(struct kgdb_tss_cache);
		*this_cache = cache;
		cache->pc = frame_func_unwind(next_frame);
		frame_unwind_register(next_frame, SP_REGNUM, buf);
		cache->sp = extract_unsigned_integer(buf,
		    register_size(current_gdbarch, SP_REGNUM));
		cache->tss = i386fbsd_fetch_tss();
	}
	return (cache);
}

static void
i386fbsd_dblfault_this_id(struct frame_info *next_frame, void **this_cache,
    struct frame_id *this_id)
{
	struct kgdb_tss_cache *cache;

	cache = i386fbsd_tss_cache(next_frame, this_cache);
	*this_id = frame_id_build(cache->sp, cache->pc);
}

static void
i386fbsd_dblfault_prev_register(struct frame_info *next_frame,
    void **this_cache, int regnum, int *optimizedp, enum lval_type *lvalp,
    CORE_ADDR *addrp, int *realnump, void *valuep)
{
	char dummy_valuep[MAX_REGISTER_SIZE];
	struct kgdb_tss_cache *cache;
	int ofs, regsz;

	regsz = register_size(current_gdbarch, regnum);

	if (valuep == NULL)
		valuep = dummy_valuep;
	memset(valuep, 0, regsz);
	*optimizedp = 0;
	*addrp = 0;
	*lvalp = not_lval;
	*realnump = -1;

	ofs = (regnum >= I386_EAX_REGNUM && regnum <= I386_FS_REGNUM)
	    ? i386fbsd_tss_offset[regnum] : -1;
	if (ofs == -1)
		return;

	cache = i386fbsd_tss_cache(next_frame, this_cache);
	if (cache->tss == 0)
		return;
	*addrp = cache->tss + ofs;
	*lvalp = lval_memory;
	target_read_memory(*addrp, valuep, regsz);
}

static const struct frame_unwind i386fbsd_dblfault_unwind = {
        UNKNOWN_FRAME,
        &i386fbsd_dblfault_this_id,
        &i386fbsd_dblfault_prev_register
};

struct kgdb_frame_cache {
	int		frame_type;
	CORE_ADDR	pc;
	CORE_ADDR	sp;
};
#define	FT_NORMAL		1
#define	FT_INTRFRAME		2
#define	FT_INTRTRAPFRAME	3
#define	FT_TIMERFRAME		4
#endif

static int i386fbsd_frame_offset[15] = {
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

#if 1
static struct trad_frame_cache *
i386fbsd_trapframe_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct trad_frame_cache *cache;
  struct i386fbsd_info *info;
  CORE_ADDR addr, func, pc, sp;
  const char *name;
  ULONGEST cs;
  int i;

  if (*this_cache != NULL)
    return (*this_cache);

  info = get_i386fbsd_info();
  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);
  sp = get_frame_register_unsigned (this_frame, I386_ESP_REGNUM);

  find_pc_partial_function (get_frame_pc (this_frame), &name, NULL, NULL);
#if 1
  if (name[0] != 'X')
#else
    if (strcmp(name, "calltrap") == 0 ||
	strcmp(name, "Xlcall_syscall") == 0 ||
	strcmp(name, "Xint0x80_syscall") == 0)
#endif
    /* Traps in later kernels pass the trap frame by reference. */
    /* System calls should be here as well */
    sp += info->ofs_fix;
  else if (strcmp(name, "Xtimerint") == 0)
    /* Timer interrupts also pass the trap frame by reference. */
    sp += info->ofs_fix;
  else if (strcmp(name, "Xcpustop") == 0 ||
	   strcmp(name, "Xrendezvous") == 0 ||
	   strcmp(name, "Xipi_intr_bitmap_handler") == 0 ||
	   strcmp(name, "Xlazypmap") == 0)
    /* These handlers push a trap frame only. */
  else {
    /* XXX: System calls fall through to here */
    /* XXX: fork_trampoline is a bit of a bear.  If fork_exit hasn't been
       called (kthread has never run), then %esp in the pcb points to the
       trapframe.  If fork_exit has been called, then %esp in fork_exit's
       frame is &tf - 12. */
    /* Interrupt frames pass the IDT vector in addition to the trap frame. */
    sp += info->ofs_fix + 4;
  }

  for (i = 0; i < ARRAY_SIZE (i386fbsd_trapframe_offset); i++)
    if (i386fbsd_trapframe_offset[i] != -1)
      trad_frame_set_reg_addr (cache, i, sp + i386fbsd_trapframe_offset[i]);

  /* Read %cs from trap frame.  */
  addr = sp + i386fbsd_trapframe_offset[I386_CS_REGNUM];
  cs = read_memory_unsigned_integer (addr, 4, byte_order);

  if ((cs & I386_SEL_RPL) == I386_SEL_UPL)
    {
      /* Trap from user space; terminate backtrace.  */
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
  ULONGEST cs;
  const char *name;

  cs = get_frame_register_unsigned (this_frame, I386_CS_REGNUM);
  if ((cs & I386_SEL_RPL) == I386_SEL_UPL)
    return 0;

  find_pc_partial_function (get_frame_pc (this_frame), &name, NULL, NULL);
  /* XXX: "fork_trampoline"? */
  return (name && ((strcmp (name, "calltrap") == 0)
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
#else
static struct kgdb_frame_cache *
i386fbsd_frame_cache(struct frame_info *next_frame, void **this_cache)
{
	char buf[MAX_REGISTER_SIZE];
	struct kgdb_frame_cache *cache;
	char *pname;

	cache = *this_cache;
	if (cache == NULL) {
		cache = FRAME_OBSTACK_ZALLOC(struct kgdb_frame_cache);
		*this_cache = cache;
		cache->pc = frame_func_unwind(next_frame);
		find_pc_partial_function(cache->pc, &pname, NULL, NULL);
		if (pname[0] != 'X')
			cache->frame_type = FT_NORMAL;
		else if (strcmp(pname, "Xtimerint") == 0)
			cache->frame_type = FT_TIMERFRAME;
		else if (strcmp(pname, "Xcpustop") == 0 ||
		    strcmp(pname, "Xrendezvous") == 0 ||
		    strcmp(pname, "Xipi_intr_bitmap_handler") == 0 ||
		    strcmp(pname, "Xlazypmap") == 0)
			cache->frame_type = FT_INTRTRAPFRAME;
		else
			cache->frame_type = FT_INTRFRAME;
		frame_unwind_register(next_frame, SP_REGNUM, buf);
		cache->sp = extract_unsigned_integer(buf,
		    register_size(current_gdbarch, SP_REGNUM));
	}
	return (cache);
}

static void
i386fbsd_trapframe_this_id(struct frame_info *next_frame, void **this_cache,
    struct frame_id *this_id)
{
	struct kgdb_frame_cache *cache;

	cache = i386fbsd_frame_cache(next_frame, this_cache);
	*this_id = frame_id_build(cache->sp, cache->pc);
}

static void
i386fbsd_trapframe_prev_register(struct frame_info *next_frame,
    void **this_cache, int regnum, int *optimizedp, enum lval_type *lvalp,
    CORE_ADDR *addrp, int *realnump, void *valuep)
{
	char dummy_valuep[MAX_REGISTER_SIZE];
	struct kgdb_frame_cache *cache;
	struct i386fbsd_info *info;
	int ofs, regsz;

	info = get_i386fbsd_info();
	regsz = register_size(current_gdbarch, regnum);

	if (valuep == NULL)
		valuep = dummy_valuep;
	memset(valuep, 0, regsz);
	*optimizedp = 0;
	*addrp = 0;
	*lvalp = not_lval;
	*realnump = -1;

	ofs = (regnum >= I386_EAX_REGNUM && regnum <= I386_FS_REGNUM)
	    ? i386fbsd_frame_offset[regnum] + info->ofs_fix : -1;
	if (ofs == -1)
		return;

	cache = i386fbsd_frame_cache(next_frame, this_cache);
	switch (cache->frame_type) {
	case FT_NORMAL:
		break;
	case FT_INTRFRAME:
		ofs += 4;
		break;
	case FT_TIMERFRAME:
		break;
	case FT_INTRTRAPFRAME:
		ofs -= info->ofs_fix;
		break;
	default:
		fprintf_unfiltered(gdb_stderr, "Correct FT_XXX frame offsets "
		   "for %d\n", cache->frame_type);
		break;
	}
	*addrp = cache->sp + ofs;
	*lvalp = lval_memory;
	target_read_memory(*addrp, valuep, regsz);
}

static const struct frame_unwind i386fbsd_trapframe_unwind = {
        UNKNOWN_FRAME,
        &i386fbsd_trapframe_this_id,
        &i386fbsd_trapframe_prev_register
};

const struct frame_unwind *
kgdb_trgt_trapframe_sniffer(struct frame_info *next_frame)
{
	char *pname;
	CORE_ADDR pc;

	pc = frame_pc_unwind(next_frame);
	pname = NULL;
	find_pc_partial_function(pc, &pname, NULL, NULL);
	if (pname == NULL)
		return (NULL);
	if (strcmp(pname, "dblfault_handler") == 0)
		return (&i386fbsd_dblfault_unwind);
	if (strcmp(pname, "calltrap") == 0 ||
	    (pname[0] == 'X' && pname[1] != '_'))
		return (&i386fbsd_trapframe_unwind);
	/* printf("%s: %llx =%s\n", __func__, pc, pname); */
	return (NULL);
}
#endif

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
}
