/* Target-dependent code for FreeBSD/i386 kernels.

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
#include "fbsd-trapframe.h"
#include "gdbcore.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "trad-frame.h"

#include "fbsd-kern.h"
#include "i386-tdep.h"

#ifdef __i386__
#include "kgdb.h"

#include <sys/proc.h>
#include <machine/pcb.h>
#include <machine/frame.h>
#include <machine/segments.h>
#include <machine/tss.h>
#endif

static const struct regcache_map_entry i386_fbsd_pcbmap[] =
  {
    { 1, I386_EDI_REGNUM, 4 },
    { 1, I386_ESI_REGNUM, 4 },
    { 1, I386_EBP_REGNUM, 4 },
    { 1, I386_ESP_REGNUM, 4 },
    { 1, I386_EBX_REGNUM, 4 },
    { 1, I386_EIP_REGNUM, 4 },
    { 0 }
  };

static const struct regset i386_fbsd_pcbregset =
  {
    i386_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
i386_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		      const void *buf, size_t len)

{
  regcache->supply_regset (&i386_fbsd_pcbregset, -1, buf, len);
}

#ifdef __i386__
static const struct regcache_map_entry i386_fbsd_tssmap[] =
  {
    { 1, REGCACHE_MAP_SKIP, 4 }, /* tss_link */
    { 2, REGCACHE_MAP_SKIP, 4 }, /* ss:esp ring 0 */
    { 2, REGCACHE_MAP_SKIP, 4 }, /* ss:esp ring 1 */
    { 2, REGCACHE_MAP_SKIP, 4 }, /* ss:esp ring 2 */
    { 1, REGCACHE_MAP_SKIP, 4 }, /* cr3 */
    { 1, I386_EIP_REGNUM, 4 },
    { 1, I386_EFLAGS_REGNUM, 4 },
    { 8, I386_EAX_REGNUM, 4 },
    { 1, I386_ES_REGNUM, 4 },
    { 1, I386_CS_REGNUM, 4 },
    { 1, I386_SS_REGNUM, 4 },
    { 1, I386_DS_REGNUM, 4 },
    { 1, I386_FS_REGNUM, 4 },
    { 1, I386_GS_REGNUM, 4 },
    { 0 }
  };

/* If the current thread is executing on a CPU, fetch the common_tss
   for that CPU.

   This is painful because 'struct pcpu' is variant sized, so we can't
   use it.  Instead, we lookup the GDT selector for this CPU and
   extract the base of the TSS from there.  */

static CORE_ADDR
i386_fbsd_fetch_tss ()
{
	struct kthr *kt;
	struct segment_descriptor sd;
	CORE_ADDR addr, cpu0prvpage, tss;

	kt = kgdb_thr_lookup_tid(inferior_ptid.tid());
	if (kt == NULL || kt->cpu == NOCPU || kt->cpu < 0)
		return (0);

	addr = kgdb_lookup("gdt");
	if (addr == 0)
		return (0);
	addr += (kt->cpu * NGDT + GPROC0_SEL) * sizeof(sd);
	if (target_read_memory(addr, (gdb_byte *)&sd, sizeof(sd)) != 0)
		return (0);
	if (sd.sd_type != SDT_SYS386BSY) {
		warning ("descriptor is not a busy TSS");
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
		try {
			cpu0prvpage = parse_and_eval_address("cpu0prvpage");
		} catch (const gdb_exception_error &e) {
			return (0);
		}
		tss = cpu0prvpage + (tss & PAGE_MASK);
	}
	return (tss);
}

static void
i386_fbsd_dblfault_init (const struct fbsd_trapframe *self,
			 frame_info_ptr this_frame,
			 struct trad_frame_cache *this_cache,
			 CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR tss;

  tss = i386_fbsd_fetch_tss ();

  trad_frame_set_reg_regmap (this_cache, i386_fbsd_tssmap, tss,
			     regcache_map_entry_size (i386_fbsd_tssmap));

  /* Construct the frame ID using the function start.  */
  trad_frame_set_id (this_cache, frame_id_build (tss, func));
}

static bool
i386_fbsd_dblfault_matches (const char *name)
{
  return (strcmp (name, "dblfault_handler") == 0);
}

static const struct fbsd_trapframe i386_fbsd_dblfault =
{
  i386_fbsd_dblfault_matches,
  i386_fbsd_dblfault_init
};
#endif

static const struct regcache_map_entry i386_fbsd_trapframe_map[] =
  {
    { 1, I386_FS_REGNUM, 4 },
    { 1, I386_ES_REGNUM, 4 },
    { 1, I386_DS_REGNUM, 4 },
    { 1, I386_EDI_REGNUM, 4 },
    { 1, I386_ESI_REGNUM, 4 },
    { 1, I386_EBP_REGNUM, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 }, /* tf_isp */
    { 1, I386_EBX_REGNUM, 4 },
    { 1, I386_EDX_REGNUM, 4 },
    { 1, I386_ECX_REGNUM, 4 },
    { 1, I386_EAX_REGNUM, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 }, /* tf_trapno */
    { 1, REGCACHE_MAP_SKIP, 4 }, /* tf_err */
    { 1, I386_EIP_REGNUM, 4 },
    { 1, I386_CS_REGNUM, 4 },
    { 1, I386_EFLAGS_REGNUM, 4 },
    { 1, I386_ESP_REGNUM, 4 },
    { 1, I386_SS_REGNUM, 4 },
    { 0 }
  };

static void
i386_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			  frame_info_ptr this_frame,
			  struct trad_frame_cache *this_cache,
			  CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR cs, offset, pc, sp;
  int size;

  sp = get_frame_register_unsigned (this_frame, I386_ESP_REGNUM);

  if (strcmp (name, "calltrap") == 0 ||
      strcmp (name, "Xlcall_syscall") == 0 ||
      strcmp (name, "Xint0x80_syscall") == 0)
    /* Traps pass the trap frame by reference. */
    sp += 4;
  else if (strcmp (name, "Xtimerint") == 0)
    /* Timer interrupts also pass the trap frame by reference. */
    sp += 4;
  else if (strcmp (name, "Xcpustop") == 0 ||
	   strcmp (name, "Xrendezvous") == 0 ||
	   strcmp (name, "Xipi_intr_bitmap_handler") == 0 ||
	   strcmp (name, "Xlazypmap") == 0)
    /* These handlers push a trap frame only. */
    ;
  else if (strcmp (name, "fork_trampoline") == 0)
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
    sp += 8;
  }

  /* %ss/%esp are only present in the trapframe for a trap from
     userland.  */
  offset = regcache_map_offset (i386_fbsd_trapframe_map, I386_CS_REGNUM,
				gdbarch);
  cs = read_memory_unsigned_integer (sp + offset, 4, byte_order);
  if ((cs & I386_SEL_RPL) == I386_SEL_KPL)
    size = regcache_map_entry_size (i386_fbsd_trapframe_map);
  else
    size = regcache_map_offset (i386_fbsd_trapframe_map, I386_ESP_REGNUM,
				gdbarch);

  trad_frame_set_reg_regmap (this_cache, i386_fbsd_trapframe_map, sp, size);

  /* Read %eip from trap frame.  */
  offset = regcache_map_offset (i386_fbsd_trapframe_map, I386_EIP_REGNUM,
				gdbarch);
  pc = read_memory_unsigned_integer (sp + offset, 4, byte_order);

  if (pc == 0 && strcmp (name, "fork_trampoline") == 0)
    {
      /* Initial frame of a kthread; terminate backtrace.  */
      trad_frame_set_id (this_cache, outer_frame_id);
    }
  else
    {
      /* Construct the frame ID using the function start.  */
      trad_frame_set_id (this_cache, frame_id_build (sp, func));
    }
}

static bool
i386_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "calltrap") == 0
	  || strcmp (name, "fork_trampoline") == 0
	  || (name[0] == 'X' && name[1] != '_'));
}

static const struct fbsd_trapframe i386_fbsd_trapframe =
{
  i386_fbsd_trapframe_matches,
  i386_fbsd_trapframe_init
};

static void
i386_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  fbsd_kernel_init_abi (info, gdbarch);

  i386_elf_init_abi (info, gdbarch);

#ifdef __i386__
  fbsd_trapframe_prepend_unwinder (gdbarch, &i386_fbsd_dblfault);
#endif
  fbsd_trapframe_prepend_unwinder (gdbarch, &i386_fbsd_trapframe);

  set_gdbarch_supply_fbsd_pcb (gdbarch, i386_fbsd_supply_pcb);
}

void _initialize_i386_fbsd_kern ();
void
_initialize_i386_fbsd_kern ()
{
  /* This is used for both i386 and amd64, but amd64 always
     includes this target, so just include it here.  */
  gdbarch_register_osabi_sniffer (bfd_arch_i386,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_i386, 0, GDB_OSABI_FREEBSD_KERNEL,
			  i386_fbsd_kernel_init_abi);
}
