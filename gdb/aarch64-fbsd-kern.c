/* Target-dependent code for FreeBSD/aarch64 kernels.

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
#include "aarch64-tdep.h"

static const struct regcache_map_entry aarch64_fbsd_pcbmap[] =
  {
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, REGCACHE_MAP_SKIP, 8 },
    { 1, AARCH64_SP_REGNUM, 8 },
    { 0 }
  };

static const struct regset aarch64_fbsd_pcbregset =
  {
    aarch64_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
aarch64_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
			 const void *buf, size_t len)
{
  regcache->supply_regset (&aarch64_fbsd_pcbregset, -1, buf, len);
}

static const struct regcache_map_entry aarch64_fbsd_trapframe_map[] =
  {
    { 1, AARCH64_SP_REGNUM, 8 },
    { 1, AARCH64_LR_REGNUM, 8 },
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_CPSR_REGNUM, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* esr */
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 0 }
  };

static void
aarch64_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			     frame_info_ptr this_frame,
			     struct trad_frame_cache *this_cache,
			     CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR offset, pc, sp;

  sp = get_frame_register_unsigned (this_frame, AARCH64_SP_REGNUM);

  if (strcmp (name, "fork_trampoline") == 0 && get_frame_pc (this_frame) == func)
    {
      /* fork_exit hasn't been called (kthread has never run), so SP
	 hasn't been initialized yet.  The stack pointer is stored in
	 the X2 in the pcb.  */
      sp = get_frame_register_unsigned (this_frame, AARCH64_X0_REGNUM + 2);
    }

  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_trapframe_map, sp,
			     regcache_map_entry_size (aarch64_fbsd_trapframe_map));

  /* Read $PC from trap frame.  */
  offset = regcache_map_offset (aarch64_fbsd_trapframe_map, AARCH64_PC_REGNUM,
				gdbarch);
  pc = read_memory_unsigned_integer (sp + offset, 8, byte_order);

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
aarch64_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "handle_el1h_sync") == 0
	  || strcmp (name, "handle_el1h_irq") == 0
	  || strcmp (name, "handle_el0_sync") == 0
	  || strcmp (name, "handle_el0_irq") == 0
	  || strcmp (name, "handle_el0_error") == 0
	  || strcmp (name, "fork_trampoline") == 0);
}

static const struct fbsd_trapframe aarch64_fbsd_trapframe =
{
  aarch64_fbsd_trapframe_matches,
  aarch64_fbsd_trapframe_init
};

/* Implement the 'init_osabi' method of struct gdb_osabi_handler.  */

static void
aarch64_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  fbsd_kernel_init_abi (info, gdbarch);

  fbsd_trapframe_prepend_unwinder (gdbarch, &aarch64_fbsd_trapframe);

  /* Enable longjmp.  */
  tdep->jb_pc = 13;

  set_gdbarch_supply_fbsd_pcb (gdbarch, aarch64_fbsd_supply_pcb);
}

void _initialize_aarch64_fbsd_kern ();
void
_initialize_aarch64_fbsd_kern ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_aarch64,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_aarch64, 0, GDB_OSABI_FREEBSD_KERNEL,
			  aarch64_fbsd_kernel_init_abi);
}
