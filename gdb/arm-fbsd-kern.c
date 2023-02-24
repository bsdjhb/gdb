/* Target-dependent code for FreeBSD/arm kernels.

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
#include "arm-tdep.h"

static const struct regcache_map_entry arm_fbsd_pcbmap[] =
  {
    { 9, 4, 4 }, /* r4 ... r12 */
    { 1, ARM_SP_REGNUM, 4 },
    { 1, ARM_LR_REGNUM, 4 },
    { 1, ARM_PC_REGNUM, 4 },
    { 0 }
  };

static const struct regset arm_fbsd_pcbregset =
  {
    arm_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
arm_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		     const void *buf, size_t len)
{
  regcache->supply_regset (&arm_fbsd_pcbregset, -1, buf, len);

  /* XXX: This is a gross hack, but the ARM frame unwinders need the
     value of xPSR to determine if Thumb mode is active.  FreeBSD's
     kernels never use Thumb.  */
  regcache->raw_supply_zeroed (ARM_PS_REGNUM);
}

#define PSR_MODE        0x0000001f      /* mode mask */
#define PSR_USR32_MODE  0x00000010

static const struct regcache_map_entry arm_fbsd_trapframe_map[] =
  {
    { 1, ARM_PS_REGNUM, 4 },
    { 13, 0, 4 }, /* r0 .. r12 */
    { 2, REGCACHE_MAP_SKIP, 4 }, /* usr sp/lr */
    { 1, ARM_SP_REGNUM, 4 },
    { 1, ARM_LR_REGNUM, 4 },
    { 1, ARM_PC_REGNUM, 4 },
    { 0 }
  };

static const struct regcache_map_entry arm_fbsd_trapframe_user_map[] =
  {
    { 1, ARM_PS_REGNUM, 4 },
    { 13, 0, 4 }, /* r0 .. r12 */
    { 1, ARM_SP_REGNUM, 4 },
    { 1, ARM_LR_REGNUM, 4 },
    { 2, REGCACHE_MAP_SKIP, 4 }, /* svc sp/lr */
    { 1, ARM_PC_REGNUM, 4 },
    { 0 }
  };

static void
arm_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			 frame_info_ptr this_frame,
			 struct trad_frame_cache *this_cache,
			 CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  const struct regcache_map_entry *trapframe_map;
  uint32_t psr;
  CORE_ADDR offset, pc, sp;

  sp = get_frame_register_unsigned (this_frame, ARM_SP_REGNUM);

  /* Read $PSR to determine where SP and LR are. */
  psr = read_memory_unsigned_integer (sp, 4, byte_order);
  if ((psr & PSR_MODE) == PSR_USR32_MODE)
    trapframe_map = arm_fbsd_trapframe_user_map;
  else
    trapframe_map = arm_fbsd_trapframe_map;

  trad_frame_set_reg_regmap (this_cache, trapframe_map, sp,
			     regcache_map_entry_size (trapframe_map));

  /* Read $PC from trap frame.  */
  offset = regcache_map_offset (trapframe_map, ARM_PC_REGNUM, gdbarch);
  pc = read_memory_unsigned_integer (sp + offset, 4, byte_order);

  if (pc == 0 && strcmp (name, "swi_entry") == 0)
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
arm_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "data_abort_entry") == 0
	  || strcmp (name, "prefetch_abort_entry") == 0
	  || strcmp (name, "undefined_entry") == 0
	  || strcmp (name, "exception_exit") == 0
	  || strcmp (name, "irq_entry") == 0
	  || strcmp (name, "swi_entry") == 0
	  || strcmp (name, "swi_exit") == 0);
}

static const struct fbsd_trapframe arm_fbsd_trapframe =
{
  arm_fbsd_trapframe_matches,
  arm_fbsd_trapframe_init
};

/* Implement the 'init_osabi' method of struct gdb_osabi_handler.  */

static void
arm_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  arm_gdbarch_tdep *tdep = gdbarch_tdep<arm_gdbarch_tdep> (gdbarch);

  fbsd_kernel_init_abi (info, gdbarch);

  fbsd_trapframe_prepend_unwinder (gdbarch, &arm_fbsd_trapframe);

  tdep->jb_pc = 24;
  tdep->jb_elt_size = 4;

  set_gdbarch_supply_fbsd_pcb (gdbarch, arm_fbsd_supply_pcb);

  /* Single stepping.  */
  set_gdbarch_software_single_step (gdbarch, arm_software_single_step);
}

void _initialize_arm_fbsd_kern ();
void
_initialize_arm_fbsd_kern ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_arm,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_arm, 0, GDB_OSABI_FREEBSD_KERNEL,
			  arm_fbsd_kernel_init_abi);
}
