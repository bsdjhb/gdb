/* Target-dependent code for FreeBSD/riscv64 kernels.

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
#include "riscv-tdep.h"

static const struct regcache_map_entry riscv_fbsd_pcbmap[] =
  {
    { 1, RISCV_RA_REGNUM, 0 },
    { 1, RISCV_SP_REGNUM, 0 },
    { 1, RISCV_GP_REGNUM, 0 },
    { 1, RISCV_TP_REGNUM, 0 },
    { 2, RISCV_FP_REGNUM, 0 },	/* s0 - s1 */
    { 10, 18, 0 },		/* s2 - s11 */
    { 0 }
  };

static const struct regset riscv_fbsd_pcbregset =
  {
    riscv_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
riscv_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		       const void *buf, size_t len)
{
  regcache->raw_supply_zeroed (RISCV_ZERO_REGNUM);
  regcache->supply_regset (&riscv_fbsd_pcbregset, -1, buf, len);

  /* Supply the RA as PC as well to simulate the PC as if the thread
     had just returned. */
  regcache->raw_supply (RISCV_PC_REGNUM, buf);
}

static const struct regcache_map_entry riscv_fbsd_trapframe_map[] =
  {
    { 1, RISCV_RA_REGNUM, 0 },
    { 1, RISCV_SP_REGNUM, 0 },
    { 1, RISCV_GP_REGNUM, 0 },
    { 1, RISCV_TP_REGNUM, 0 },
    { 3, 5, 0 },		/* t0 - t2 */
    { 4, 28, 0 },		/* t3 - t6 */
    { 2, RISCV_FP_REGNUM, 0 },	/* s0 - s1 */
    { 10, 18, 0 },		/* s2 - s11 */
    { 8, RISCV_A0_REGNUM, 0 },	/* a0 - a7 */
    { 1, RISCV_PC_REGNUM, 0 },
    { 1, RISCV_CSR_SSTATUS_REGNUM, 0 },
    { 1, RISCV_CSR_STVAL_REGNUM, 0 },
    { 1, RISCV_CSR_SCAUSE_REGNUM, 0 },
    { 0 }
  };

static void
riscv_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			   frame_info_ptr this_frame,
			   struct trad_frame_cache *this_cache,
			   CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR offset, pc, sp;

  sp = get_frame_register_unsigned (this_frame, RISCV_SP_REGNUM);

  trad_frame_set_reg_regmap (this_cache, riscv_fbsd_trapframe_map, sp,
			     regcache_map_entry_size (riscv_fbsd_trapframe_map,
						      gdbarch));

  /* Read $PC from trap frame.  */
  offset = regcache_map_offset (riscv_fbsd_trapframe_map, RISCV_PC_REGNUM,
				gdbarch);
  pc = read_memory_unsigned_integer (sp + offset, riscv_isa_xlen (gdbarch),
				     byte_order);

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
riscv_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "cpu_exception_handler_user") == 0
	  || strcmp (name, "cpu_exception_handler_supervisor") == 0);
}

static const struct fbsd_trapframe riscv_fbsd_trapframe =
{
  riscv_fbsd_trapframe_matches,
  riscv_fbsd_trapframe_init
};

/* Implement the 'init_osabi' method of struct gdb_osabi_handler.  */

static void
riscv_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  fbsd_kernel_init_abi (info, gdbarch);

  fbsd_trapframe_prepend_unwinder (gdbarch, &riscv_fbsd_trapframe);

  set_gdbarch_software_single_step (gdbarch, riscv_software_single_step);

  set_gdbarch_supply_fbsd_pcb (gdbarch, riscv_fbsd_supply_pcb);
}

void _initialize_riscv_fbsd_kern ();
void
_initialize_riscv_fbsd_kern ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_riscv,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_riscv, 0, GDB_OSABI_FREEBSD_KERNEL,
			  riscv_fbsd_kernel_init_abi);
}
