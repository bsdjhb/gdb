/* Target-dependent code for FreeBSD/powerpc kernels.

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
#include "ppc-tdep.h"
#include "ppc64-tdep.h"

#define	PCB_OFF_R12	0
#define	PCB_OFF_CR	20
#define	PCB_OFF_SP	21
#define	PCB_OFF_TOC	22
#define	PCB_OFF_LR	23

static const struct regcache_map_entry ppc32_fbsd_pcbmap[] =
  {
    { 20, PPC_R0_REGNUM + 12, 4 }, /* r12 ... r31 */
    { 1, PPC_CR_REGNUM, 4 },
    { 1, PPC_R0_REGNUM + 1, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 },
    { 1, PPC_LR_REGNUM, 4 },
    { 0 }
  };

static const struct regcache_map_entry ppc64_fbsd_pcbmap[] =
  {
    { 20, PPC_R0_REGNUM + 12, 8 }, /* r12 ... r31 */
    { 1, PPC_CR_REGNUM, 8 },
    { 2, PPC_R0_REGNUM + 1, 8 },
    { 1, PPC_LR_REGNUM, 8 },
    { 0 }
  };

static const struct regset ppc32_fbsd_pcbregset =
  {
    ppc32_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static const struct regset ppc64_fbsd_pcbregset =
  {
    ppc64_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
ppc_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		     const void *buf, size_t len)
{
  ppc_gdbarch_tdep *tdep = gdbarch_tdep<ppc_gdbarch_tdep> (gdbarch);
  const struct regcache_map_entry *regmap;
  const struct regset *regset;

  if (tdep->wordsize == 8)
    {
      regmap = ppc64_fbsd_pcbmap;
      regset = &ppc64_fbsd_pcbregset;
    }
  else
    {
      regmap = ppc32_fbsd_pcbmap;
      regset = &ppc32_fbsd_pcbregset;
    }
  regcache->supply_regset (regset, -1, buf, len);

  /* Supply PC as a copy of LR.  */
  int offset = regcache_map_offset (regmap, PPC_LR_REGNUM, gdbarch);
  regcache->raw_supply (PPC_PC_REGNUM, (const char *)buf + offset);
}

#define	OFF_FIXREG	0
#define	OFF_LR		32
#define	OFF_CR		33
#define	OFF_XER		34
#define	OFF_CTR		35
#define	OFF_SRR0	36

static const struct regcache_map_entry ppc_fbsd_trapframe_map[] =
  {
    { 32, PPC_R0_REGNUM, 0 }, /* r0 ... r31 */
    { 1, PPC_LR_REGNUM, 0 },
    { 1, PPC_CR_REGNUM, 0 },
    { 1, PPC_XER_REGNUM, 0 },
    { 1, PPC_CTR_REGNUM, 0 },
    { 1, PPC_PC_REGNUM, 0 },
    { 1, PPC_MSR_REGNUM, 0 },
    { 0 }
  };

static void
ppc_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			 frame_info_ptr this_frame,
			 struct trad_frame_cache *this_cache,
			 CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  ppc_gdbarch_tdep *tdep = gdbarch_tdep<ppc_gdbarch_tdep> (gdbarch);
  CORE_ADDR base;
  int i;

  base = get_frame_register_unsigned (this_frame, gdbarch_sp_regnum (gdbarch));
  if (tdep->wordsize == 8)
    base += 48;
  else
    base += 8;

  trad_frame_set_reg_regmap (this_cache, ppc_fbsd_trapframe_map, base,
			     regcache_map_entry_size (ppc_fbsd_trapframe_map,
						      gdbarch));

  /* Construct the frame ID using the function start.  */
  trad_frame_set_id (this_cache, frame_id_build (base, func));
}

static bool
ppc_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "trapagain") == 0
	  || strcmp (name, "trapexit") == 0
	  || strcmp (name, "dbtrap") == 0);
}

static const struct fbsd_trapframe ppc_fbsd_trapframe =
{
  ppc_fbsd_trapframe_matches,
  ppc_fbsd_trapframe_init
};

static void
ppc_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  ppc_gdbarch_tdep *tdep = gdbarch_tdep<ppc_gdbarch_tdep> (gdbarch);

  fbsd_kernel_init_abi (info, gdbarch);

  fbsd_trapframe_prepend_unwinder (gdbarch, &ppc_fbsd_trapframe);

  set_gdbarch_supply_fbsd_pcb (gdbarch, ppc_fbsd_supply_pcb);

  /* FreeBSD doesn't support the 128-bit `long double' from the psABI.  */
  set_gdbarch_long_double_bit (gdbarch, 64);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_double);

  if (tdep->wordsize == 4)
    {
      set_gdbarch_return_value (gdbarch, ppc_sysv_abi_broken_return_value);
    }

  if (tdep->wordsize == 8)
    {
      set_gdbarch_convert_from_func_ptr_addr
	(gdbarch, ppc64_convert_from_func_ptr_addr);
      set_gdbarch_elf_make_msymbol_special (gdbarch,
					    ppc64_elf_make_msymbol_special);
    }
}

void _initialize_ppc_fbsd_kern ();
void
_initialize_ppc_fbsd_kern ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_powerpc,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_powerpc, bfd_mach_ppc,
			  GDB_OSABI_FREEBSD_KERNEL,
			  ppc_fbsd_kernel_init_abi);
  gdbarch_register_osabi (bfd_arch_powerpc, bfd_mach_ppc64,
			  GDB_OSABI_FREEBSD_KERNEL,
			  ppc_fbsd_kernel_init_abi);
}
