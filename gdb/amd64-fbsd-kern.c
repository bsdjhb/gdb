/* Target-dependent code for FreeBSD/amd64 kernels.

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
#include "gdbsupport/x86-xstate.h"
#include "amd64-tdep.h"

static const struct regcache_map_entry amd64_fbsd_pcbmap[] =
  {
    { 1, AMD64_R15_REGNUM, 8 },
    { 1, AMD64_R14_REGNUM, 8 },
    { 1, AMD64_R13_REGNUM, 8 },
    { 1, AMD64_R12_REGNUM, 8 },
    { 1, AMD64_RBP_REGNUM, 8 },
    { 1, AMD64_RSP_REGNUM, 8 },
    { 1, AMD64_RBX_REGNUM, 8 },
    { 1, AMD64_RIP_REGNUM, 8 },
    { 0 }
  };

static const struct regset amd64_fbsd_pcbregset =
  {
    amd64_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
amd64_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		       const void *buf, size_t len)
{
  regcache->supply_regset (&amd64_fbsd_pcbregset, -1, buf, len);
}

static const struct regcache_map_entry amd64_fbsd_trapframe_map[] =
  {
    { 1, AMD64_RDI_REGNUM, 8 },
    { 1, AMD64_RSI_REGNUM, 8 },
    { 1, AMD64_RDX_REGNUM, 8 },
    { 1, AMD64_RCX_REGNUM, 8 },
    { 2, AMD64_R8_REGNUM, 8 },
    { 1, AMD64_RAX_REGNUM, 8 },
    { 1, AMD64_RBX_REGNUM, 8 },
    { 1, AMD64_RBP_REGNUM, 8 },
    { 6, AMD64_R10_REGNUM, 8 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* tf_trapno */
    { 1, AMD64_FS_REGNUM, 2 },
    { 1, AMD64_GS_REGNUM, 2 },
    { 1, REGCACHE_MAP_SKIP, 8 },	/* tf_addr */
    { 1, REGCACHE_MAP_SKIP, 4 },	/* tf_flags */
    { 1, AMD64_EFLAGS_REGNUM, 8 },
    { 1, AMD64_ES_REGNUM, 2 },
    { 1, AMD64_DS_REGNUM, 2 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* tf_err */
    { 1, AMD64_RIP_REGNUM, 8 },
    { 1, AMD64_CS_REGNUM, 8 },
    { 1, AMD64_EFLAGS_REGNUM, 8 },
    { 1, AMD64_RSP_REGNUM, 8 },
    { 1, AMD64_SS_REGNUM, 8 },
    { 0 }
  };

static void
amd64_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			   frame_info_ptr this_frame,
			   struct trad_frame_cache *this_cache,
			   CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR offset, pc, sp;

  sp = get_frame_register_unsigned (this_frame, AMD64_RSP_REGNUM);

  if (strcmp (name, "fork_trampoline") == 0 && get_frame_pc (this_frame) == func)
    {
      /* fork_exit hasn't been called (kthread has never run), so %rsp
	 in the pcb points to the trapframe.  GDB has auto-adjusted
	 %rsp for this frame to account for the "call" into
	 fork_trampoline, so "undo" the adjustment.  */
      sp += 8;
    }

  trad_frame_set_reg_regmap (this_cache, amd64_fbsd_trapframe_map, sp,
			     regcache_map_entry_size (amd64_fbsd_trapframe_map));

  /* Read %rip from trap frame.  */
  offset = regcache_map_offset (amd64_fbsd_trapframe_map, AMD64_RIP_REGNUM,
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
amd64_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "calltrap") == 0
	  || strcmp (name, "fast_syscall_common") == 0
	  || strcmp (name, "fork_trampoline") == 0
	  || strcmp (name, "mchk_calltrap") == 0
	  || strcmp (name, "nmi_calltrap") == 0
	  || (name[0] == 'X' && name[1] != '_'));
}

static const struct fbsd_trapframe amd64_fbsd_trapframe =
{
  amd64_fbsd_trapframe_matches,
  amd64_fbsd_trapframe_init
};

static void
amd64_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  fbsd_kernel_init_abi (info, gdbarch);

  amd64_init_abi (info, gdbarch,
		  amd64_target_description (X86_XSTATE_SSE_MASK, true));

  fbsd_trapframe_prepend_unwinder (gdbarch, &amd64_fbsd_trapframe);

  set_gdbarch_supply_fbsd_pcb (gdbarch, amd64_fbsd_supply_pcb);
}

void _initialize_amd64_fbsd_kern ();
void
_initialize_amd64_fbsd_kern ()
{
  gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64,
			  GDB_OSABI_FREEBSD_KERNEL, amd64_fbsd_kernel_init_abi);
}
