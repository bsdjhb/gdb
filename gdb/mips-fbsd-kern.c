/*
 * Copyright (c) 2007 Juniper Networks, Inc.
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

#include "defs.h"
#include "fbsd-trapframe.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "trad-frame.h"

#include "fbsd-kern.h"
#include "mips-tdep.h"

/* Size of struct trapframe in registers. */
#define	TRAPFRAME_WORDS	74

static const struct regcache_map_entry mips_fbsd_pcbmap[] =
  {
    { TRAPFRAME_WORDS, REGCACHE_MAP_SKIP, 0 }, /* user trapframe */
    { 7, MIPS_S2_REGNUM - 2, 0 }, /* s0 ... s7 */
    { 1, MIPS_SP_REGNUM, 0 },
    { 1, MIPS_S2_REGNUM + 6, 0 },
    { 1, MIPS_RA_REGNUM, 0 },
    { 1, MIPS_PS_REGNUM, 0 },
    { 1, MIPS_GP_REGNUM, 0 },
    { 1, MIPS_EMBED_PC_REGNUM, 0 },
  };

static const struct regset mips_fbsd_pcbregset =
  {
    mips_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
mips_fbsd_supply_pcb (gdbarch *gdbarch, struct regcache *regcache,
		      const void *buf, size_t len)
{
  regcache->supply_regset (&mips_fbsd_pcbregset, -1, buf, len);
}

static void
mips_fbsd_trapframe_init (const struct fbsd_trapframe *self,
			  frame_info_ptr this_frame,
			  struct trad_frame_cache *this_cache,
			  CORE_ADDR func, const char *name)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  size_t regsize = mips_isa_regsize (gdbarch);
  CORE_ADDR addr, sp;
  int regnum;

  sp = get_frame_register_signed (this_frame,
				  MIPS_SP_REGNUM + gdbarch_num_regs (gdbarch));

  /* Skip over CALLFRAME_SIZ.  */
  addr = sp;
  if (regsize == 8)
    addr += regsize * 4;
  else
    addr += regsize * (4 + 2);

  /* GPRs.  Skip zero.  */
  addr += regsize;
  for (regnum = MIPS_AT_REGNUM; regnum <= MIPS_RA_REGNUM; regnum++)
    {
      trad_frame_set_reg_addr (this_cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);
      addr += regsize;
    }

  regnum = MIPS_PS_REGNUM;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* HI and LO.  */
  regnum = mips_regnum (gdbarch)->lo;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;
  regnum = mips_regnum (gdbarch)->hi;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* BADVADDR.  */
  regnum = mips_regnum (gdbarch)->badvaddr;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* CAUSE.  */
  regnum = mips_regnum (gdbarch)->cause;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* PC.  */
  regnum = mips_regnum (gdbarch)->pc;
  trad_frame_set_reg_addr (this_cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static bool
mips_fbsd_trapframe_matches (const char *name)
{
  return (strcmp (name, "MipsKernIntr") == 0
	  || strcmp (name, "MipsKernGenException") == 0
	  || strcmp (name, "MipsTLBInvalidException") == 0);
}

static const struct fbsd_trapframe mips_fbsd_trapframe =
{
  mips_fbsd_trapframe_matches,
  mips_fbsd_trapframe_init,
};

static void
mips_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  enum mips_abi abi = mips_abi (gdbarch);

  fbsd_kernel_init_abi (info, gdbarch);

  set_gdbarch_software_single_step (gdbarch, mips_software_single_step);

  switch (abi)
    {
      case MIPS_ABI_O32:
	break;
      case MIPS_ABI_N32:
	set_gdbarch_long_double_bit (gdbarch, 128);
	set_gdbarch_long_double_format (gdbarch, floatformats_ieee_quad);
	break;
      case MIPS_ABI_N64:
	set_gdbarch_long_double_bit (gdbarch, 128);
	set_gdbarch_long_double_format (gdbarch, floatformats_ieee_quad);
	break;
    }

  fbsd_trapframe_prepend_unwinder (gdbarch, &mips_fbsd_trapframe);

  set_gdbarch_supply_fbsd_pcb (gdbarch, mips_fbsd_supply_pcb);
}

void _initialize_mips_fbsd_kern ();
void
_initialize_mips_fbsd_kern ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_mips,
				  bfd_target_elf_flavour,
				  fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_mips, 0, GDB_OSABI_FREEBSD_KERNEL,
			  mips_fbsd_kernel_init_abi);
}
