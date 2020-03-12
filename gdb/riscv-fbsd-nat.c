/* Native-dependent code for FreeBSD/riscv.

   Copyright (C) 2018-2019 Free Software Foundation, Inc.

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
#include "target.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <machine/reg.h>
#ifdef PT_GETCAPREGS
#include <sys/sysctl.h>
#endif

#include "fbsd-nat.h"
#include "riscv-tdep.h"
#include "riscv-fbsd-tdep.h"
#include "inf-ptrace.h"

struct riscv_fbsd_nat_target final : public fbsd_nat_target
{
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;
#ifdef PT_GETCAPREGS
  const struct target_desc *read_description () override;
#endif
};

static riscv_fbsd_nat_target the_riscv_fbsd_nat_target;

#ifdef PT_GETCAPREGS
static int capreg_size;
#endif

/* Determine if PT_GETREGS fetches REGNUM.  */

static bool
getregs_supplies (struct gdbarch *gdbarch, int regnum)
{
  return ((regnum >= RISCV_RA_REGNUM && regnum <= RISCV_PC_REGNUM)
	  || regnum == RISCV_CSR_SSTATUS_REGNUM);
}

/* Determine if PT_GETFPREGS fetches REGNUM.  */

static bool
getfpregs_supplies (struct gdbarch *gdbarch, int regnum)
{
  return ((regnum >= RISCV_FIRST_FP_REGNUM && regnum <= RISCV_LAST_FP_REGNUM)
	  || regnum == RISCV_CSR_FCSR_REGNUM);
}

#ifdef PT_GETCAPREGS
/* Determine if PT_GETCAPREGS fetches REGNUM.  */

static bool
getcapregs_supplies (struct gdbarch *gdbarch, int regnum)
{
  return regcache_map_entry_supplies (riscv_fbsd_capregmap, regnum);
}
#endif

/* Fetch register REGNUM from the inferior.  If REGNUM is -1, do this
   for all registers.  */

void
riscv_fbsd_nat_target::fetch_registers (struct regcache *regcache,
					int regnum)
{
  pid_t pid = get_ptrace_pid (regcache->ptid ());

  struct gdbarch *gdbarch = regcache->arch ();
  if (regnum == -1 || regnum == RISCV_ZERO_REGNUM)
    regcache->raw_supply_zeroed (RISCV_ZERO_REGNUM);
  if (regnum == -1 || getregs_supplies (gdbarch, regnum))
    {
      struct reg regs;

      if (ptrace (PT_GETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't get registers"));

      regcache->supply_regset (&riscv_fbsd_gregset, regnum, &regs,
			       sizeof (regs));
    }

  if (regnum == -1 || getfpregs_supplies (gdbarch, regnum))
    {
      struct fpreg fpregs;

      if (ptrace (PT_GETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't get floating point status"));

      regcache->supply_regset (&riscv_fbsd_fpregset, regnum, &fpregs,
			       sizeof (fpregs));
    }

#ifdef PT_GETCAPREGS
  if (capreg_size != 0)
    {
      if (regnum == -1 || regnum == RISCV_CNULL_REGNUM)
	regcache->raw_supply_zeroed (RISCV_CNULL_REGNUM);
      if (regnum == -1 || getcapregs_supplies (gdbarch, regnum))
	{
	  struct capreg capregs;

	  if (ptrace (PT_GETCAPREGS, pid, (PTRACE_TYPE_ARG3) &capregs, 0) == -1)
	    perror_with_name (_("Couldn't get capability registers"));

	  regcache->supply_regset (&riscv_fbsd_capregset, regnum, &capregs,
				   sizeof (capregs));
	}
    }
#endif
}

/* Store register REGNUM back into the inferior.  If REGNUM is -1, do
   this for all registers.  */

void
riscv_fbsd_nat_target::store_registers (struct regcache *regcache,
					int regnum)
{
  pid_t pid = get_ptrace_pid (regcache->ptid ());

  struct gdbarch *gdbarch = regcache->arch ();
  if (regnum == -1 || getregs_supplies (gdbarch, regnum))
    {
      struct reg regs;

      if (ptrace (PT_GETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't get registers"));

      regcache->collect_regset (&riscv_fbsd_gregset, regnum, &regs,
			       sizeof (regs));

      if (ptrace (PT_SETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't write registers"));
    }

  if (regnum == -1 || getfpregs_supplies (gdbarch, regnum))
    {
      struct fpreg fpregs;

      if (ptrace (PT_GETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't get floating point status"));

      regcache->collect_regset (&riscv_fbsd_fpregset, regnum, &fpregs,
				sizeof (fpregs));

      if (ptrace (PT_SETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't write floating point status"));
    }

#ifdef notyet
#ifdef PT_GETCAPREGS
  if (capreg_size != 0
      && (regnum == -1 || getcapregs_supplies (gdbarch, regnum)))
    {
      struct capreg capregs;

      if (ptrace (PT_GETCAPREGS, pid, (PTRACE_TYPE_ARG3) &capregs, 0) == -1)
	perror_with_name (_("Couldn't get capability registers"));

      regcache->collect_regset_regset (&riscv_fbsd_capregset, regnum, &capregs,
				       sizeof (capregs));

      if (ptrace (PT_SETCAPREGS, pid, (PTRACE_TYPE_ARG3) &capregs, 0) == -1)
	perror_with_name (_("Couldn't write capability registers"));
    }
#endif
#endif
}

#ifdef PT_GETCAPREGS
/* Implement the read_description method.  */

const struct target_desc *
riscv_fbsd_nat_target::read_description ()
{
  struct riscv_gdbarch_features features;
  struct reg *reg;

  features.xlen = sizeof (reg->ra);
  features.clen = capreg_size;
  features.flen = sizeof (uint64_t);

  return riscv_create_target_description (features);
}
#endif

void
_initialize_riscv_fbsd_nat (void)
{
  add_inf_child_target (&the_riscv_fbsd_nat_target);

#ifdef PT_GETCAPREGS
  size_t len = sizeof (capreg_size);
  if (sysctlbyname ("security.cheri.capability_size", &capreg_size, &len,
		    NULL, 0) != 0)
    capreg_size = 0;
#endif
}
