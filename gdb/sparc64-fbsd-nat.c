/* Native-dependent code for FreeBSD/sparc64.

   Copyright (C) 2003-2023 Free Software Foundation, Inc.

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
#include "regcache.h"
#include "target.h"

#include "fbsd-nat.h"
#include "sparc64-tdep.h"
#include "sparc-nat.h"

/* Add some extra features to the generic SPARC target.  */
static sparc_target<fbsd_nat_target> the_sparc64_fbsd_nat_target;

void _initialize_sparc64fbsd_nat ();
void
_initialize_sparc64fbsd_nat ()
{
  add_inf_child_target (&the_sparc64_fbsd_nat_target);

  sparc_gregmap = &sparc64fbsd_gregmap;
}
