/* FreeBSD kernel trapframe unwinder.

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

#ifndef FBSD_TRAP_FRAME_H
#define FBSD_TRAP_FRAME_H

struct trad_frame;
class frame_info_ptr;
struct trad_frame_cache;

/* Exception entry points in the FreeBSD kernel save the register
   state of the interrupted context in a struct trapframe on the
   kernel stack.  Exception entry points are identified by the symbol
   name.  */

struct fbsd_trapframe
{
  /* Return true if a function name matches.  */
  bool (*matches) (const char *name);

  /* Initialize a trad-frame cache corresponding to the trapframe.  */
  void (*init) (const struct fbsd_trapframe *self,
		frame_info_ptr this_frame,
		struct trad_frame_cache *this_cache, CORE_ADDR func,
		const char *name);
};

void fbsd_trapframe_prepend_unwinder (struct gdbarch *gdbarch,
				      const struct fbsd_trapframe *trapframe);

#endif
