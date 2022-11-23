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

#include "defs.h"
#include "fbsd-trapframe.h"
#include "frame-unwind.h"
#include "gdbarch.h"
#include "trad-frame.h"

struct fbsd_trapframe_cache
{
  const struct fbsd_trapframe *trapframe;
  struct trad_frame_cache *trad_cache;
  const char *name;
};

static struct trad_frame_cache *
fbsd_trapframe_cache (frame_info_ptr this_frame,
		      void **this_cache)
{
  struct fbsd_trapframe_cache *trap_cache
    = (struct fbsd_trapframe_cache *) *this_cache;

  if (trap_cache->trad_cache == NULL)
    {
      trap_cache->trad_cache = trad_frame_cache_zalloc (this_frame);
      trap_cache->trapframe->init (trap_cache->trapframe, this_frame,
				   trap_cache->trad_cache,
				   get_frame_func (this_frame),
				   trap_cache->name);
    }
  return trap_cache->trad_cache;
}

static void
fbsd_trapframe_this_id (frame_info_ptr this_frame,
			void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *trad_cache
    = fbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (trad_cache, this_id);
}

static struct value *
fbsd_trapframe_prev_register (frame_info_ptr this_frame,
			      void **this_cache, int prev_regnum)
{
  struct trad_frame_cache *trad_cache
    = fbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (trad_cache, this_frame, prev_regnum);
}

static const char *
fbsd_trapframe_match (const struct fbsd_trapframe *trapframe,
		      CORE_ADDR pc)
{
  const char *name;
  int i;

  find_pc_partial_function (pc, &name, nullptr, nullptr);
  if (name == nullptr)
    return nullptr;

  if (trapframe->matches (name))
    return name;
  return nullptr;
}

static int
fbsd_trapframe_sniffer (const struct frame_unwind *self,
			frame_info_ptr this_frame,
			void **this_cache)
{
  const struct fbsd_trapframe *trapframe
    = (const struct fbsd_trapframe *)self->unwind_data;
  CORE_ADDR pc = get_frame_pc (this_frame);

  const char *name = fbsd_trapframe_match (trapframe, pc);
  if (name == nullptr)
    return 0;
  struct fbsd_trapframe_cache *trap_cache
    = FRAME_OBSTACK_ZALLOC (struct fbsd_trapframe_cache);
  trap_cache->trapframe = trapframe;
  trap_cache->name = name;
  (*this_cache) = trap_cache;
  return 1;
}

void
fbsd_trapframe_prepend_unwinder (struct gdbarch *gdbarch,
				 const struct fbsd_trapframe *trapframe)
{
  struct frame_unwind *unwinder;

  unwinder = GDBARCH_OBSTACK_ZALLOC (gdbarch, struct frame_unwind);

  unwinder->type = SIGTRAMP_FRAME;
  unwinder->unwind_data = (const struct frame_data *) trapframe;
  unwinder->sniffer = fbsd_trapframe_sniffer;
  unwinder->stop_reason = default_frame_unwind_stop_reason;
  unwinder->this_id = fbsd_trapframe_this_id;
  unwinder->prev_register = fbsd_trapframe_prev_register;
  frame_unwind_prepend_unwinder (gdbarch, unwinder);
}
