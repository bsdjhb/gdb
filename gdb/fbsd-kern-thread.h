/* FreeBSD kernel thread support

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

#ifndef FBSD_KERN_THREAD_H
#define FBSD_KERN_THREAD_H

#include <list>

struct fbsd_kthread_info
{
  /* Address of 'struct thread' object.  */
  CORE_ADDR thread_address;

  /* Address of 'struct proc' object.  */
  CORE_ADDR proc_address;

  /* Address of 'struct pcb' object.  */
  CORE_ADDR pcb_address;

  /* pid of containing process.  */
  LONGEST pid;

  /* kernel thread ID.  */
  LONGEST tid;

  /* CPU currently executing on, or -1 if suspended.  */
  int cpu;
};

/* Return a list of the current kernel threads.  This is a best effort
   function which may return a partial list if invald addreses are
   encountered while walking the relevant data structures to enumerate
   processes and threads.

   Each thread found is described by a fbsd_kthread_info object in the
   returned list.  */

extern std::list<fbsd_kthread_info>
fbsd_kthread_list_threads (gdbarch *gdbarch);

/* Return the name of a kernel thread.  */

extern const char *fbsd_kthread_name (const struct fbsd_kthread_info *ki);

/* Return extra information about a kernel thread.  */

extern const char *fbsd_kthread_extra_info (const struct fbsd_kthread_info *ki);

#endif /* fbsd-kern-thread.h */
