/* Handle modules for FreeBSD kernels.

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
#include "gdbarch.h"
#include "gdbcore.h"
#include "progspace.h"
#include "symfile.h"
#include "gdbsupport/symbol.h"

#include "fbsd-tdep.h"
#include "solist.h"
#include "solib.h"
#include "solib-fbsd-kld.h"

struct lm_info_kld : public lm_info_base
{
  CORE_ADDR base_address = 0;
  CORE_ADDR current_address = 0;
};

struct fbsd_kld_info
{
  /* Offsets of fields in linker_file structure.  */
  LONGEST off_address;
  LONGEST off_pathname;
  LONGEST off_next;

  /* Address of TAILQ_HEAD of linker_file structures.  */
  CORE_ADDR linker_files_addr;

  /* Address of pointer to kernel's linker_file.  */
  CORE_ADDR kernel_file_addr;
};

/* Per-program-space data key.  */
static const registry<program_space>::key<fbsd_kld_info> fbsd_kld_pspace_data;

/* Get the current kld data.  If none is found yet, add it now.  This
   function always returns a valid object.  */

static struct fbsd_kld_info *
get_fbsd_kld_info (void)
{
  struct fbsd_kld_info *info;

  info = fbsd_kld_pspace_data.get (current_program_space);
  if (info == nullptr)
    info = fbsd_kld_pspace_data.emplace (current_program_space);

  return info;
}

/* Implement the "relocate_section_addresses" target_so_ops method.  */

static void
fbsd_kld_relocate_section_addresses (struct so_list *so,
				struct target_section *sec)
{
  lm_info_kld *li = (lm_info_kld *) so->lm_info;
  struct bfd_section *bfd_sec = sec->the_bfd_section;
  bfd *abfd = bfd_sec->owner;

  if (abfd->flags & (EXEC_P | DYNAMIC))
    {
      /* Kernels and modules built as DSOs are simple offsets.  */
      sec->addr += li->base_address;
      sec->endaddr += li->base_address;
    }
  else
    {
      /* Kernel modules built as object files need each section to be
	 relocated explicitly factoring in alignment.  */
      if (sec == &so->sections->front ())
	li->current_address = li->base_address;
      else
	li->current_address = align_power (li->current_address,
					   bfd_section_alignment (bfd_sec));
      sec->addr = li->current_address;
      sec->endaddr = li->current_address + bfd_section_size (bfd_sec);
      li->current_address = sec->endaddr;
    }
}

/* Implement the "free_so" target_so_ops method.  */

static void
fbsd_kld_free_so (struct so_list *so)
{
  lm_info_kld *li = (lm_info_kld *) so->lm_info;

  delete li;
}

/* Implement the "clear_solib" target_so_ops method.  */

static void
fbsd_kld_clear_solib ()
{
  struct fbsd_kld_info *info;

  info = get_fbsd_kld_info();

  memset(info, 0, sizeof(*info));
}

/* Implement the "solib_create_inferior_hook" target_so_ops method.  */

static void
fbsd_kld_solib_create_inferior_hook (int from_tty)
{
  gdbarch *gdbarch = target_gdbarch ();
  struct fbsd_kld_info *info = get_fbsd_kld_info();

  /* FreeBSD kernels 10.3 and later include the offset of relevant
     members in struct linker_file as global constants.  If those
     constants don't exist, fall back to using debug symbols.  */
  try
    {
      info->off_address = fbsd_read_integer_by_name (gdbarch, "kld_off_address");
      info->off_pathname = fbsd_read_integer_by_name (gdbarch,
						      "kld_off_pathname");
      info->off_next = fbsd_read_integer_by_name (gdbarch, "kld_off_next");
    }
  catch (const gdb_exception_error &e)
    {
      try
	{
	  struct symbol *linker_file_sym
	    = lookup_symbol_in_language ("struct linker_file", nullptr,
					 STRUCT_DOMAIN, language_c,
					 nullptr).symbol;
	  if (linker_file_sym == nullptr)
	    error (_("Unable to find struct linker_file symbol"));

	  info->off_address = lookup_struct_elt (linker_file_sym->type (),
						 "address", 0).offset / 8;
	  info->off_pathname = lookup_struct_elt (linker_file_sym->type (),
						  "pathname", 0).offset / 8;

	  struct type *link_type
	    = lookup_struct_elt_type (linker_file_sym->type (), "link", 0);
	  if (link_type == nullptr)
	    error (_("Unable to find link type"));

	  info->off_next = lookup_struct_elt (link_type, "tqe_next", 0).offset
	    / 8;
	}
      catch (const gdb_exception_error &e2)
	{
	  return;
	}
    }

  /* Lookup addresses of relevant global variables.  */
  struct bound_minimal_symbol msymbol
    = lookup_minimal_symbol ("linker_files", nullptr,
			     current_program_space->symfile_object_file);
  if (msymbol.minsym == nullptr)
    return;
  info->linker_files_addr = msymbol.value_address ();

  msymbol = lookup_minimal_symbol ("linker_kernel_file", nullptr,
				   current_program_space->symfile_object_file);
  if (msymbol.minsym == nullptr)
    return;
  info->kernel_file_addr = msymbol.value_address ();

  solib_add (nullptr, from_tty, auto_solib_add);
}

/* Implement the "current_sos" target_so_ops method.  */

static struct so_list *
fbsd_kld_current_sos (void)
{
  struct fbsd_kld_info *info = get_fbsd_kld_info();
  if (info->kernel_file_addr == 0)
    return nullptr;

  gdbarch *gdbarch = target_gdbarch ();
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  struct so_list *head = NULL;
  struct so_list *tail = NULL;

  CORE_ADDR kernel, lf, next_lf;

  try
    {
      kernel = read_memory_typed_address (info->kernel_file_addr, ptr_type);
      lf = read_memory_typed_address (info->linker_files_addr, ptr_type);
    }
  catch (const gdb_exception_error &e)
    {
      return nullptr;
    }
  for ( ; lf != 0; lf = next_lf)
    {
      CORE_ADDR address, pathname;
      try
	{
	  address = read_memory_typed_address (lf + info->off_address,
					       ptr_type);
	  pathname = read_memory_typed_address (lf + info->off_pathname,
						ptr_type);
	  next_lf = read_memory_typed_address (lf + info->off_next,
					       ptr_type);
	}
      catch (const gdb_exception_error &e)
	{
	  break;
	}

      /* Skip the main kernel linker file.  */
      if (lf == kernel)
	continue;

      gdb::unique_xmalloc_ptr<char> path
	= target_read_string (pathname, SO_NAME_MAX_PATH_SIZE - 1);
      if (path == nullptr)
	break;

      so_list_up newobj (XCNEW (struct so_list));

      lm_info_kld *li = new lm_info_kld;
      newobj->lm_info = li;

      strncpy (newobj->so_name, path.get (), SO_NAME_MAX_PATH_SIZE - 1);
      newobj->so_name[SO_NAME_MAX_PATH_SIZE - 1] = '\0';
      strcpy (newobj->so_original_name, newobj->so_name);
      li->base_address = address;

      if (head == nullptr)
	head = newobj.get ();
      else
	tail->next = newobj.get ();
      tail = newobj.release ();
    }

  return head;
}

static int
fbsd_kld_open_symbol_file_object (int from_tty)
{
  return 0;
}

static int
fbsd_kld_in_dynsym_resolve_code (CORE_ADDR pc)
{
  return 0;
}

const struct target_so_ops fbsd_kld_so_ops =
{
  fbsd_kld_relocate_section_addresses,
  fbsd_kld_free_so,
  nullptr,
  fbsd_kld_clear_solib,
  fbsd_kld_solib_create_inferior_hook,
  fbsd_kld_current_sos,
  fbsd_kld_open_symbol_file_object,
  fbsd_kld_in_dynsym_resolve_code,
  solib_bfd_open,
};
