/*
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/gnu/usr.bin/gdb/kgdb/main.c 260027 2013-12-28 23:31:22Z marcel $");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <kvm.h>
#include <limits.h>
#include <paths.h>
#ifdef CROSS_DEBUGGER
#include <proc_service.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libgdb stuff. */
#include <defs.h>
#include "elf-bfd.h"
#include <frame.h>
#include <frame-unwind.h>
#include <inferior.h>
#include <interps.h>
#include <cli-out.h>
#include <main.h>
#include <objfiles.h>
#include "observer.h"
#include "osabi.h"
#include <target.h>
#include <top.h>
#include <ui-file.h>
#include <bfd.h>
#include <gdbcore.h>

#include <unistd.h>

#include "kgdb.h"

static int dumpnr;
static int quiet;
static int verbose;

static char crashdir[PATH_MAX];
static char *kernel;
static char *remote;
static char *vmcore;
static struct ui_file *parse_gdberr;

/*
 * TODO:
 * - test remote kgdb (see if threads and klds work)
 * - possibly split kthr.c out into a separate thread_stratum target that
 *   uses new_objfile test to push itself when a FreeBSD kernel is loaded
 *   (check for kernel osabi)
 * - test alternate kgdb_lookup()
 * - fix kgdb built on amd64 to include i386 cross-debug support
 * - propose expanded libkvm interface that supports cross-debug and moves
 *   MD bits of kgdb into the library (examining PCB's and exporting a
 *   stable-ABI struct of registers, similarly for trapframe handling and
 *   stop-pcb stuff
 */

#ifdef CROSS_DEBUGGER
ps_err_e
ps_pglobal_lookup(struct ps_prochandle *ph, const char *obj, const char *name,
    psaddr_t *sym_addr)
{
	struct minimal_symbol *ms;
	CORE_ADDR addr;

	ms = lookup_minimal_symbol (name, NULL, NULL);
	if (ms == NULL)
		return PS_NOSYM;

	addr = SYMBOL_VALUE_ADDRESS (ms);
	store_typed_address(sym_addr, builtin_type_void_data_ptr, addr);
	return PS_OK;
}
#endif

static void
usage(void)
{

	fprintf(stderr,
	    "usage: %s [-afqvw] [-b rate] [-d crashdir] [-c core | -n dumpnr | -r device]\n"
	    "\t[kernel [core]]\n", getprogname());
	exit(1);
}

static void
kernel_from_dumpnr(int nr)
{
	char path[PATH_MAX];
	FILE *info;
	char *s;
	struct stat st;
	int l;

	/*
	 * If there's a kernel image right here in the crash directory, then
	 * use it.  The kernel image is either called kernel.<nr> or is in a
	 * subdirectory kernel.<nr> and called kernel.  The latter allows us
	 * to collect the modules in the same place.
	 */
	snprintf(path, sizeof(path), "%s/kernel.%d", crashdir, nr);
	if (stat(path, &st) == 0) {
		if (S_ISREG(st.st_mode)) {
			kernel = strdup(path);
			return;
		}
		if (S_ISDIR(st.st_mode)) {
			snprintf(path, sizeof(path), "%s/kernel.%d/kernel",
			    crashdir, nr);
			if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
				kernel = strdup(path);
				return;
			}
		}
	}

	/*
	 * No kernel image here.  Parse the dump header.  The kernel object
	 * directory can be found there and we probably have the kernel
	 * image still in it.  The object directory may also have a kernel
	 * with debugging info (called kernel.debug).  If we have a debug
	 * kernel, use it.
	 */
	snprintf(path, sizeof(path), "%s/info.%d", crashdir, nr);
	info = fopen(path, "r");
	if (info == NULL) {
		warn("%s", path);
		return;
	}
	while (fgets(path, sizeof(path), info) != NULL) {
		l = strlen(path);
		if (l > 0 && path[l - 1] == '\n')
			path[--l] = '\0';
		if (strncmp(path, "    ", 4) == 0) {
			s = strchr(path, ':');
			s = (s == NULL) ? path + 4 : s + 1;
			l = snprintf(path, sizeof(path), "%s/kernel.debug", s);
			if (stat(path, &st) == -1 || !S_ISREG(st.st_mode)) {
				path[l - 6] = '\0';
				if (stat(path, &st) == -1 ||
				    !S_ISREG(st.st_mode))
					break;
			}
			kernel = strdup(path);
			break;
		}
	}
	fclose(info);
}

#if 0
static void
kgdb_new_objfile(struct objfile *objfile)
{
	static int once = 1;

	/*
	 * XXX: GDB axed push_remote_target() upstream.  Possibly just
	 * put it back.
	 */
	if (once && objfile != NULL && objfile == symfile_objfile) {
		/*
		 * The initial kernel has just been loaded.  Start the
		 * remote target if we have one.
		 */
		once = 0;
		if (remote != NULL)
			push_remote_target (remote, 0);
	}
}
#endif

static void
restore_stderr(void *arg)
{

	gdb_stderr = (struct ui_file *)arg;
}

/*
 * Parse an expression and return its value.  If 'quiet' is true, then
 * any error messages from the parser are masked.
 */
CORE_ADDR
kgdb_parse_quiet(const char *exp)
{
	struct cleanup *old_chain;
	CORE_ADDR n;

	old_chain = make_cleanup(restore_stderr, gdb_stderr);
	gdb_stderr = parse_gdberr;
	n = parse_and_eval_address(exp);
	do_cleanups(old_chain);
	return (n);
}

#define	MSGBUF_SEQ_TO_POS(size, seq)	((seq) % (size))

void
kgdb_dmesg(void)
{
	CORE_ADDR bufp;
	int size, rseq, wseq;
	gdb_byte c;

	/*
	 * Display the unread portion of the message buffer. This gives the
	 * user a some initial data to work from.
	 */
	if (quiet)
		return;
	bufp = parse_and_eval_address("msgbufp->msg_ptr");
	size = parse_and_eval_long("msgbufp->msg_size");
	if (bufp == 0 || size == 0)
		return;
	rseq = parse_and_eval_long("msgbufp->msg_rseq");
	wseq = parse_and_eval_long("msgbufp->msg_wseq");
	rseq = MSGBUF_SEQ_TO_POS(size, rseq);
	wseq = MSGBUF_SEQ_TO_POS(size, wseq);
	if (rseq == wseq)
		return;

	printf("\nUnread portion of the kernel message buffer:\n");
	while (rseq < wseq) {
		read_memory(bufp + rseq, &c, 1);
		putchar(c);
		rseq++;
		if (rseq == size)
			rseq = 0;
	}
	if (c != '\n')
		putchar('\n');
	putchar('\n');
}

static enum gdb_osabi
fbsd_kernel_osabi_sniffer(bfd *abfd)
{
	asection *s;

	/* FreeBSD ELF kernels have a FreeBSD/ELF OS ABI. */
	if (elf_elfheader(abfd)->e_ident[EI_OSABI] != ELFOSABI_FREEBSD)
		return (GDB_OSABI_UNKNOWN);

	/* FreeBSD ELF kernels have an interpreter path of "/red/herring". */
	s = bfd_get_section_by_name(abfd, ".interp");
	if (s != NULL && s->size == strlen("/red/herring") &&
	    memcmp(s->contents, "/red/herring", strlen("/red/herring")) == 0)
		return (GDB_OSABI_FREEBSD_ELF_KERNEL);

	return (GDB_OSABI_UNKNOWN);
}

extern void _initialize_amd64_kgdb_tdep(void);

static void
kgdb_init(char *argv0 __unused)
{

	parse_gdberr = mem_fileopen();
	set_prompt("(kgdb) ");
	gdbarch_register_osabi_sniffer(bfd_arch_unknown,
				       bfd_target_elf_flavour,
				       fbsd_kernel_osabi_sniffer);
	/* XXX */
	_initialize_amd64_kgdb_tdep();
	initialize_kgdb_target();
	initialize_kld_target();
#if 0
	observer_attach_new_objfile (kgdb_new_objfile);
#endif
}

/*
 * Remote targets can support any number of syntaxes and we want to
 * support them all with one addition: we support specifying a device
 * node for a serial device without the "/dev/" prefix.
 *
 * What we do is to stat(2) the existing remote target first.  If that
 * fails, we try it with "/dev/" prepended.  If that succeeds we use
 * the resulting path, otherwise we use the original target.  If
 * either stat(2) succeeds make sure the file is either a character
 * device or a FIFO.
 */
static void
verify_remote(void)
{
	char path[PATH_MAX];
	struct stat st;

	if (stat(remote, &st) != 0) {
		snprintf(path, sizeof(path), "/dev/%s", remote);
		if (stat(path, &st) != 0)
			return;
		free(remote);
		remote = strdup(path);
	}
	if (!S_ISCHR(st.st_mode) && !S_ISFIFO(st.st_mode))
		errx(1, "%s: not a special file, FIFO or socket", remote);
}

static void
add_arg(struct captured_main_args *args, char *arg)
{

	args->argc++;
	args->argv = reallocf(args->argv, (args->argc + 1) * sizeof(char *));
	if (args->argv == NULL)
		err(1, "Out of memory building argument list");
	args->argv[args->argc] = arg;
}

int
main(int argc, char *argv[])
{
	char path[PATH_MAX];
	struct stat st;
	struct captured_main_args args;
	char *s;
	int a, ch;

	dumpnr = -1;

	strlcpy(crashdir, "/var/crash", sizeof(crashdir));
	s = getenv("KGDB_CRASH_DIR");
	if (s != NULL)
		strlcpy(crashdir, s, sizeof(crashdir));

	/* Convert long options into short options. */
	for (a = 1; a < argc; a++) {
		s = argv[a];
		if (s[0] == '-') {
			s++;
			/* Long options take either 1 or 2 dashes. */
			if (s[0] == '-')
				s++;
			if (strcmp(s, "quiet") == 0)
				argv[a] = "-q";
			else if (strcmp(s, "fullname") == 0)
				argv[a] = "-f";
		}
	}

	quiet = 0;
	memset (&args, 0, sizeof args);
	args.interpreter_p = INTERP_CONSOLE;
	args.argv = malloc(sizeof(char *));
	args.argv[0] = argv[0];

	while ((ch = getopt(argc, argv, "ab:c:d:fn:qr:vw")) != -1) {
		switch (ch) {
		case 'a':
			annotation_level++;
			break;
		case 'b': {
			int i;
			char *p;

			i = strtol(optarg, &p, 0);
			if (*p != '\0' || p == optarg)
				warnx("warning: could not set baud rate to `%s'.\n",
				    optarg);
			else
				baud_rate = i;
			break;
		}
		case 'c':	/* use given core file. */
			if (vmcore != NULL) {
				warnx("option %c: can only be specified once",
				    optopt);
				usage();
				/* NOTREACHED */
			}
			vmcore = strdup(optarg);
			break;
		case 'd':	/* lookup dumps in given directory. */
			strlcpy(crashdir, optarg, sizeof(crashdir));
			break;
		case 'f':
			annotation_level = 1;
			break;
		case 'n':	/* use dump with given number. */
			dumpnr = strtol(optarg, &s, 0);
			if (dumpnr < 0 || *s != '\0') {
				warnx("option %c: invalid kernel dump number",
				    optopt);
				usage();
				/* NOTREACHED */
			}
			break;
		case 'q':
			quiet = 1;
			add_arg(&args, "-q");
			break;
		case 'r':	/* use given device for remote session. */
			if (remote != NULL) {
				warnx("option %c: can only be specified once",
				    optopt);
				usage();
				/* NOTREACHED */
			}
			remote = strdup(optarg);
			break;
		case 'v':	/* increase verbosity. */
			verbose++;
			break;
		case 'w':	/* core file is writeable. */
			add_arg(&args, "--write");
			break;
		case '?':
		default:
			usage();
		}
	}

	if (((vmcore != NULL) ? 1 : 0) + ((dumpnr >= 0) ? 1 : 0) +
	    ((remote != NULL) ? 1 : 0) > 1) {
		warnx("options -c, -n and -r are mutually exclusive");
		usage();
		/* NOTREACHED */
	}

	if (verbose > 1)
		warnx("using %s as the crash directory", crashdir);

	if (argc > optind)
		kernel = strdup(argv[optind++]);

	if (argc > optind && (dumpnr >= 0 || remote != NULL)) {
		warnx("options -n and -r do not take a core file. Ignored");
		optind = argc;
	}

	if (dumpnr >= 0) {
		snprintf(path, sizeof(path), "%s/vmcore.%d", crashdir, dumpnr);
		if (stat(path, &st) == -1)
			err(1, "%s", path);
		if (!S_ISREG(st.st_mode))
			errx(1, "%s: not a regular file", path);
		vmcore = strdup(path);
	} else if (remote != NULL) {
		verify_remote();
	} else if (argc > optind) {
		if (vmcore == NULL)
			vmcore = strdup(argv[optind++]);
		if (argc > optind)
			warnx("multiple core files specified. Ignored");
	} else if (vmcore == NULL && kernel == NULL) {
		vmcore = strdup(_PATH_MEM);
		kernel = strdup(getbootfile());
	}

	if (verbose) {
		if (vmcore != NULL)
			warnx("core file: %s", vmcore);
		if (remote != NULL)
			warnx("device file: %s", remote);
		if (kernel != NULL)
			warnx("kernel image: %s", kernel);
	}

	/* A remote target requires an explicit kernel argument. */
	if (remote != NULL && kernel == NULL) {
		warnx("remote debugging requires a kernel");
		usage();
		/* NOTREACHED */
	}

	/* If we don't have a kernel image yet, try to find one. */
	if (kernel == NULL) {
		if (dumpnr >= 0)
			kernel_from_dumpnr(dumpnr);

		if (kernel == NULL)
			errx(1, "couldn't find a suitable kernel image");
		if (verbose)
			warnx("kernel image: %s", kernel);
	}
	add_arg(&args, kernel);

	if (vmcore != NULL)
		add_arg(&args, vmcore);

	/* The libgdb code uses optind too. Reset it... */
	optind = 0;

	/* Terminate argv list. */
	add_arg(&args, NULL);

	deprecated_init_ui_hook = kgdb_init;

	return (gdb_main(&args));
}
