/*
 * SYS-ASSERT
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <ucontext.h>
#include <signal.h>
#include <linux/unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <syslog.h>
/* for PR_SET_DUMPABLE */
#include <sys/prctl.h>
#include "sys-assert.h"
/* for demangle */
/* Fix for the issue: http://sourceware.org/bugzilla/show_bug.cgi?id=14243
 */
#define PACKAGE_VERSION  "0.3.3"
#define PACKAGE "sys-assert"
#include <bfd.h>
#include <libiberty.h>
#define DMGL_PARAMS   (1 << 0)
#define DMGL_ANSI   (1 << 1)
#define DMGL_VERBOSE	 (1 << 3)

#define CMDLINE_PATH "/proc/self/cmdline"
#define EXE_PATH "/proc/self/exe"
#define MAPS_PATH "/proc/self/maps"
#define MEMINFO_PATH "/proc/meminfo"
#define VERINFO_PATH "/etc/info.ini"
#define STATUS_PATH "/proc/self/status"

#define CRASH_INFO_PATH "/opt/share/crash/info"
#define CRASH_REPORT_PATH   "/opt/usr/share/crash/report"
#define CRASH_NOTI_PATH	"/opt/share/crash/curbs.log"

#define CRASH_CALLSTACKINFO_TITLE "Callstack Information"
#define CRASH_CALLSTACKINFO_TITLE_E "End of Call Stack"
#define CRASH_MAPSINFO_TITLE "Maps Information"
#define CRASH_MAPSINFO_TITLE_E "End of Maps Information"
#define CRASH_MEMINFO_TITLE "Memory Information"
#define CRASH_REGISTERINFO_TITLE "Register Information"

#define SUPPORT_LIBC_BACKTRACE 1
#define FUNC_NAME_MAX_LEN 128
#define FILE_LEN 255
#define PATH_LEN (FILE_LEN + NAME_MAX)
#define BUF_SIZE 255
#define CALLSTACK_SIZE 100
/* permission for open file */
#define DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
/* permission for open file */
#define FILE_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

int sig_to_handle[] = { /* SIGHUP, SIGINT, SIGQUIT, */ SIGILL, /*SIGTRAP, */
	SIGABRT,	/*SIGIOT, */SIGBUS,
	SIGFPE, /*SIGKILL, SIGUSR1 */ SIGSEGV,	/*SIGUSR2, */
	SIGPIPE			/*SIGXCPU,SIGXFSZ,,, */
};
#define NUM_SIG_TO_HANDLE	\
	((int)(sizeof(sig_to_handle)/sizeof(sig_to_handle[0])))

struct sigaction g_oldact[NUM_SIG_TO_HANDLE];

static char *fgets_fd(char *s, int n, int fd)
{
	char c;
	register char *cs;
	int num = 0;

	cs = s;
	while (--n > 0 && (num = read(fd, &c, 1) > 0)) {
		if ((*cs++ = c) == '\n')
			break;
	}
	*cs = '\0';
	return (num == 0 && cs == s) ? NULL : s;
}

/* WARNING : formatted string buffer is limited to 1024 byte */
static int fprintf_fd(int fd, const char *fmt, ...)
{
	int n;
	char buff[1024];
	va_list args;

	va_start(args, fmt);
	n = vsnprintf(buff, 1024 - 1, fmt, args);
	write(fd, buff, n);
	va_end(args);
	return n;
}
static char *remove_path(const char *cmd)
{
	char *t;
	char *r;

	t = r = (char *)cmd;
	while (*t) {
		if (*t == '/')
			r = t + 1;
		t++;
	}
	return r;
}

static char *get_fpath(long *value, struct addr_node *start)
{
	struct addr_node *t_node;
	struct addr_node *n_node;

	if (value == 0 || start == NULL)
		return NULL;
	t_node = start;
	n_node = t_node->next;
	while (t_node) {
		if (t_node->endaddr <= value) {
			/* next node */
			if (n_node == NULL)
				return NULL;
			t_node = n_node;
			n_node = n_node->next;
		} else if (t_node->startaddr <= value)
			return t_node->fpath;
		else
			return NULL;
	}
}

static long *get_start_addr(long *value, struct addr_node *start)
{
	struct addr_node *t_node;
	struct addr_node *n_node;

	if (value == 0 || start == NULL)
		return NULL;
	t_node = start;
	n_node = t_node->next;
	while (t_node) {
		if (t_node->endaddr <= value) {
			/* next node */
			if (n_node == NULL)
				return NULL;
			t_node = n_node;
			n_node = n_node->next;
		} else if (t_node->startaddr <= value)
			return t_node->startaddr;
		else
			return NULL;
	}
}
extern char *bfd_demangle (bfd *, const char *, int);
/* get function symbol from elf */
static int
trace_symbols(void *const *array, int size, struct addr_node *start, int fd_cs)
{
	Dl_info info_funcs;
	Elf32_Ehdr elf_h;
	Elf32_Shdr *s_headers;
	Elf32_Sym *symtab_entry;
	unsigned int offset_addr;
	unsigned int start_addr;
	unsigned int addr;
	int i;
	int cnt;
	int strtab_index = 0;
	int symtab_index = 0;
	int num_st = 0;
	int fd;
	int ret;
	char *demangled_sname = NULL;
	char filename[NAME_MAX];

	for (cnt = 0; cnt < size; cnt++) {
		num_st = 0;
		/* FIXME : for walking on stack trace */
		if (dladdr(array[cnt], &info_funcs) == 0) {
			fprintf(stderr, "[sys-assert]dladdr returnes error!\n");
			/* print just address */
			fprintf_fd(fd_cs, "dladdr failed %2d: (%p) %s\n", cnt, array[cnt], dlerror());
			continue;
		}
		start_addr = (unsigned int)get_start_addr(array[cnt], start);
		addr = (unsigned int)array[cnt];
		/* because of launchpad,
		 * return value of dladdr when find executable is wrong.
		 * so fix dli_fname here */
		if (info_funcs.dli_fbase == (void *)BASE_LAUNCHPAD_ADDR
				&& (strncmp("/opt/apps/", info_funcs.dli_fname,
						strlen("/opt/apps/")) == 0)) {
			info_funcs.dli_fname = get_fpath(array[cnt], start);
			offset_addr = addr;
		} else {
			offset_addr = addr - start_addr;
		}
		if (info_funcs.dli_sname == NULL) {
			strcpy(filename, info_funcs.dli_fname);
			fd = open(filename, O_RDONLY);
			if (fd < 0) {
				strcpy(filename, strchr(info_funcs.dli_fname, '/'));
				fd = open(filename, O_RDONLY);
				if (fd < 0) {
					fprintf_fd(fd_cs,
							"can't open %2d: (%p) [%s] + %p\n",
							cnt, array[cnt],
							info_funcs.dli_fname, offset_addr);
					continue;
				}
			}
			ret = read(fd, &elf_h, sizeof(Elf32_Ehdr));
			if (ret < sizeof(Elf32_Ehdr)) {
				fprintf_fd(fd_cs,
						"%2d: (%p) [%s] + %p\n",
						cnt, array[cnt],
						info_funcs.dli_fname, offset_addr);
				continue;
			}
			if (elf_h.e_type == ET_EXEC) {
				info_funcs.dli_fbase = 0;
				offset_addr = addr;
			}
			s_headers =
				(Elf32_Shdr *) mmap(0,
						elf_h.e_shnum *
						sizeof
						(Elf32_Shdr),
						PROT_READ |
						PROT_WRITE,
						MAP_PRIVATE |
						MAP_ANONYMOUS, -1, 0);
			if (s_headers == NULL) {
				fprintf(stderr, "[sys-assert]malloc failed\n");
				fprintf_fd(fd_cs,
						"%2d: (%p) [%s] + %p\n",
						cnt, array[cnt],
						info_funcs.dli_fname, offset_addr);
				continue;
			}
			lseek(fd, elf_h.e_shoff, SEEK_SET);
			if (elf_h.e_shentsize > sizeof(Elf32_Shdr))
				return false;
			for (i = 0; i < elf_h.e_shnum; i++) {
				ret =
					read(fd, &s_headers[i], elf_h.e_shentsize);
				if (ret < elf_h.e_shentsize) {
					fprintf(stderr,
							"[sys-assert]read error\n");
					munmap(s_headers,
							elf_h.e_shnum *
							sizeof(Elf32_Shdr));
					return false;
				}
			}
			for (i = 0; i < elf_h.e_shnum; i++) {
				if (s_headers[i].sh_type == SHT_SYMTAB) {
					symtab_index = i;
					num_st =
						s_headers[i].sh_size /
						s_headers[i].sh_entsize;
					break;
				}
			}
			/*.strtab index */
			strtab_index = s_headers[symtab_index].sh_link;
			symtab_entry =
				(Elf32_Sym *)mmap(0, sizeof(Elf32_Sym) * num_st,
						PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (symtab_entry == NULL) {
				fprintf(stderr, "[sys-assert]malloc failed\n");
				munmap(s_headers,
						elf_h.e_shnum * sizeof(Elf32_Shdr));
				return false;
			}
			lseek(fd, s_headers[symtab_index].sh_offset, SEEK_SET);
			for (i = 0; i < num_st; i++) {
				ret =
					read(fd, &symtab_entry[i],
							sizeof(Elf32_Sym));
				if (ret < sizeof(Elf32_Sym)) {
					fprintf_fd(fd_cs,
							"[sys-assert]symtab_entry[%d],\
							num_st=%d, readnum = %d\n",
							i, num_st, ret);
					break;
				}
				if (((info_funcs.dli_fbase +
								symtab_entry[i].st_value)
							<= array[cnt])
						&& (array[cnt] <=
							(info_funcs.dli_fbase +
							 symtab_entry
							 [i].st_value +
							 symtab_entry[i].st_size))) {
					if (symtab_entry[i].st_shndx !=
							STN_UNDEF) {
						lseek(fd, s_headers
								[strtab_index].sh_offset +
								symtab_entry[i].st_name,
								SEEK_SET);
						info_funcs.dli_sname = (void *)
							mmap(0, FUNC_NAME_MAX_LEN,
									PROT_READ | PROT_WRITE,
									MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
						ret =
							read(fd,
									info_funcs.dli_sname,
									FUNC_NAME_MAX_LEN);
						info_funcs.dli_saddr =
							info_funcs.dli_fbase +
							symtab_entry[i].st_value;
					}
					break;
				}
			}
			munmap(s_headers, elf_h.e_shnum * sizeof(Elf32_Shdr));
			munmap(symtab_entry, sizeof(Elf32_Sym) * num_st);
			close(fd);
		}
		if (info_funcs.dli_sname != NULL) {
			demangled_sname = bfd_demangle(NULL,
					info_funcs.dli_sname,
					DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE);
			if (array[cnt] >= info_funcs.dli_saddr) {
				fprintf_fd(fd_cs,
						"%2d: %s + 0x%x (%p) [%s] + %p\n",
						cnt,
						demangled_sname ? demangled_sname : info_funcs.dli_sname,
						(array[cnt] - info_funcs.dli_saddr),
						array[cnt],
						info_funcs.dli_fname, offset_addr);
			} else {
				fprintf_fd(fd_cs,
						"%2d: %s - 0x%x (%p) [%s] + %p\n",
						cnt,
						demangled_sname ? demangled_sname : info_funcs.dli_sname,
						(info_funcs.dli_saddr - array[cnt]),
						array[cnt],
						info_funcs.dli_fname, offset_addr);
			}
			if (demangled_sname)
				free(demangled_sname);
		} else {
			fprintf_fd(fd_cs,
					"%2d: (%p) [%s] + %p\n",
					cnt, array[cnt],
					info_funcs.dli_fname, offset_addr);
		}
	}
	return true;
}
/* get address list from maps  with print to file */
static struct addr_node *get_addr_list_from_maps_with_print(int fd_maps, int fd)
{
	int result;
	char linebuf[BUF_SIZE];
	char addr[20];
	char perm[5];
	char path[PATH_LEN];
	long *saddr;
	long *eaddr;
	int fpath_len;
	struct addr_node *head = NULL;
	struct addr_node *tail = NULL;
	struct addr_node *t_node = NULL;

	fprintf_fd(fd, "\n%s\n", CRASH_MAPSINFO_TITLE);

/* parsing the maps to get executable code address */
	while (fgets_fd(linebuf, BUF_SIZE, fd_maps) != NULL) {
		memset(path, 0, PATH_LEN);
		result =
		    sscanf(linebuf, "%s %s %*s %*s %*s %s ", addr, perm, path);
		perm[4] = 0;
/*if perm[2]=='x',addr is valid value so we have to store the address */
#ifdef TARGET
		if ((perm[2] == 'x' && path[0] == '/')
				|| (perm[1] == 'w' && path[0] != '/'))
#else
		if (strncmp(perm, "r-xp", 4) == 0)
#endif
		{
			/* add addr node to list */
			addr[8] = 0;
			saddr = (long *)strtoul(addr, NULL, 16);
			eaddr = (long *)strtoul(&addr[9], NULL, 16);
			/* make node and attach to the list */
			t_node =
			    (struct addr_node *)mmap(0,
						     sizeof
						     (struct
						      addr_node),
						     PROT_READ |
						     PROT_WRITE,
						     MAP_PRIVATE
						     | MAP_ANONYMOUS, -1, 0);
			if (t_node == NULL) {
				fprintf(stderr, "error : mmap\n");
				return NULL;
			}
			memcpy(t_node->perm, perm, 5);
			t_node->startaddr = saddr;
			t_node->endaddr = eaddr;
			t_node->fpath = NULL;
			fpath_len = strlen(path);
			if (fpath_len > 0) {
				t_node->fpath =
				    (char *)mmap(0,
						 fpath_len + 1,
						 PROT_READ |
						 PROT_WRITE,
						 MAP_PRIVATE |
						 MAP_ANONYMOUS, -1, 0);
				memset(t_node->fpath, 0, fpath_len + 1);
				memcpy(t_node->fpath, path, fpath_len);
				fprintf_fd(fd, "%08x %08x %s %s\n",
						(unsigned int)t_node->startaddr,
						(unsigned int)t_node->endaddr,
						t_node->perm, t_node->fpath);
			} else {
				t_node->fpath =
				    (char *)mmap(0, 8,
						 PROT_READ |
						 PROT_WRITE,
						 MAP_PRIVATE |
						 MAP_ANONYMOUS, -1, 0);
				memset(t_node->fpath, 0, 8);
				memcpy(t_node->fpath, "[anony]", 7);
			}
			t_node->next = NULL;
			if (head == NULL) {
				head = t_node;
				tail = t_node;
			} else {
				tail->next = t_node;
				tail = t_node;
			}
		}
	}
	fprintf_fd(fd, "%s\n", CRASH_MAPSINFO_TITLE_E);
	return head;
}
/* get address list from maps */
static struct addr_node *get_addr_list_from_maps(int fd_maps)
{
	int result;
	char linebuf[BUF_SIZE];
	char addr[20];
	char perm[5];
	char path[PATH_LEN];
	long *saddr;
	long *eaddr;
	int fpath_len;
	struct addr_node *head = NULL;
	struct addr_node *tail = NULL;
	struct addr_node *t_node = NULL;

/* parsing the maps to get executable code address */
	while (fgets_fd(linebuf, BUF_SIZE, fd_maps) != NULL) {
		memset(path, 0, PATH_LEN);
		result =
		    sscanf(linebuf, "%s %s %*s %*s %*s %s ", addr, perm, path);
		perm[4] = 0;
/*if perm[2]=='x',addr is valid value so we have to store the address */
#ifdef TARGET
		if ((perm[2] == 'x' && path[0] == '/')
				|| (perm[1] == 'w' && path[0] != '/'))
#else
		if (strncmp(perm, "r-xp", 4) == 0)
#endif
		{
			/* add addr node to list */
			addr[8] = 0;
			saddr = (long *)strtoul(addr, NULL, 16);
			eaddr = (long *)strtoul(&addr[9], NULL, 16);
			/* make node and attach to the list */
			t_node =
			    (struct addr_node *)mmap(0,
						     sizeof
						     (struct
						      addr_node),
						     PROT_READ |
						     PROT_WRITE,
						     MAP_PRIVATE
						     | MAP_ANONYMOUS, -1, 0);
			if (t_node == NULL) {
				fprintf(stderr, "error : mmap\n");
				return NULL;
			}
			memcpy(t_node->perm, perm, 5);
			t_node->startaddr = saddr;
			t_node->endaddr = eaddr;
			t_node->fpath = NULL;
			fpath_len = strlen(path);
			if (fpath_len > 0) {
				t_node->fpath =
				    (char *)mmap(0,
						 fpath_len + 1,
						 PROT_READ |
						 PROT_WRITE,
						 MAP_PRIVATE |
						 MAP_ANONYMOUS, -1, 0);
				memset(t_node->fpath, 0, fpath_len + 1);
				memcpy(t_node->fpath, path, fpath_len);
			} else {
				t_node->fpath =
				    (char *)mmap(0, 8,
						 PROT_READ |
						 PROT_WRITE,
						 MAP_PRIVATE |
						 MAP_ANONYMOUS, -1, 0);
				memset(t_node->fpath, 0, 8);
				memcpy(t_node->fpath, "[anony]", 7);
			}

			t_node->next = NULL;
			if (head == NULL) {
				head = t_node;
				tail = t_node;
			} else {
				tail->next = t_node;
				tail = t_node;
			}
		}
	}
	return head;
}

static void print_node_to_file(struct addr_node *start, int fd)
{
	struct addr_node *t_node;

	t_node = start;
	fprintf_fd(fd, "\n%s\n", CRASH_MAPSINFO_TITLE);
	while (t_node) {
		if (!strncmp("[anony]", t_node->fpath, strlen("[anony]"))) {
			t_node = t_node->next;
		} else {
			fprintf_fd(fd, "%08x %08x %s %s\n",
				(unsigned int)t_node->startaddr,
				(unsigned int)t_node->endaddr,
				t_node->perm, t_node->fpath);
			t_node = t_node->next;
		}
	}
	fprintf_fd(fd, "%s\n", CRASH_MAPSINFO_TITLE_E);
}

static void free_all_nodes(struct addr_node *start)
{
	struct addr_node *t_node, *n_node;
	int fpath_len;

	if (start == NULL)
		return;
	t_node = start;
	n_node = t_node->next;
	while (t_node) {
		if (t_node->fpath != NULL) {
			fpath_len = strlen(t_node->fpath);
			munmap(t_node->fpath, fpath_len + 1);
		}
		munmap(t_node, sizeof(struct addr_node));
		if (n_node == NULL)
			break;
		t_node = n_node;
		n_node = n_node->next;
	}
}

static void print_signal_info(const siginfo_t *info, int fd)
{
	int signum = info->si_signo;

	fprintf_fd(fd, "Signal: %d\n", signum);
	switch (signum) {
	case SIGINT:
		fprintf_fd(fd, "      (SIGINT)\n");
		break;
	case SIGILL:
		fprintf_fd(fd, "      (SIGILL)\n");
		break;
	case SIGABRT:
		fprintf_fd(fd, "      (SIGABRT)\n");
		break;
	case SIGBUS:
		fprintf_fd(fd, "      (SIGBUS)\n");
		break;
	case SIGFPE:
		fprintf_fd(fd, "      (SIGFPE)\n");
		break;
	case SIGKILL:
		fprintf_fd(fd, "      (SIGKILL)\n");
		break;
	case SIGSEGV:
		fprintf_fd(fd, "      (SIGSEGV)\n");
		break;
	case SIGPIPE:
		fprintf_fd(fd, "      (SIGPIPE)\n");
		break;
	default:
		fprintf_fd(fd, "\n");
	}
	/* print signal si_code info */
	fprintf_fd(fd, "      si_code: %d\n", info->si_code);
	if (info->si_code <= 0 || info->si_code >= 0x80) {
		switch (info->si_code) {
#ifdef SI_TKILL
		case SI_TKILL:
			/* FIXME : print exe name displace with info->si_pid */
			fprintf_fd(fd,
				   "      signal sent by tkill (sent by pid %d, uid %d)\n",
				   info->si_pid, info->si_uid);
			fprintf_fd(fd, "      TIMER: %d\n", SI_TIMER);
			break;
#endif
#ifdef SI_USER
		case SI_USER:
			/* FIXME : print exe name displace with info->si_pid */
			fprintf_fd(fd,
				   "      signal sent by kill (sent by pid %d, uid %d)\n",
				   info->si_pid, info->si_uid);
			break;
#endif
#ifdef SI_KERNEL
		case SI_KERNEL:
			fprintf_fd(fd, "      signal sent by the kernel\n");
			break;
#endif
		}

	} else if (signum == SIGILL) {
		switch (info->si_code) {
		case ILL_ILLOPC:
			fprintf_fd(fd, "      illegal opcode\n");
			break;
		case ILL_ILLOPN:
			fprintf_fd(fd, "      illegal operand\n");
			break;
		case ILL_ILLADR:
			fprintf_fd(fd, "      illegal addressing mode\n");
			break;
		case ILL_ILLTRP:
			fprintf_fd(fd, "      illegal trap\n");
			break;
		case ILL_PRVOPC:
			fprintf_fd(fd, "      privileged opcode\n");
			break;
		case ILL_PRVREG:
			fprintf_fd(fd, "      privileged register\n");
			break;
		case ILL_COPROC:
			fprintf_fd(fd, "      coprocessor error\n");
			break;
		case ILL_BADSTK:
			fprintf_fd(fd, "      internal stack error\n");
			break;
		default:
			fprintf_fd(fd, "      illegal si_code = %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "      si_addr: %p\n", info->si_addr);
	} else if (signum == SIGFPE) {
		switch (info->si_code) {
		case FPE_INTDIV:
			fprintf_fd(fd, "      integer divide by zero\n");
			break;
		case FPE_INTOVF:
			fprintf_fd(fd, "      integer overflow\n");
			break;
		case FPE_FLTDIV:
			fprintf_fd(fd, "      floating-point divide by zero\n");
			break;
		case FPE_FLTOVF:
			fprintf_fd(fd, "      floating-point overflow\n");
			break;
		case FPE_FLTUND:
			fprintf_fd(fd, "      floating-point underflow\n");
			break;
		case FPE_FLTRES:
			fprintf_fd(fd, "      floating-point inexact result\n");
			break;
		case FPE_FLTINV:
			fprintf_fd(fd, "      invalid floating-point operation\n");
			break;
		case FPE_FLTSUB:
			fprintf_fd(fd, "      subscript out of range\n");
			break;
		default:
			fprintf_fd(fd, "      illegal si_code: %d\n", info->si_code);
			break;
		}
	} else if (signum == SIGSEGV) {
		switch (info->si_code) {
		case SEGV_MAPERR:
			fprintf_fd(fd, "      address not mapped to object\n");
			break;
		case SEGV_ACCERR:
			fprintf_fd(fd,
				   "      invalid permissions for mapped object\n");
			break;
		default:
			fprintf_fd(fd, "      illegal si_code: %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "      si_addr = %p\n", info->si_addr);
	} else if (signum == SIGBUS) {
		switch (info->si_code) {
		case BUS_ADRALN:
			fprintf_fd(fd, "      invalid address alignment\n");
			break;
		case BUS_ADRERR:
			fprintf_fd(fd, "      nonexistent physical address\n");
			break;
		case BUS_OBJERR:
			fprintf_fd(fd, "      object-specific hardware error\n");
			break;
		default:
			fprintf_fd(fd, "      illegal si_code: %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "      si_addr: %p\n", info->si_addr);

	}
}


#define VIP_PATH		"/tmp/vip"
#define PERMANENT_PATH	"/tmp/permanent"

static int check_redscreen(int pid)
{
	DIR *dp;
	struct dirent *dirp;
	char pid_str[10];

	snprintf(pid_str, 10, "%d", pid);
	if ((dp = opendir(VIP_PATH)) == NULL) {
		return 0;
	} else {
		while ((dirp = readdir(dp)) != NULL) {
			if (strcmp(dirp->d_name, pid_str) == 0) {
				fprintf(stderr, "pid=%d is VIP process\n", pid);
				closedir(dp);
				return 1;
			}
		}
	}
	closedir(dp);
	if ((dp = opendir(PERMANENT_PATH)) == NULL) {
		return 0;
	} else {
		while ((dirp = readdir(dp)) != NULL) {
			if (strcmp(dirp->d_name, pid_str) == 0) {
				fprintf(stderr,
					"pid=%d is Permanent process\n", pid);
				closedir(dp);
				return 1;
			}
		}
	}
	closedir(dp);
	return 0;
}
/*localtime() can not use in signal handler,
so we need signal safe version of localtime */
static inline void get_localtime(time_t cur_time, struct tm *ctime)
{
	int tday[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int time_var = cur_time;
	int i = 0;

	ctime->tm_sec = time_var % 60;
	time_var /= 60;
	ctime->tm_min = time_var % 60;
	time_var /= 60;
	/* do we need to fix up timze zone ? */
	ctime->tm_hour = time_var % 24;
	time_var /= 24;
	int year = 1970;
	int leak_year = 0;
	while (time_var > 365 + (leak_year = (((year % 4) == 0)
					&& ((year % 100) != 0))
				|| ((year % 400) == 0))) {
		time_var = time_var - 365 - leak_year;
		year++;
	}
	ctime->tm_year = year;
	leak_year = (((year % 4) == 0) && ((year % 100) != 0))
	    || ((year % 400) == 0);
	time_var++;
	while (time_var > tday[i]) {
		time_var -= tday[i];
		if (i == 1)
			time_var -= leak_year;
		i++;
	}
	ctime->tm_mon = ++i;
	ctime->tm_mday = time_var;
}
#ifdef STANDALONE
void sighandler(int signum, siginfo_t *info, void *context)
{
	/* for context info */
	ucontext_t *ucontext = context;
	void *callstack_addrs[CALLSTACK_SIZE];
	int cnt_callstack = 0;
	/* for backtrace_symbols() */
	char **callstack_strings;
	struct addr_node *head = NULL;
	int i;
	/* file descriptor */
	int fd_cs;		/* for cs file */
	int fd_maps;		/* for maps */
	int fd_meminfo;		/* for meminfo */
	int fd_verinfo;		/* for version info */
	int fd_cmdline;		/* for cmdline */
	int fd_status;		/* for status */
	int fd_curbs;		/* for inotify */
	pid_t cs_pid;
	pid_t cs_tid;
	char cs_timestr[64];
	char cs_processname[NAME_MAX] = {0,};
	char cs_exepath[PATH_LEN] = {0,};
	char cs_filepath[PATH_LEN];
	/* for get time  */
	time_t cur_time;
	struct tm ctime;
	char timestr[64];
	/* for get info */
	int thread_use;
	char *p_exepath = NULL;
	char tag[64];
	char infoname[20];
	char memsize1[24];
	char linebuf[BUF_SIZE];

	cur_time = time(NULL);
	gmtime_r(&cur_time, &ctime);
	/*localtime_r(&cur_time, &ctime);*/
	/*get_localtime(cur_time, &ctime);*/
	/* get pid */
	cs_pid = getpid();
	cs_tid = (long int)syscall(__NR_gettid);
	/* open maps file */
	if ((fd_maps = open(MAPS_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", MAPS_PATH);
	} else {
		/* parsing the maps to get code segment address*/
		head = get_addr_list_from_maps(fd_maps);
		close(fd_maps);
	}
	if (head == NULL) {
		fprintf(stderr, ">>>>error : cannot get address list from maps\n");
	} else {
#ifdef TARGET
#ifndef SUPPORT_LIBC_BACKTRACE
		/* backtrace using fp */
		long *SP;	/* point to the top of stack */
		long *PC;	/* point to the program counter */
		long *BP = __libc_stack_end;
		long *FP;
		long *framep;
		/* get sp , pc and bp */
		SP = (long *)ucontext->uc_mcontext.arm_sp;
		PC = (long *)ucontext->uc_mcontext.arm_pc;
		FP = (long *)ucontext->uc_mcontext.arm_fp;
		framep = (long *)FP;
		callstack_addrs[cnt_callstack++] =
			(long *)ucontext->uc_mcontext.arm_pc;
		if (FP != NULL) {
			for (; framep < BP;) {
				if (is_valid_addr(framep, head) == false)
					break;

				if (is_valid_addr((long *)*framep, head) == false)
					break;

				callstack_addrs[cnt_callstack] = (long *)*framep;

				framep--;
				framep = (long *)(*framep);
				cnt_callstack++;

				if (cnt_callstack == CALLSTACK_SIZE)
					break;
				if (framep < FP)
					break;
			}
		}
#else		/*SUPPORT_LIBC_BACKTRACE*/
		cnt_callstack = backtrace(callstack_addrs, CALLSTACK_SIZE);
		if (cnt_callstack > 2) {
			cnt_callstack -= 2;
		} else {
			callstack_addrs[2] = (long *)ucontext->uc_mcontext.arm_pc;
			callstack_addrs[3] = (long *)ucontext->uc_mcontext.arm_lr;
			cnt_callstack = 2;
		}
#endif
#else		/* i386 */

#if __x86_64__
	layout *ebp = ucontext->uc_mcontext.gregs[REG_RBP];
	callstack_addrs[cnt_callstack++] =
		(long *)ucontext->uc_mcontext.gregs[REG_RIP];
#else
	layout *ebp = ucontext->uc_mcontext.gregs[REG_EBP];
	callstack_addrs[cnt_callstack++] =
		(long *)ucontext->uc_mcontext.gregs[REG_EIP];
#endif
	while (ebp) {
		callstack_addrs[cnt_callstack++] = ebp->ret;
		ebp = ebp->ebp;
	}
	callstack_strings = backtrace_symbols(callstack_addrs, cnt_callstack);
#endif
	}
	/* get exepath */
	if ((fd_cmdline = open(CMDLINE_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", CMDLINE_PATH);
		return;
	} else {
		i = read(fd_cmdline, cs_exepath, sizeof(cs_exepath));
		close(fd_cmdline);
		if (i <= 0) {
			fprintf(stderr, "[sys-assert]can't get cmdline\n");
			return;
		} else {
			cs_exepath[i] = '\0';
		}
	}
	/* get processname */
	if ( (p_exepath = remove_path(cs_exepath)) == NULL)
		return;
	snprintf(cs_processname, NAME_MAX, "%s", p_exepath);
	/* added temporary skip  when crash-worker is asserted */
	if (!strcmp(cs_processname, "crash-worker") || !strcmp(cs_processname, "crash-popup"))
		return;
	/* thread check */
	if (cs_pid == cs_tid) {
		thread_use = false;
	} else {
		thread_use = true;
	}
	/* make crash info file name */
	strftime(cs_timestr, sizeof(cs_timestr), "%Y%m%d%H%M%S", &ctime);
	if (snprintf(cs_filepath, PATH_LEN,
				"%s/%s_%s.cs", CRASH_REPORT_PATH, cs_processname, cs_timestr) == 0) {
		fprintf(stderr,
				"[sys-assert]can't make crash info file name : %s%s\n",
				cs_processname, cs_timestr);
		return;
	}
	/* check crash info dump directory, make directory if absent */
	if (access(CRASH_REPORT_PATH, F_OK) == -1) {
		if (mkdir(CRASH_REPORT_PATH, DIR_PERMS) < 0) {
			fprintf(stderr,
					"[sys-assert]can't make dir : %s errno : %s\n",
					CRASH_REPORT_PATH, strerror(errno));
			return;
		}
	}
	/* logging crash information to syslog */
	syslog(LOG_ERR, "crashed [%s] processname=%s, pid=%d, tid=%d, signal=%d",
			cs_timestr, cs_processname, cs_pid, cs_tid, info->si_signo);
	/* complete filepath_cs */
	if (!strlen(cs_filepath))
		return;
	/* create cs file */
	if ((fd_cs = creat(cs_filepath, FILE_PERMS)) < 0) {
		fprintf(stderr,
				"[sys-assert]can't create %s. errno = %s\n",
				cs_filepath, strerror(errno));
		return;
	}
	/* print version info */
	fprintf_fd(fd_cs, "S/W Version Information\n");
	if ((fd_verinfo = open(VERINFO_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", VERINFO_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, fd_verinfo) != NULL) {
			if (strncmp("Major=", linebuf, 6) == 0) {
				fprintf_fd(fd_cs, "%s", linebuf);
			} else if (strncmp("Minor=", linebuf, 6) == 0) {
				fprintf_fd(fd_cs, "%s", linebuf);
			} else if (strncmp("Build=", linebuf, 6) == 0) {
				fprintf_fd(fd_cs, "%s", linebuf);
			} else if (strncmp("Date=", linebuf, 5) == 0) {
				fprintf_fd(fd_cs, "%s", linebuf);
			} else if (strncmp("Time=", linebuf, 5) == 0) {
				fprintf_fd(fd_cs, "%s", linebuf);
				break;
			}
		}
		close(fd_verinfo);
	}
	/* print app info */
	fprintf_fd(fd_cs, "Process Name: %s\n", cs_processname);
	fprintf_fd(fd_cs, "PID: %d\n", cs_pid);
	/* print time  */
	/*localtime_r(&cur_time, &ctime);*/
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &ctime);
	fprintf_fd(fd_cs, "Date: %s ( UTC )\n", timestr);
	/* print exe path */
	fprintf_fd(fd_cs, "Executable File Path: %s\n", cs_exepath);
	/* print thread info */
	if (thread_use == true) {
		fprintf_fd(fd_cs,
				"This process is multi-thread process\npid=%d tid=%d\n",
				cs_pid, cs_tid);
	}
	/* print signal info */
	print_signal_info(info, fd_cs);
	fsync(fd_cs);
	/* print additional info */
#ifdef TARGET
	fprintf_fd(fd_cs, "\n%s\n", CRASH_REGISTERINFO_TITLE);
	fprintf_fd(fd_cs,
			"r0   = 0x%08x, r1   = 0x%08x\nr2   = 0x%08x, r3   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r0,
			ucontext->uc_mcontext.arm_r1,
			ucontext->uc_mcontext.arm_r2, ucontext->uc_mcontext.arm_r3);
	fprintf_fd(fd_cs,
			"r4   = 0x%08x, r5   = 0x%08x\nr6   = 0x%08x, r7   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r4,
			ucontext->uc_mcontext.arm_r5,
			ucontext->uc_mcontext.arm_r6, ucontext->uc_mcontext.arm_r7);
	fprintf_fd(fd_cs,
			"r8   = 0x%08x, r9   = 0x%08x\nr10  = 0x%08x, fp   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r8,
			ucontext->uc_mcontext.arm_r9,
			ucontext->uc_mcontext.arm_r10, ucontext->uc_mcontext.arm_fp);
	fprintf_fd(fd_cs,
			"ip   = 0x%08x, sp   = 0x%08x\nlr   = 0x%08x, pc   = 0x%08x\n",
			ucontext->uc_mcontext.arm_ip,
			ucontext->uc_mcontext.arm_sp,
			ucontext->uc_mcontext.arm_lr, ucontext->uc_mcontext.arm_pc);
	fprintf_fd(fd_cs, "cpsr = 0x%08x\n", ucontext->uc_mcontext.arm_cpsr);
#else
	fprintf_fd(fd_cs, "\n%s\n", CRASH_REGISTERINFO_TITLE);

#if __x86_64__
	fprintf_fd(fd_cs,
			"rdi = 0x%08x, rsi = 0x%08x\nrbp = 0x%08x, esp = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RDI],
			ucontext->uc_mcontext.gregs[REG_RSI],
			ucontext->uc_mcontext.gregs[REG_RBP],
			ucontext->uc_mcontext.gregs[REG_RSP]);
	fprintf_fd(fd_cs,
			"rax = 0x%08x, rbx = 0x%08x\nrcx = 0x%08x, rdx = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RAX],
			ucontext->uc_mcontext.gregs[REG_RBX],
			ucontext->uc_mcontext.gregs[REG_RCX],
			ucontext->uc_mcontext.gregs[REG_RDX]);
	fprintf_fd(fd_cs,
			"rip = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RIP]);

#else
	fprintf_fd(fd_cs,
			"gs  = 0x%08x, fs  = 0x%08x\nes  = 0x%08x, ds  = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_GS],
			ucontext->uc_mcontext.gregs[REG_FS],
			ucontext->uc_mcontext.gregs[REG_ES],
			ucontext->uc_mcontext.gregs[REG_DS]);
	fprintf_fd(fd_cs,
			"edi = 0x%08x, esi = 0x%08x\nebp = 0x%08x, esp = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EDI],
			ucontext->uc_mcontext.gregs[REG_ESI],
			ucontext->uc_mcontext.gregs[REG_EBP],
			ucontext->uc_mcontext.gregs[REG_ESP]);
	fprintf_fd(fd_cs,
			"eax = 0x%08x, ebx = 0x%08x\necx = 0x%08x, edx = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EAX],
			ucontext->uc_mcontext.gregs[REG_EBX],
			ucontext->uc_mcontext.gregs[REG_ECX],
			ucontext->uc_mcontext.gregs[REG_EDX]);
	fprintf_fd(fd_cs,
			"eip = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EIP]);
#endif

#endif
	/* print meminfo */
	fprintf_fd(fd_cs, "\n%s\n", CRASH_MEMINFO_TITLE);
	if ((fd_meminfo = open(MEMINFO_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", MEMINFO_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, fd_meminfo) != NULL) {
			sscanf(linebuf, "%s %s %*s", infoname, memsize1);
			if (strcmp("MemTotal:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("MemFree:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s  %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("Buffers:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s  %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("Cached:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
				break;
			}
		}
		close(fd_meminfo);
	}
	if ((fd_status = open(STATUS_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", STATUS_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, fd_status) != NULL) {
			sscanf(linebuf, "%s %s %*s", infoname, memsize1);
			if (strcmp("VmPeak:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmSize:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmLck:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmPin:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmHWM:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmRSS:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmData:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmStk:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmExe:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmLib:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmPTE:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmSwap:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
				break;
			}
		}
		close(fd_status);
	}
	if (head == NULL) {
		fprintf_fd(fd_cs, "Failed to get address list\n");
		fprintf(stderr, ">>>>error : cannot get address list from maps\n");
	} else {
		/* print maps information */
		print_node_to_file(head, fd_cs);
		/* print callstack */
		fprintf_fd(fd_cs, "\n%s (PID:%d)\n", CRASH_CALLSTACKINFO_TITLE, cs_pid);
		fprintf_fd(fd_cs, "Call Stack Count: %d\n", cnt_callstack);
		if (false ==
				trace_symbols(&callstack_addrs[2], cnt_callstack, head, fd_cs)) {
			fprintf(stderr, "[sys-assert] trace_symbols failed\n");
		}
		fprintf_fd(fd_cs, "%s\n", CRASH_CALLSTACKINFO_TITLE_E);
		free_all_nodes(head);
	}
	/* cs file sync */
	fsync(fd_cs);
	/* clean up */
	if (close(fd_cs) == -1)
		fprintf(stderr, "[sys-assert] fd_cs close error!!\n");
	for (i = 0; i < NUM_SIG_TO_HANDLE; i++) {
		if (sig_to_handle[i] == signum) {
			sigaction(signum, &g_oldact[i], NULL);
			break;
		}
	}
	raise(signum);
}
#else
void sighandler(int signum, siginfo_t *info, void *context)
{
	/* for context info */
	ucontext_t *ucontext = context;
	void *callstack_addrs[CALLSTACK_SIZE];
	int cnt_callstack = 0;
	/* for backtrace_symbols() */
	char **callstack_strings;
	struct addr_node *head = NULL;
	int i;
	/* file descriptor */
	int fd_cs;		/* for cs file */
	int fd_maps;		/* for maps */
	int fd_meminfo;		/* for meminfo */
	int fd_cmdline;		/* for cmdline */
	int fd_status;		/* for status */
	int fd_curbs;		/* for inotify */
	pid_t cs_pid;
	pid_t cs_tid;
	char cs_timestr[64];
	char cs_processname[NAME_MAX] = {0,};
	char cs_exepath[PATH_LEN] = {0,};
	char cs_filepath[PATH_LEN];
	/* for get time  */
	time_t cur_time;
	/* for get info */
	int thread_use;
	char *p_exepath = NULL;
	char tag[64];
	char infoname[20];
	char memsize1[24];
	char linebuf[BUF_SIZE];

	cur_time = time(NULL);
	/* get pid */
	cs_pid = getpid();
	cs_tid = (long int)syscall(__NR_gettid);
	/* open maps file */
	if ((fd_maps = open(MAPS_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", MAPS_PATH);
	} else {
		/* parsing the maps to get code segment address*/
		head = get_addr_list_from_maps(fd_maps);
		close(fd_maps);
	}
	if (head == NULL) {
		fprintf(stderr, ">>>>error : cannot get address list from maps\n");
	} else {
#ifdef TARGET
#ifndef SUPPORT_LIBC_BACKTRACE
		/* backtrace using fp */
		long *SP;	/* point to the top of stack */
		long *PC;	/* point to the program counter */
		long *BP = __libc_stack_end;
		long *FP;
		long *framep;
		/* get sp , pc and bp */
		SP = (long *)ucontext->uc_mcontext.arm_sp;
		PC = (long *)ucontext->uc_mcontext.arm_pc;
		FP = (long *)ucontext->uc_mcontext.arm_fp;
		framep = (long *)FP;
		callstack_addrs[cnt_callstack++] =
			(long *)ucontext->uc_mcontext.arm_pc;
		if (FP != NULL) {
			for (; framep < BP;) {
				if (is_valid_addr(framep, head) == false)
					break;

				if (is_valid_addr((long *)*framep, head) == false)
					break;

				callstack_addrs[cnt_callstack] = (long *)*framep;

				framep--;
				framep = (long *)(*framep);
				cnt_callstack++;

				if (cnt_callstack == CALLSTACK_SIZE)
					break;
				if (framep < FP)
					break;
			}
		}
#else		/*SUPPORT_LIBC_BACKTRACE*/
		cnt_callstack = backtrace(callstack_addrs, CALLSTACK_SIZE);
		if (cnt_callstack > 2) {
			cnt_callstack -= 2;
		} else {
			callstack_addrs[2] = (long *)ucontext->uc_mcontext.arm_pc;
			callstack_addrs[3] = (long *)ucontext->uc_mcontext.arm_lr;
			cnt_callstack = 2;
		}
#endif
#else		/* i386 */
#if __x86_64__
	layout *ebp = ucontext->uc_mcontext.gregs[REG_RBP];
	callstack_addrs[cnt_callstack++] =
		(long *)ucontext->uc_mcontext.gregs[REG_RIP];
#else
	layout *ebp = ucontext->uc_mcontext.gregs[REG_EBP];
	callstack_addrs[cnt_callstack++] =
		(long *)ucontext->uc_mcontext.gregs[REG_EIP];
#endif
	while (ebp) {
		callstack_addrs[cnt_callstack++] = ebp->ret;
		ebp = ebp->ebp;
	}
	callstack_strings = backtrace_symbols(callstack_addrs, cnt_callstack);
	if (cnt_callstack > 2) {
		cnt_callstack -= 2;
	} else {
#if __x86_64__
		callstack_addrs[2] = (long *)ucontext->uc_mcontext.gregs[REG_RIP];
		callstack_addrs[3] = (long *)ucontext->uc_mcontext.gregs[REG_RSP];
#else
		callstack_addrs[2] = (long *)ucontext->uc_mcontext.gregs[REG_EIP];
		callstack_addrs[3] = (long *)ucontext->uc_mcontext.gregs[REG_ESP];
#endif
		cnt_callstack = 2;
	}
#endif
	}
	/* get exepath */
	if ((fd_cmdline = open(CMDLINE_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", CMDLINE_PATH);
		return;
	} else {
		i = read(fd_cmdline, cs_exepath, sizeof(cs_exepath));
		close(fd_cmdline);
		if (i <= 0) {
			fprintf(stderr, "[sys-assert]can't get cmdline\n");
			return;
		} else {
			cs_exepath[i] = '\0';
		}
	}
	/* get processname */
	if ( (p_exepath = remove_path(cs_exepath)) == NULL)
		return;
	snprintf(cs_processname, NAME_MAX, "%s", p_exepath);
	/* added temporary skip  when crash-worker is asserted */
	if (!strcmp(cs_processname, "crash-worker") || !strcmp(cs_processname, "crash-popup"))
		return;
	/* thread check */
	if (cs_pid == cs_tid) {
		thread_use = false;
	} else {
		thread_use = true;
	}
	/* make crash info file name */
	snprintf(cs_timestr, sizeof(cs_timestr), "%lu", cur_time);
	if (snprintf(cs_filepath, PATH_LEN,
				"%s/%d_%s.info", CRASH_INFO_PATH, cs_pid, cs_timestr) == 0) {
		fprintf(stderr,
				"[sys-assert]can't make crash info file name : %d%s\n",
				cs_pid, cs_timestr);
		return;
	}
	/* check crash info dump directory, make directory if absent */
	if (access(CRASH_INFO_PATH, F_OK) == -1) {
		if (mkdir(CRASH_INFO_PATH, DIR_PERMS) < 0) {
			fprintf(stderr,
					"[sys-assert]can't make dir : %s errno : %s\n",
					CRASH_INFO_PATH, strerror(errno));
			return;
		}
	}
	/* logging crash information to syslog */
	syslog(LOG_ERR, "crashed [%s] processname=%s, pid=%d, tid=%d, signal=%d",
			cs_timestr, cs_processname, cs_pid, cs_tid, info->si_signo);
	/* complete filepath_cs */
	if (!strlen(cs_filepath))
		return;
	/* create cs file */
	if ((fd_cs = creat(cs_filepath, FILE_PERMS)) < 0) {
		fprintf(stderr,
				"[sys-assert]can't create %s. errno = %s\n",
				cs_filepath, strerror(errno));
		return;
	}
	/* print thread info */
	if (thread_use == true) {
		fprintf_fd(fd_cs,
				"This process is multi-thread process\npid=%d tid=%d\n",
				cs_pid, cs_tid);
	}
	/* print signal info */
	print_signal_info(info, fd_cs);
	fsync(fd_cs);
	/* print additional info */
#ifdef TARGET
	fprintf_fd(fd_cs, "\n%s\n", CRASH_REGISTERINFO_TITLE);
	fprintf_fd(fd_cs,
			"r0   = 0x%08x, r1   = 0x%08x\nr2   = 0x%08x, r3   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r0,
			ucontext->uc_mcontext.arm_r1,
			ucontext->uc_mcontext.arm_r2, ucontext->uc_mcontext.arm_r3);
	fprintf_fd(fd_cs,
			"r4   = 0x%08x, r5   = 0x%08x\nr6   = 0x%08x, r7   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r4,
			ucontext->uc_mcontext.arm_r5,
			ucontext->uc_mcontext.arm_r6, ucontext->uc_mcontext.arm_r7);
	fprintf_fd(fd_cs,
			"r8   = 0x%08x, r9   = 0x%08x\nr10  = 0x%08x, fp   = 0x%08x\n",
			ucontext->uc_mcontext.arm_r8,
			ucontext->uc_mcontext.arm_r9,
			ucontext->uc_mcontext.arm_r10, ucontext->uc_mcontext.arm_fp);
	fprintf_fd(fd_cs,
			"ip   = 0x%08x, sp   = 0x%08x\nlr   = 0x%08x, pc   = 0x%08x\n",
			ucontext->uc_mcontext.arm_ip,
			ucontext->uc_mcontext.arm_sp,
			ucontext->uc_mcontext.arm_lr, ucontext->uc_mcontext.arm_pc);
	fprintf_fd(fd_cs, "cpsr = 0x%08x\n", ucontext->uc_mcontext.arm_cpsr);
#else
	fprintf_fd(fd_cs, "\n%s\n", CRASH_REGISTERINFO_TITLE);

#if __x86_64__
	fprintf_fd(fd_cs,
			"rdi = 0x%08x, rsi = 0x%08x\nrbp = 0x%08x, esp = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RDI],
			ucontext->uc_mcontext.gregs[REG_RSI],
			ucontext->uc_mcontext.gregs[REG_RBP],
			ucontext->uc_mcontext.gregs[REG_RSP]);
	fprintf_fd(fd_cs,
			"rax = 0x%08x, rbx = 0x%08x\nrcx = 0x%08x, rdx = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RAX],
			ucontext->uc_mcontext.gregs[REG_RBX],
			ucontext->uc_mcontext.gregs[REG_RCX],
			ucontext->uc_mcontext.gregs[REG_RDX]);
	fprintf_fd(fd_cs,
			"rip = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_RIP]);
#else
	fprintf_fd(fd_cs,
			"gs  = 0x%08x, fs  = 0x%08x\nes  = 0x%08x, ds  = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_GS],
			ucontext->uc_mcontext.gregs[REG_FS],
			ucontext->uc_mcontext.gregs[REG_ES],
			ucontext->uc_mcontext.gregs[REG_DS]);
	fprintf_fd(fd_cs,
			"edi = 0x%08x, esi = 0x%08x\nebp = 0x%08x, esp = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EDI],
			ucontext->uc_mcontext.gregs[REG_ESI],
			ucontext->uc_mcontext.gregs[REG_EBP],
			ucontext->uc_mcontext.gregs[REG_ESP]);
	fprintf_fd(fd_cs,
			"eax = 0x%08x, ebx = 0x%08x\necx = 0x%08x, edx = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EAX],
			ucontext->uc_mcontext.gregs[REG_EBX],
			ucontext->uc_mcontext.gregs[REG_ECX],
			ucontext->uc_mcontext.gregs[REG_EDX]);
	fprintf_fd(fd_cs,
			"eip = 0x%08x\n",
			ucontext->uc_mcontext.gregs[REG_EIP]);
#endif

#endif
	/* print meminfo */
	fprintf_fd(fd_cs, "\n%s\n", CRASH_MEMINFO_TITLE);
	if ((fd_meminfo = open(MEMINFO_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", MEMINFO_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, fd_meminfo) != NULL) {
			sscanf(linebuf, "%s %s %*s", infoname, memsize1);
			if (strcmp("MemTotal:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("MemFree:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s  %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("Buffers:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s  %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("Cached:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
				break;
			}
		}
		close(fd_meminfo);
	}
	if ((fd_status = open(STATUS_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", STATUS_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, fd_status) != NULL) {
			sscanf(linebuf, "%s %s %*s", infoname, memsize1);
			if (strcmp("VmPeak:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmSize:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmLck:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmPin:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n", infoname,
						memsize1);
			} else if (strcmp("VmHWM:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmRSS:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmData:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmStk:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmExe:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmLib:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmPTE:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s    %8s KB\n",
						infoname, memsize1);
			} else if (strcmp("VmSwap:", infoname) == 0) {
				fprintf_fd(fd_cs, "%s   %8s KB\n",
						infoname, memsize1);
				break;
			}
		}
		close(fd_status);
	}
	if (head == NULL) {
		fprintf_fd(fd_cs, "Failed to get address list\n");
		fprintf(stderr, ">>>>error : cannot get address list from maps\n");
	} else {
		/* print maps information */
		print_node_to_file(head, fd_cs);
		/* print callstack */
		fprintf_fd(fd_cs, "\n%s (PID:%d)\n", CRASH_CALLSTACKINFO_TITLE, cs_pid);
		fprintf_fd(fd_cs, "Call Stack Count: %d\n", cnt_callstack);
		if (false ==
				trace_symbols(&callstack_addrs[2], cnt_callstack, head, fd_cs)) {
			fprintf(stderr, "[sys-assert] trace_symbols failed\n");
		}
		fprintf_fd(fd_cs, "%s\n", CRASH_CALLSTACKINFO_TITLE_E);
		free_all_nodes(head);
	}
	/* cs file sync */
	fsync(fd_cs);
	/* clean up */
	if (close(fd_cs) == -1)
		fprintf(stderr, "[sys-assert] fd_cs close error!!\n");
	/* core dump set */
	if (prctl(PR_GET_DUMPABLE) == 0) {
		prctl(PR_SET_DUMPABLE, 1);
	}
	/* NOTIFY CRASH */
	if ((fd_curbs = open(CRASH_NOTI_PATH, O_RDWR | O_APPEND)) < 0) {
		fprintf(stderr, "[sys-assert]cannot make %s !\n", CRASH_NOTI_PATH);
	} else {
		fprintf_fd(fd_curbs, "S|%s|%s|%d|%s|%d\n",
				cs_processname, cs_timestr, cs_pid, cs_exepath,
				strlen(cs_processname) + strlen(cs_exepath));
		close(fd_curbs);
	}
	for (i = 0; i < NUM_SIG_TO_HANDLE; i++) {
		if (sig_to_handle[i] == signum) {
			sigaction(signum, &g_oldact[i], NULL);
			break;
		}
	}
	raise(signum);
}
#endif
__attribute__ ((constructor))
void init()
{
	int i;

	for (i = 0; i < NUM_SIG_TO_HANDLE; i++) {
		struct sigaction act;
		act.sa_sigaction = (void *)sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		act.sa_flags |= SA_RESETHAND;
		if (sigaction(sig_to_handle[i], &act, &g_oldact[i]) < 0) {
			perror("[sys-assert]could not set signal handler ");
			continue;
		}
	}
}
