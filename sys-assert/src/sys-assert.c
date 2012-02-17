
/*
 * SYS-ASSERT
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jeesun Kim <iamjs.kim@samsung.com> Youngkyeong Yun <yk.yun@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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
#include <unistd.h>
#include <dirent.h>
#include <time.h>
/* for PR_SET_DUMPABLE */
#include <sys/prctl.h>
#include "sys-assert.h"

#define VERINFO_PATH "/etc/info.ini"
#define CS_DIR "/opt/share/hidden_storage/SLP_debug/"
#define DBG_DIR	"/usr/lib/debug"
#define MAPS_PATH "/proc/self/maps"
#define EXE_PATH "/proc/self/exe"
#define CMDLINE_PATH "/proc/self/cmdline"

#define INOTIFY_BS "/opt/bs/curbs.log"

/* 100412 for avatar-factory */
#define NAME_AVATAR "avatar-factory"

#define SUPPORT_LIBC_BACKTRACE 1
#define USE_SYMBOL_DB 1

#define FUNC_NAME_MAX_LEN 128
#define PATH_LEN 256
#define BUF_SIZE 256
#define CALLSTACK_SIZE 100

/* permission for open file */
#define DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
/* permission for open file */
#define FILE_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

int sig_to_handle[] = { /* SIGHUP, SIGINT, */ SIGQUIT, SIGILL, /*SIGTRAP, */ SIGABRT,	/*SIGIOT, */
	SIGBUS,
	SIGFPE, /*SIGKILL, SIGUSR1 */ SIGSEGV,	/*SIGUSR2, */
	SIGPIPE			/*SIGXCPU,SIGXFSZ,,, */
};

#define NUM_SIG_TO_HANDLE	((int)(sizeof(sig_to_handle)/sizeof(sig_to_handle[0])))

struct sigaction g_oldact[NUM_SIG_TO_HANDLE];

void sighandler(int signum, siginfo_t *info, void *context)
{
	ucontext_t *ucontext = context;
	void *callstack_addrs[CALLSTACK_SIZE];
	int cnt_callstack = 0;
	/* for backtrace_symbols() */
	char **callstack_strings;
	struct addr_node *head;
	int i;
	int csfd;		/* file descriptor for cs file */
	int mapsfd;		/* file descriptor for maps */
	int meminfo;		/* file descriptor for meminfo */
	int verinfo;		/* file descriptor for version info */
	int curbs;		/* for inotify */
	int cmdlinefd;		/* fd for cmdline */

	/* for get meminfo */
	char linebuf[BUF_SIZE];
	char infoname[20];
	char memsize1[24];

	/* for get app name */
	char *exename_p = NULL;
	char exe_path[PATH_LEN];
	char temp_path[PATH_LEN];
	char filename_cs[PATH_LEN];
	char filepath_cs[PATH_LEN];

	pid_t pid;
	pid_t tid;
	int thread_use;
	int redscreen_flg = 0;	/* for determine redscreen */
	int lauched_by_avatar = 0;	/* for determine launched by avatar-factory or not */

	pid = getpid();
	tid = (long int)syscall(__NR_gettid);

	fprintf(stderr, "[sys_assert]START of sighandler \n");

	/* thread check */
	if (pid == tid) {
		thread_use = false;
		fprintf(stderr,
			"[sys_assert]this thread is main thread. pid=%d\n",
			pid);
	} else {
		thread_use = true;
		fprintf(stderr,
			"[sys_assert]this process is multi-thread process. pid=%d, tid=%d\n",
			pid, tid);
	}

	/* print time  */
	time_t cur_time;
	struct tm ctime;
	char timestr[64]= {0, };
	cur_time = time(NULL);
	gmtime_r(&cur_time, &ctime);
//	get_localtime(cur_time, &ctime);

	/* make debug directory if absent */
	if (access(CS_DIR, F_OK) == -1) {
		if (mkdir(CS_DIR, DIR_PERMS) < 0) {
			fprintf(stderr,
				"[sys-assert]can't make dir : %s errno : %s\n",
				CS_DIR, strerror(errno));
			return;
		}
	}
	memset(exe_path, 0, PATH_LEN);

	if ((cmdlinefd = open(CMDLINE_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", CMDLINE_PATH);
	} else {
		read(cmdlinefd, exe_path, BUF_SIZE - 1);
		exename_p = remove_path(exe_path);
		fprintf(stderr, "[sys-assert]exename = %s \n", exename_p);
	}

	/* added temporary from dpkg-deb */
	if (!strcmp(exename_p, "dpkg-deb")) {
		return;
	}

	/* make directory name, file name */
	strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", &ctime);
	if (snprintf(temp_path, PATH_LEN, "%s_%d_%s", exename_p, pid, timestr) == 0) {
//	    (temp_path, PATH_LEN, "%s_%d_%02d%02d%02d%02d%02d%02d",
//	     exename_p, pid, ctime.tm_year, ctime.tm_mon, ctime.tm_mday,
//	     ctime.tm_hour, ctime.tm_min, ctime.tm_sec) == 0) {
		fprintf(stderr,
			"[sys-assert]can't make temp file name : %s%d\n",
			exename_p, pid);
		return;
	}

	if (snprintf(filename_cs, PATH_LEN, "%s.cs", temp_path) == 0) {
		fprintf(stderr,
			"[sys-assert]can't make file name : %s%d\n",
			exename_p, pid);
		return;
	}

	if (snprintf(filepath_cs, PATH_LEN, "%s%s/", CS_DIR, temp_path)
	    == 0) {
		fprintf(stderr,
			"[sys-assert]can't make file path : %s%s%d.cs\n",
			CS_DIR, exename_p, pid);
		return;
	}

	/* make dir for cs file */
	if (mkdir(filepath_cs, DIR_PERMS) < 0) {
		fprintf(stderr, "[sys-assert]can't make dir : %s\n",
			filepath_cs);
		return;
	}

	/* complete filepath_cs */
	strncat(filepath_cs, filename_cs, sizeof(filename_cs));

	/* create cs file */
	if ((csfd = creat(filepath_cs, FILE_PERMS)) < 0) {
		fprintf(stderr,
			"[sys-assert]can't create %s. errno = %s\n",
			filepath_cs, strerror(errno));
		return;
	}
#ifdef BTDEBUG
	else
		fprintf(stderr, "[sys-assert]create %s\n", filepath_cs);
#endif

	/* open maps file */
	if ((mapsfd = open(MAPS_PATH, O_RDONLY)) < 0) {
		fprintf_fd(csfd, "Failed to open (%s)\n", MAPS_PATH);
		fprintf(stderr, "[sys-assert]can't open %s\n", MAPS_PATH);
		close(csfd);
		return;
	}
#ifdef BTDEBUG
	else
		fprintf(stderr, "[sys-assert]open %s\n", MAPS_PATH);
#endif

	/* parsing the maps to get code segment address */

	head = get_addr_list_from_maps(mapsfd);
#ifdef BTDEBUG
	fprintf(stderr, "[sys-assert]after get_addr_list_from_maps\n");
#endif

	if (head == NULL) {
		fprintf_fd(csfd, "Failed to get address list\n");
		fprintf(stderr,
			">>>>error : cannot get address list from maps\n");
		close(csfd);
		close(mapsfd);
		return;
	}
	/* check this process is vip/permanent */
	redscreen_flg = check_redscreen(pid);

	fprintf_fd(csfd, "%s\n", redscreen_flg ? "RED SCREEN" : "BLUE SCREEN");

	/* print version info */
	fprintf_fd(csfd,
		   "******************************\ns/w version\n******************************\n");
	if ((verinfo = open(VERINFO_PATH, O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", VERINFO_PATH);
	} else {
		while (fgets_fd(linebuf, BUF_SIZE, verinfo) != NULL) {
			if (strncmp("Major=", linebuf, 6) == 0) {
				fprintf_fd(csfd, "%s", linebuf);
			} else if (strncmp("Minor=", linebuf, 6) == 0) {
				fprintf_fd(csfd, "%s", linebuf);
			} else if (strncmp("Build=", linebuf, 6) == 0) {
				fprintf_fd(csfd, "%s", linebuf);
			} else if (strncmp("Date=", linebuf, 5) == 0) {
				fprintf_fd(csfd, "%s", linebuf);
			} else if (strncmp("Time=", linebuf, 5) == 0) {
				fprintf_fd(csfd, "%s", linebuf);
				break;
			}
		}
		close(verinfo);

	}
	fprintf_fd(csfd, "*******************************\n");
	fprintf_fd(csfd, "AppName : %s\n", exename_p);
	fprintf_fd(csfd, "signal number : %d\n", info->si_signo);
	fprintf_fd(csfd, "file name : %s\n", filename_cs);
	fprintf_fd(csfd, "pid : %d\n", pid);

	if ((meminfo = open("/proc/meminfo", O_RDONLY)) < 0) {
		fprintf(stderr, "[sys-assert]can't open %s\n", "/proc/meminfo");
	} else {
		fprintf_fd(csfd,
			   "*******************************\nMem information\n*******************************\n");
		while (fgets_fd(linebuf, BUF_SIZE, meminfo) != NULL) {
			sscanf(linebuf, "%s %s %*s", infoname, memsize1);

			if (strcmp("MemTotal:", infoname) == 0) {
				fprintf_fd(csfd, "%s %s kB\n", infoname,
					   memsize1);
			} else if (strcmp("MemFree:", infoname) == 0) {
				fprintf_fd(csfd, "%s %s kB\n", infoname,
					   memsize1);
			} else if (strcmp("Buffers:", infoname) == 0) {
				fprintf_fd(csfd, "%s  %s kB\n",
					   infoname, memsize1);
			} else if (strcmp("Cached:", infoname) == 0) {
				fprintf_fd(csfd, "%s   %s kB\n",
					   infoname, memsize1);
			}
		}
		close(meminfo);
	}

	/* print signal information */
	fprintf_fd(csfd, "*******************************\nextra information\n\
*******************************\n");

	/* print time  */
	strftime(timestr, sizeof(timestr), "%Y.%m.%d %H:%M:%S", &ctime);
	fprintf_fd(csfd, "time = %s ( UTC )\n", timestr);

	/* print exe path */
	fprintf_fd(csfd, "exe path = %s\n", exe_path);
	fprintf(stderr, "[sys assert]exe path = %s\n", exe_path);
	if (lauched_by_avatar)
		fprintf_fd(csfd, "this process is lauched by avatar-factory\n");

	/* print thread info */
	if (thread_use == true) {
		fprintf_fd(csfd,
			   "this process is multi-thread process\npid=%d tid=%d\n",
			   pid, tid);
	}

	/* print signal info */
	print_signal_info(info, csfd);

	/* print additional info */
#ifdef TARGET
	fprintf_fd(csfd,
		   "r0 = 0x%08x, r1 = 0x%08x\nr2 = 0x%08x, r3 = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r0,
		   ucontext->uc_mcontext.arm_r1,
		   ucontext->uc_mcontext.arm_r2, ucontext->uc_mcontext.arm_r3);
	fprintf_fd(csfd,
		   "r4 = 0x%08x, r5 = 0x%08x\nr6 = 0x%08x, r7 = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r4,
		   ucontext->uc_mcontext.arm_r5,
		   ucontext->uc_mcontext.arm_r6, ucontext->uc_mcontext.arm_r7);
	fprintf_fd(csfd,
		   "r8 = 0x%08x, r9 = 0x%08x\nr10 = 0x%08x, fp = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r8,
		   ucontext->uc_mcontext.arm_r9,
		   ucontext->uc_mcontext.arm_r10, ucontext->uc_mcontext.arm_fp);
	fprintf_fd(csfd,
		   "ip = 0x%08x, sp = 0x%08x\nlr = 0x%08x, pc = 0x%08x\n",
		   ucontext->uc_mcontext.arm_ip,
		   ucontext->uc_mcontext.arm_sp,
		   ucontext->uc_mcontext.arm_lr, ucontext->uc_mcontext.arm_pc);
	fprintf_fd(csfd, "cpsr = 0x%08x\n", ucontext->uc_mcontext.arm_cpsr);

#ifdef BTDEBUG
	fprintf_fd(csfd, "fault_address = %p\n",
		   ucontext->uc_mcontext.fault_address);
	fprintf_fd(csfd, "uc_stack.ss_sp = %p\n", ucontext->uc_stack.ss_sp);
	fprintf_fd(csfd, "uc_stack.ss_size = %d\n", ucontext->uc_stack.ss_size);
#endif
	fprintf_fd(csfd, "*******************************\ncallstack information (PID:%d)\n\
*******************************\n",
		   pid);

#ifndef SUPPORT_LIBC_BACKTRACE
	/* backtrace using fp */
	{
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

#ifdef BTDEBUG
		print_node_to_file(head, 2);
#endif

		if (FP != NULL) {
			for (; framep < BP;) {
				if (is_valid_addr(framep, head) == false)
					break;

				if (is_valid_addr((long *)*framep, head)
				    == false)
					break;

				callstack_addrs[cnt_callstack] =
				    (long *)*framep;

				framep--;
				framep = (long *)(*framep);
				cnt_callstack++;

				if (cnt_callstack == CALLSTACK_SIZE)
					break;
				if (framep < FP)
					break;
			}

		}
		fprintf_fd(csfd, "cnt_callstack = %d\n", cnt_callstack);

		/* print callstack */
		if (false ==
		    trace_symbols(callstack_addrs, cnt_callstack, head, csfd)) {
			callstack_strings =
			    backtrace_symbols(callstack_addrs, cnt_callstack);
			/* print callstack information */
			for (i = 0; i < cnt_callstack; i++) {
				fprintf_fd(csfd, "%2d: %s\n", i,
					   callstack_strings[i]);
			}
		}

		if (FP == NULL) {
			fprintf_fd(csfd,
				   "there is no callstack because of fp == NULL\n");
		}
	}
#else

	cnt_callstack = backtrace(callstack_addrs, CALLSTACK_SIZE);
	if (cnt_callstack > 2) {
		cnt_callstack -= 2;
	} else {
		callstack_addrs[2] = (long *)ucontext->uc_mcontext.arm_pc;
		callstack_addrs[3] = (long *)ucontext->uc_mcontext.arm_lr;
		cnt_callstack = 2;
	}
	fprintf_fd(csfd, "cnt_callstack = %d\n", cnt_callstack);

	/* print callstack */
	if (false ==
	    trace_symbols(&callstack_addrs[2], cnt_callstack, head, csfd)) {
		fprintf(stderr, "[sys-assert] trace_symbols failed \n");
	}
#endif

#else				/* i386 */
	fprintf_fd(csfd, "*******************************\ncallstack information (PID:%d)\n\
*******************************\n",
		   pid);

	layout *ebp = ucontext->uc_mcontext.gregs[REG_EBP];
	callstack_addrs[cnt_callstack++] =
	    (long *)ucontext->uc_mcontext.gregs[REG_EIP];
	while (ebp) {
		callstack_addrs[cnt_callstack++] = ebp->ret;
		ebp = ebp->ebp;
	}
	callstack_strings = backtrace_symbols(callstack_addrs, cnt_callstack);
	/* print callstack information */
	for (i = 0; i < cnt_callstack; i++) {
		fprintf_fd(csfd, "%2d: %s\n", i, callstack_strings[i]);
	}
#endif
	fprintf_fd(csfd, "end of call stack\n");

	/* print maps information */
	print_node_to_file(head, csfd);

	/* clean up */
	free_all_nodes(head);
	close(mapsfd);
	close(csfd);

	if (prctl(PR_GET_DUMPABLE) == 0) {
		fprintf(stderr, "[sys-assert]set PR_SET_DUMPABLE to 1\n");
		prctl(PR_SET_DUMPABLE, 1);
	}

	if ((curbs = open(INOTIFY_BS, O_RDWR | O_APPEND)) < 0) {
		fprintf(stderr, "[sys-assert]cannot make %s !\n", INOTIFY_BS);
	} else {
		fprintf_fd(curbs, "%s %s\n", filepath_cs,
			   redscreen_flg ? "RED" : "BLUE");
		close(curbs);
	}

	for (i = 0; i < NUM_SIG_TO_HANDLE; i++) {
		if (sig_to_handle[i] == signum) {
			sigaction(signum, &g_oldact[i], NULL);
			fprintf(stderr,
				"sighandler = %p, g_sig_oldact[i] = %p\n",
				(void *)sighandler, g_oldact[i].sa_handler);

			break;
		}
	}
	raise(signum);

	fprintf(stderr, "[sys_assert]END of sighandler\n");

}

__attribute__ ((constructor))
void init()
{
	pid_t pid;
	pid = getpid();
	int i;
	for (i = 0; i < NUM_SIG_TO_HANDLE; i++) {
		struct sigaction act;
		act.sa_handler = (void *)sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		act.sa_flags |= SA_RESETHAND;
		if (sigaction(sig_to_handle[i], &act, &g_oldact[i]) < 0) {
			perror("[sys-assert]could not set signal handler ");
			continue;
		}
	}
}

#ifdef TARGET
/* get function symbol from elf */
static int
trace_symbols(void *const *array, int size, struct addr_node *start, int csfd)
{
	int cnt;
	Dl_info info_funcs;
#ifndef USE_SYMBOL_DB
	int i;
	Elf32_Ehdr elf_h;
	Elf32_Shdr *s_headers;
	int strtab_index = 0;
	int symtab_index = 0;
	int num_st = 0;
	Elf32_Sym *symtab_entry;
	int fd;
	int ret;
	char filename[256];
#endif
	unsigned int offset_addr;
	unsigned int start_addr;
	unsigned int addr;

	for (cnt = 0; cnt < size; cnt++) {
#ifndef USE_SYMBOL_DB
		num_st = 0;
#endif
		/* FIXME : for walking on stack trace */
		if (dladdr(array[cnt], &info_funcs) == 0) {
			fprintf(stderr, "[sys-assert]dladdr returnes error!\n");
			/* print just address */
			fprintf_fd(csfd, "%2d: (%p)\n", cnt, array[cnt]);

			continue;
		}
		start_addr = (unsigned int)get_start_addr(array[cnt], start);
		addr = (unsigned int)array[cnt];

		/* because of launchpad, 
		 * return value of dladdr when find executable is wrong. 
		 * so fix dli_fname here
		 */
		if (info_funcs.dli_fbase == (void *)0x8000
		    &&
		    (strncmp
		     ("/opt/apps/", info_funcs.dli_fname,
		      strlen("/opt/apps/")) == 0)) {
			fprintf(stderr,
				"[sys-assert][%d] fname = %s, fbase = %p, sname = %s, saddr = %p\n",
				cnt, info_funcs.dli_fname,
				info_funcs.dli_fbase,
				info_funcs.dli_sname, info_funcs.dli_saddr);
			info_funcs.dli_fname = get_fpath(array[cnt], start);
			offset_addr = addr;
			fprintf(stderr,
				"[sys-assert][%d] start_addr : %x, addr : %x, offset_addr : %x \n",
				cnt, start_addr, addr, offset_addr);
		} else {
			offset_addr = addr - start_addr;
		}

		if (info_funcs.dli_sname == NULL) {
#ifndef USE_SYMBOL_DB
			/* FIXME : get dbg file name from debuglink and search dbg file in DBG_DIR */

			strcpy(filename, DBG_DIR);
			strncat(filename, info_funcs.dli_fname, 128);

			fd = open(filename, O_RDONLY);
			if (fd < 0) {
				fprintf_fd(csfd,
					   "%2d: (%p) [%s]+%p\n",
					   cnt, array[cnt],
					   info_funcs.dli_fname, offset_addr);
				continue;
			}

			ret = read(fd, &elf_h, sizeof(Elf32_Ehdr));
			if (ret < sizeof(Elf32_Ehdr)) {
				fprintf(stderr,
					"[sys-assert]readnum = %d, [%s]\n",
					ret, info_funcs.dli_fname);
				fprintf_fd(csfd,
					   "%2d: (%p) [%s]+%p\n",
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
				fprintf_fd(csfd,
					   "%2d: (%p) [%s]+%p\n",
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
				/* find out .symtab Section index */
				if (s_headers[i].sh_type == SHT_SYMTAB) {
					symtab_index = i;
					num_st =
					    s_headers[i].sh_size /
					    s_headers[i].sh_entsize;
					/* number of .symtab entry */
					break;
				}
			}

			/*.strtab index */
			strtab_index = s_headers[symtab_index].sh_link;
			symtab_entry =
			    (Elf32_Sym *)mmap(0, sizeof(Elf32_Sym) * num_st,
					      PROT_READ | PROT_WRITE,
					      MAP_PRIVATE | MAP_ANONYMOUS, -1,
					      0);
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
					fprintf(stderr,
						"[sys-assert]symtab_entry[%d], num_st=%d, readnum = %d\n",
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
						lseek(fd,
						      s_headers
						      [strtab_index].sh_offset +
						      symtab_entry[i].st_name,
						      SEEK_SET);
						info_funcs.dli_sname = (void *)
						    mmap(0,
							 FUNC_NAME_MAX_LEN,
							 PROT_READ
							 |
							 PROT_WRITE,
							 MAP_PRIVATE
							 |
							 MAP_ANONYMOUS, -1, 0);
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
#endif
			fprintf_fd(csfd, "%2d: (%p) [%s]+%p\n",
				   cnt, array[cnt],
				   info_funcs.dli_fname, offset_addr);
		} else {

			if (array[cnt] >= info_funcs.dli_saddr) {
				fprintf_fd(csfd,
					   "%2d: %s+0x%x(%p) [%s]+%p\n",
					   cnt,
					   info_funcs.dli_sname,
					   (array[cnt] -
					    info_funcs.dli_saddr),
					   array[cnt],
					   info_funcs.dli_fname, offset_addr);
			} else {
				fprintf_fd(csfd,
					   "%2d: %s-0x%x(%p) [%s]+%p\n",
					   cnt,
					   info_funcs.dli_sname,
					   (info_funcs.dli_saddr
					    - array[cnt]),
					   array[cnt],
					   info_funcs.dli_fname, offset_addr);
			}
		}
	}

	return true;

}
#endif

/* get address list from maps */
static struct addr_node *get_addr_list_from_maps(int mapsfd)
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
	while (fgets_fd(linebuf, BUF_SIZE, mapsfd) != NULL) {
#ifdef BTDEBUG
		fprintf(stderr, "%s", linebuf);
#endif
		memset(path, 0, PATH_LEN);
		result =
		    sscanf(linebuf, "%s %s %*s %*s %*s %s ", addr, perm, path);
		perm[4] = 0;
#ifdef BTDEBUG
		fprintf(stderr,
			"addr = %s, perm = %s, fpath = %s, length=%d\n",
			addr, perm, path, strlen(path));
#endif
		/*if perm[2]=='x', addr is valid value so we have to store the address */
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
#ifdef BTDEBUG
		fprintf(stderr, "end of while loop\n");
#endif
	}
	return head;
}

static void print_node_to_file(struct addr_node *start, int fd)
{
	struct addr_node *t_node;
	t_node = start;

	fprintf(stderr, "[sys-assert]start print_node_to_file\n");

	fprintf_fd(fd,
		   "******************************\nmaps  information\n******************************\n");
	while (t_node) {
		fprintf_fd(fd, "%08x %08x %s %s\n",
			   (unsigned int)t_node->startaddr,
			   (unsigned int)t_node->endaddr,
			   t_node->perm, t_node->fpath);
		t_node = t_node->next;
	}
	fprintf_fd(fd, "end of maps information\n");
}

#ifdef BTDEBUG
static void print_node(struct addr_node *start)
{
	struct addr_node *t_node;
	t_node = start;
	while (t_node) {
		printf("[%08x-%08x]\n",
		       (unsigned int)t_node->startaddr,
		       (unsigned int)t_node->endaddr);
		t_node = t_node->next;
	}
}
#endif

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

static long *get_start_addr(long *value, struct addr_node *start)
{
	struct addr_node *t_node;
	struct addr_node *n_node;
	t_node = start;
	n_node = t_node->next;
#ifdef BTDEBUG
	fprintf(stderr, "in is_valid_addr(), value %p ", value);
#endif
	if (value == 0 || start == NULL) {
#ifdef BTDEBUG
		fprintf(stderr, "is invalid address\n");
#endif
		return NULL;
	}

	while (t_node) {
		if (t_node->endaddr <= value) {
			/* next node */
			if (n_node == NULL) {
#ifdef BTDEBUG
				fprintf(stderr, "is invalid address\n");
#endif
				return NULL;
			}
			t_node = n_node;
			n_node = n_node->next;
		} else if (t_node->startaddr <= value) {
#ifdef BTDEBUG
			fprintf(stderr, "is valid address\n");
			fprintf(stderr,
				"value = %p \n t_node->startaddr = %p\n t_node->fpath =%s\n",
				value, t_node->startaddr, t_node->fpath);

#endif
			return t_node->startaddr;
		} else {
#ifdef BTDEBUG
			fprintf(stderr, "is invalid address\n");
#endif
			return NULL;
		}
	}
#ifdef BTDEBUG
	fprintf(stderr, "is invalid address\n");
#endif
	return NULL;
}

static char *get_fpath(long *value, struct addr_node *start)
{
	struct addr_node *t_node;
	struct addr_node *n_node;
	t_node = start;
	n_node = t_node->next;
	if (value == 0 || start == NULL) {
		return NULL;
	}

	while (t_node) {
		if (t_node->endaddr <= value) {
			/* next node */
			if (n_node == NULL) {
				return NULL;
			}
			t_node = n_node;
			n_node = n_node->next;
		} else if (t_node->startaddr <= value) {
			return t_node->fpath;
		} else {
			return NULL;
		}
	}
	return NULL;
}

static void print_signal_info(const siginfo_t *info, int fd)
{

	int signum = info->si_signo;
	fprintf_fd(fd, "signal = %d ", signum);
	switch (signum) {
	case SIGINT:
		fprintf_fd(fd, "(SIGINT)\n");
		break;
	case SIGILL:
		fprintf_fd(fd, "(SIGILL)\n");
		break;
	case SIGABRT:
		fprintf_fd(fd, "(SIGABRT)\n");
		break;
	case SIGBUS:
		fprintf_fd(fd, "(SIGBUS)\n");
		break;
	case SIGFPE:
		fprintf_fd(fd, "(SIGFPE)\n");
		break;
	case SIGKILL:
		fprintf_fd(fd, "(SIGKILL)\n");
		break;
	case SIGSEGV:
		fprintf_fd(fd, "(SIGSEGV)\n");
		break;
	case SIGPIPE:
		fprintf_fd(fd, "(SIGPIPE)\n");
		break;
	default:
		fprintf_fd(fd, "\n");
	}

	/* print signal si_code info */
	fprintf_fd(fd, "si_code = %d\n", info->si_code);

	if (info->si_code <= 0 || info->si_code >= 0x80) {
		switch (info->si_code) {
#ifdef SI_TKILL
		case SI_TKILL:
			/* FIXME : print exe name displace with info->si_pid */
			fprintf_fd(fd,
				   "signal sent by tkill (sent by pid %d, uid %d) \n",
				   info->si_pid, info->si_uid);
			fprintf_fd(fd, "TIMER = %d\n", SI_TIMER);
			break;
#endif
#ifdef SI_USER
		case SI_USER:
			/* FIXME : print exe name displace with info->si_pid */
			fprintf_fd(fd,
				   "signal sent by kill (sent by pid %d, uid %d) \n",
				   info->si_pid, info->si_uid);
			break;
#endif
#ifdef SI_KERNEL
		case SI_KERNEL:
			fprintf_fd(fd, "signal sent by the kernel\n");
			break;
#endif
		}

	} else if (signum == SIGILL) {
		switch (info->si_code) {
		case ILL_ILLOPC:
			fprintf_fd(fd, "illegal opcode\n");
			break;
		case ILL_ILLOPN:
			fprintf_fd(fd, "illegal operand\n");
			break;
		case ILL_ILLADR:
			fprintf_fd(fd, "illegal addressing mode\n");
			break;
		case ILL_ILLTRP:
			fprintf_fd(fd, "illegal trap\n");
			break;
		case ILL_PRVOPC:
			fprintf_fd(fd, "privileged opcode\n");
			break;
		case ILL_PRVREG:
			fprintf_fd(fd, "privileged register\n");
			break;
		case ILL_COPROC:
			fprintf_fd(fd, "coprocessor error\n");
			break;
		case ILL_BADSTK:
			fprintf_fd(fd, "internal stack error\n");
			break;
		default:
			fprintf_fd(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "si_addr = %p\n", info->si_addr);
	} else if (signum == SIGFPE) {
		switch (info->si_code) {
		case FPE_INTDIV:
			fprintf_fd(fd, "integer divide by zero\n");
			break;
		case FPE_INTOVF:
			fprintf_fd(fd, "integer overflow\n");
			break;
		case FPE_FLTDIV:
			fprintf_fd(fd, "floating-point divide by zero\n");
			break;
		case FPE_FLTOVF:
			fprintf_fd(fd, "floating-point overflow\n");
			break;
		case FPE_FLTUND:
			fprintf_fd(fd, "floating-point underflow\n");
			break;
		case FPE_FLTRES:
			fprintf_fd(fd, "floating-point inexact result\n");
			break;
		case FPE_FLTINV:
			fprintf_fd(fd, "invalid floating-point operation\n");
			break;
		case FPE_FLTSUB:
			fprintf_fd(fd, "subscript out of range\n");
			break;
		default:
			fprintf_fd(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
	} else if (signum == SIGSEGV) {
		switch (info->si_code) {
		case SEGV_MAPERR:
			fprintf_fd(fd, "address not mapped to object\n");
			break;
		case SEGV_ACCERR:
			fprintf_fd(fd,
				   "invalid permissions for mapped object\n");
			break;
		default:
			fprintf_fd(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "si_addr = %p\n", info->si_addr);
	} else if (signum == SIGBUS) {
		switch (info->si_code) {
		case BUS_ADRALN:
			fprintf_fd(fd, "invalid address alignment\n");
			break;
		case BUS_ADRERR:
			fprintf_fd(fd, "nonexistent physical address\n");
			break;
		case BUS_OBJERR:
			fprintf_fd(fd, "object-specific hardware error\n");
			break;
		default:
			fprintf_fd(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		fprintf_fd(fd, "si_addr = %p\n", info->si_addr);

	}
}

char *fgets_fd(char *s, int n, int fd)
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
int fprintf_fd(int fd, const char *fmt, ...)
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
		if (*t == '/' || *t == '.')
			r = t + 1;
		t++;
	}
	return r;
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

/* localtime() can not use in signal handler, so we need signal safe version of localtime */
inline static void get_localtime(time_t cur_time, struct tm *ctime)
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

	while (time_var >
	       365 + (leak_year = (((year % 4) == 0) && ((year % 100) != 0))
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

	fprintf(stderr, "local time %d %d %d %d:%d:%d \n",
		ctime->tm_year, ctime->tm_mon, ctime->tm_mday,
		ctime->tm_hour, ctime->tm_min, ctime->tm_sec);
}
