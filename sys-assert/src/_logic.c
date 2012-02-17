/*
 * sys-assert
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Jeesun Kim <iamjs.kim@samsung.com>
 * 
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of
 * SAMSUNG ELECTRONICS (Confidential Information). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with SAMSUNG ELECTRONICS.  SAMSUNG make no representations or warranties
 * about the suitability of the software, either express or implied,
 * including but not limited to the implied warranties of merchantability,
 * fitness for a particular purpose, or non-infringement. SAMSUNG shall
 * not be liable for any damages suffered by licensee as a result of
 * using, modifying or distributing this software or its derivatives.
 */



#define CS_DIR "/opt/share/hidden_storage/SLP_debug"
#define VERINFO_PATH "/etc/info.ini"
#define CMDLINE_PATH "/proc/self/cmdline"


/* WARNING : formatted string buffer is limited to 1024 byte */
int _fdrintf(int fd, const char *fmt, ...)
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

static char *_get_dir_name(char *src)
{
	char *t, *r;

	t = r = (char *)src;

	while (*t) {
		if (*t == '/' || *t == '.')
			r = t + 1;
		t++;
	}
	return r;
}

int _get_appname(char *apppath, char *appname, int size)
{
	int pfd, ret;

	pfd = open(CMDLINE_PATH, O_RDONLY);
	if (pfd < 0) {
		fprintf(stderr, "Failed to open (%s)\n", CMDLINE_PATH);
	}

	read(pfd, apppath, size);
	snprintf(appname, size, "%s",
			pfd < 0 ? "Unknown" : _get_dir_name(buf));

	close(pfd);
}

int _filter_with_appname(char *appname)
{
	retvm_if(appname == NULL, -1, "Invalid argument: appname is NULL\n");
	if (!strcmp(appname, "dpkg-deb")) {
		return -1;
	}
	return 0;
}

int _check_pid_exist(char *dir, char *strpid)
{
	int ret = 0;
	DIR *dp;
	struct dirent *dirp;

	dp = opendir(dir);
	if (dp == NULL) {
		fprintf(stderr, "Failed to open (%s)\n", dir);
		return -1;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (!strcmp(dirp->d_name, strpid)) {
			ret = 1;
		}
	}
	closedir(dp);
	return ret;
}

void _write_crash_color(int fd, int pid)
{
	int color = 0;
	DIR *dp;
	struct dirent *dirp;
	char strpid[10];

	snprintf(strpid, sizeof(strpid), "%d", pid);

	if (_check_pid_exist("/tmp/vip", strpid) > 0) {
		fprintf(stderr, "pid=%d is VIP process\n", pid);
		_fprintf(fd, "RED SCREEN");

	} else if (_check_pid_exist("/tmp/permanent", strpid) > 0) {
		fprintf(stderr, "pid=%d is Permanent process\n", pid);
		_fprintf(fd, "BLUE SCREEN");
		}
	}
}

void _write_sw_version(int fd)
{
	int pfd;
	char *str1 = "Major=";
	char *str2 = "Minor=";
	char *str3 = "Build=";
	char *str4 = "Date=";
	char *str5 = "Time=";
	char buf[256] = {0, };
	int len1, len2, len3, len4, len5;

	len1 = strlen(str1);
	len2 = strlen(str2);
	len3 = strlen(str3);
	len4 = strlen(str4);
	len5 = strlen(str5);

	pfd = open(VERINFO_PATH, O_RDONLY);
	if (pfd < 0) {
		fprintf(stderr, "Failed to open (%s)\n", VERINFO_PATH);
		return;
	}

	_fdrintf(fd,
			"******************************\n"
			"s/w version\n"
			"******************************\n");
	while (fgets_fd(buf, sizeof(buf), pfd) != NULL) {
		if (!strncmp(str1, buf, len1)) {
			_fdrintf(fd, "%s", buf);

		} else if (!strncmp(str2, buf, len2)) {
			_fdrintf(fd, "%s", buf);

		} else if (!strncmp(str3, buf, len3)) {
			_fdrintf(fd, "%s", buf);

		} else if (!strncmp(str4, buf, len4)) {
			_fdrintf(fd, "%s", buf);

		} else if (!strncmp(str5, buf, len5)) {
			_fdrintf(fd, "%s", buf);
		}
	}
	close(pfd);

}

void _write_app_information(int fd, char *appname, int signo, char *csname, int pid)
{
	char buf[256] = {0, };

	_fdrintf(fd, "*******************************\n");
	_fdrintf(fd, "AppName : %s\n", appname);
	_fdrintf(fd, "signal number : %d\n", signo);
	snprintf(buf, sizeof(buf), "%s.cs", csname);
	_fdrintf(fd, "file name : %s\n", bug);
	_fdrintf(fd, "pid : %d\n", pid);
}

void _write_memory_information(int fd)
{
	int pfd;
	int len1, len2, len3, len4;
	char *str1 = "MemTotal:";
	char *str2 = "MemFree:";
	char *str3 = "Buffers:";
	char *str4 = "Cached:";
	char buf[256] = {0, };
	char infoname[20];
	char memsize[24];

	len1 = strlen(str1);
	len2 = strlen(str2);
	len3 = strlen(str3);
	len4 = strlen(str4);

	pfd = open("/proc/meminfo", O_RDONLY);
	if (pfd < 0) {
		fprintf(stderr, "Failed to open (%s)\n", "/proc/meminfo");
		return;
	}

	_fprintf(fd,
			"*******************************\n"
			"Mem information\n"
			"*******************************\n");
	while (fgets_fd(buf, sizeof(buf), pfd) != NULL) {
		sscanf(buf, "%s %s %*s", infoname, memsize);

		if (!strncmp(str1, infoname, len1)) {
			_fprintf(fd, "%s %s kB\n", infoname, memsize);

		} else if (!strncmp(str2, infoname, len2)) {
			_fprintf(fd, "%s %s kB\n", infoname, memsize);

		} else if (!strncmp(str3, infoname, len3)) {
			_fprintf(fd, "%s %s kB\n", infoname, memsize);

		} else if (!strmcmp(str4, infoname, len4)) {
			_fprintf(fd, "%s %s kB\n", infoname, memsize);
		}
	}
	close(pfd);
}

void _write_extra_information(int fd, time_t ctime, char *apppath, pid_t pid)
{
	char strtime[256] = {0, };

	_fprintf(fd,
			"*******************************\n"
			"extra information\n"
			"*******************************\n");

	strftime(strtime, sizeof(strtime), "%Y.%m.%d %H:%M:%S", &ctime);
	_fprintf(fd, "time = %s ( UTC )\n", strtime);
	_fprintf(fd, "exe path = %s\n", apppath);

	tid = (long int)syscall(__NR_gettid);
	if (pid == tid) {
		_fprintf(fd, "This process is main thread(%u)\n", pid);

	} else {
		_fprintf(fd, "This process is multi-thread process(pid:%d tid:%d)\n", pid, tid);

	}
}

void _write_signal_information(int fd, const siginfo_t *info)
{

	int signum = info->si_signo;
	_fprintf(fd, "signal = %d ", signum);
	switch (signum) {
	case SIGINT:
		_fprintf(fd, "(SIGINT)\n");
		break;
	case SIGILL:
		_fprintf(fd, "(SIGILL)\n");
		break;
	case SIGABRT:
		_fprintf(fd, "(SIGABRT)\n");
		break;
	case SIGBUS:
		_fprintf(fd, "(SIGBUS)\n");
		break;
	case SIGFPE:
		_fprintf(fd, "(SIGFPE)\n");
		break;
	case SIGKILL:
		_fprintf(fd, "(SIGKILL)\n");
		break;
	case SIGSEGV:
		_fprintf(fd, "(SIGSEGV)\n");
		break;
	case SIGPIPE:
		_fprintf(fd, "(SIGPIPE)\n");
		break;
	default:
		_fprintf(fd, "\n");
	}

	/* print signal si_code info */
	_fprintf(fd, "si_code = %d\n", info->si_code);

	if (info->si_code <= 0 || info->si_code >= 0x80) {
		switch (info->si_code) {
#ifdef SI_TKILL
		case SI_TKILL:
			/* FIXME : print exe name displace with info->si_pid */
			_fprintf(fd,
				   "signal sent by tkill (sent by pid %d, uid %d) \n",
				   info->si_pid, info->si_uid);
			_fprintf(fd, "TIMER = %d\n", SI_TIMER);
			break;
#endif
#ifdef SI_USER
		case SI_USER:
			/* FIXME : print exe name displace with info->si_pid */
			_fprintf(fd,
				   "signal sent by kill (sent by pid %d, uid %d) \n",
				   info->si_pid, info->si_uid);
			break;
#endif
#ifdef SI_KERNEL
		case SI_KERNEL:
			_fprintf(fd, "signal sent by the kernel\n");
			break;
#endif
		}

	} else if (signum == SIGILL) {
		switch (info->si_code) {
		case ILL_ILLOPC:
			_fprintf(fd, "illegal opcode\n");
			break;
		case ILL_ILLOPN:
			_fprintf(fd, "illegal operand\n");
			break;
		case ILL_ILLADR:
			_fprintf(fd, "illegal addressing mode\n");
			break;
		case ILL_ILLTRP:
			_fprintf(fd, "illegal trap\n");
			break;
		case ILL_PRVOPC:
			_fprintf(fd, "privileged opcode\n");
			break;
		case ILL_PRVREG:
			_fprintf(fd, "privileged register\n");
			break;
		case ILL_COPROC:
			_fprintf(fd, "coprocessor error\n");
			break;
		case ILL_BADSTK:
			_fprintf(fd, "internal stack error\n");
			break;
		default:
			_fprintf(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		_fprintf(fd, "si_addr = %p\n", info->si_addr);
	} else if (signum == SIGFPE) {
		switch (info->si_code) {
		case FPE_INTDIV:
			_fprintf(fd, "integer divide by zero\n");
			break;
		case FPE_INTOVF:
			_fprintf(fd, "integer overflow\n");
			break;
		case FPE_FLTDIV:
			_fprintf(fd, "floating-point divide by zero\n");
			break;
		case FPE_FLTOVF:
			_fprintf(fd, "floating-point overflow\n");
			break;
		case FPE_FLTUND:
			_fprintf(fd, "floating-point underflow\n");
			break;
		case FPE_FLTRES:
			_fprintf(fd, "floating-point inexact result\n");
			break;
		case FPE_FLTINV:
			_fprintf(fd, "invalid floating-point operation\n");
			break;
		case FPE_FLTSUB:
			_fprintf(fd, "subscript out of range\n");
			break;
		default:
			_fprintf(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
	} else if (signum == SIGSEGV) {
		switch (info->si_code) {
		case SEGV_MAPERR:
			_fprintf(fd, "address not mapped to object\n");
			break;
		case SEGV_ACCERR:
			_fprintf(fd,
				   "invalid permissions for mapped object\n");
			break;
		default:
			_fprintf(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		_fprintf(fd, "si_addr = %p\n", info->si_addr);
	} else if (signum == SIGBUS) {
		switch (info->si_code) {
		case BUS_ADRALN:
			_fprintf(fd, "invalid address alignment\n");
			break;
		case BUS_ADRERR:
			_fprintf(fd, "nonexistent physical address\n");
			break;
		case BUS_OBJERR:
			_fprintf(fd, "object-specific hardware error\n");
			break;
		default:
			_fprintf(fd, "illegal si_code = %d\n", info->si_code);
			break;
		}
		_fprintf(fd, "si_addr = %p\n", info->si_addr);

	}
}

void _write_context_information(int fd, void *context)
{
	ucontext_t *ucontext = context;
#ifdef TARGET
	_fprintf(fd,
		   "r0 = 0x%08x, r1 = 0x%08x\nr2 = 0x%08x, r3 = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r0,
		   ucontext->uc_mcontext.arm_r1,
		   ucontext->uc_mcontext.arm_r2,
		   ucontext->uc_mcontext.arm_r3);
	_fprintf(fd,
		   "r4 = 0x%08x, r5 = 0x%08x\nr6 = 0x%08x, r7 = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r4,
		   ucontext->uc_mcontext.arm_r5,
		   ucontext->uc_mcontext.arm_r6,
		   ucontext->uc_mcontext.arm_r7);
	_fprintf(fd,
		   "r8 = 0x%08x, r9 = 0x%08x\nr10 = 0x%08x, fp = 0x%08x\n",
		   ucontext->uc_mcontext.arm_r8,
		   ucontext->uc_mcontext.arm_r9,
		   ucontext->uc_mcontext.arm_r10,
		   ucontext->uc_mcontext.arm_fp);
	_fprintf(fd,
		   "ip = 0x%08x, sp = 0x%08x\nlr = 0x%08x, pc = 0x%08x\n",
		   ucontext->uc_mcontext.arm_ip,
		   ucontext->uc_mcontext.arm_sp,
		   ucontext->uc_mcontext.arm_lr,
		   ucontext->uc_mcontext.arm_pc);
	_fprintf(fd, "cpsr = 0x%08x\n", ucontext->uc_mcontext.arm_cpsr);

#ifdef BTDEBUG
	_fprintf(fd, "fault_address = %p\n",
			ucontext->uc_mcontext.fault_address);
	_fprintf(fd, "uc_stack.ss_sp = %p\n",
			ucontext->uc_stack.ss_sp);
	_fprintf(fd, "uc_stack.ss_size = %d\n",
			ucontext->uc_stack.ss_size);
}

/* get address list from maps */
static struct addr_node *_get_addr_list_from_maps(int mapsfd)
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



void _write_callstack_information(int fd, struct addr_node *head, void *context)
{
	ucontext_t *ucontext = context;
#ifndef SUPPORT_LIBC_BACKTRACE
	/* backtrace using fp */
	long *SP;	/* point to the top of stack */
	long *PC;	/* point to the program counter */
	long *BP = __libc_stack_end;
	long *FP;
	long *framep;
	void *callstack_addrs[CALLSTACK_SIZE];
	int cnt_callstack = 0;
	int i;

	SP = (long *)ucontext->uc_mcontext.arm_sp;
	PC = (long *)ucontext->uc_mcontext.arm_pc;
	FP = (long *)ucontext->uc_mcontext.arm_fp;
	framep = (long *)FP;

	callstack_addrs[cnt_callstack++] =
		(long *)ucontext->uc_mcontext.arm_pc;

	/* parsing the maps to get code segment address */
#ifdef BTDEBUG
	_write_maps_information(2, head);
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
	_fprintf(fd, "cnt_callstack = %d\n", cnt_callstack);

	/* print callstack */
	if (false ==
			trace_symbols(callstack_addrs, cnt_callstack, head, fd)) {
		callstack_strings =
			backtrace_symbols(callstack_addrs, cnt_callstack);
		/* print callstack information */
		for (i = 0; i < cnt_callstack; i++) {
			_fprintf(fd, "%2d: %s\n", i,
					callstack_strings[i]);
		}
	}

	if (FP == NULL) {
		_fprintf(fd,
				"there is no callstack because of fp == NULL\n");
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
	_fprintf(fd, "cnt_callstack = %d\n", cnt_callstack);

	/* print callstack */
	if (false ==
			trace_symbols(&callstack_addrs[2], cnt_callstack, head, fd)) {
		fprintf(stderr, "[sys-assert] trace_symbols failed \n");
	}
#endif
#else				/* i386 */
	_fprintf(fd,
			"*******************************\n"
			"callstack information (PID:%d)\n"
			"*******************************\n", pid);

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
		_fprintf(fd, "%2d: %s\n", i, callstack_strings[i]);
	}
#endif
	_fprintf(fd, "end of call stack\n");

}

void _write_maps_information(int fd, struct addr_node *start)
{
	struct addr_node *t_node;
	t_node = start;

	_fprintf(fd,
			"******************************\n"
			"maps  information\n"
			"******************************\n");
	while (t_node) {
		_fprintf(fd, "%08x %08x %s %s\n",
			   (unsigned int)t_node->startaddr,
			   (unsigned int)t_node->endaddr,
			   t_node->perm, t_node->fpath);
		t_node = t_node->next;
	}
	_fprintf(fd, "end of maps information\n");


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



void sighandler(int signum, siginfo_t *info, void *context)
{
	int ret;
	pid_t pid, tid;
	time_t tt;
	struct tm ctime;
	char apppath[256] = {0, };
	char appname[256] = {0, };
	char strtime[256] = {0, };
	char cspath[256] = {0, };
	char csname[256] = {0, };
	char csfile[256] = {0, };
	struct addr_node *head;

	ret = access(CS_DIR, F_OK);
	if (ret < 0) {
		fprintf(stderr, "Failed to access (%s)\n", CS_DIR);
		if (mkdir(CS_DIR, DIR_PERMS) < 0) {
			fprintf(stderr, "Failed to mkdir (%s) err(%s)\n",
					CS_DIR, strerror(errno));
			return;
		}
	}

	_get_appname(apppath, appname, sizeof(appname));
	if (_filter_with_appname(appname) < 0) {
		return;
	}

	/* get cs name */
	pid = getpid();
	tt = time(NULL);
	gmtime_r(&tt, &ctime);
	strftime(strtime, sizeof(strtime), "%Y%m%d%H%M%S", &ctime);
	snprintf(csname, sizeof(csname), "%s_%s_%s", appname, pid, strtime);

	/* make cspath */
	snprintf(cspath, sizeof(cspath), "%s/%s", CS_DIR, csname);
	ret = mkdir(cspath, DIR_PERMS);
	if (ret < 0) {
		fprintf(stderr, "Failed to mkdir (%s)\n", cspath);
		return;
	}

	/* get csfile */
	snprintf(csfile, sizeof(csfile), "%s/%s.cs", cspath, csname);
	fd = creat(csfile, FILE_PERMS);
	if (fd < 0) {
		fprintf(stderr, "Failed to create (%s) err(%s)\n",
				csfile, strerror(errno));
		return;
	}
	fprintf(stderr, "create (%s) and get fd\n", csfile);

	/* start writing in csfile */
	_write_crash_color(fd, pid);
	_write_sw_version(fd);
	_write_app_information(fd, appname, info->si_signo, csname, pid);
	_write_memory_information(fd);
	_write_extra_information(fd, ctime, apppath, pid);
	_write_signal_information(fd, info);
	_write_context_information(fd, context);

	if ((mapsfd = open(MAPS_PATH, O_RDONLY)) < 0) {
		_fprintf(fd, "Failed to open (%s)\n", MAPS_PATH);
		fprintf(stderr, "Failed to open (%s)\n", MAPS_PATH);
		close(fd);
		return;
	}

	head = _get_addr_list_from_maps(mapsfd);

	_write_callstack_information(fd, head, context);
	_write_maps_information(fd, head);

	free_all_nodes(head);
	close(mapsfd);

	close(fd);




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


