
/*
 *  LOCKUPINFO
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jeesun Kim <iamjs.kim@samsung.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "_util_log.h"

#define VERINFO_PATH "/etc/info.ini"
#define DEBUG_DIR "/opt/share/hidden_storage/SLP_debug"
#define PATH_LEN 256
#define BUF_SIZE 256
#define PERMS 0755
#define FILE_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* lockupinfo launch key combination: 
 * 1. volume side key up
 * 2. volume side key down
 * 3. home key
 * 4. home key
 * 5. volume side key up
 * 6. volume side key down
 * 7. volume side key up
 * 8. home key
 */

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

int main()
{
	char lbuf[BUF_SIZE];
	char name[32] = {0, };
	char size[32] = {0, };
	char unit[32] = {0, };
	int csfd;
	int tmpfd;
	int meminfo;
	int verinfo;

	fprintf(stderr, "[lockupinfo] executed\n");

	/* get time  */
	time_t cur_time;
	struct tm ctime;
	cur_time = time(NULL);
	localtime_r(&cur_time, &ctime);

	char nbuf[256] = {0, };	/* name buf */
	char dbuf[256] = {0, };	/* dir buf */
	char ibuf[256] = {0, };	/* info buf */
	char cbuf[256] = {0, };	/* cmd buf */
	char tbuf[256] = {0, };	/* temp buf */
	int ret;

//	snprintf(nbuf, sizeof(nbuf), "debuginfo_%02d%02d%02d%02d%02d%02d",
//			ctime->tm_year, ctime->tm_mon, ctime->tm_mday,
//			ctime->tm_hour, ctime->tm_min, ctime->tm_sec);

	strftime(tbuf, sizeof(tbuf), "%Y%m%d%H%M%S", &ctime);
	snprintf(nbuf, sizeof(nbuf), "debuginfo_%s", tbuf);

	/* make debug directory if absent */
	ret = access(DEBUG_DIR, F_OK);
	if (ret < 0) {
		if (ret = mkdir(DEBUG_DIR, PERMS) < 0) {
			_E("Failed to mkdir %s(errno:%d)\n", DEBUG_DIR, ret);
			return -1;
		}
	}

	snprintf(dbuf, sizeof(dbuf), "%s/%s", DEBUG_DIR, nbuf);
	ret = mkdir(dbuf, PERMS);
	retvm_if(ret < 0, -1, "Failed to mkdir %s(errno:%d)\n", dbuf, ret);

	snprintf(dbuf, sizeof(dbuf), "%s/%s/%s", DEBUG_DIR, nbuf, "files");
	ret = mkdir(dbuf, PERMS);
	retvm_if(ret < 0, -1, "Failed to mkdir %s(errno:%d)\n", dbuf, ret);
	_D("lockupinfo dir [%s]\n", dbuf);

	snprintf(ibuf, sizeof(ibuf), "%s/%s.info", dbuf, nbuf);

	/* create .info file */
	csfd = creat(ibuf, FILE_PERMS);
	retvm_if(csfd < 0, -1, "Failed to creat %s\n", ibuf);

	/* print version info */
	fprintf_fd(csfd, "******************************\n");
	fprintf_fd(csfd, "s/w version\n");
	fprintf_fd(csfd, "******************************\n");

	verinfo = open(VERINFO_PATH, O_RDONLY);
	if (verinfo < 0) {
		_E("Failed to open %s\n", VERINFO_PATH);

	} else {
		while (fgets_fd(lbuf, BUF_SIZE, verinfo)) {
			if (strncmp("Major=", lbuf, 6) == 0) {
				fprintf_fd(csfd, "%s", lbuf);

			} else if (strncmp("Minor=", lbuf, 6) == 0) {
				fprintf_fd(csfd, "%s", lbuf);

			} else if (strncmp("Date=", lbuf, 5) == 0) {
				fprintf_fd(csfd, "%s", lbuf);

			} else if (strncmp("Time=", lbuf, 5) == 0) {
				fprintf_fd(csfd, "%s", lbuf);
				break;
			}
		}
		close(verinfo);

	}

	/* print mem info */
	meminfo = open("/proc/meminfo", O_RDONLY);
	if (meminfo < 0) {
		_E("Failed to open %s\n", "/proc/meminfo");

	} else {
		fprintf_fd(csfd, "*******************************\n");
		fprintf_fd(csfd, "Mem information\n");
		fprintf_fd(csfd, "*******************************\n");

		while (fgets_fd(lbuf, BUF_SIZE, meminfo) != NULL) {
			sscanf(lbuf, "%s %s %s", name, size, unit);

			if (strcmp("MemTotal:", name) == 0) {
				fprintf_fd(csfd, "%s\t%10.0d %s\n", name, atoi(size), unit);

			} else if (strcmp("MemFree:", name) == 0) {
				fprintf_fd(csfd, "%s\t%10.0d %s\n", name, atoi(size), unit);

			} else if (strcmp("Buffers:", name) == 0) {
				fprintf_fd(csfd, "%s\t%10.0d %s\n", name, atoi(size), unit);

			} else if (strcmp("Cached:", name) == 0) {
				fprintf_fd(csfd, "%s\t%10.0d %s\n", name, atoi(size), unit);

			}
		}
		close(meminfo);
	}

	/* ps info */
	snprintf(cbuf, sizeof(cbuf), "%s > %s",
			"ps ax -o pid,tid,ppid,f,stat,pcpu,pmem,wchan,command", "/tmp/ps_tmp.log");
	system(cbuf);

	tmpfd = open("/tmp/ps_tmp.log", O_RDONLY);
	if (tmpfd < 0) {
		_E("Failed to open %s\n", "/tmp/ps_tmp.log");
	} else {
		fprintf_fd(csfd, "*******************************\n");
		fprintf_fd(csfd, "PS information\n");
		fprintf_fd(csfd, "*******************************\n");

		while (fgets_fd(lbuf, BUF_SIZE, tmpfd) != NULL) {
			fprintf_fd(csfd, "%s", lbuf);
		}
		close(tmpfd);
		unlink("/tmp/ps_tmp.log");
	}

	/* ping info */
	snprintf(cbuf, sizeof(cbuf), "%s 2> %s",
			"xinfo -p", "/tmp/ping_tmp.log");
	system(cbuf);

	if ((tmpfd = open("/tmp/ping_tmp.log", O_RDONLY)) < 0) {
		fprintf(stderr, "[lockupinfo]can't open %s\n",
			"/tmp/ping_tmp.log");
	} else {
		fprintf_fd(csfd, "*******************************\n");
		fprintf_fd(csfd, "ping test for all top level windows\n");
		fprintf_fd(csfd, "*******************************\n");

		while (fgets_fd(lbuf, BUF_SIZE, tmpfd)) {
			fprintf_fd(csfd, "%s", lbuf);
		}
		close(tmpfd);
		unlink("/tmp/ping_tmp.log");
	}

	/* dump topvwins */
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"/usr/bin/xinfo -xwd_topvwins", dbuf);
	system(cbuf);

	/* close lockupinfoXXXX.info */
	close(csfd);

	snprintf(cbuf, sizeof(cbuf), "%s %s/%s.info %s/%s/%s.cs",
			"cp", dbuf, nbuf, DEBUG_DIR, nbuf, nbuf);
	system(cbuf);



	/* make dlog file */
	snprintf(tbuf, sizeof(tbuf), "%s/%s", dbuf, "main.log");
	snprintf(cbuf, sizeof(cbuf), "dlogutil -v time -d -f %s *:v", tbuf);
	system(cbuf);

	snprintf(tbuf, sizeof(tbuf), "%s/radio.log", dbuf);
	fprintf(stderr, "radio log path = %s\n", tbuf);
	snprintf(cbuf, sizeof(cbuf), "dlogutil -v time -b radio -d -f %s *:v", tbuf);
	system(cbuf);


	/* dump window manager info 
	 * this code came from window team
	 */
	fprintf(stderr, "[lockupinfo]dump window manager info\n");
	snprintf(cbuf, sizeof(cbuf), "%s %s/%s",
			"/usr/bin/e_comp_util -l DUMP_INFO -f", dbuf, "e_comp.log");
	system(cbuf);

	snprintf(cbuf, sizeof(cbuf), "%s %s/%s",
			"/usr/bin/border_win_info -p ALL -f", dbuf, "e_illume2.log");
	system(cbuf);

	system("/usr/bin/keygrab_status 2");
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"cp -af /opt/var/log/keygrab_status.txt", cbuf);
	system(cbuf);

	snprintf(cbuf, sizeof(cbuf), "%s %s/%s",
			"/usr/bin/screenshot bmp", cbuf, "slp_screenshot.bmp");
	system(cbuf);

	snprintf(cbuf, sizeof(cbuf), "%s > %s/%s",
			"xinfo -topvwins 2", dbuf, "xinfo_topvwins.txt");
	system(cbuf);

	/* end from window team */

	/*  copy prev xorg log */
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"cp /opt/var/log/prev.Xorg.*", dbuf);
	system(cbuf);

	/*  copy xorg log */
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"cp /opt/var/log/Xorg.*", dbuf);
	system(cbuf);

	/* dump a list of current tasks and their information */
	/* requsted by window team */
	/*snprintf(cbuf, sizeof(cbuf), "echo t > /proc/sysrq-trigger");
	 *system(cbuf);
	 */

	/* copy syslog messages */
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"cp /opt/var/log/messages*", dbuf);
	system(cbuf);

	/* copy nand log */
	snprintf(cbuf, sizeof(cbuf), "%s %s",
			"cp /opt/var/log/nandlog_*", dbuf);
	system(cbuf);

	/* launch bluescreen */
	pid_t bs_pid;

	if ((bs_pid = fork()) < 0) {
		fprintf(stderr, "[lockupinfo] fork_error\n");

	} else if (bs_pid == 0) {
		if (execl
		    ("/usr/bin/blue-screen", "blue-screen", ibuf,
		     "LOCKUPINFO", (char *)0) < 0) {
			fprintf(stderr, "[lockupinfo] exec_error\n");
		}
		_exit(1);	/*/ shouldn't get here */
	}

	fprintf(stderr, "[lockupinfo] exit\n");
	return 0;

}


