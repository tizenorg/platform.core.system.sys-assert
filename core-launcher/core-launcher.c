/*
 * CORE-LAUNCHER
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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <sys/types.h>

#define CRASH_NOTI_DIR      "/opt/share/crash"
#define CRASH_NOTI_FILE     "curbs.log"
#define CRASH_NOTI_PATH    CRASH_NOTI_DIR"/"CRASH_NOTI_FILE

#define CRASH_CHECK_COREDUMP_NUM (10)
#define CRASH_CHECK_SIZE (1024 * 512)
#define CRASH_CHECK_DISK_PATH   "/opt/usr"
#define CRASH_INFO_PATH    "/opt/share/crash/info"
#define CRASH_CORE_PATH "/opt/usr/share/crash/core"
#define CRASH_SAVE_PATH "/opt/usr/share/crash"
#define CRASH_DUMP_PATH "/opt/usr/share/crash/dump"
#define CRASH_REPORT_PATH   "/opt/usr/share/crash/report"

#define TIZEN_OPT_USR_MOUNT "/dev/mmcblk0p7"
#define TIZEN_OPT_USR_TYPE "ext4"

#define CRASH_TIME_MAX 65
#define CRASH_INFO_EXPAND_SIZE 5
#define CRASH_CORE_INFO_MATCH_TIMEGAP 10
#define BUF_SIZE 1024
#define PATH_MAX 4096

#define DEBUG_CORE_LAUNCHER

static ssize_t safewrite(int fd, const void *buf, size_t count)
{
	ssize_t n;
	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);
	return n;
}

static bool _check_previous_coredump_num(char *check_dir, int check_num)
{
	DIR *dp;
	struct dirent *de;
	int count = 0;

	if (check_dir == NULL)
		return false;
	if (check_num == 0)
		return true;
	dp = opendir(check_dir);
	if (dp == NULL) {
		fprintf(stderr, "error opendir %s\n", check_dir);
		return false;
	}
	while (de = readdir(dp)) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (de->d_ino != 0 )
			count++;
	}
	closedir(dp);
	if (check_num < count)
		return false;
	else
		return true;
}
/* check disk available size */
static bool _check_disk_available(char *mount_dir, int check_size)
{
	struct statfs lstatfs;

	if (mount_dir == NULL)
		return false;
	if (check_size == 0)
		return true;
	if (statfs(mount_dir, &lstatfs) < 0) {
		fprintf(stderr, "can't get statfs %s\n", mount_dir);
		return false;
	} else {
		if (check_size <=
				lstatfs.f_bavail * (lstatfs.f_bsize/1024)) {
			return true;
		} else {
			fprintf(stderr, "NO %d < %d\n", check_size,
					(int)(lstatfs.f_bavail * (lstatfs.f_bsize/1024)));
			return false;
		}
	}
}
static bool _check_crash_name_timesec(char *filename,
		char *pid, char *timesec)
{
	if (filename == NULL || pid == NULL || timesec == NULL)
		return false;
	int pid_len = 0;
	int times_len = 0;
	long infotime = 0;
	long coretime = 0;
	long timegap = 0;
	char tbuf[CRASH_TIME_MAX] = {0, };
	int len = strlen(filename);
	int i = 0;
	for (i = 0; i < len; i++) {
		if (filename[i] == '_') {
			pid_len = i;
			times_len = len - i - CRASH_INFO_EXPAND_SIZE;
			break;
		}
	}
	if (!strncmp(pid, filename, i)) {
		strncpy(tbuf, &(filename[i+1]), times_len);
		infotime = atol(tbuf);
		coretime = atol(timesec);
		timegap = labs(infotime - coretime);
		if (timegap < CRASH_CORE_INFO_MATCH_TIMEGAP)
			return true;
		return false;
	}
	return false;
}
static bool check_crash_libsysinfo(char *pid, char *timesec)
{
	DIR *dp;
	struct dirent *de;
	dp = opendir(CRASH_INFO_PATH);
	if (dp == NULL) {
		fprintf(stderr, "error opendir %s\n", CRASH_INFO_PATH);
		return false;
	}
	while (de = readdir(dp)) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (_check_crash_name_timesec(de->d_name,
					pid, timesec) == 1) {
			closedir(dp);
			return true;
		}
	}
	closedir(dp);
	return false;
}
/*
 * 1  2  3  4
 * %e %t %p %s
 */
int main(int argc, char *argv[])
{
	int fd_curbs;       /* for inotify */
	int fd_coredump;       /* for core dump */
	char buf[BUF_SIZE];
	int i;
	bool haveinfo = false;
	bool filesaveon = false;
	int corefilesize = 0;
	char corefile[PATH_MAX] = {0, }; /* corefile buf */
	char notimsg[BUF_SIZE] = {0, }; /* crash noti message */
	ssize_t nread;
	const unsigned long mntflags = 0;
#ifdef DEBUG_CORE_LAUNCHER
	FILE *tfp;
	char cwd[PATH_MAX];
	snprintf(cwd, PATH_MAX,
			"/tmp/%s_%s_%s_%s.info",
			argv[1], argv[2], argv[3], argv[4]);
	tfp = fopen(cwd, "w+");
	if (tfp == NULL)
		exit(EXIT_FAILURE);
	fprintf(tfp, "argc=%d\n", argc);
	for (i = 0; i < argc; i++)
		fprintf(tfp, "argc[%d]=<%s>\n", i, argv[i]);
#endif
	/* check that process name is crash-worker or crash-popup, because prevent infinite called */
	if (!strcmp(argv[1], "crash-worker") || !strcmp(argv[1], "crash-popup")) {
#ifdef DEBUG_CORE_LAUNCHER
		fclose(tfp);
#endif
		exit(EXIT_SUCCESS);
	}
	/* check already know crash is reported and triggerd by libsys-assert lib */
	haveinfo = check_crash_libsysinfo(argv[3], argv[2]);
	/* check core dump path for saving */
	if (access(CRASH_CORE_PATH, F_OK) != 0) {
		/* if can't access core dump path, try mount that */
		if (mount(TIZEN_OPT_USR_MOUNT,
					CRASH_CHECK_DISK_PATH,
					TIZEN_OPT_USR_TYPE, mntflags, NULL) != 0)
			sleep(2);
		else
			filesaveon = true;

	/* one more check core dump path for saving */
		if (access(CRASH_CORE_PATH, F_OK) != 0)
			filesaveon = false;
	} else
		filesaveon = true;

	/* check that disk extra sapce is available */
	if (_check_disk_available(CRASH_CHECK_DISK_PATH,
				CRASH_CHECK_SIZE) == true) {
		/* check previous coredump file number,
		   because if system_server was dead,
		   crash-worker didn't working.
		   so coredump stacked an unlimited number*/
		filesaveon = _check_previous_coredump_num(CRASH_CORE_PATH,
				CRASH_CHECK_COREDUMP_NUM);
	}

	if (filesaveon == true) {
		snprintf(corefile, PATH_MAX,
				"%s/%s_%s_%s.core",
				CRASH_CORE_PATH, argv[3], argv[4], argv[1]);
		fd_coredump = open(corefile, O_WRONLY | O_SYNC | O_CREAT | O_TRUNC, 0644);
		if (fd_coredump < 0) {
			fprintf(stderr,
					"[core-launcher]cannot open core dump file!\n");
		} else {
			corefilesize = 0;
			while ((nread = read(STDIN_FILENO, buf, BUF_SIZE)) > 0)	{
				corefilesize += nread;
				safewrite(fd_coredump, buf, nread);
			}
			fsync(fd_coredump);
			close(fd_coredump);
		}
	}

	if (haveinfo == false) {
		/* NOTIFY CRASH */
		fd_curbs = open(CRASH_NOTI_PATH, O_RDWR | O_APPEND);
		if (fd_curbs < 0) {
			fprintf(stderr,
					"[core-launcher]cannot make %s !\n",
					CRASH_NOTI_PATH);
		} else {
			snprintf(notimsg, BUF_SIZE,
					"C|%s|%s|%s|%s|%d\n",
					argv[1], argv[2], argv[3], argv[4], strlen(argv[1]) + strlen(argv[4]));
			write(fd_curbs, notimsg, strlen(notimsg));
			close(fd_curbs);
		}
	}
#ifdef DEBUG_CORE_LAUNCHER
	fprintf(tfp, "haveinfo check(%d) %s %s\n", haveinfo, argv[1], argv[2]);
	if (filesaveon == true)
		fprintf(tfp, "Total bytes in core dump: %d\n", corefilesize);
	else
		fprintf(tfp, "We didn't save core dump\n");
	fclose(tfp);
#endif
	exit(EXIT_SUCCESS);
}

