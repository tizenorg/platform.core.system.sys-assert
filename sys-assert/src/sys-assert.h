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




#ifndef _DEBUG_ASSERT_H_
#define _DEBUG_ASSERT_H_

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

	struct addr_node {
		long *startaddr;
		long *endaddr;
		char perm[5];
		char *fpath;
		struct addr_node *next;
	};

#ifdef __arm__
	typedef struct layout {
		struct layout *fp;
		void *ret;
	} layout;

#else
	typedef struct layout {
		struct layout *ebp;
		void *ret;
	} layout;
#endif

	extern void *__libc_stack_end;

	static int trace_symbols(void *const *array, int size,
				 struct addr_node *start, int csfd);

	static struct addr_node *get_addr_list_from_maps(int fd);

	static void print_node_to_file(struct addr_node *start, int fd);

#ifdef BTDEBUG
	static void print_node(struct addr_node *start);
#endif
	static void free_all_nodes(struct addr_node *start);

	static long *get_start_addr(long *value, struct addr_node *start);

	static char *get_fpath(long *value, struct addr_node *start);

	static void print_signal_info(const siginfo_t *info, int fd);

	char *fgets_fd(char *s, int n, int fd);

	int fprintf_fd(int fd, const char *fmt, ...);

	static char *remove_path(const char *cmd);

	static int check_redscreen(int pid);

	inline static void get_localtime(time_t cur_time, struct tm *ctime);

#ifdef __cplusplus
}
#endif
#endif				/* _DEBUG_ASSERT_H_ */
