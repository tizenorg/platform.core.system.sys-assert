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



#ifndef __LOCKUPINFO_UTIL_LOG_H__
#define __LOCKUPINFO_UTIL_LOG_H__

#include <unistd.h>
//#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "LOCKUPINFO"
#define _E(fmt, arg...) fprintf(stderr, "[%s,%d] "fmt,__FUNCTION__,__LINE__,##arg)
#define _D(fmt, arg...) fprintf(stderr, "[%s,%d] "fmt,__FUNCTION__,__LINE__,##arg)
//#define _E(fmt, arg...) LOGE("[%s,%d] "fmt,__FUNCTION__,__LINE__,##arg)
//#define _D(fmt, arg...) LOGD("[%s,%d] "fmt,__FUNCTION__,__LINE__,##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if(expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if(expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retm_if(expr, fmt, arg...) do { \
	if(expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return; \
	} \
} while (0)

#define ret_if(expr) do { \
	if(expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return; \
	} \
} while (0)


#endif				/* __LOCKUPINFO_UTIL_LOG_H__ */
