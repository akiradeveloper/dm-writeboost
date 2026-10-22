/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef WB_TEST_LINUX_MATH64_H
#define WB_TEST_LINUX_MATH64_H

#include <linux/types.h>

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

#endif
