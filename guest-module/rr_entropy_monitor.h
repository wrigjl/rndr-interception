/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * rr_entropy_monitor.h - UAPI for the rr-entropy-monitor control device.
 *
 * Shared between the guest kernel module and userspace (test programs and,
 * eventually, rr).  The module registers a misc character device at
 * RRMON_DEVICE_PATH; a process controls monitoring with ioctls on it.
 *
 * Each ioctl takes a pointer to a __s32 PID (a thread-group id).  The
 * permission model matches ptrace(2) attach: the caller must be able to
 * PTRACE_MODE_ATTACH the target with its real credentials, so the access
 * tiers are governed by the standard kernel.yama.ptrace_scope sysctl --
 *   scope 0: any process with a matching real UID/GID;
 *   scope 1: only the caller's own descendants (the Debian/Ubuntu default);
 *   scope 2: CAP_SYS_PTRACE only.
 * A caller can always act on itself / its own thread group, and
 * CAP_SYS_PTRACE (root) can register or deregister any process.
 *
 * RRMON_IOC_IS_MONITORED returns 1 if the PID is currently monitored, 0 if
 * not (via the ioctl return value); it is a test/observability affordance.
 */
#ifndef _RR_ENTROPY_MONITOR_H
#define _RR_ENTROPY_MONITOR_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define RRMON_DEVICE_NAME	"rr-entropy-monitor"
#define RRMON_DEVICE_PATH	"/dev/" RRMON_DEVICE_NAME

#define RRMON_IOC_MAGIC		0xE7
#define RRMON_IOC_REGISTER	_IOW(RRMON_IOC_MAGIC, 1, __s32)
#define RRMON_IOC_DEREGISTER	_IOW(RRMON_IOC_MAGIC, 2, __s32)
#define RRMON_IOC_IS_MONITORED	_IOW(RRMON_IOC_MAGIC, 3, __s32)

#endif /* _RR_ENTROPY_MONITOR_H */
