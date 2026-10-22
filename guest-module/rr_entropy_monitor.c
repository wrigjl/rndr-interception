/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Copyright (c) 2026 Jason L. Wright
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * rr_entropy_monitor.c - Guest kernel module for per-process
 *                        RNDR/RNDRRS interception via KVM.
 *
 * This module is the middle layer of the three-layer per-process
 * hardware-entropy interception system described in the accompanying
 * CSET 2026 paper.
 *
 * It exposes a misc character device, /dev/rr-entropy-monitor,
 * controlled with three ioctls (see rr_entropy_monitor.h):
 *
 *   RRMON_IOC_REGISTER      Register a PID (thread-group id) for
 *                           monitoring.
 *   RRMON_IOC_DEREGISTER    Deregister a PID.
 *   RRMON_IOC_IS_MONITORED  Query whether a PID is monitored
 *                           (returns 1/0 via the ioctl return value).
 *
 * Registration is gated by the ptrace attach-permission model
 * (ptrace_may_access with real credentials), so the access tiers are
 * governed by the standard kernel.yama.ptrace_scope sysctl.  The device
 * node is created mode 0666; opening it is harmless, and the privileged
 * decision is made per-target on each ioctl.
 *
 * The module:
 *
 *  1. Resolves PIDs to page-table base addresses (TTBR0_EL1
 *     BADDR: phys(mm->pgd) masked to bits [47:1]).
 *  2. Issues KVM hypercalls to register/deregister those bases
 *     in the hypervisor's monitored set.
 *  3. Tracks process lifecycle events (fork, exec, exit) via
 *     scheduler tracepoints to keep the monitored set current.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/tracepoint.h>
#include <linux/cpufeature.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>

#include "rr_entropy_monitor.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Jason L. Wright <wrigjaso@isu.edu>");
MODULE_DESCRIPTION(
	"Guest kernel module for per-process RNDR/RNDRRS "
	"interception via KVM hypercall");
MODULE_VERSION("0.1");

/*
 * Hypervisor registration ABI.  Must match the modified KVM host.
 *
 * Two SMCCC vendor-hyp function IDs (chosen high to avoid the
 * pKVM-reserved range), invoked via HVC.  Mirror the definitions in
 * the KVM host patch (arch/arm64/kvm/hypercalls.c).
 */
#define ARM_SMCCC_KVM_FUNC_RR_REGISTER		0x100
#define ARM_SMCCC_KVM_FUNC_RR_DEREGISTER	0x101
#define ARM_SMCCC_VENDOR_HYP_KVM_RR_REGISTER_FUNC_ID			\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,	\
			   ARM_SMCCC_OWNER_VENDOR_HYP,			\
			   ARM_SMCCC_KVM_FUNC_RR_REGISTER)
#define ARM_SMCCC_VENDOR_HYP_KVM_RR_DEREGISTER_FUNC_ID			\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,	\
			   ARM_SMCCC_OWNER_VENDOR_HYP,			\
			   ARM_SMCCC_KVM_FUNC_RR_DEREGISTER)
#define RR_TTBR0_BADDR_MASK		GENMASK_ULL(47, 1)

/* ----------------------------------------------------------------
 * Internal data structures
 * ---------------------------------------------------------------- */

/*
 * Hash table of monitored processes, keyed by page-table base.
 * 6 bits => 64 buckets, more than enough for the expected
 * small number of monitored processes.
 */
#define MONITORED_HT_BITS	6

struct monitored_proc {
	struct hlist_node	node;
	pid_t			tgid;
	unsigned long		pgd_base;
};

static DEFINE_HASHTABLE(monitored_ht, MONITORED_HT_BITS);
static DEFINE_SPINLOCK(monitored_lock);

/* ----------------------------------------------------------------
 * Tracepoint references
 * ----------------------------------------------------------------
 * We look up tracepoints by name at init time rather than using
 * the DECLARE_TRACE / register_trace_* macros, which would
 * require including internal scheduler headers.  This approach
 * is the idiomatic way for out-of-tree modules.
 */
static struct tracepoint *tp_fork;
static struct tracepoint *tp_exec;
static struct tracepoint *tp_exit;

/* ----------------------------------------------------------------
 * Page-table base computation
 * ---------------------------------------------------------------- */

/*
 * Compute the page-table base that the KVM host will see for this mm
 * when its user code executes the entropy instruction.  The hash-table
 * key: the TTBR0_EL1 BADDR, i.e. the physical address of mm->pgd (the
 * ASID is not stored in mm->pgd; it is inserted into TTBR0[63:48] only
 * when the CPU loads it).  Masked to BADDR to match the host.
 */
static unsigned long compute_user_pgd_base(struct mm_struct *mm)
{
	unsigned long base = 0;

	base = virt_to_phys(mm->pgd) & RR_TTBR0_BADDR_MASK;

	return base;
}

/* ----------------------------------------------------------------
 * KVM hypercall wrappers
 * ---------------------------------------------------------------- */

static long hc_register_pgd_base(unsigned long base)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_RR_REGISTER_FUNC_ID,
			     base, &res);
	return (long)res.a0;
}

static long hc_deregister_pgd_base(unsigned long base)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_RR_DEREGISTER_FUNC_ID,
			     base, &res);
	return (long)res.a0;
}

/* ----------------------------------------------------------------
 * Monitored-set helpers
 * ---------------------------------------------------------------- */

/*
 * Look up a monitored_proc entry by tgid.
 * Caller must hold monitored_lock.
 */
static struct monitored_proc *find_by_tgid(pid_t tgid)
{
	struct monitored_proc *mp;
	int bkt;

	hash_for_each(monitored_ht, bkt, mp, node) {
		if (mp->tgid == tgid)
			return mp;
	}
	return NULL;
}

/*
 * Look up a monitored_proc entry by page-table base.
 * Caller must hold monitored_lock.
 */
static struct monitored_proc *find_by_pgd_base(unsigned long pgd_base)
{
	struct monitored_proc *mp;

	hash_for_each_possible(monitored_ht, mp, node, pgd_base) {
		if (mp->pgd_base == pgd_base)
			return mp;
	}
	return NULL;
}

/*
 * Registration permission follows the ptrace attach model, which is
 * coherent because rr does attach to the target.  Ideally we would call
 * the kernel's ptrace_may_access(), but it is not exported to modules,
 * so we reimplement the same tiers here, gated by our own scope
 * parameter that mirrors kernel.yama.ptrace_scope (the real yama sysctl
 * value is likewise unreadable from a module):
 *
 *   scope 0: any process with a matching real UID/GID;
 *   scope 1: only the caller's own descendants (the default, matching
 *            the Debian/Ubuntu yama default);
 *   scope 2: CAP_SYS_PTRACE only.
 *
 * A caller may always act on itself / its own thread group, and
 * CAP_SYS_PTRACE (root) bypasses the scope check entirely.
 */
static int rrmon_scope = 1;
module_param(rrmon_scope, int, 0644);
MODULE_PARM_DESC(rrmon_scope,
	"ptrace-style permission scope: 0=any same-UID process, "
	"1=descendants only (default), 2=CAP_SYS_PTRACE only. "
	"Mirrors kernel.yama.ptrace_scope.");

/*
 * Real-credential ownership check, equivalent to the base
 * __ptrace_may_access() test for PTRACE_MODE_ATTACH_REALCREDS: the
 * caller's real UID/GID must match all three of the target's UIDs/GIDs.
 * Caller must hold a reference on @task.
 */
static bool creds_allow(struct task_struct *task)
{
	const struct cred *caller = current_cred();
	const struct cred *target;
	bool ok;

	rcu_read_lock();
	target = __task_cred(task);
	ok = uid_eq(caller->uid, target->uid) &&
	     uid_eq(caller->uid, target->euid) &&
	     uid_eq(caller->uid, target->suid) &&
	     gid_eq(caller->gid, target->gid) &&
	     gid_eq(caller->gid, target->egid) &&
	     gid_eq(caller->gid, target->sgid);
	rcu_read_unlock();

	return ok;
}

/*
 * Is the current task an ancestor of @task (walking real_parent)?  This
 * is the scope-1 "descendants only" test, equivalent to yama's
 * task_is_descendant().
 */
static bool current_is_ancestor(struct task_struct *task)
{
	struct task_struct *walker;
	bool found = false;

	rcu_read_lock();
	for (walker = task; walker->pid > 0;
	     walker = rcu_dereference(walker->real_parent)) {
		struct task_struct *parent = rcu_dereference(walker->real_parent);

		if (!parent)
			break;
		if (same_thread_group(parent, current)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

/*
 * Check whether the calling process may register/deregister @task.
 * Returns 0 if permitted, negative errno otherwise.  The caller must
 * hold a reference on @task.
 */
static int check_perm(struct task_struct *task)
{
	/* A task may always act on itself / its own thread group. */
	if (same_thread_group(task, current))
		return 0;

	/* CAP_SYS_PTRACE bypasses the scope check (root: anyone). */
	if (capable(CAP_SYS_PTRACE))
		return 0;

	/* scope 2: nothing beyond CAP_SYS_PTRACE, already handled. */
	if (rrmon_scope >= 2)
		return -EPERM;

	/* Base ownership requirement for scopes 0 and 1. */
	if (!creds_allow(task))
		return -EPERM;

	/* scope 1: additionally require a descendant. */
	if (rrmon_scope == 1 && !current_is_ancestor(task))
		return -EPERM;

	return 0;
}

/*
 * Register a process for monitoring.  Resolves the tgid to a
 * page-table base and issues the KVM hypercall.
 *
 * Permission: the caller must have ptrace-attach permission
 * on the target process (same uid or CAP_SYS_PTRACE).
 *
 * Returns 0 on success, negative errno on failure.
 */
static int register_process(pid_t tgid)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct monitored_proc *mp;
	unsigned long pgd_base;
	long hc_ret;
	int ret = 0;

	rcu_read_lock();
	task = pid_task(find_vpid(tgid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);
	rcu_read_unlock();

	ret = check_perm(task);
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EINVAL;
	}

	pgd_base = compute_user_pgd_base(mm);
	mmput(mm);
	put_task_struct(task);

	mp = kmalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return -ENOMEM;

	mp->tgid = tgid;
	mp->pgd_base = pgd_base;

	spin_lock(&monitored_lock);
	if (find_by_tgid(tgid)) {
		spin_unlock(&monitored_lock);
		kfree(mp);
		return -EEXIST;
	}
	hash_add(monitored_ht, &mp->node, pgd_base);
	spin_unlock(&monitored_lock);

	hc_ret = hc_register_pgd_base(pgd_base);
	if (hc_ret < 0) {
		spin_lock(&monitored_lock);
		hash_del(&mp->node);
		spin_unlock(&monitored_lock);
		kfree(mp);
		return (int)hc_ret;
	}

	__module_get(THIS_MODULE);
	pr_info("rr_entropy_monitor: registered tgid %d "
		"pgd_base 0x%lx\n", tgid, pgd_base);
	return 0;
}

/*
 * Deregister a process by tgid.
 *
 * Permission: same ptrace-attach check as register_process().
 */
static int deregister_process(pid_t tgid)
{
	struct task_struct *task;
	struct monitored_proc *mp;
	unsigned long pgd_base;
	int ret;

	rcu_read_lock();
	task = pid_task(find_vpid(tgid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);
	rcu_read_unlock();

	ret = check_perm(task);
	put_task_struct(task);
	if (ret)
		return ret;

	spin_lock(&monitored_lock);
	mp = find_by_tgid(tgid);
	if (!mp) {
		spin_unlock(&monitored_lock);
		return -ESRCH;
	}
	pgd_base = mp->pgd_base;
	hash_del(&mp->node);
	spin_unlock(&monitored_lock);

	hc_deregister_pgd_base(pgd_base);
	module_put(THIS_MODULE);
	pr_info("rr_entropy_monitor: deregistered tgid %d "
		"pgd_base 0x%lx\n", tgid, pgd_base);
	kfree(mp);
	return 0;
}

/*
 * Deregister a process by page-table base (used from tracepoint
 * handlers where we already know the base).
 */
static void deregister_pgd_base(unsigned long pgd_base)
{
	struct monitored_proc *mp;

	spin_lock(&monitored_lock);
	mp = find_by_pgd_base(pgd_base);
	if (!mp) {
		spin_unlock(&monitored_lock);
		return;
	}
	pr_debug("rr_entropy_monitor: deregister pgd_base 0x%lx "
		 "(tgid %d)\n", pgd_base, mp->tgid);
	hash_del(&mp->node);
	spin_unlock(&monitored_lock);

	hc_deregister_pgd_base(pgd_base);
	module_put(THIS_MODULE);
	kfree(mp);
}

/*
 * Check whether a tgid is currently monitored.
 * Caller must hold monitored_lock.
 */
static bool is_monitored(pid_t tgid)
{
	return find_by_tgid(tgid) != NULL;
}

/* ----------------------------------------------------------------
 * Tracepoint callbacks
 * ---------------------------------------------------------------- */

/*
 * sched_process_fork handler.
 *
 * If the parent is monitored and the child has a new mm (i.e.,
 * not CLONE_VM), register the child's page-table base.  When CLONE_VM is
 * used (vfork, pthread_create), the child shares the parent's
 * mm and page-table base, so no new registration is needed.
 */
static void probe_sched_process_fork(void *data,
				     struct task_struct *parent,
				     struct task_struct *child)
{
	struct mm_struct *child_mm;
	struct monitored_proc *mp;
	unsigned long pgd_base;
	bool parent_monitored;

	spin_lock(&monitored_lock);
	parent_monitored = is_monitored(parent->tgid);
	spin_unlock(&monitored_lock);

	if (!parent_monitored)
		return;

	/* CLONE_VM: child shares parent's mm and page-table base. */
	if (child->mm == parent->mm)
		return;

	child_mm = get_task_mm(child);
	if (!child_mm)
		return;

	pgd_base = compute_user_pgd_base(child_mm);
	mmput(child_mm);

	mp = kmalloc(sizeof(*mp), GFP_ATOMIC);
	if (!mp) {
		pr_warn("rr_entropy_monitor: fork: alloc failed "
			"for child tgid %d\n", child->tgid);
		return;
	}

	mp->tgid = child->tgid;
	mp->pgd_base = pgd_base;

	spin_lock(&monitored_lock);
	hash_add(monitored_ht, &mp->node, pgd_base);
	spin_unlock(&monitored_lock);

	hc_register_pgd_base(pgd_base);
	__module_get(THIS_MODULE);
	pr_info("rr_entropy_monitor: fork: registered child "
		"tgid %d pgd_base 0x%lx\n", child->tgid, pgd_base);
}

/*
 * sched_process_exec handler.
 *
 * On execve, the process gets a new mm (and thus a new page-table base).
 * Deregister the old base and register the new one.
 */
static void probe_sched_process_exec(void *data,
				     struct task_struct *task,
				     pid_t old_pid,
				     struct linux_binprm *bprm)
{
	struct monitored_proc *mp;
	struct mm_struct *mm;
	unsigned long old_base, new_base;
	struct monitored_proc *new_mp;

	spin_lock(&monitored_lock);
	mp = find_by_tgid(task->tgid);
	if (!mp) {
		spin_unlock(&monitored_lock);
		return;
	}
	old_base = mp->pgd_base;
	hash_del(&mp->node);
	spin_unlock(&monitored_lock);

	hc_deregister_pgd_base(old_base);
	module_put(THIS_MODULE);
	kfree(mp);

	/* Register the new mm's page-table base. */
	mm = get_task_mm(task);
	if (!mm) {
		pr_warn("rr_entropy_monitor: exec: no mm for "
			"tgid %d after exec\n", task->tgid);
		return;
	}

	new_base = compute_user_pgd_base(mm);
	mmput(mm);

	new_mp = kmalloc(sizeof(*new_mp), GFP_ATOMIC);
	if (!new_mp) {
		pr_warn("rr_entropy_monitor: exec: alloc failed "
			"for tgid %d\n", task->tgid);
		return;
	}

	new_mp->tgid = task->tgid;
	new_mp->pgd_base = new_base;

	spin_lock(&monitored_lock);
	hash_add(monitored_ht, &new_mp->node, new_base);
	spin_unlock(&monitored_lock);

	hc_register_pgd_base(new_base);
	__module_get(THIS_MODULE);
	pr_info("rr_entropy_monitor: exec: tgid %d old pgd_base "
		"0x%lx -> new pgd_base 0x%lx\n",
		task->tgid, old_base, new_base);
}

/*
 * sched_process_exit handler.
 *
 * Deregister the page-table base only when the last thread in the group
 * exits, to avoid premature deregistration for multithreaded
 * processes.
 *
 * task->mm is already NULL here (exit_mm() ran before this
 * tracepoint fires), so we use task->signal->live instead.
 * exit_signals() decrements signal->live before exit_mm() runs,
 * so a value of 0 here means this is the last live thread.
 */
static void probe_sched_process_exit(void *data,
				     struct task_struct *task)
{
	struct monitored_proc *mp;

	spin_lock(&monitored_lock);
	mp = find_by_tgid(task->tgid);
	spin_unlock(&monitored_lock);

	if (!mp)
		return;

	if (atomic_read(&task->signal->live) != 0)
		return;

	deregister_pgd_base(mp->pgd_base);
	pr_info("rr_entropy_monitor: exit: deregistered "
		"tgid %d\n", task->tgid);
}

/* ----------------------------------------------------------------
 * Tracepoint lookup infrastructure
 * ---------------------------------------------------------------- */

struct tp_lookup {
	const char	*name;
	struct tracepoint **tp;
};

static struct tp_lookup tp_table[] = {
	{ "sched_process_fork", &tp_fork },
	{ "sched_process_exec", &tp_exec },
	{ "sched_process_exit", &tp_exit },
};

static void lookup_tracepoints(struct tracepoint *tp,
			       void *priv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tp_table); i++) {
		if (strcmp(tp->name, tp_table[i].name) == 0)
			*tp_table[i].tp = tp;
	}
}

/* ----------------------------------------------------------------
 * Control character device: /dev/rr-entropy-monitor
 *
 * Register/deregister a process (by thread-group id) for monitoring,
 * or query whether one is monitored.  Each ioctl takes a pointer to a
 * __s32 PID.  See rr_entropy_monitor.h for the ABI and the ptrace-based
 * permission model.
 * ---------------------------------------------------------------- */

static long rrmon_ioctl(struct file *filp, unsigned int cmd,
			unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	__s32 pid;
	bool monitored;

	switch (cmd) {
	case RRMON_IOC_REGISTER:
		if (copy_from_user(&pid, uarg, sizeof(pid)))
			return -EFAULT;
		if (pid <= 0)
			return -EINVAL;
		return register_process(pid);

	case RRMON_IOC_DEREGISTER:
		if (copy_from_user(&pid, uarg, sizeof(pid)))
			return -EFAULT;
		if (pid <= 0)
			return -EINVAL;
		return deregister_process(pid);

	case RRMON_IOC_IS_MONITORED:
		if (copy_from_user(&pid, uarg, sizeof(pid)))
			return -EFAULT;
		if (pid <= 0)
			return -EINVAL;
		spin_lock(&monitored_lock);
		monitored = is_monitored(pid);
		spin_unlock(&monitored_lock);
		return monitored ? 1 : 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations rrmon_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= rrmon_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

static struct miscdevice rrmon_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= RRMON_DEVICE_NAME,
	.fops	= &rrmon_fops,
	.mode	= 0666,
};

/* ----------------------------------------------------------------
 * Module init / exit
 * ---------------------------------------------------------------- */

static bool running_under_kvm(void)
{
	/*
	 * Probe the SMCCC vendor-hyp call UID.  A vendor hypervisor (KVM)
	 * answers with its UID; bare metal or a non-vendor hypervisor returns
	 * NOT_SUPPORTED.  We avoid comparing the exact KVM UID because its
	 * representation changed across kernels (four REG_n words vs a single
	 * uuid_t); presence of a vendor-hyp responder is sufficient here, and
	 * the registration HVC is a harmless no-op otherwise.
	 */
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, &res);

	return (long)res.a0 != SMCCC_RET_NOT_SUPPORTED;
}

static int __init rrmon_init(void)
{
	int ret;

	if (!running_under_kvm()) {
		pr_err("rr_entropy_monitor: not running under "
		       "KVM; module requires a KVM hypervisor "
		       "host\n");
		return -ENODEV;
	}

	pr_info("rr_entropy_monitor: KVM hypervisor detected\n");

	/* Look up scheduler tracepoints by name. */
	for_each_kernel_tracepoint(lookup_tracepoints, NULL);

	if (!tp_fork || !tp_exec || !tp_exit) {
		pr_err("rr_entropy_monitor: failed to find "
		       "required scheduler tracepoints\n");
		return -ENOENT;
	}

	/* Register tracepoint probes. */
	ret = tracepoint_probe_register(tp_fork,
					probe_sched_process_fork,
					NULL);
	if (ret) {
		pr_err("rr_entropy_monitor: failed to register "
		       "fork probe: %d\n", ret);
		return ret;
	}

	ret = tracepoint_probe_register(tp_exec,
					probe_sched_process_exec,
					NULL);
	if (ret) {
		pr_err("rr_entropy_monitor: failed to register "
		       "exec probe: %d\n", ret);
		goto err_unreg_fork;
	}

	ret = tracepoint_probe_register(tp_exit,
					probe_sched_process_exit,
					NULL);
	if (ret) {
		pr_err("rr_entropy_monitor: failed to register "
		       "exit probe: %d\n", ret);
		goto err_unreg_exec;
	}

	/* Create the control character device. */
	ret = misc_register(&rrmon_misc);
	if (ret) {
		pr_err("rr_entropy_monitor: failed to register misc "
		       "device: %d\n", ret);
		goto err_unreg_exit;
	}

	pr_info("rr_entropy_monitor: loaded, control device at "
		"%s\n", RRMON_DEVICE_PATH);
	return 0;

err_unreg_exit:
	tracepoint_probe_unregister(tp_exit,
				    probe_sched_process_exit,
				    NULL);
err_unreg_exec:
	tracepoint_probe_unregister(tp_exec,
				    probe_sched_process_exec,
				    NULL);
err_unreg_fork:
	tracepoint_probe_unregister(tp_fork,
				    probe_sched_process_fork,
				    NULL);
	return ret;
}

static void __exit rrmon_exit(void)
{
	struct monitored_proc *mp;
	struct hlist_node *tmp;
	int bkt;

	misc_deregister(&rrmon_misc);

	tracepoint_probe_unregister(tp_exit,
				    probe_sched_process_exit,
				    NULL);
	tracepoint_probe_unregister(tp_exec,
				    probe_sched_process_exec,
				    NULL);
	tracepoint_probe_unregister(tp_fork,
				    probe_sched_process_fork,
				    NULL);

	/*
	 * Ensure all tracepoint callbacks have completed on all
	 * CPUs before we free the monitored set entries.
	 */
	tracepoint_synchronize_unregister();

	/* Deregister all remaining monitored page-table bases from KVM. */
	spin_lock(&monitored_lock);
	hash_for_each_safe(monitored_ht, bkt, tmp, mp, node) {
		hc_deregister_pgd_base(mp->pgd_base);
		hash_del(&mp->node);
		kfree(mp);
	}
	spin_unlock(&monitored_lock);

	pr_info("rr_entropy_monitor: unloaded\n");
}

module_init(rrmon_init);
module_exit(rrmon_exit);
