// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/filter.h>
#include <linux/ctype.h>
#include <linux/jiffies.h>
#include <linux/pid_namespace.h>
#include <linux/poison.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/btf_ids.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/kasan.h>

#include "../../lib/kstrtox.h"

/* If kernel subsystem is allowing eBPF programs to call this function,
 * inside its own verifier_ops->get_func_proto() callback it should return
 * bpf_map_lookup_elem_proto, so that verifier can properly check the arguments
 *
 * Different map implementations will rely on rcu in map methods
 * lookup/update/delete, therefore eBPF programs must run under rcu lock
 * if program is allowed to access maps, so check rcu_read_lock_held() or
 * rcu_read_lock_trace_held() in all three functions.
 */
BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
	   void *, value, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return map->ops->map_update_elem(map, key, value, flags);
}

const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_delete_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return map->ops->map_delete_elem(map, key);
}

const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_3(bpf_map_push_elem, struct bpf_map *, map, void *, value, u64, flags)
{
	return map->ops->map_push_elem(map, value, flags);
}

const struct bpf_func_proto bpf_map_push_elem_proto = {
	.func		= bpf_map_push_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_map_pop_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_pop_elem(map, value);
}

const struct bpf_func_proto bpf_map_pop_elem_proto = {
	.func		= bpf_map_pop_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

BPF_CALL_2(bpf_map_peek_elem, struct bpf_map *, map, void *, value)
{
	return map->ops->map_peek_elem(map, value);
}

const struct bpf_func_proto bpf_map_peek_elem_proto = {
	.func		= bpf_map_peek_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

BPF_CALL_3(bpf_map_lookup_percpu_elem, struct bpf_map *, map, void *, key, u32, cpu)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return (unsigned long) map->ops->map_lookup_percpu_elem(map, key, cpu);
}

const struct bpf_func_proto bpf_map_lookup_percpu_elem_proto = {
	.func		= bpf_map_lookup_percpu_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_user_rnd_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_smp_processor_id)
{
	return smp_processor_id();
}

const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.allow_fastcall	= true,
};

BPF_CALL_0(bpf_get_numa_node_id)
{
	return numa_node_id();
}

const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	.func		= bpf_get_numa_node_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_ns)
{
	/* NMI safe access to clock monotonic */
	return ktime_get_mono_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_boot_ns)
{
	/* NMI safe access to clock boottime */
	return ktime_get_boot_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.func		= bpf_ktime_get_boot_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_coarse_ns)
{
	return ktime_get_coarse_ns();
}

const struct bpf_func_proto bpf_ktime_get_coarse_ns_proto = {
	.func		= bpf_ktime_get_coarse_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_ktime_get_tai_ns)
{
	/* NMI safe access to clock tai */
	return ktime_get_tai_fast_ns();
}

const struct bpf_func_proto bpf_ktime_get_tai_ns_proto = {
	.func		= bpf_ktime_get_tai_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_pid_tgid)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		return -EINVAL;

	return (u64) task->tgid << 32 | task->pid;
}

const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_0(bpf_get_current_uid_gid)
{
	struct task_struct *task = current;
	kuid_t uid;
	kgid_t gid;

	if (unlikely(!task))
		return -EINVAL;

	current_uid_gid(&uid, &gid);
	return (u64) from_kgid(&init_user_ns, gid) << 32 |
		     from_kuid(&init_user_ns, uid);
}

const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_2(bpf_get_current_comm, char *, buf, u32, size)
{
	struct task_struct *task = current;

	if (unlikely(!task))
		goto err_clear;

	/* Verifier guarantees that size > 0 */
	strscpy_pad(buf, task->comm, size);
	return 0;
err_clear:
	memset(buf, 0, size);
	return -EINVAL;
}

const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

#if defined(CONFIG_QUEUED_SPINLOCKS) || defined(CONFIG_BPF_ARCH_SPINLOCK)

static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;
	union {
		__u32 val;
		arch_spinlock_t lock;
	} u = { .lock = __ARCH_SPIN_LOCK_UNLOCKED };

	compiletime_assert(u.val == 0, "__ARCH_SPIN_LOCK_UNLOCKED not 0");
	BUILD_BUG_ON(sizeof(*l) != sizeof(__u32));
	BUILD_BUG_ON(sizeof(*lock) != sizeof(__u32));
	preempt_disable();
	arch_spin_lock(l);
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	arch_spinlock_t *l = (void *)lock;

	arch_spin_unlock(l);
	preempt_enable();
}

#else

static inline void __bpf_spin_lock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;

	BUILD_BUG_ON(sizeof(*l) != sizeof(*lock));
	do {
		atomic_cond_read_relaxed(l, !VAL);
	} while (atomic_xchg(l, 1));
}

static inline void __bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	atomic_t *l = (void *)lock;

	atomic_set_release(l, 0);
}

#endif

static DEFINE_PER_CPU(unsigned long, irqsave_flags);

static inline void __bpf_spin_lock_irqsave(struct bpf_spin_lock *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	__bpf_spin_lock(lock);
	__this_cpu_write(irqsave_flags, flags);
}

NOTRACE_BPF_CALL_1(bpf_spin_lock, struct bpf_spin_lock *, lock)
{
	__bpf_spin_lock_irqsave(lock);
	return 0;
}

const struct bpf_func_proto bpf_spin_lock_proto = {
	.func		= bpf_spin_lock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
	.arg1_btf_id    = BPF_PTR_POISON,
};

static inline void __bpf_spin_unlock_irqrestore(struct bpf_spin_lock *lock)
{
	unsigned long flags;

	flags = __this_cpu_read(irqsave_flags);
	__bpf_spin_unlock(lock);
	local_irq_restore(flags);
}

NOTRACE_BPF_CALL_1(bpf_spin_unlock, struct bpf_spin_lock *, lock)
{
	__bpf_spin_unlock_irqrestore(lock);
	return 0;
}

const struct bpf_func_proto bpf_spin_unlock_proto = {
	.func		= bpf_spin_unlock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
	.arg1_btf_id    = BPF_PTR_POISON,
};

void copy_map_value_locked(struct bpf_map *map, void *dst, void *src,
			   bool lock_src)
{
	struct bpf_spin_lock *lock;

	if (lock_src)
		lock = src + map->record->spin_lock_off;
	else
		lock = dst + map->record->spin_lock_off;
	preempt_disable();
	__bpf_spin_lock_irqsave(lock);
	copy_map_value(map, dst, src);
	__bpf_spin_unlock_irqrestore(lock);
	preempt_enable();
}

BPF_CALL_0(bpf_jiffies64)
{
	return get_jiffies_64();
}

const struct bpf_func_proto bpf_jiffies64_proto = {
	.func		= bpf_jiffies64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

#ifdef CONFIG_CGROUPS
BPF_CALL_0(bpf_get_current_cgroup_id)
{
	struct cgroup *cgrp;
	u64 cgrp_id;

	rcu_read_lock();
	cgrp = task_dfl_cgroup(current);
	cgrp_id = cgroup_id(cgrp);
	rcu_read_unlock();

	return cgrp_id;
}

const struct bpf_func_proto bpf_get_current_cgroup_id_proto = {
	.func		= bpf_get_current_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_1(bpf_get_current_ancestor_cgroup_id, int, ancestor_level)
{
	struct cgroup *cgrp;
	struct cgroup *ancestor;
	u64 cgrp_id;

	rcu_read_lock();
	cgrp = task_dfl_cgroup(current);
	ancestor = cgroup_ancestor(cgrp, ancestor_level);
	cgrp_id = ancestor ? cgroup_id(ancestor) : 0;
	rcu_read_unlock();

	return cgrp_id;
}

const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto = {
	.func		= bpf_get_current_ancestor_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};
#endif /* CONFIG_CGROUPS */

#define BPF_STRTOX_BASE_MASK 0x1F

static int __bpf_strtoull(const char *buf, size_t buf_len, u64 flags,
			  unsigned long long *res, bool *is_negative)
{
	unsigned int base = flags & BPF_STRTOX_BASE_MASK;
	const char *cur_buf = buf;
	size_t cur_len = buf_len;
	unsigned int consumed;
	size_t val_len;
	char str[64];

	if (!buf || !buf_len || !res || !is_negative)
		return -EINVAL;

	if (base != 0 && base != 8 && base != 10 && base != 16)
		return -EINVAL;

	if (flags & ~BPF_STRTOX_BASE_MASK)
		return -EINVAL;

	while (cur_buf < buf + buf_len && isspace(*cur_buf))
		++cur_buf;

	*is_negative = (cur_buf < buf + buf_len && *cur_buf == '-');
	if (*is_negative)
		++cur_buf;

	consumed = cur_buf - buf;
	cur_len -= consumed;
	if (!cur_len)
		return -EINVAL;

	cur_len = min(cur_len, sizeof(str) - 1);
	memcpy(str, cur_buf, cur_len);
	str[cur_len] = '\0';
	cur_buf = str;

	cur_buf = _parse_integer_fixup_radix(cur_buf, &base);
	val_len = _parse_integer(cur_buf, base, res);

	if (val_len & KSTRTOX_OVERFLOW)
		return -ERANGE;

	if (val_len == 0)
		return -EINVAL;

	cur_buf += val_len;
	consumed += cur_buf - str;

	return consumed;
}

static int __bpf_strtoll(const char *buf, size_t buf_len, u64 flags,
			 long long *res)
{
	unsigned long long _res;
	bool is_negative;
	int err;

	err = __bpf_strtoull(buf, buf_len, flags, &_res, &is_negative);
	if (err < 0)
		return err;
	if (is_negative) {
		if ((long long)-_res > 0)
			return -ERANGE;
		*res = -_res;
	} else {
		if ((long long)_res < 0)
			return -ERANGE;
		*res = _res;
	}
	return err;
}

BPF_CALL_4(bpf_strtol, const char *, buf, size_t, buf_len, u64, flags,
	   s64 *, res)
{
	long long _res;
	int err;

	*res = 0;
	err = __bpf_strtoll(buf, buf_len, flags, &_res);
	if (err < 0)
		return err;
	*res = _res;
	return err;
}

const struct bpf_func_proto bpf_strtol_proto = {
	.func		= bpf_strtol,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(s64),
};

BPF_CALL_4(bpf_strtoul, const char *, buf, size_t, buf_len, u64, flags,
	   u64 *, res)
{
	unsigned long long _res;
	bool is_negative;
	int err;

	*res = 0;
	err = __bpf_strtoull(buf, buf_len, flags, &_res, &is_negative);
	if (err < 0)
		return err;
	if (is_negative)
		return -EINVAL;
	*res = _res;
	return err;
}

const struct bpf_func_proto bpf_strtoul_proto = {
	.func		= bpf_strtoul,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(u64),
};

BPF_CALL_3(bpf_strncmp, const char *, s1, u32, s1_sz, const char *, s2)
{
	return strncmp(s1, s2, s1_sz);
}

static const struct bpf_func_proto bpf_strncmp_proto = {
	.func		= bpf_strncmp,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
};

BPF_CALL_4(bpf_get_ns_current_pid_tgid, u64, dev, u64, ino,
	   struct bpf_pidns_info *, nsdata, u32, size)
{
	struct task_struct *task = current;
	struct pid_namespace *pidns;
	int err = -EINVAL;

	if (unlikely(size != sizeof(struct bpf_pidns_info)))
		goto clear;

	if (unlikely((u64)(dev_t)dev != dev))
		goto clear;

	if (unlikely(!task))
		goto clear;

	pidns = task_active_pid_ns(task);
	if (unlikely(!pidns)) {
		err = -ENOENT;
		goto clear;
	}

	if (!ns_match(&pidns->ns, (dev_t)dev, ino))
		goto clear;

	nsdata->pid = task_pid_nr_ns(task, pidns);
	nsdata->tgid = task_tgid_nr_ns(task, pidns);
	return 0;
clear:
	memset((void *)nsdata, 0, (size_t) size);
	return err;
}

const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto = {
	.func		= bpf_get_ns_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};

static const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
	.func		= bpf_get_raw_cpu_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_5(bpf_event_output_data, void *, ctx, struct bpf_map *, map,
	   u64, flags, void *, data, u64, size)
{
	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return bpf_event_output(map, flags, data, size, NULL, 0, NULL);
}

const struct bpf_func_proto bpf_event_output_data_proto =  {
	.func		= bpf_event_output_data,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_CONST_MAP_PTR,
	.arg3_type      = ARG_ANYTHING,
	.arg4_type      = ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};

BPF_CALL_3(bpf_copy_from_user, void *, dst, u32, size,
	   const void __user *, user_ptr)
{
	int ret = copy_from_user(dst, user_ptr, size);

	if (unlikely(ret)) {
		memset(dst, 0, size);
		ret = -EFAULT;
	}

	return ret;
}

const struct bpf_func_proto bpf_copy_from_user_proto = {
	.func		= bpf_copy_from_user,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_copy_from_user_task, void *, dst, u32, size,
	   const void __user *, user_ptr, struct task_struct *, tsk, u64, flags)
{
	int ret;

	/* flags is not used yet */
	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(!size))
		return 0;

	ret = access_process_vm(tsk, (unsigned long)user_ptr, dst, size, 0);
	if (ret == size)
		return 0;

	memset(dst, 0, size);
	/* Return -EFAULT for partial read */
	return ret < 0 ? ret : -EFAULT;
}

const struct bpf_func_proto bpf_copy_from_user_task_proto = {
	.func		= bpf_copy_from_user_task,
	.gpl_only	= true,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_BTF_ID,
	.arg4_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.arg5_type	= ARG_ANYTHING
};

BPF_CALL_2(bpf_per_cpu_ptr, const void *, ptr, u32, cpu)
{
	if (cpu >= nr_cpu_ids)
		return (unsigned long)NULL;

	return (unsigned long)per_cpu_ptr((const void __percpu *)(const uintptr_t)ptr, cpu);
}

const struct bpf_func_proto bpf_per_cpu_ptr_proto = {
	.func		= bpf_per_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_this_cpu_ptr, const void *, percpu_ptr)
{
	return (unsigned long)this_cpu_ptr((const void __percpu *)(const uintptr_t)percpu_ptr);
}

const struct bpf_func_proto bpf_this_cpu_ptr_proto = {
	.func		= bpf_this_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
};

static int bpf_trace_copy_string(char *buf, void *unsafe_ptr, char fmt_ptype,
		size_t bufsz)
{
	void __user *user_ptr = (__force void __user *)unsafe_ptr;

	buf[0] = 0;

	switch (fmt_ptype) {
	case 's':
#ifdef CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
		if ((unsigned long)unsafe_ptr < TASK_SIZE)
			return strncpy_from_user_nofault(buf, user_ptr, bufsz);
		fallthrough;
#endif
	case 'k':
		return strncpy_from_kernel_nofault(buf, unsafe_ptr, bufsz);
	case 'u':
		return strncpy_from_user_nofault(buf, user_ptr, bufsz);
	}

	return -EINVAL;
}

/* Per-cpu temp buffers used by printf-like helpers to store the bprintf binary
 * arguments representation.
 */
#define MAX_BPRINTF_BIN_ARGS	512

/* Support executing three nested bprintf helper calls on a given CPU */
#define MAX_BPRINTF_NEST_LEVEL	3
struct bpf_bprintf_buffers {
	char bin_args[MAX_BPRINTF_BIN_ARGS];
	char buf[MAX_BPRINTF_BUF];
};

static DEFINE_PER_CPU(struct bpf_bprintf_buffers[MAX_BPRINTF_NEST_LEVEL], bpf_bprintf_bufs);
static DEFINE_PER_CPU(int, bpf_bprintf_nest_level);

static int try_get_buffers(struct bpf_bprintf_buffers **bufs)
{
	int nest_level;

	preempt_disable();
	nest_level = this_cpu_inc_return(bpf_bprintf_nest_level);
	if (WARN_ON_ONCE(nest_level > MAX_BPRINTF_NEST_LEVEL)) {
		this_cpu_dec(bpf_bprintf_nest_level);
		preempt_enable();
		return -EBUSY;
	}
	*bufs = this_cpu_ptr(&bpf_bprintf_bufs[nest_level - 1]);

	return 0;
}

void bpf_bprintf_cleanup(struct bpf_bprintf_data *data)
{
	if (!data->bin_args && !data->buf)
		return;
	if (WARN_ON_ONCE(this_cpu_read(bpf_bprintf_nest_level) == 0))
		return;
	this_cpu_dec(bpf_bprintf_nest_level);
	preempt_enable();
}

/*
 * bpf_bprintf_prepare - Generic pass on format strings for bprintf-like helpers
 *
 * Returns a negative value if fmt is an invalid format string or 0 otherwise.
 *
 * This can be used in two ways:
 * - Format string verification only: when data->get_bin_args is false
 * - Arguments preparation: in addition to the above verification, it writes in
 *   data->bin_args a binary representation of arguments usable by bstr_printf
 *   where pointers from BPF have been sanitized.
 *
 * In argument preparation mode, if 0 is returned, safe temporary buffers are
 * allocated and bpf_bprintf_cleanup should be called to free them after use.
 */
int bpf_bprintf_prepare(char *fmt, u32 fmt_size, const u64 *raw_args,
			u32 num_args, struct bpf_bprintf_data *data)
{
	bool get_buffers = (data->get_bin_args && num_args) || data->get_buf;
	char *unsafe_ptr = NULL, *tmp_buf = NULL, *tmp_buf_end, *fmt_end;
	struct bpf_bprintf_buffers *buffers = NULL;
	size_t sizeof_cur_arg, sizeof_cur_ip;
	int err, i, num_spec = 0;
	u64 cur_arg;
	char fmt_ptype, cur_ip[16], ip_spec[] = "%pXX";

	fmt_end = strnchr(fmt, fmt_size, 0);
	if (!fmt_end)
		return -EINVAL;
	fmt_size = fmt_end - fmt;

	if (get_buffers && try_get_buffers(&buffers))
		return -EBUSY;

	if (data->get_bin_args) {
		if (num_args)
			tmp_buf = buffers->bin_args;
		tmp_buf_end = tmp_buf + MAX_BPRINTF_BIN_ARGS;
		data->bin_args = (u32 *)tmp_buf;
	}

	if (data->get_buf)
		data->buf = buffers->buf;

	for (i = 0; i < fmt_size; i++) {
		if ((!isprint(fmt[i]) && !isspace(fmt[i])) || !isascii(fmt[i])) {
			err = -EINVAL;
			goto out;
		}

		if (fmt[i] != '%')
			continue;

		if (fmt[i + 1] == '%') {
			i++;
			continue;
		}

		if (num_spec >= num_args) {
			err = -EINVAL;
			goto out;
		}

		/* The string is zero-terminated so if fmt[i] != 0, we can
		 * always access fmt[i + 1], in the worst case it will be a 0
		 */
		i++;

		/* skip optional "[0 +-][num]" width formatting field */
		while (fmt[i] == '0' || fmt[i] == '+'  || fmt[i] == '-' ||
		       fmt[i] == ' ')
			i++;
		if (fmt[i] >= '1' && fmt[i] <= '9') {
			i++;
			while (fmt[i] >= '0' && fmt[i] <= '9')
				i++;
		}

		if (fmt[i] == 'p') {
			sizeof_cur_arg = sizeof(long);

			if (fmt[i + 1] == 0 || isspace(fmt[i + 1]) ||
			    ispunct(fmt[i + 1])) {
				if (tmp_buf)
					cur_arg = raw_args[num_spec];
				goto nocopy_fmt;
			}

			if ((fmt[i + 1] == 'k' || fmt[i + 1] == 'u') &&
			    fmt[i + 2] == 's') {
				fmt_ptype = fmt[i + 1];
				i += 2;
				goto fmt_str;
			}

			if (fmt[i + 1] == 'K' ||
			    fmt[i + 1] == 'x' || fmt[i + 1] == 's' ||
			    fmt[i + 1] == 'S') {
				if (tmp_buf)
					cur_arg = raw_args[num_spec];
				i++;
				goto nocopy_fmt;
			}

			if (fmt[i + 1] == 'B') {
				if (tmp_buf)  {
					err = snprintf(tmp_buf,
						       (tmp_buf_end - tmp_buf),
						       "%pB",
						       (void *)(long)raw_args[num_spec]);
					tmp_buf += (err + 1);
				}

				i++;
				num_spec++;
				continue;
			}

			/* only support "%pI4", "%pi4", "%pI6" and "%pi6". */
			if ((fmt[i + 1] != 'i' && fmt[i + 1] != 'I') ||
			    (fmt[i + 2] != '4' && fmt[i + 2] != '6')) {
				err = -EINVAL;
				goto out;
			}

			i += 2;
			if (!tmp_buf)
				goto nocopy_fmt;

			sizeof_cur_ip = (fmt[i] == '4') ? 4 : 16;
			if (tmp_buf_end - tmp_buf < sizeof_cur_ip) {
				err = -ENOSPC;
				goto out;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = copy_from_kernel_nofault(cur_ip, unsafe_ptr,
						       sizeof_cur_ip);
			if (err < 0)
				memset(cur_ip, 0, sizeof_cur_ip);

			/* hack: bstr_printf expects IP addresses to be
			 * pre-formatted as strings, ironically, the easiest way
			 * to do that is to call snprintf.
			 */
			ip_spec[2] = fmt[i - 1];
			ip_spec[3] = fmt[i];
			err = snprintf(tmp_buf, tmp_buf_end - tmp_buf,
				       ip_spec, &cur_ip);

			tmp_buf += err + 1;
			num_spec++;

			continue;
		} else if (fmt[i] == 's') {
			fmt_ptype = fmt[i];
fmt_str:
			if (fmt[i + 1] != 0 &&
			    !isspace(fmt[i + 1]) &&
			    !ispunct(fmt[i + 1])) {
				err = -EINVAL;
				goto out;
			}

			if (!tmp_buf)
				goto nocopy_fmt;

			if (tmp_buf_end == tmp_buf) {
				err = -ENOSPC;
				goto out;
			}

			unsafe_ptr = (char *)(long)raw_args[num_spec];
			err = bpf_trace_copy_string(tmp_buf, unsafe_ptr,
						    fmt_ptype,
						    tmp_buf_end - tmp_buf);
			if (err < 0) {
				tmp_buf[0] = '\0';
				err = 1;
			}

			tmp_buf += err;
			num_spec++;

			continue;
		} else if (fmt[i] == 'c') {
			if (!tmp_buf)
				goto nocopy_fmt;

			if (tmp_buf_end == tmp_buf) {
				err = -ENOSPC;
				goto out;
			}

			*tmp_buf = raw_args[num_spec];
			tmp_buf++;
			num_spec++;

			continue;
		}

		sizeof_cur_arg = sizeof(int);

		if (fmt[i] == 'l') {
			sizeof_cur_arg = sizeof(long);
			i++;
		}
		if (fmt[i] == 'l') {
			sizeof_cur_arg = sizeof(long long);
			i++;
		}

		if (fmt[i] != 'i' && fmt[i] != 'd' && fmt[i] != 'u' &&
		    fmt[i] != 'x' && fmt[i] != 'X') {
			err = -EINVAL;
			goto out;
		}

		if (tmp_buf)
			cur_arg = raw_args[num_spec];
nocopy_fmt:
		if (tmp_buf) {
			tmp_buf = PTR_ALIGN(tmp_buf, sizeof(u32));
			if (tmp_buf_end - tmp_buf < sizeof_cur_arg) {
				err = -ENOSPC;
				goto out;
			}

			if (sizeof_cur_arg == 8) {
				*(u32 *)tmp_buf = *(u32 *)&cur_arg;
				*(u32 *)(tmp_buf + 4) = *((u32 *)&cur_arg + 1);
			} else {
				*(u32 *)tmp_buf = (u32)(long)cur_arg;
			}
			tmp_buf += sizeof_cur_arg;
		}
		num_spec++;
	}

	err = 0;
out:
	if (err)
		bpf_bprintf_cleanup(data);
	return err;
}

BPF_CALL_5(bpf_snprintf, char *, str, u32, str_size, char *, fmt,
	   const void *, args, u32, data_len)
{
	struct bpf_bprintf_data data = {
		.get_bin_args	= true,
	};
	int err, num_args;

	if (data_len % 8 || data_len > MAX_BPRINTF_VARARGS * 8 ||
	    (data_len && !args))
		return -EINVAL;
	num_args = data_len / 8;

	/* ARG_PTR_TO_CONST_STR guarantees that fmt is zero-terminated so we
	 * can safely give an unbounded size.
	 */
	err = bpf_bprintf_prepare(fmt, UINT_MAX, args, num_args, &data);
	if (err < 0)
		return err;

	err = bstr_printf(str, str_size, fmt, data.bin_args);

	bpf_bprintf_cleanup(&data);

	return err + 1;
}

const struct bpf_func_proto bpf_snprintf_proto = {
	.func		= bpf_snprintf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
	.arg4_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

struct bpf_async_cb {
	struct bpf_map *map;
	struct bpf_prog *prog;
	void __rcu *callback_fn;
	void *value;
	union {
		struct rcu_head rcu;
		struct work_struct delete_work;
	};
	u64 flags;
};

/* BPF map elements can contain 'struct bpf_timer'.
 * Such map owns all of its BPF timers.
 * 'struct bpf_timer' is allocated as part of map element allocation
 * and it's zero initialized.
 * That space is used to keep 'struct bpf_async_kern'.
 * bpf_timer_init() allocates 'struct bpf_hrtimer', inits hrtimer, and
 * remembers 'struct bpf_map *' pointer it's part of.
 * bpf_timer_set_callback() increments prog refcnt and assign bpf callback_fn.
 * bpf_timer_start() arms the timer.
 * If user space reference to a map goes to zero at this point
 * ops->map_release_uref callback is responsible for cancelling the timers,
 * freeing their memory, and decrementing prog's refcnts.
 * bpf_timer_cancel() cancels the timer and decrements prog's refcnt.
 * Inner maps can contain bpf timers as well. ops->map_release_uref is
 * freeing the timers when inner map is replaced or deleted by user space.
 */
struct bpf_hrtimer {
	struct bpf_async_cb cb;
	struct hrtimer timer;
	atomic_t cancelling;
};

struct bpf_work {
	struct bpf_async_cb cb;
	struct work_struct work;
	struct work_struct delete_work;
};

/* the actual struct hidden inside uapi struct bpf_timer and bpf_wq */
struct bpf_async_kern {
	union {
		struct bpf_async_cb *cb;
		struct bpf_hrtimer *timer;
		struct bpf_work *work;
	};
	/* bpf_spin_lock is used here instead of spinlock_t to make
	 * sure that it always fits into space reserved by struct bpf_timer
	 * regardless of LOCKDEP and spinlock debug flags.
	 */
	struct bpf_spin_lock lock;
} __attribute__((aligned(8)));

enum bpf_async_type {
	BPF_ASYNC_TYPE_TIMER = 0,
	BPF_ASYNC_TYPE_WQ,
};

static DEFINE_PER_CPU(struct bpf_hrtimer *, hrtimer_running);

static enum hrtimer_restart bpf_timer_cb(struct hrtimer *hrtimer)
{
	struct bpf_hrtimer *t = container_of(hrtimer, struct bpf_hrtimer, timer);
	struct bpf_map *map = t->cb.map;
	void *value = t->cb.value;
	bpf_callback_t callback_fn;
	void *key;
	u32 idx;

	BTF_TYPE_EMIT(struct bpf_timer);
	callback_fn = rcu_dereference_check(t->cb.callback_fn, rcu_read_lock_bh_held());
	if (!callback_fn)
		goto out;

	/* bpf_timer_cb() runs in hrtimer_run_softirq. It doesn't migrate and
	 * cannot be preempted by another bpf_timer_cb() on the same cpu.
	 * Remember the timer this callback is servicing to prevent
	 * deadlock if callback_fn() calls bpf_timer_cancel() or
	 * bpf_map_delete_elem() on the same timer.
	 */
	this_cpu_write(hrtimer_running, t);
	if (map->map_type == BPF_MAP_TYPE_ARRAY) {
		struct bpf_array *array = container_of(map, struct bpf_array, map);

		/* compute the key */
		idx = ((char *)value - array->value) / array->elem_size;
		key = &idx;
	} else { /* hash or lru */
		key = value - round_up(map->key_size, 8);
	}

	callback_fn((u64)(long)map, (u64)(long)key, (u64)(long)value, 0, 0);
	/* The verifier checked that return value is zero. */

	this_cpu_write(hrtimer_running, NULL);
out:
	return HRTIMER_NORESTART;
}

static void bpf_wq_work(struct work_struct *work)
{
	struct bpf_work *w = container_of(work, struct bpf_work, work);
	struct bpf_async_cb *cb = &w->cb;
	struct bpf_map *map = cb->map;
	bpf_callback_t callback_fn;
	void *value = cb->value;
	void *key;
	u32 idx;

	BTF_TYPE_EMIT(struct bpf_wq);

	callback_fn = READ_ONCE(cb->callback_fn);
	if (!callback_fn)
		return;

	if (map->map_type == BPF_MAP_TYPE_ARRAY) {
		struct bpf_array *array = container_of(map, struct bpf_array, map);

		/* compute the key */
		idx = ((char *)value - array->value) / array->elem_size;
		key = &idx;
	} else { /* hash or lru */
		key = value - round_up(map->key_size, 8);
	}

        rcu_read_lock_trace();
        migrate_disable();

	callback_fn((u64)(long)map, (u64)(long)key, (u64)(long)value, 0, 0);

	migrate_enable();
	rcu_read_unlock_trace();
}

static void bpf_wq_delete_work(struct work_struct *work)
{
	struct bpf_work *w = container_of(work, struct bpf_work, delete_work);

	cancel_work_sync(&w->work);

	kfree_rcu(w, cb.rcu);
}

static void bpf_timer_delete_work(struct work_struct *work)
{
	struct bpf_hrtimer *t = container_of(work, struct bpf_hrtimer, cb.delete_work);

	/* Cancel the timer and wait for callback to complete if it was running.
	 * If hrtimer_cancel() can be safely called it's safe to call
	 * kfree_rcu(t) right after for both preallocated and non-preallocated
	 * maps.  The async->cb = NULL was already done and no code path can see
	 * address 't' anymore. Timer if armed for existing bpf_hrtimer before
	 * bpf_timer_cancel_and_free will have been cancelled.
	 */
	hrtimer_cancel(&t->timer);
	kfree_rcu(t, cb.rcu);
}

static int __bpf_async_init(struct bpf_async_kern *async, struct bpf_map *map, u64 flags,
			    enum bpf_async_type type)
{
	struct bpf_async_cb *cb;
	struct bpf_hrtimer *t;
	struct bpf_work *w;
	clockid_t clockid;
	size_t size;
	int ret = 0;

	if (in_nmi())
		return -EOPNOTSUPP;

	switch (type) {
	case BPF_ASYNC_TYPE_TIMER:
		size = sizeof(struct bpf_hrtimer);
		break;
	case BPF_ASYNC_TYPE_WQ:
		size = sizeof(struct bpf_work);
		break;
	default:
		return -EINVAL;
	}

	__bpf_spin_lock_irqsave(&async->lock);
	t = async->timer;
	if (t) {
		ret = -EBUSY;
		goto out;
	}

	/* Allocate via bpf_map_kmalloc_node() for memcg accounting. Until
	 * kmalloc_nolock() is available, avoid locking issues by using
	 * __GFP_HIGH (GFP_ATOMIC & ~__GFP_RECLAIM).
	 */
	cb = bpf_map_kmalloc_node(map, size, __GFP_HIGH, map->numa_node);
	if (!cb) {
		ret = -ENOMEM;
		goto out;
	}

	switch (type) {
	case BPF_ASYNC_TYPE_TIMER:
		clockid = flags & (MAX_CLOCKS - 1);
		t = (struct bpf_hrtimer *)cb;

		atomic_set(&t->cancelling, 0);
		INIT_WORK(&t->cb.delete_work, bpf_timer_delete_work);
		hrtimer_init(&t->timer, clockid, HRTIMER_MODE_REL_SOFT);
		t->timer.function = bpf_timer_cb;
		cb->value = (void *)async - map->record->timer_off;
		break;
	case BPF_ASYNC_TYPE_WQ:
		w = (struct bpf_work *)cb;

		INIT_WORK(&w->work, bpf_wq_work);
		INIT_WORK(&w->delete_work, bpf_wq_delete_work);
		cb->value = (void *)async - map->record->wq_off;
		break;
	}
	cb->map = map;
	cb->prog = NULL;
	cb->flags = flags;
	rcu_assign_pointer(cb->callback_fn, NULL);

	WRITE_ONCE(async->cb, cb);
	/* Guarantee the order between async->cb and map->usercnt. So
	 * when there are concurrent uref release and bpf timer init, either
	 * bpf_timer_cancel_and_free() called by uref release reads a no-NULL
	 * timer or atomic64_read() below returns a zero usercnt.
	 */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		/* maps with timers must be either held by user space
		 * or pinned in bpffs.
		 */
		WRITE_ONCE(async->cb, NULL);
		kfree(cb);
		ret = -EPERM;
	}
out:
	__bpf_spin_unlock_irqrestore(&async->lock);
	return ret;
}

BPF_CALL_3(bpf_timer_init, struct bpf_async_kern *, timer, struct bpf_map *, map,
	   u64, flags)
{
	clock_t clockid = flags & (MAX_CLOCKS - 1);

	BUILD_BUG_ON(MAX_CLOCKS != 16);
	BUILD_BUG_ON(sizeof(struct bpf_async_kern) > sizeof(struct bpf_timer));
	BUILD_BUG_ON(__alignof__(struct bpf_async_kern) != __alignof__(struct bpf_timer));

	if (flags >= MAX_CLOCKS ||
	    /* similar to timerfd except _ALARM variants are not supported */
	    (clockid != CLOCK_MONOTONIC &&
	     clockid != CLOCK_REALTIME &&
	     clockid != CLOCK_BOOTTIME))
		return -EINVAL;

	return __bpf_async_init(timer, map, flags, BPF_ASYNC_TYPE_TIMER);
}

static const struct bpf_func_proto bpf_timer_init_proto = {
	.func		= bpf_timer_init,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

static int __bpf_async_set_callback(struct bpf_async_kern *async, void *callback_fn,
				    struct bpf_prog_aux *aux, unsigned int flags,
				    enum bpf_async_type type)
{
	struct bpf_prog *prev, *prog = aux->prog;
	struct bpf_async_cb *cb;
	int ret = 0;

	if (in_nmi())
		return -EOPNOTSUPP;
	__bpf_spin_lock_irqsave(&async->lock);
	cb = async->cb;
	if (!cb) {
		ret = -EINVAL;
		goto out;
	}
	if (!atomic64_read(&cb->map->usercnt)) {
		/* maps with timers must be either held by user space
		 * or pinned in bpffs. Otherwise timer might still be
		 * running even when bpf prog is detached and user space
		 * is gone, since map_release_uref won't ever be called.
		 */
		ret = -EPERM;
		goto out;
	}
	prev = cb->prog;
	if (prev != prog) {
		/* Bump prog refcnt once. Every bpf_timer_set_callback()
		 * can pick different callback_fn-s within the same prog.
		 */
		prog = bpf_prog_inc_not_zero(prog);
		if (IS_ERR(prog)) {
			ret = PTR_ERR(prog);
			goto out;
		}
		if (prev)
			/* Drop prev prog refcnt when swapping with new prog */
			bpf_prog_put(prev);
		cb->prog = prog;
	}
	rcu_assign_pointer(cb->callback_fn, callback_fn);
out:
	__bpf_spin_unlock_irqrestore(&async->lock);
	return ret;
}

BPF_CALL_3(bpf_timer_set_callback, struct bpf_async_kern *, timer, void *, callback_fn,
	   struct bpf_prog_aux *, aux)
{
	return __bpf_async_set_callback(timer, callback_fn, aux, 0, BPF_ASYNC_TYPE_TIMER);
}

static const struct bpf_func_proto bpf_timer_set_callback_proto = {
	.func		= bpf_timer_set_callback,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_PTR_TO_FUNC,
};

BPF_CALL_3(bpf_timer_start, struct bpf_async_kern *, timer, u64, nsecs, u64, flags)
{
	struct bpf_hrtimer *t;
	int ret = 0;
	enum hrtimer_mode mode;

	if (in_nmi())
		return -EOPNOTSUPP;
	if (flags & ~(BPF_F_TIMER_ABS | BPF_F_TIMER_CPU_PIN))
		return -EINVAL;
	__bpf_spin_lock_irqsave(&timer->lock);
	t = timer->timer;
	if (!t || !t->cb.prog) {
		ret = -EINVAL;
		goto out;
	}

	if (flags & BPF_F_TIMER_ABS)
		mode = HRTIMER_MODE_ABS_SOFT;
	else
		mode = HRTIMER_MODE_REL_SOFT;

	if (flags & BPF_F_TIMER_CPU_PIN)
		mode |= HRTIMER_MODE_PINNED;

	hrtimer_start(&t->timer, ns_to_ktime(nsecs), mode);
out:
	__bpf_spin_unlock_irqrestore(&timer->lock);
	return ret;
}

static const struct bpf_func_proto bpf_timer_start_proto = {
	.func		= bpf_timer_start,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

static void drop_prog_refcnt(struct bpf_async_cb *async)
{
	struct bpf_prog *prog = async->prog;

	if (prog) {
		bpf_prog_put(prog);
		async->prog = NULL;
		rcu_assign_pointer(async->callback_fn, NULL);
	}
}

BPF_CALL_1(bpf_timer_cancel, struct bpf_async_kern *, timer)
{
	struct bpf_hrtimer *t, *cur_t;
	bool inc = false;
	int ret = 0;

	if (in_nmi())
		return -EOPNOTSUPP;
	rcu_read_lock();
	__bpf_spin_lock_irqsave(&timer->lock);
	t = timer->timer;
	if (!t) {
		ret = -EINVAL;
		goto out;
	}

	cur_t = this_cpu_read(hrtimer_running);
	if (cur_t == t) {
		/* If bpf callback_fn is trying to bpf_timer_cancel()
		 * its own timer the hrtimer_cancel() will deadlock
		 * since it waits for callback_fn to finish.
		 */
		ret = -EDEADLK;
		goto out;
	}

	/* Only account in-flight cancellations when invoked from a timer
	 * callback, since we want to avoid waiting only if other _callbacks_
	 * are waiting on us, to avoid introducing lockups. Non-callback paths
	 * are ok, since nobody would synchronously wait for their completion.
	 */
	if (!cur_t)
		goto drop;
	atomic_inc(&t->cancelling);
	/* Need full barrier after relaxed atomic_inc */
	smp_mb__after_atomic();
	inc = true;
	if (atomic_read(&cur_t->cancelling)) {
		/* We're cancelling timer t, while some other timer callback is
		 * attempting to cancel us. In such a case, it might be possible
		 * that timer t belongs to the other callback, or some other
		 * callback waiting upon it (creating transitive dependencies
		 * upon us), and we will enter a deadlock if we continue
		 * cancelling and waiting for it synchronously, since it might
		 * do the same. Bail!
		 */
		ret = -EDEADLK;
		goto out;
	}
drop:
	drop_prog_refcnt(&t->cb);
out:
	__bpf_spin_unlock_irqrestore(&timer->lock);
	/* Cancel the timer and wait for associated callback to finish
	 * if it was running.
	 */
	ret = ret ?: hrtimer_cancel(&t->timer);
	if (inc)
		atomic_dec(&t->cancelling);
	rcu_read_unlock();
	return ret;
}

static const struct bpf_func_proto bpf_timer_cancel_proto = {
	.func		= bpf_timer_cancel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
};

static struct bpf_async_cb *__bpf_async_cancel_and_free(struct bpf_async_kern *async)
{
	struct bpf_async_cb *cb;

	/* Performance optimization: read async->cb without lock first. */
	if (!READ_ONCE(async->cb))
		return NULL;

	__bpf_spin_lock_irqsave(&async->lock);
	/* re-read it under lock */
	cb = async->cb;
	if (!cb)
		goto out;
	drop_prog_refcnt(cb);
	/* The subsequent bpf_timer_start/cancel() helpers won't be able to use
	 * this timer, since it won't be initialized.
	 */
	WRITE_ONCE(async->cb, NULL);
out:
	__bpf_spin_unlock_irqrestore(&async->lock);
	return cb;
}

/* This function is called by map_delete/update_elem for individual element and
 * by ops->map_release_uref when the user space reference to a map reaches zero.
 */
void bpf_timer_cancel_and_free(void *val)
{
	struct bpf_hrtimer *t;

	t = (struct bpf_hrtimer *)__bpf_async_cancel_and_free(val);

	if (!t)
		return;
	/* We check that bpf_map_delete/update_elem() was called from timer
	 * callback_fn. In such case we don't call hrtimer_cancel() (since it
	 * will deadlock) and don't call hrtimer_try_to_cancel() (since it will
	 * just return -1). Though callback_fn is still running on this cpu it's
	 * safe to do kfree(t) because bpf_timer_cb() read everything it needed
	 * from 't'. The bpf subprog callback_fn won't be able to access 't',
	 * since async->cb = NULL was already done. The timer will be
	 * effectively cancelled because bpf_timer_cb() will return
	 * HRTIMER_NORESTART.
	 *
	 * However, it is possible the timer callback_fn calling us armed the
	 * timer _before_ calling us, such that failing to cancel it here will
	 * cause it to possibly use struct hrtimer after freeing bpf_hrtimer.
	 * Therefore, we _need_ to cancel any outstanding timers before we do
	 * kfree_rcu, even though no more timers can be armed.
	 *
	 * Moreover, we need to schedule work even if timer does not belong to
	 * the calling callback_fn, as on two different CPUs, we can end up in a
	 * situation where both sides run in parallel, try to cancel one
	 * another, and we end up waiting on both sides in hrtimer_cancel
	 * without making forward progress, since timer1 depends on time2
	 * callback to finish, and vice versa.
	 *
	 *  CPU 1 (timer1_cb)			CPU 2 (timer2_cb)
	 *  bpf_timer_cancel_and_free(timer2)	bpf_timer_cancel_and_free(timer1)
	 *
	 * To avoid these issues, punt to workqueue context when we are in a
	 * timer callback.
	 */
	if (this_cpu_read(hrtimer_running)) {
		queue_work(system_unbound_wq, &t->cb.delete_work);
		return;
	}

	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		/* If the timer is running on other CPU, also use a kworker to
		 * wait for the completion of the timer instead of trying to
		 * acquire a sleepable lock in hrtimer_cancel() to wait for its
		 * completion.
		 */
		if (hrtimer_try_to_cancel(&t->timer) >= 0)
			kfree_rcu(t, cb.rcu);
		else
			queue_work(system_unbound_wq, &t->cb.delete_work);
	} else {
		bpf_timer_delete_work(&t->cb.delete_work);
	}
}

/* This function is called by map_delete/update_elem for individual element and
 * by ops->map_release_uref when the user space reference to a map reaches zero.
 */
void bpf_wq_cancel_and_free(void *val)
{
	struct bpf_work *work;

	BTF_TYPE_EMIT(struct bpf_wq);

	work = (struct bpf_work *)__bpf_async_cancel_and_free(val);
	if (!work)
		return;
	/* Trigger cancel of the sleepable work, but *do not* wait for
	 * it to finish if it was running as we might not be in a
	 * sleepable context.
	 * kfree will be called once the work has finished.
	 */
	schedule_work(&work->delete_work);
}

BPF_CALL_2(bpf_kptr_xchg, void *, dst, void *, ptr)
{
	unsigned long *kptr = dst;

	/* This helper may be inlined by verifier. */
	return xchg(kptr, (unsigned long)ptr);
}

/* Unlike other PTR_TO_BTF_ID helpers the btf_id in bpf_kptr_xchg()
 * helper is determined dynamically by the verifier. Use BPF_PTR_POISON to
 * denote type that verifier will determine.
 */
static const struct bpf_func_proto bpf_kptr_xchg_proto = {
	.func         = bpf_kptr_xchg,
	.gpl_only     = false,
	.ret_type     = RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id   = BPF_PTR_POISON,
	.arg1_type    = ARG_KPTR_XCHG_DEST,
	.arg2_type    = ARG_PTR_TO_BTF_ID_OR_NULL | OBJ_RELEASE,
	.arg2_btf_id  = BPF_PTR_POISON,
};

/* Since the upper 8 bits of dynptr->size is reserved, the
 * maximum supported size is 2^24 - 1.
 */
#define DYNPTR_MAX_SIZE	((1UL << 24) - 1)
#define DYNPTR_TYPE_SHIFT	28
#define DYNPTR_SIZE_MASK	0xFFFFFF
#define DYNPTR_RDONLY_BIT	BIT(31)

bool __bpf_dynptr_is_rdonly(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & DYNPTR_RDONLY_BIT;
}

void bpf_dynptr_set_rdonly(struct bpf_dynptr_kern *ptr)
{
	ptr->size |= DYNPTR_RDONLY_BIT;
}

static void bpf_dynptr_set_type(struct bpf_dynptr_kern *ptr, enum bpf_dynptr_type type)
{
	ptr->size |= type << DYNPTR_TYPE_SHIFT;
}

static enum bpf_dynptr_type bpf_dynptr_get_type(const struct bpf_dynptr_kern *ptr)
{
	return (ptr->size & ~(DYNPTR_RDONLY_BIT)) >> DYNPTR_TYPE_SHIFT;
}

u32 __bpf_dynptr_size(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & DYNPTR_SIZE_MASK;
}

static void bpf_dynptr_set_size(struct bpf_dynptr_kern *ptr, u32 new_size)
{
	u32 metadata = ptr->size & ~DYNPTR_SIZE_MASK;

	ptr->size = new_size | metadata;
}

int bpf_dynptr_check_size(u32 size)
{
	return size > DYNPTR_MAX_SIZE ? -E2BIG : 0;
}

void bpf_dynptr_init(struct bpf_dynptr_kern *ptr, void *data,
		     enum bpf_dynptr_type type, u32 offset, u32 size)
{
	ptr->data = data;
	ptr->offset = offset;
	ptr->size = size;
	bpf_dynptr_set_type(ptr, type);
}

void bpf_dynptr_set_null(struct bpf_dynptr_kern *ptr)
{
	memset(ptr, 0, sizeof(*ptr));
}

static int bpf_dynptr_check_off_len(const struct bpf_dynptr_kern *ptr, u32 offset, u32 len)
{
	u32 size = __bpf_dynptr_size(ptr);

	if (len > size || offset > size - len)
		return -E2BIG;

	return 0;
}

BPF_CALL_4(bpf_dynptr_from_mem, void *, data, u32, size, u64, flags, struct bpf_dynptr_kern *, ptr)
{
	int err;

	BTF_TYPE_EMIT(struct bpf_dynptr);

	err = bpf_dynptr_check_size(size);
	if (err)
		goto error;

	/* flags is currently unsupported */
	if (flags) {
		err = -EINVAL;
		goto error;
	}

	bpf_dynptr_init(ptr, data, BPF_DYNPTR_TYPE_LOCAL, 0, size);

	return 0;

error:
	bpf_dynptr_set_null(ptr);
	return err;
}

static const struct bpf_func_proto bpf_dynptr_from_mem_proto = {
	.func		= bpf_dynptr_from_mem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_LOCAL | MEM_UNINIT | MEM_WRITE,
};

BPF_CALL_5(bpf_dynptr_read, void *, dst, u32, len, const struct bpf_dynptr_kern *, src,
	   u32, offset, u64, flags)
{
	enum bpf_dynptr_type type;
	int err;

	if (!src->data || flags)
		return -EINVAL;

	err = bpf_dynptr_check_off_len(src, offset, len);
	if (err)
		return err;

	type = bpf_dynptr_get_type(src);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		/* Source and destination may possibly overlap, hence use memmove to
		 * copy the data. E.g. bpf_dynptr_from_mem may create two dynptr
		 * pointing to overlapping PTR_TO_MAP_VALUE regions.
		 */
		memmove(dst, src->data + src->offset + offset, len);
		return 0;
	case BPF_DYNPTR_TYPE_SKB:
		return __bpf_skb_load_bytes(src->data, src->offset + offset, dst, len);
	case BPF_DYNPTR_TYPE_XDP:
		return __bpf_xdp_load_bytes(src->data, src->offset + offset, dst, len);
	default:
		WARN_ONCE(true, "bpf_dynptr_read: unknown dynptr type %d\n", type);
		return -EFAULT;
	}
}

static const struct bpf_func_proto bpf_dynptr_read_proto = {
	.func		= bpf_dynptr_read,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_dynptr_write, const struct bpf_dynptr_kern *, dst, u32, offset, void *, src,
	   u32, len, u64, flags)
{
	enum bpf_dynptr_type type;
	int err;

	if (!dst->data || __bpf_dynptr_is_rdonly(dst))
		return -EINVAL;

	err = bpf_dynptr_check_off_len(dst, offset, len);
	if (err)
		return err;

	type = bpf_dynptr_get_type(dst);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		if (flags)
			return -EINVAL;
		/* Source and destination may possibly overlap, hence use memmove to
		 * copy the data. E.g. bpf_dynptr_from_mem may create two dynptr
		 * pointing to overlapping PTR_TO_MAP_VALUE regions.
		 */
		memmove(dst->data + dst->offset + offset, src, len);
		return 0;
	case BPF_DYNPTR_TYPE_SKB:
		return __bpf_skb_store_bytes(dst->data, dst->offset + offset, src, len,
					     flags);
	case BPF_DYNPTR_TYPE_XDP:
		if (flags)
			return -EINVAL;
		return __bpf_xdp_store_bytes(dst->data, dst->offset + offset, src, len);
	default:
		WARN_ONCE(true, "bpf_dynptr_write: unknown dynptr type %d\n", type);
		return -EFAULT;
	}
}

static const struct bpf_func_proto bpf_dynptr_write_proto = {
	.func		= bpf_dynptr_write,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_dynptr_data, const struct bpf_dynptr_kern *, ptr, u32, offset, u32, len)
{
	enum bpf_dynptr_type type;
	int err;

	if (!ptr->data)
		return 0;

	err = bpf_dynptr_check_off_len(ptr, offset, len);
	if (err)
		return 0;

	if (__bpf_dynptr_is_rdonly(ptr))
		return 0;

	type = bpf_dynptr_get_type(ptr);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		return (unsigned long)(ptr->data + ptr->offset + offset);
	case BPF_DYNPTR_TYPE_SKB:
	case BPF_DYNPTR_TYPE_XDP:
		/* skb and xdp dynptrs should use bpf_dynptr_slice / bpf_dynptr_slice_rdwr */
		return 0;
	default:
		WARN_ONCE(true, "bpf_dynptr_data: unknown dynptr type %d\n", type);
		return 0;
	}
}

static const struct bpf_func_proto bpf_dynptr_data_proto = {
	.func		= bpf_dynptr_data,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_DYNPTR_MEM_OR_NULL,
	.arg1_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

const struct bpf_func_proto bpf_get_current_task_proto __weak;
const struct bpf_func_proto bpf_get_current_task_btf_proto __weak;
const struct bpf_func_proto bpf_probe_read_user_proto __weak;
const struct bpf_func_proto bpf_probe_read_user_str_proto __weak;
const struct bpf_func_proto bpf_probe_read_kernel_proto __weak;
const struct bpf_func_proto bpf_probe_read_kernel_str_proto __weak;
const struct bpf_func_proto bpf_task_pt_regs_proto __weak;

const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_map_push_elem:
		return &bpf_map_push_elem_proto;
	case BPF_FUNC_map_pop_elem:
		return &bpf_map_pop_elem_proto;
	case BPF_FUNC_map_peek_elem:
		return &bpf_map_peek_elem_proto;
	case BPF_FUNC_map_lookup_percpu_elem:
		return &bpf_map_lookup_percpu_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_ktime_get_tai_ns:
		return &bpf_ktime_get_tai_ns_proto;
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	case BPF_FUNC_ringbuf_query:
		return &bpf_ringbuf_query_proto;
	case BPF_FUNC_strncmp:
		return &bpf_strncmp_proto;
	case BPF_FUNC_strtol:
		return &bpf_strtol_proto;
	case BPF_FUNC_strtoul:
		return &bpf_strtoul_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_ns_current_pid_tgid:
		return &bpf_get_ns_current_pid_tgid_proto;
	default:
		break;
	}

	if (!bpf_token_capable(prog->aux->token, CAP_BPF))
		return NULL;

	switch (func_id) {
	case BPF_FUNC_spin_lock:
		return &bpf_spin_lock_proto;
	case BPF_FUNC_spin_unlock:
		return &bpf_spin_unlock_proto;
	case BPF_FUNC_jiffies64:
		return &bpf_jiffies64_proto;
	case BPF_FUNC_per_cpu_ptr:
		return &bpf_per_cpu_ptr_proto;
	case BPF_FUNC_this_cpu_ptr:
		return &bpf_this_cpu_ptr_proto;
	case BPF_FUNC_timer_init:
		return &bpf_timer_init_proto;
	case BPF_FUNC_timer_set_callback:
		return &bpf_timer_set_callback_proto;
	case BPF_FUNC_timer_start:
		return &bpf_timer_start_proto;
	case BPF_FUNC_timer_cancel:
		return &bpf_timer_cancel_proto;
	case BPF_FUNC_kptr_xchg:
		return &bpf_kptr_xchg_proto;
	case BPF_FUNC_for_each_map_elem:
		return &bpf_for_each_map_elem_proto;
	case BPF_FUNC_loop:
		return &bpf_loop_proto;
	case BPF_FUNC_user_ringbuf_drain:
		return &bpf_user_ringbuf_drain_proto;
	case BPF_FUNC_ringbuf_reserve_dynptr:
		return &bpf_ringbuf_reserve_dynptr_proto;
	case BPF_FUNC_ringbuf_submit_dynptr:
		return &bpf_ringbuf_submit_dynptr_proto;
	case BPF_FUNC_ringbuf_discard_dynptr:
		return &bpf_ringbuf_discard_dynptr_proto;
	case BPF_FUNC_dynptr_from_mem:
		return &bpf_dynptr_from_mem_proto;
	case BPF_FUNC_dynptr_read:
		return &bpf_dynptr_read_proto;
	case BPF_FUNC_dynptr_write:
		return &bpf_dynptr_write_proto;
	case BPF_FUNC_dynptr_data:
		return &bpf_dynptr_data_proto;
#ifdef CONFIG_CGROUPS
	case BPF_FUNC_cgrp_storage_get:
		return &bpf_cgrp_storage_get_proto;
	case BPF_FUNC_cgrp_storage_delete:
		return &bpf_cgrp_storage_delete_proto;
	case BPF_FUNC_get_current_cgroup_id:
		return &bpf_get_current_cgroup_id_proto;
	case BPF_FUNC_get_current_ancestor_cgroup_id:
		return &bpf_get_current_ancestor_cgroup_id_proto;
#endif
	default:
		break;
	}

	if (!bpf_token_capable(prog->aux->token, CAP_PERFMON))
		return NULL;

	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_task_btf:
		return &bpf_get_current_task_btf_proto;
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	case BPF_FUNC_probe_read_kernel:
		return security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 ?
		       NULL : &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read_user_str:
		return &bpf_probe_read_user_str_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 ?
		       NULL : &bpf_probe_read_kernel_str_proto;
	case BPF_FUNC_snprintf_btf:
		return &bpf_snprintf_btf_proto;
	case BPF_FUNC_snprintf:
		return &bpf_snprintf_proto;
	case BPF_FUNC_task_pt_regs:
		return &bpf_task_pt_regs_proto;
	case BPF_FUNC_trace_vprintk:
		return bpf_get_trace_vprintk_proto();
	default:
		return NULL;
	}
}
EXPORT_SYMBOL_GPL(bpf_base_func_proto);

/*
 * Bifrost helper-proto resolver. Thin wrapper around bpf_base_func_proto for
 * out-of-tree modules that need to lower DIF/etc. into eBPF without depending
 * on tracing-only protos in kernel/trace/bpf_trace.c.
 *
 * `prog` MUST be the real prog — bpf_base_func_proto uses
 * `prog->aux->token` for the CAP_BPF gate that protects the second
 * switch (spin_lock, jiffies64, ringbuf_*, etc.). With prog=NULL, the
 * verifier's mark_fastcall_pattern_for_call NULL-derefs at +0x2c when
 * any of those helpers are encountered in a kprobe program.
 */
extern const struct bpf_func_proto bpf_get_stack_proto;

const struct bpf_func_proto *bifrost_get_func_proto(enum bpf_func_id func_id,
						    const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_get_stack:
		return &bpf_get_stack_proto;
	default:
		break;
	}
	return bpf_base_func_proto(func_id, prog);
}
EXPORT_SYMBOL_GPL(bifrost_get_func_proto);

/*
 * Bifrost kprobe / uprobe verifier ops.
 *
 * Background: bpf_verifier_ops[BPF_PROG_TYPE_KPROBE] is populated by a macro
 * expansion in include/linux/bpf_types.h that's gated on CONFIG_BPF_EVENTS,
 * and the canonical kprobe_verifier_ops struct lives in
 * kernel/trace/bpf_trace.c (also gated on CONFIG_BPF_EVENTS via
 * obj-$(CONFIG_BPF_EVENTS) += bpf_trace.o in kernel/trace/Makefile).
 * CONFIG_BPF_EVENTS itself depends on (KPROBE_EVENTS || UPROBE_EVENTS) &&
 * PERF_EVENTS, which pulls in the full FTRACE / TRACING / BPF_EVENTS
 * tracefs surface.
 *
 * Bifrost's guest driver (drivers/bifrost/) loads BPF_PROG_TYPE_KPROBE
 * programs via its own register_kprobe path (no kprobe-event tracefs surface
 * needed) and its own register_uprobe path. We only need the verifier-side
 * struct so bpf_check() finds env->ops != NULL when verifying these
 * program types — the kfunc-resolution path in mark_fastcall_patterns
 * derefs env->ops->get_func_proto and crashes otherwise.
 *
 * To avoid carrying all of FTRACE/BPF_EVENTS for the verifier ops alone,
 * provide minimal kprobe_verifier_ops + uprobe_verifier_ops here when
 * CONFIG_BIFROST_GUEST=y AND CONFIG_BPF_EVENTS=n. The bpf_types.h macro
 * expansion is widened in the same patch to consume our definitions.
 *
 * Same is_valid_access semantics as bpf_trace.c (pt_regs, BPF_READ-only,
 * naturally aligned). Helper resolution goes through bifrost_get_func_proto
 * which is bpf_base_func_proto — covers the helpers bifrost lowering emits
 * (map_lookup_elem family, ktime_get_ns, get_smp_processor_id,
 * get_current_pid_tgid, get_current_task, etc.). Tracing-only helpers
 * (bpf_perf_event_output, bpf_get_stackid, ...) are intentionally absent;
 * bifrost programs don't use them — they ship records via bifrost_kfunc_*
 * SHMEM helpers instead.
 */
#if defined(CONFIG_BIFROST_GUEST) && !defined(CONFIG_BPF_EVENTS)
static bool bifrost_kprobe_prog_is_valid_access(int off, int size,
						enum bpf_access_type type,
						const struct bpf_prog *prog,
						struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct pt_regs))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	if (off + size > sizeof(struct pt_regs))
		return false;
	return true;
}

static const struct bpf_func_proto *
bifrost_kprobe_prog_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	return bifrost_get_func_proto(func_id, prog);
}

const struct bpf_verifier_ops kprobe_verifier_ops = {
	.get_func_proto  = bifrost_kprobe_prog_func_proto,
	.is_valid_access = bifrost_kprobe_prog_is_valid_access,
};

const struct bpf_prog_ops kprobe_prog_ops = {
};
#endif

/*
 * Bifrost vmlinux BTF range accessor. The linker symbols __start_BTF /
 * __stop_BTF aren't exported to modules; this thin shim hands the raw
 * byte range to bifrost_guest so it can ferry the kernel's own BTF over
 * the virtio bridge to the host (where libdtrace / aya-obj will consume
 * it for CO-RE relocation against guest types).
 */
extern char __start_BTF[], __stop_BTF[];
const void *bifrost_btf_data(unsigned long *size)
{
	if (size)
		*size = __stop_BTF - __start_BTF;
	return __start_BTF;
}
EXPORT_SYMBOL_GPL(bifrost_btf_data);

/*
 * Bifrost kallsyms walker. kallsyms_on_each_symbol is non-static but
 * not EXPORT_SYMBOL'd, so OOT modules can't reach it directly. Wrap
 * it here (vmlinux can call it via normal external linkage) and
 * export the wrapper so bifrost_guest can ferry the (addr, name)
 * table to the host for stack symbolication.
 *
 * The callback returns non-zero to stop iteration (matches the inner
 * kallsyms_on_each_symbol contract).
 */
extern int kallsyms_on_each_symbol(int (*fn)(void *, const char *, unsigned long),
				   void *data);
int bifrost_walk_kallsyms(int (*cb)(void *, const char *, unsigned long),
			  void *data)
{
	return kallsyms_on_each_symbol(cb, data);
}
EXPORT_SYMBOL_GPL(bifrost_walk_kallsyms);

/*
 * Bifrost kernel stack-trace shim. stack_trace_save_regs uses the
 * arch unwinder (arch_stack_walk on arm64), which handles kprobe
 * context, IRQ stacks, and the kretprobe trampoline correctly.
 * It's not EXPORT_SYMBOL'd for OOT modules, so we wrap it.
 *
 *   regs:    pt_regs at the probe site.
 *   store:   caller-provided u64 array to receive PCs.
 *   nr:      max number of PCs to write.
 *   skipnr:  number of frames to skip at the top.
 * Returns: number of PCs actually written.
 */
extern unsigned int stack_trace_save_regs(struct pt_regs *regs,
					  unsigned long *store,
					  unsigned int size,
					  unsigned int skipnr);
unsigned int bifrost_stack_walk(struct pt_regs *regs, unsigned long *store,
				unsigned int nr, unsigned int skipnr)
{
	return stack_trace_save_regs(regs, store, nr, skipnr);
}
EXPORT_SYMBOL_GPL(bifrost_stack_walk);

/*
 * Write `task`'s executable path (mm->exe_file's d_path) into `buf`.
 * Returns the number of bytes written (NUL-terminator included) on
 * success, 0 if the task has no mm or exe_file (kthreads, exit race),
 * or a negative errno on buffer too small.
 *
 * Companion to gustack: a userspace-stack record's hex PCs become
 * much more useful when the host knows which ELF they belong to.
 * The bifrost worker calls this for each gustack record it drains
 * from the kernel-side ringbuf, looking up the firing task by gpid
 * (which the BPF prologue already wrote into the record).
 */
int bifrost_task_exe_path(struct task_struct *task, char *buf, unsigned int size)
{
	struct mm_struct *mm;
	struct file *exe;
	char *p;

	if (!buf || size == 0)
		return -EINVAL;
	if (!task || (task->flags & PF_KTHREAD))
		return 0;

	mm = get_task_mm(task);
	if (!mm)
		return 0;
	rcu_read_lock();
	exe = rcu_dereference(mm->exe_file);
	if (!exe) {
		rcu_read_unlock();
		mmput(mm);
		return 0;
	}
	get_file(exe);
	rcu_read_unlock();

	p = d_path(&exe->f_path, buf, size);
	if (IS_ERR(p)) {
		fput(exe);
		mmput(mm);
		return PTR_ERR(p);
	}
	/* d_path writes from the END of the buffer backwards. Move the
	 * resolved string to the start so the caller can read it as a
	 * normal C string at offset 0. */
	{
		size_t len = strlen(p);
		if (len + 1 > size) {
			fput(exe);
			mmput(mm);
			return -ENAMETOOLONG;
		}
		memmove(buf, p, len + 1);
		fput(exe);
		mmput(mm);
		return (int)(len + 1);
	}
}
EXPORT_SYMBOL_GPL(bifrost_task_exe_path);

/*
 * Find a task_struct by tgid. Wraps find_task_by_vpid with refcount
 * bump so the caller can safely access mm/etc. without RCU. Returns
 * NULL if no such task. Caller must put_task_struct after use.
 */
struct task_struct *bifrost_find_task_by_tgid(unsigned int tgid)
{
	struct task_struct *t;

	rcu_read_lock();
	t = find_task_by_vpid(tgid);
	if (t)
		get_task_struct(t);
	rcu_read_unlock();
	return t;
}
EXPORT_SYMBOL_GPL(bifrost_find_task_by_tgid);

void bifrost_put_task(struct task_struct *t)
{
	if (t)
		put_task_struct(t);
}
EXPORT_SYMBOL_GPL(bifrost_put_task);

/*
 * Allocate a SHMEM region for the bifrost data plane. Used by the
 * bifrost guest module to back the host-shared event ringbuf, VMA
 * cache, BTF blob, and kallsyms blob.
 *
 * Backed by vmalloc — non-contiguous physical, contiguous kernel
 * virtual. Avoids the MAX_PAGE_ORDER ceiling that rules out
 * 16 MB physically-contiguous allocations (order=12 exceeds the
 * default arm64 limit). The caller-provided @pfns array receives
 * one PFN per PAGE_SIZE chunk; the host's libkrun device walks
 * the array and computes a per-page host VA via
 *   `mem.get_host_address(GuestAddress(pfn * PAGE_SIZE))`
 * since libkrun maps all guest RAM into the host process flat,
 * the per-page host VAs are predictable from the PFNs.
 *
 * @size must be a multiple of PAGE_SIZE. @pfns_capacity must be
 * >= size / PAGE_SIZE. On success returns the kernel-virtual base
 * address; on failure returns NULL.
 */
void *bifrost_alloc_shmem(unsigned long size, unsigned long *pfns,
			  unsigned long pfns_capacity,
			  unsigned long *out_n_pages)
{
	void *va;
	unsigned long n_pages, i;

	if (!size || (size & (PAGE_SIZE - 1)) || !pfns || !out_n_pages)
		return NULL;
	n_pages = size >> PAGE_SHIFT;
	if (n_pages > pfns_capacity)
		return NULL;

	va = vmalloc(size);
	if (!va)
		return NULL;
	memset(va, 0, size);

	for (i = 0; i < n_pages; i++) {
		struct page *p = vmalloc_to_page((char *)va + i * PAGE_SIZE);
		if (!p) {
			vfree(va);
			return NULL;
		}
		pfns[i] = page_to_pfn(p);
	}
	*out_n_pages = n_pages;
	return va;
}
EXPORT_SYMBOL_GPL(bifrost_alloc_shmem);

void bifrost_free_shmem(void *addr, unsigned long size)
{
	(void)size;
	if (addr)
		vfree(addr);
}
EXPORT_SYMBOL_GPL(bifrost_free_shmem);

/*
 * SHMEM event ringbuf — Phase 2 of the bifrost data plane.
 *
 * The bifrost guest module pre-publishes the SHMEM region's kernel
 * VA and ringbuf parameters via `bifrost_set_shmem_ringbuf`. The
 * shmem_reserve / shmem_submit kfuncs (defined alongside the other
 * bifrost kfuncs above) read the published pointer and operate
 * directly on the in-region header.
 *
 * Header layout (matches host's `ShmemRingbufHdr`):
 *   +0   u32 magic   ('BFSH', stamped at probe time)
 *   +4   u32 version
 *   +8   u64 region_len
 *   +16  u64 ringbuf_off       (data area start — typically 4 KB)
 *   +24  u64 ringbuf_len       (data area length, multiple of 8)
 *   +32  u64 producer_pos      (monotonic; offset into data = pos % len)
 *   +40  u64 consumer_pos
 *   +96  u64 dropped_records   (reserve failures after SHMEM is live)
 *   +104 u64 dropped_bytes     (payload bytes refused by reserve)
 *
 * Record format (8-byte aligned):
 *   +0   u32 size               (payload bytes; 0 unused for now)
 *   +4   u32 flags              (bit 0 = ready)
 *   +8   payload[size]
 *   ...  pad to next 8-byte boundary
 *
 * v1 simplification: no wrap. Producer fails reserve once
 * `producer_pos + aligned_size > consumer_pos + ringbuf_len` or
 * once a record would cross the end-of-buffer boundary. The host
 * must drain to advance consumer_pos. Wrap-aware reservation is a
 * follow-on iteration.
 */
/* Per-CPU sub-ring state. Each CPU gets its own cache line at
 * `header + per_cpu_state_off + cpu * 64`. Layout matches the
 * host-side bifrost::cli::control_shmem::DataShmSnapshot
 * per-CPU readback. The remaining 32 bytes after the 4 atomic64
 * counters pad the struct to one cache line; future per-class
 * drop counters (W7 follow-on) consume that headroom.
 */
/* W7 follow-on: per-class drop attribution. Each per-CPU cache
 * line now carries dropped_records / dropped_bytes for each of
 * four DTrace drop classes — principal (regular probe records),
 * agg (aggregation snapshots), stkstr (stack/VMA-table side
 * records), and dblerr (error-clause-action faults). The host
 * shutdown summary surfaces the per-class taxonomy in
 * `[bifrost] guest-ring drop summary: drops=N (principal=N agg=N
 * stkstr=N dblerr=N)`.
 *
 * Drop-class assignment: BPF-callable
 * `bifrost_kfunc_shmem_reserve` defaults to PRINCIPAL.
 * Kernel-internal callers
 * (push_agg_snapshot, publish_vma_table, symtab pumps) pass an
 * explicit class via `bifrost_shmem_reserve_kernel_class`.
 *
 * Struct expands from 64 to 128 bytes (two cache lines per CPU);
 * `BIFROST_PER_CPU_STATE_STRIDE` bumps to 128 to match. With
 * `BIFROST_NUM_CPUS_MAX = 16` the per-CPU array consumes 2 KB
 * — comfortably under the 4 KB SHMEM header page.
 */
#define BIFROST_DROP_CLASS_PRINCIPAL 0
#define BIFROST_DROP_CLASS_AGG       1
#define BIFROST_DROP_CLASS_STKSTR    2
#define BIFROST_DROP_CLASS_DBLERR    3
#define BIFROST_DROP_CLASS_MAX       4

struct bifrost_shmem_per_cpu {
	atomic64_t producer_pos;
	atomic64_t consumer_pos;
	atomic64_t dropped_records[BIFROST_DROP_CLASS_MAX];
	atomic64_t dropped_bytes[BIFROST_DROP_CLASS_MAX];
	u8 _pad[32];
} __aligned(128);

/* SHMEM ringbuf header (SHMEM_VERSION 4 — per-CPU principal
 * buffer). The 6 MB ringbuf area is carved into `num_cpus`
 * equal-size sub-rings of length `per_cpu_ring_len` each,
 * starting at `ringbuf_off + cpu * per_cpu_ring_len`. Producer
 * (BPF program) picks its sub-ring via `smp_processor_id() %
 * num_cpus`; consumer (host renderer) round-robins drain across
 * all `num_cpus` sub-rings. Eliminates the cross-CPU CAS
 * contention on a single `producer_pos` that was the practical
 * throughput ceiling under hot workloads (compile-profile at
 * FIRE_GAP=0.05 dropped 1.7M records / 16 s on the single-ring
 * layout). */
#define BIFROST_NUM_CPUS_MAX 16
#define BIFROST_PER_CPU_STATE_OFF 128
/* W7 follow-on: stride bumps from 64 to 128 to fit per-class
 * drop counters. With NUM_CPUS_MAX=16 the per-CPU array is 2 KB. */
#define BIFROST_PER_CPU_STATE_STRIDE 128

struct bifrost_shmem_ringbuf_hdr {
	u32 magic;
	u32 version;
	u64 region_len;
	u64 ringbuf_off;
	u64 ringbuf_len;
	/* Phase 3a: BTF + kallsyms in-region. */
	u64 btf_off;
	u64 btf_len;
	u64 ksyms_off;
	u64 ksyms_len;
	/* Phase 3b: per-(tgid,exec_id) VMA cache. */
	u64 vma_cache_off;
	u64 vma_cache_len;
	/* W1: per-CPU principal buffer */
	u32 num_cpus;
	u32 per_cpu_state_stride;
	u64 per_cpu_ring_len;
	u64 per_cpu_state_off;
	u8 _pad[24];
	/* per-CPU state starts here at offset 128, one cache line per
	 * CPU. Accessed via the `bifrost_shmem_pcpu(hdr, cpu)` helper
	 * below so future relayout doesn't change call sites. */
	struct bifrost_shmem_per_cpu per_cpu[BIFROST_NUM_CPUS_MAX];
};
static_assert(offsetof(struct bifrost_shmem_ringbuf_hdr, per_cpu) ==
		      BIFROST_PER_CPU_STATE_OFF,
	      "per_cpu state must land at offset 128");
static_assert(sizeof(struct bifrost_shmem_per_cpu) ==
		      BIFROST_PER_CPU_STATE_STRIDE,
	      "per_cpu state must be one cache line");

#define BIFROST_RB_FLAG_READY     (1u << 0)
#define BIFROST_RB_FLAG_PADDING   (1u << 1)
#define BIFROST_RB_RECORD_HDR     8
/* Bumped from 8 KB to 64 KB to fit agg-snapshot records (worst-
 * case ~41 KB at 2048 entries × 20 bytes). With 16 per-CPU
 * sub-rings carved from 6 MB total, each sub-ring is 384 KB —
 * a max-size record consumes ~17 % of one sub-ring. */
#define BIFROST_RB_MAX_RECORD     65536

static char *bifrost_shmem_va __read_mostly;
static unsigned long bifrost_shmem_len __read_mostly;

static inline struct bifrost_shmem_per_cpu *
bifrost_shmem_pcpu(struct bifrost_shmem_ringbuf_hdr *hdr, unsigned int cpu)
{
	if (cpu >= hdr->num_cpus)
		cpu = 0;
	return &hdr->per_cpu[cpu];
}

static void bifrost_shmem_note_drop(struct bifrost_shmem_ringbuf_hdr *hdr,
				    unsigned int cpu, u32 size,
				    unsigned int class)
{
	struct bifrost_shmem_per_cpu *pc = bifrost_shmem_pcpu(hdr, cpu);

	if (class >= BIFROST_DROP_CLASS_MAX)
		class = BIFROST_DROP_CLASS_PRINCIPAL;
	atomic64_inc(&pc->dropped_records[class]);
	atomic64_add(size, &pc->dropped_bytes[class]);
}

/*
 * Called by the bifrost guest module after the SHMEM region is
 * allocated and the host has acked SHMEM_INIT. Initializes the
 * ringbuf header in-place and publishes `bifrost_shmem_va` so the
 * reserve/submit kfuncs can find it. Idempotent.
 */
int bifrost_set_shmem_ringbuf(void *shmem_va, unsigned long region_len,
			      unsigned long ringbuf_off,
			      unsigned long ringbuf_len,
			      unsigned long btf_off, unsigned long btf_len,
			      unsigned long ksyms_off, unsigned long ksyms_len,
			      unsigned long vma_cache_off,
			      unsigned long vma_cache_len)
{
	struct bifrost_shmem_ringbuf_hdr *hdr;
	unsigned int num_cpus, cpu;
	u64 per_cpu_ring_len;

	if (!shmem_va || region_len < ringbuf_off + ringbuf_len)
		return -EINVAL;
	if (ringbuf_len & 7)
		return -EINVAL;
	if (btf_len && btf_off + btf_len > region_len)
		return -EINVAL;
	if (ksyms_len && ksyms_off + ksyms_len > region_len)
		return -EINVAL;
	if (vma_cache_len && vma_cache_off + vma_cache_len > region_len)
		return -EINVAL;

	/* Pick the number of per-CPU sub-rings: min(possible CPUs,
	 * BIFROST_NUM_CPUS_MAX). The kfunc selects via
	 * `smp_processor_id() % num_cpus`, so on hosts with more CPUs
	 * than NUM_CPUS_MAX multiple CPUs share a sub-ring (still
	 * better than the single-ring layout). 8-byte-align the
	 * per-CPU length so each sub-ring's producer/consumer math
	 * stays on the existing alignment guarantees. */
	num_cpus = num_possible_cpus();
	if (num_cpus == 0)
		num_cpus = 1;
	if (num_cpus > BIFROST_NUM_CPUS_MAX)
		num_cpus = BIFROST_NUM_CPUS_MAX;
	per_cpu_ring_len = (ringbuf_len / num_cpus) & ~7ULL;
	if (per_cpu_ring_len < 4096)
		return -EINVAL;

	hdr = (struct bifrost_shmem_ringbuf_hdr *)shmem_va;
	hdr->region_len = region_len;
	hdr->ringbuf_off = ringbuf_off;
	hdr->ringbuf_len = ringbuf_len;
	hdr->btf_off = btf_off;
	hdr->btf_len = btf_len;
	hdr->ksyms_off = ksyms_off;
	hdr->ksyms_len = ksyms_len;
	hdr->vma_cache_off = vma_cache_off;
	hdr->vma_cache_len = vma_cache_len;
	hdr->num_cpus = num_cpus;
	hdr->per_cpu_state_stride = BIFROST_PER_CPU_STATE_STRIDE;
	hdr->per_cpu_ring_len = per_cpu_ring_len;
	hdr->per_cpu_state_off = BIFROST_PER_CPU_STATE_OFF;

	for (cpu = 0; cpu < BIFROST_NUM_CPUS_MAX; cpu++) {
		struct bifrost_shmem_per_cpu *pc = &hdr->per_cpu[cpu];
		unsigned int klass;

		atomic64_set(&pc->producer_pos, 0);
		atomic64_set(&pc->consumer_pos, 0);
		for (klass = 0; klass < BIFROST_DROP_CLASS_MAX; klass++) {
			atomic64_set(&pc->dropped_records[klass], 0);
			atomic64_set(&pc->dropped_bytes[klass], 0);
		}
	}
	smp_wmb();

	WRITE_ONCE(bifrost_shmem_va, (char *)shmem_va);
	WRITE_ONCE(bifrost_shmem_len, region_len);
	return 0;
}
EXPORT_SYMBOL_GPL(bifrost_set_shmem_ringbuf);

void bifrost_clear_shmem_ringbuf(void)
{
	WRITE_ONCE(bifrost_shmem_va, NULL);
	smp_wmb();
	WRITE_ONCE(bifrost_shmem_len, 0);
}
EXPORT_SYMBOL_GPL(bifrost_clear_shmem_ringbuf);

/*
 * Pack the firing task's file-backed VMA table into @buf for the
 * gustack symbolicator on the host. Each entry describes one VMA's
 * runtime range (`start`, `end`), its file offset (so PCs can be
 * translated to file offsets), and the path of its backing file.
 *
 * Wire format:
 *   struct bifrost_vma_table_hdr {
 *       u32 n_vmas;
 *       u32 strings_off;   // byte offset within @buf where path strings start
 *       u32 strings_len;   // bytes of valid path data
 *       u32 reserved;
 *       struct bifrost_vma_table_entry entries[n_vmas];
 *       char strings[strings_len];   // NUL-separated d_path() outputs
 *   };
 *   struct bifrost_vma_table_entry {
 *       u64 start;
 *       u64 end;
 *       u64 file_offset;     // pgoff << PAGE_SHIFT
 *       u32 prot;            // VM_READ/WRITE/EXEC bits
 *       u32 path_off;        // byte offset within strings[] (not into @buf!)
 *   };
 *
 * Bounded scope: we cap at BIFROST_VMA_TABLE_MAX entries (96), paired
 * with an 8KB buf size on the host emit prologue (see
 * host/bifrost/src/lower/mod.rs). Real server processes turn out to
 * carry far more file-backed VMAs than the per-shared-library count
 * suggests: ubuntu:24.04 redis-server has 70 file-backed VMAs across
 * 18 distinct backing files (text + skip-page + r-x + r-- + rw- per
 * lib, plus the binary itself + libstdc++ + libcrypto + libssl + libm
 * + libjemalloc + libsystemd + …). The earlier cap of 32 with a
 * 1008-byte strings buffer was actually bound by the strings buffer,
 * not the entry count: redis-server's table cut off at VMA #23
 * (libgcrypt), silently dropping libc + everything past it. Cap=96
 * with strings_avail=5104 bytes publishes redis-server's full table
 * with comfortable headroom for postgres-class processes.
 *
 * Returns: bytes written on success, 0 if no mm or trylock failed
 * (acceptable degradation in atomic context — host falls back to
 * the previous record's table if cached, else raw hex), or negative
 * errno on buffer too small.
 *
 * Atomic-safe: uses mmap_read_trylock so it never sleeps. d_path is
 * spin-protected internally; safe to call from kprobe context.
 */
#define BIFROST_VMA_TABLE_MAX 96
struct bifrost_vma_table_entry_kern {
	u64 start;
	u64 end;
	u64 file_offset;
	u32 prot;
	u32 path_off;
};
struct bifrost_vma_table_hdr_kern {
	u32 n_vmas;
	u32 strings_off;
	u32 strings_len;
	u32 reserved;
};
int bifrost_emit_vma_table(struct task_struct *task, char *buf, unsigned int size)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct bifrost_vma_table_hdr_kern *hdr;
	struct bifrost_vma_table_entry_kern *entries;
	char *strings_base;
	u32 entries_size, strings_off, strings_pos = 0, strings_avail;
	u32 n = 0;
	int ret = 0;

	if (!buf || size < sizeof(*hdr) + sizeof(*entries) * 2 + 256)
		return -EINVAL;
	if (!task || (task->flags & PF_KTHREAD))
		return 0;

	entries_size = sizeof(*hdr) + sizeof(*entries) * BIFROST_VMA_TABLE_MAX;
	if (size <= entries_size)
		return -EINVAL;
	strings_off = entries_size;
	strings_avail = size - strings_off;

	hdr = (struct bifrost_vma_table_hdr_kern *)buf;
	entries = (struct bifrost_vma_table_entry_kern *)(buf + sizeof(*hdr));
	strings_base = buf + strings_off;

	/* Zero the header so partial fills are safe to interpret. */
	memset(hdr, 0, sizeof(*hdr));
	hdr->strings_off = strings_off;

	mm = get_task_mm(task);
	if (!mm) {
		hdr->n_vmas = 0;
		hdr->strings_len = 0;
		return entries_size;
	}

	/* mmap_read_trylock so kprobe atomic context never sleeps. If we
	 * lose the lock race, ferry an empty table — the host renderer
	 * tolerates a missing or empty table by falling back to raw hex. */
	if (!mmap_read_trylock(mm)) {
		mmput(mm);
		hdr->n_vmas = 0;
		hdr->strings_len = 0;
		return entries_size;
	}

	{
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
			char *p;
			const char *resolved = NULL;
			size_t len;
			int from_special = 0;

			if (n >= BIFROST_VMA_TABLE_MAX)
				break;

			if (vma->vm_file) {
				/* File-backed: resolve dentry chain. */
				if (strings_pos + 1 >= strings_avail)
					break;
				p = strings_base + strings_pos;
				resolved = d_path(&vma->vm_file->f_path, p,
						  strings_avail - strings_pos);
				if (IS_ERR(resolved))
					continue;
				len = strlen(resolved);
				if (len + 1 > strings_avail - strings_pos)
					break;
				memmove(p, resolved, len + 1);
			} else if (vma->vm_ops && vma->vm_ops->name) {
				/* vDSO + similar special mappings: vm_ops->name
				 * returns "[vdso]", "[vvar]", etc. The vDSO PCs
				 * in user stacks live here. The host symbolicator
				 * has special handling for "[vdso]" — looks the
				 * PC up against vmlinux's __vdso_* symbols. */
				const char *nm = vma->vm_ops->name(vma);
				if (!nm)
					continue;
				len = strlen(nm);
				if (len + 1 > strings_avail - strings_pos)
					break;
				p = strings_base + strings_pos;
				memcpy(p, nm, len + 1);
				resolved = p;
				from_special = 1;
			} else {
				continue;
			}

			entries[n].start = vma->vm_start;
			entries[n].end = vma->vm_end;
			entries[n].file_offset = from_special ? 0
				: ((u64)vma->vm_pgoff << PAGE_SHIFT);
			entries[n].prot = (u32)(vma->vm_flags &
						 (VM_READ | VM_WRITE | VM_EXEC));
			entries[n].path_off = strings_pos;
			strings_pos += len + 1;
			n++;
		}
	}

	mmap_read_unlock(mm);
	mmput(mm);

	hdr->n_vmas = n;
	hdr->strings_len = strings_pos;
	ret = strings_off + strings_pos;
	return ret;
}
EXPORT_SYMBOL_GPL(bifrost_emit_vma_table);

void bpf_list_head_free(const struct btf_field *field, void *list_head,
			struct bpf_spin_lock *spin_lock)
{
	struct list_head *head = list_head, *orig_head = list_head;

	BUILD_BUG_ON(sizeof(struct list_head) > sizeof(struct bpf_list_head));
	BUILD_BUG_ON(__alignof__(struct list_head) > __alignof__(struct bpf_list_head));

	/* Do the actual list draining outside the lock to not hold the lock for
	 * too long, and also prevent deadlocks if tracing programs end up
	 * executing on entry/exit of functions called inside the critical
	 * section, and end up doing map ops that call bpf_list_head_free for
	 * the same map value again.
	 */
	__bpf_spin_lock_irqsave(spin_lock);
	if (!head->next || list_empty(head))
		goto unlock;
	head = head->next;
unlock:
	INIT_LIST_HEAD(orig_head);
	__bpf_spin_unlock_irqrestore(spin_lock);

	while (head != orig_head) {
		void *obj = head;

		obj -= field->graph_root.node_offset;
		head = head->next;
		/* The contained type can also have resources, including a
		 * bpf_list_head which needs to be freed.
		 */
		migrate_disable();
		__bpf_obj_drop_impl(obj, field->graph_root.value_rec, false);
		migrate_enable();
	}
}

/* Like rbtree_postorder_for_each_entry_safe, but 'pos' and 'n' are
 * 'rb_node *', so field name of rb_node within containing struct is not
 * needed.
 *
 * Since bpf_rb_tree's node type has a corresponding struct btf_field with
 * graph_root.node_offset, it's not necessary to know field name
 * or type of node struct
 */
#define bpf_rbtree_postorder_for_each_entry_safe(pos, n, root) \
	for (pos = rb_first_postorder(root); \
	    pos && ({ n = rb_next_postorder(pos); 1; }); \
	    pos = n)

void bpf_rb_root_free(const struct btf_field *field, void *rb_root,
		      struct bpf_spin_lock *spin_lock)
{
	struct rb_root_cached orig_root, *root = rb_root;
	struct rb_node *pos, *n;
	void *obj;

	BUILD_BUG_ON(sizeof(struct rb_root_cached) > sizeof(struct bpf_rb_root));
	BUILD_BUG_ON(__alignof__(struct rb_root_cached) > __alignof__(struct bpf_rb_root));

	__bpf_spin_lock_irqsave(spin_lock);
	orig_root = *root;
	*root = RB_ROOT_CACHED;
	__bpf_spin_unlock_irqrestore(spin_lock);

	bpf_rbtree_postorder_for_each_entry_safe(pos, n, &orig_root.rb_root) {
		obj = pos;
		obj -= field->graph_root.node_offset;


		migrate_disable();
		__bpf_obj_drop_impl(obj, field->graph_root.value_rec, false);
		migrate_enable();
	}
}

__bpf_kfunc_start_defs();

__bpf_kfunc void *bpf_obj_new_impl(u64 local_type_id__k, void *meta__ign)
{
	struct btf_struct_meta *meta = meta__ign;
	u64 size = local_type_id__k;
	void *p;

	p = bpf_mem_alloc(&bpf_global_ma, size);
	if (!p)
		return NULL;
	if (meta)
		bpf_obj_init(meta->record, p);
	return p;
}

__bpf_kfunc void *bpf_percpu_obj_new_impl(u64 local_type_id__k, void *meta__ign)
{
	u64 size = local_type_id__k;

	/* The verifier has ensured that meta__ign must be NULL */
	return bpf_mem_alloc(&bpf_global_percpu_ma, size);
}

/* Must be called under migrate_disable(), as required by bpf_mem_free */
void __bpf_obj_drop_impl(void *p, const struct btf_record *rec, bool percpu)
{
	struct bpf_mem_alloc *ma;

	if (rec && rec->refcount_off >= 0 &&
	    !refcount_dec_and_test((refcount_t *)(p + rec->refcount_off))) {
		/* Object is refcounted and refcount_dec didn't result in 0
		 * refcount. Return without freeing the object
		 */
		return;
	}

	if (rec)
		bpf_obj_free_fields(rec, p);

	if (percpu)
		ma = &bpf_global_percpu_ma;
	else
		ma = &bpf_global_ma;
	bpf_mem_free_rcu(ma, p);
}

__bpf_kfunc void bpf_obj_drop_impl(void *p__alloc, void *meta__ign)
{
	struct btf_struct_meta *meta = meta__ign;
	void *p = p__alloc;

	__bpf_obj_drop_impl(p, meta ? meta->record : NULL, false);
}

__bpf_kfunc void bpf_percpu_obj_drop_impl(void *p__alloc, void *meta__ign)
{
	/* The verifier has ensured that meta__ign must be NULL */
	bpf_mem_free_rcu(&bpf_global_percpu_ma, p__alloc);
}

__bpf_kfunc void *bpf_refcount_acquire_impl(void *p__refcounted_kptr, void *meta__ign)
{
	struct btf_struct_meta *meta = meta__ign;
	struct bpf_refcount *ref;

	/* Could just cast directly to refcount_t *, but need some code using
	 * bpf_refcount type so that it is emitted in vmlinux BTF
	 */
	ref = (struct bpf_refcount *)(p__refcounted_kptr + meta->record->refcount_off);
	if (!refcount_inc_not_zero((refcount_t *)ref))
		return NULL;

	/* Verifier strips KF_RET_NULL if input is owned ref, see is_kfunc_ret_null
	 * in verifier.c
	 */
	return (void *)p__refcounted_kptr;
}

static int __bpf_list_add(struct bpf_list_node_kern *node,
			  struct bpf_list_head *head,
			  bool tail, struct btf_record *rec, u64 off)
{
	struct list_head *n = &node->list_head, *h = (void *)head;

	/* If list_head was 0-initialized by map, bpf_obj_init_field wasn't
	 * called on its fields, so init here
	 */
	if (unlikely(!h->next))
		INIT_LIST_HEAD(h);

	/* node->owner != NULL implies !list_empty(n), no need to separately
	 * check the latter
	 */
	if (cmpxchg(&node->owner, NULL, BPF_PTR_POISON)) {
		/* Only called from BPF prog, no need to migrate_disable */
		__bpf_obj_drop_impl((void *)n - off, rec, false);
		return -EINVAL;
	}

	tail ? list_add_tail(n, h) : list_add(n, h);
	WRITE_ONCE(node->owner, head);

	return 0;
}

__bpf_kfunc int bpf_list_push_front_impl(struct bpf_list_head *head,
					 struct bpf_list_node *node,
					 void *meta__ign, u64 off)
{
	struct bpf_list_node_kern *n = (void *)node;
	struct btf_struct_meta *meta = meta__ign;

	return __bpf_list_add(n, head, false, meta ? meta->record : NULL, off);
}

__bpf_kfunc int bpf_list_push_back_impl(struct bpf_list_head *head,
					struct bpf_list_node *node,
					void *meta__ign, u64 off)
{
	struct bpf_list_node_kern *n = (void *)node;
	struct btf_struct_meta *meta = meta__ign;

	return __bpf_list_add(n, head, true, meta ? meta->record : NULL, off);
}

static struct bpf_list_node *__bpf_list_del(struct bpf_list_head *head, bool tail)
{
	struct list_head *n, *h = (void *)head;
	struct bpf_list_node_kern *node;

	/* If list_head was 0-initialized by map, bpf_obj_init_field wasn't
	 * called on its fields, so init here
	 */
	if (unlikely(!h->next))
		INIT_LIST_HEAD(h);
	if (list_empty(h))
		return NULL;

	n = tail ? h->prev : h->next;
	node = container_of(n, struct bpf_list_node_kern, list_head);
	if (WARN_ON_ONCE(READ_ONCE(node->owner) != head))
		return NULL;

	list_del_init(n);
	WRITE_ONCE(node->owner, NULL);
	return (struct bpf_list_node *)n;
}

__bpf_kfunc struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head)
{
	return __bpf_list_del(head, false);
}

__bpf_kfunc struct bpf_list_node *bpf_list_pop_back(struct bpf_list_head *head)
{
	return __bpf_list_del(head, true);
}

__bpf_kfunc struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
						  struct bpf_rb_node *node)
{
	struct bpf_rb_node_kern *node_internal = (struct bpf_rb_node_kern *)node;
	struct rb_root_cached *r = (struct rb_root_cached *)root;
	struct rb_node *n = &node_internal->rb_node;

	/* node_internal->owner != root implies either RB_EMPTY_NODE(n) or
	 * n is owned by some other tree. No need to check RB_EMPTY_NODE(n)
	 */
	if (READ_ONCE(node_internal->owner) != root)
		return NULL;

	rb_erase_cached(n, r);
	RB_CLEAR_NODE(n);
	WRITE_ONCE(node_internal->owner, NULL);
	return (struct bpf_rb_node *)n;
}

/* Need to copy rbtree_add_cached's logic here because our 'less' is a BPF
 * program
 */
static int __bpf_rbtree_add(struct bpf_rb_root *root,
			    struct bpf_rb_node_kern *node,
			    void *less, struct btf_record *rec, u64 off)
{
	struct rb_node **link = &((struct rb_root_cached *)root)->rb_root.rb_node;
	struct rb_node *parent = NULL, *n = &node->rb_node;
	bpf_callback_t cb = (bpf_callback_t)less;
	bool leftmost = true;

	/* node->owner != NULL implies !RB_EMPTY_NODE(n), no need to separately
	 * check the latter
	 */
	if (cmpxchg(&node->owner, NULL, BPF_PTR_POISON)) {
		/* Only called from BPF prog, no need to migrate_disable */
		__bpf_obj_drop_impl((void *)n - off, rec, false);
		return -EINVAL;
	}

	while (*link) {
		parent = *link;
		if (cb((uintptr_t)node, (uintptr_t)parent, 0, 0, 0)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(n, parent, link);
	rb_insert_color_cached(n, (struct rb_root_cached *)root, leftmost);
	WRITE_ONCE(node->owner, root);
	return 0;
}

__bpf_kfunc int bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
				    bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b),
				    void *meta__ign, u64 off)
{
	struct btf_struct_meta *meta = meta__ign;
	struct bpf_rb_node_kern *n = (void *)node;

	return __bpf_rbtree_add(root, n, (void *)less, meta ? meta->record : NULL, off);
}

__bpf_kfunc struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root)
{
	struct rb_root_cached *r = (struct rb_root_cached *)root;

	return (struct bpf_rb_node *)rb_first_cached(r);
}

/**
 * bpf_task_acquire - Acquire a reference to a task. A task acquired by this
 * kfunc which is not stored in a map as a kptr, must be released by calling
 * bpf_task_release().
 * @p: The task on which a reference is being acquired.
 */
__bpf_kfunc struct task_struct *bpf_task_acquire(struct task_struct *p)
{
	if (refcount_inc_not_zero(&p->rcu_users))
		return p;
	return NULL;
}

/**
 * bpf_task_release - Release the reference acquired on a task.
 * @p: The task on which a reference is being released.
 */
__bpf_kfunc void bpf_task_release(struct task_struct *p)
{
	put_task_struct_rcu_user(p);
}

__bpf_kfunc void bpf_task_release_dtor(void *p)
{
	put_task_struct_rcu_user(p);
}
CFI_NOSEAL(bpf_task_release_dtor);

#ifdef CONFIG_CGROUPS
/**
 * bpf_cgroup_acquire - Acquire a reference to a cgroup. A cgroup acquired by
 * this kfunc which is not stored in a map as a kptr, must be released by
 * calling bpf_cgroup_release().
 * @cgrp: The cgroup on which a reference is being acquired.
 */
__bpf_kfunc struct cgroup *bpf_cgroup_acquire(struct cgroup *cgrp)
{
	return cgroup_tryget(cgrp) ? cgrp : NULL;
}

/**
 * bpf_cgroup_release - Release the reference acquired on a cgroup.
 * If this kfunc is invoked in an RCU read region, the cgroup is guaranteed to
 * not be freed until the current grace period has ended, even if its refcount
 * drops to 0.
 * @cgrp: The cgroup on which a reference is being released.
 */
__bpf_kfunc void bpf_cgroup_release(struct cgroup *cgrp)
{
	cgroup_put(cgrp);
}

__bpf_kfunc void bpf_cgroup_release_dtor(void *cgrp)
{
	cgroup_put(cgrp);
}
CFI_NOSEAL(bpf_cgroup_release_dtor);

/**
 * bpf_cgroup_ancestor - Perform a lookup on an entry in a cgroup's ancestor
 * array. A cgroup returned by this kfunc which is not subsequently stored in a
 * map, must be released by calling bpf_cgroup_release().
 * @cgrp: The cgroup for which we're performing a lookup.
 * @level: The level of ancestor to look up.
 */
__bpf_kfunc struct cgroup *bpf_cgroup_ancestor(struct cgroup *cgrp, int level)
{
	struct cgroup *ancestor;

	if (level > cgrp->level || level < 0)
		return NULL;

	/* cgrp's refcnt could be 0 here, but ancestors can still be accessed */
	ancestor = cgrp->ancestors[level];
	if (!cgroup_tryget(ancestor))
		return NULL;
	return ancestor;
}

/**
 * bpf_cgroup_from_id - Find a cgroup from its ID. A cgroup returned by this
 * kfunc which is not subsequently stored in a map, must be released by calling
 * bpf_cgroup_release().
 * @cgid: cgroup id.
 */
__bpf_kfunc struct cgroup *bpf_cgroup_from_id(u64 cgid)
{
	struct cgroup *cgrp;

	cgrp = __cgroup_get_from_id(cgid);
	if (IS_ERR(cgrp))
		return NULL;
	return cgrp;
}

/**
 * bpf_task_under_cgroup - wrap task_under_cgroup_hierarchy() as a kfunc, test
 * task's membership of cgroup ancestry.
 * @task: the task to be tested
 * @ancestor: possible ancestor of @task's cgroup
 *
 * Tests whether @task's default cgroup hierarchy is a descendant of @ancestor.
 * It follows all the same rules as cgroup_is_descendant, and only applies
 * to the default hierarchy.
 */
__bpf_kfunc long bpf_task_under_cgroup(struct task_struct *task,
				       struct cgroup *ancestor)
{
	long ret;

	rcu_read_lock();
	ret = task_under_cgroup_hierarchy(task, ancestor);
	rcu_read_unlock();
	return ret;
}

BPF_CALL_2(bpf_current_task_under_cgroup, struct bpf_map *, map, u32, idx)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct cgroup *cgrp;

	if (unlikely(idx >= array->map.max_entries))
		return -E2BIG;

	cgrp = READ_ONCE(array->ptrs[idx]);
	if (unlikely(!cgrp))
		return -EAGAIN;

	return task_under_cgroup_hierarchy(current, cgrp);
}

const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
	.func           = bpf_current_task_under_cgroup,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
};

/**
 * bpf_task_get_cgroup1 - Acquires the associated cgroup of a task within a
 * specific cgroup1 hierarchy. The cgroup1 hierarchy is identified by its
 * hierarchy ID.
 * @task: The target task
 * @hierarchy_id: The ID of a cgroup1 hierarchy
 *
 * On success, the cgroup is returen. On failure, NULL is returned.
 */
__bpf_kfunc struct cgroup *
bpf_task_get_cgroup1(struct task_struct *task, int hierarchy_id)
{
	struct cgroup *cgrp = task_get_cgroup1(task, hierarchy_id);

	if (IS_ERR(cgrp))
		return NULL;
	return cgrp;
}
#endif /* CONFIG_CGROUPS */

/**
 * bpf_task_from_pid - Find a struct task_struct from its pid by looking it up
 * in the root pid namespace idr. If a task is returned, it must either be
 * stored in a map, or released with bpf_task_release().
 * @pid: The pid of the task being looked up.
 */
__bpf_kfunc struct task_struct *bpf_task_from_pid(s32 pid)
{
	struct task_struct *p;

	rcu_read_lock();
	p = find_task_by_pid_ns(pid, &init_pid_ns);
	if (p)
		p = bpf_task_acquire(p);
	rcu_read_unlock();

	return p;
}

/**
 * bpf_dynptr_slice() - Obtain a read-only pointer to the dynptr data.
 * @p: The dynptr whose data slice to retrieve
 * @offset: Offset into the dynptr
 * @buffer__opt: User-provided buffer to copy contents into.  May be NULL
 * @buffer__szk: Size (in bytes) of the buffer if present. This is the
 *               length of the requested slice. This must be a constant.
 *
 * For non-skb and non-xdp type dynptrs, there is no difference between
 * bpf_dynptr_slice and bpf_dynptr_data.
 *
 *  If buffer__opt is NULL, the call will fail if buffer_opt was needed.
 *
 * If the intention is to write to the data slice, please use
 * bpf_dynptr_slice_rdwr.
 *
 * The user must check that the returned pointer is not null before using it.
 *
 * Please note that in the case of skb and xdp dynptrs, bpf_dynptr_slice
 * does not change the underlying packet data pointers, so a call to
 * bpf_dynptr_slice will not invalidate any ctx->data/data_end pointers in
 * the bpf program.
 *
 * Return: NULL if the call failed (eg invalid dynptr), pointer to a read-only
 * data slice (can be either direct pointer to the data or a pointer to the user
 * provided buffer, with its contents containing the data, if unable to obtain
 * direct pointer)
 */
__bpf_kfunc void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
				   void *buffer__opt, u32 buffer__szk)
{
	const struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;
	enum bpf_dynptr_type type;
	u32 len = buffer__szk;
	int err;

	if (!ptr->data)
		return NULL;

	err = bpf_dynptr_check_off_len(ptr, offset, len);
	if (err)
		return NULL;

	type = bpf_dynptr_get_type(ptr);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		return ptr->data + ptr->offset + offset;
	case BPF_DYNPTR_TYPE_SKB:
		if (buffer__opt)
			return skb_header_pointer(ptr->data, ptr->offset + offset, len, buffer__opt);
		else
			return skb_pointer_if_linear(ptr->data, ptr->offset + offset, len);
	case BPF_DYNPTR_TYPE_XDP:
	{
		void *xdp_ptr = bpf_xdp_pointer(ptr->data, ptr->offset + offset, len);
		if (!IS_ERR_OR_NULL(xdp_ptr))
			return xdp_ptr;

		if (!buffer__opt)
			return NULL;
		bpf_xdp_copy_buf(ptr->data, ptr->offset + offset, buffer__opt, len, false);
		return buffer__opt;
	}
	default:
		WARN_ONCE(true, "unknown dynptr type %d\n", type);
		return NULL;
	}
}

/**
 * bpf_dynptr_slice_rdwr() - Obtain a writable pointer to the dynptr data.
 * @p: The dynptr whose data slice to retrieve
 * @offset: Offset into the dynptr
 * @buffer__opt: User-provided buffer to copy contents into. May be NULL
 * @buffer__szk: Size (in bytes) of the buffer if present. This is the
 *               length of the requested slice. This must be a constant.
 *
 * For non-skb and non-xdp type dynptrs, there is no difference between
 * bpf_dynptr_slice and bpf_dynptr_data.
 *
 * If buffer__opt is NULL, the call will fail if buffer_opt was needed.
 *
 * The returned pointer is writable and may point to either directly the dynptr
 * data at the requested offset or to the buffer if unable to obtain a direct
 * data pointer to (example: the requested slice is to the paged area of an skb
 * packet). In the case where the returned pointer is to the buffer, the user
 * is responsible for persisting writes through calling bpf_dynptr_write(). This
 * usually looks something like this pattern:
 *
 * struct eth_hdr *eth = bpf_dynptr_slice_rdwr(&dynptr, 0, buffer, sizeof(buffer));
 * if (!eth)
 *	return TC_ACT_SHOT;
 *
 * // mutate eth header //
 *
 * if (eth == buffer)
 *	bpf_dynptr_write(&ptr, 0, buffer, sizeof(buffer), 0);
 *
 * Please note that, as in the example above, the user must check that the
 * returned pointer is not null before using it.
 *
 * Please also note that in the case of skb and xdp dynptrs, bpf_dynptr_slice_rdwr
 * does not change the underlying packet data pointers, so a call to
 * bpf_dynptr_slice_rdwr will not invalidate any ctx->data/data_end pointers in
 * the bpf program.
 *
 * Return: NULL if the call failed (eg invalid dynptr), pointer to a
 * data slice (can be either direct pointer to the data or a pointer to the user
 * provided buffer, with its contents containing the data, if unable to obtain
 * direct pointer)
 */
__bpf_kfunc void *bpf_dynptr_slice_rdwr(const struct bpf_dynptr *p, u32 offset,
					void *buffer__opt, u32 buffer__szk)
{
	const struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data || __bpf_dynptr_is_rdonly(ptr))
		return NULL;

	/* bpf_dynptr_slice_rdwr is the same logic as bpf_dynptr_slice.
	 *
	 * For skb-type dynptrs, it is safe to write into the returned pointer
	 * if the bpf program allows skb data writes. There are two possibilities
	 * that may occur when calling bpf_dynptr_slice_rdwr:
	 *
	 * 1) The requested slice is in the head of the skb. In this case, the
	 * returned pointer is directly to skb data, and if the skb is cloned, the
	 * verifier will have uncloned it (see bpf_unclone_prologue()) already.
	 * The pointer can be directly written into.
	 *
	 * 2) Some portion of the requested slice is in the paged buffer area.
	 * In this case, the requested data will be copied out into the buffer
	 * and the returned pointer will be a pointer to the buffer. The skb
	 * will not be pulled. To persist the write, the user will need to call
	 * bpf_dynptr_write(), which will pull the skb and commit the write.
	 *
	 * Similarly for xdp programs, if the requested slice is not across xdp
	 * fragments, then a direct pointer will be returned, otherwise the data
	 * will be copied out into the buffer and the user will need to call
	 * bpf_dynptr_write() to commit changes.
	 */
	return bpf_dynptr_slice(p, offset, buffer__opt, buffer__szk);
}

__bpf_kfunc int bpf_dynptr_adjust(const struct bpf_dynptr *p, u32 start, u32 end)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;
	u32 size;

	if (!ptr->data || start > end)
		return -EINVAL;

	size = __bpf_dynptr_size(ptr);

	if (start > size || end > size)
		return -ERANGE;

	ptr->offset += start;
	bpf_dynptr_set_size(ptr, end - start);

	return 0;
}

__bpf_kfunc bool bpf_dynptr_is_null(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	return !ptr->data;
}

__bpf_kfunc bool bpf_dynptr_is_rdonly(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data)
		return false;

	return __bpf_dynptr_is_rdonly(ptr);
}

__bpf_kfunc __u32 bpf_dynptr_size(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data)
		return -EINVAL;

	return __bpf_dynptr_size(ptr);
}

__bpf_kfunc int bpf_dynptr_clone(const struct bpf_dynptr *p,
				 struct bpf_dynptr *clone__uninit)
{
	struct bpf_dynptr_kern *clone = (struct bpf_dynptr_kern *)clone__uninit;
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data) {
		bpf_dynptr_set_null(clone);
		return -EINVAL;
	}

	*clone = *ptr;

	return 0;
}

__bpf_kfunc void *bpf_cast_to_kern_ctx(void *obj)
{
	return obj;
}

__bpf_kfunc void *bpf_rdonly_cast(const void *obj__ign, u32 btf_id__k)
{
	return (void *)obj__ign;
}

__bpf_kfunc void bpf_rcu_read_lock(void)
{
	rcu_read_lock();
}

__bpf_kfunc void bpf_rcu_read_unlock(void)
{
	rcu_read_unlock();
}

struct bpf_throw_ctx {
	struct bpf_prog_aux *aux;
	u64 sp;
	u64 bp;
	int cnt;
};

static bool bpf_stack_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	struct bpf_throw_ctx *ctx = cookie;
	struct bpf_prog *prog;

	/*
	 * The RCU read lock is held to safely traverse the latch tree, but we
	 * don't need its protection when accessing the prog, since it has an
	 * active stack frame on the current stack trace, and won't disappear.
	 */
	rcu_read_lock();
	prog = bpf_prog_ksym_find(ip);
	rcu_read_unlock();
	if (!prog)
		return !ctx->cnt;
	ctx->cnt++;
	if (bpf_is_subprog(prog))
		return true;
	ctx->aux = prog->aux;
	ctx->sp = sp;
	ctx->bp = bp;
	return false;
}

__bpf_kfunc void bpf_throw(u64 cookie)
{
	struct bpf_throw_ctx ctx = {};

	arch_bpf_stack_walk(bpf_stack_walker, &ctx);
	WARN_ON_ONCE(!ctx.aux);
	if (ctx.aux)
		WARN_ON_ONCE(!ctx.aux->exception_boundary);
	WARN_ON_ONCE(!ctx.bp);
	WARN_ON_ONCE(!ctx.cnt);
	/* Prevent KASAN false positives for CONFIG_KASAN_STACK by unpoisoning
	 * deeper stack depths than ctx.sp as we do not return from bpf_throw,
	 * which skips compiler generated instrumentation to do the same.
	 */
	kasan_unpoison_task_stack_below((void *)(long)ctx.sp);
	ctx.aux->bpf_exception_cb(cookie, ctx.sp, ctx.bp, 0, 0);
	WARN(1, "A call to BPF exception callback should never return\n");
}

__bpf_kfunc int bpf_wq_init(struct bpf_wq *wq, void *p__map, unsigned int flags)
{
	struct bpf_async_kern *async = (struct bpf_async_kern *)wq;
	struct bpf_map *map = p__map;

	BUILD_BUG_ON(sizeof(struct bpf_async_kern) > sizeof(struct bpf_wq));
	BUILD_BUG_ON(__alignof__(struct bpf_async_kern) != __alignof__(struct bpf_wq));

	if (flags)
		return -EINVAL;

	return __bpf_async_init(async, map, flags, BPF_ASYNC_TYPE_WQ);
}

__bpf_kfunc int bpf_wq_start(struct bpf_wq *wq, unsigned int flags)
{
	struct bpf_async_kern *async = (struct bpf_async_kern *)wq;
	struct bpf_work *w;

	if (in_nmi())
		return -EOPNOTSUPP;
	if (flags)
		return -EINVAL;
	w = READ_ONCE(async->work);
	if (!w || !READ_ONCE(w->cb.prog))
		return -EINVAL;

	schedule_work(&w->work);
	return 0;
}

__bpf_kfunc int bpf_wq_set_callback_impl(struct bpf_wq *wq,
					 int (callback_fn)(void *map, int *key, void *value),
					 unsigned int flags,
					 void *aux__ign)
{
	struct bpf_prog_aux *aux = (struct bpf_prog_aux *)aux__ign;
	struct bpf_async_kern *async = (struct bpf_async_kern *)wq;

	if (flags)
		return -EINVAL;

	return __bpf_async_set_callback(async, callback_fn, aux, flags, BPF_ASYNC_TYPE_WQ);
}

__bpf_kfunc void bpf_preempt_disable(void)
{
	preempt_disable();
}

__bpf_kfunc void bpf_preempt_enable(void)
{
	preempt_enable();
}

struct bpf_iter_bits {
	__u64 __opaque[2];
} __aligned(8);

#define BITS_ITER_NR_WORDS_MAX 511

struct bpf_iter_bits_kern {
	union {
		__u64 *bits;
		__u64 bits_copy;
	};
	int nr_bits;
	int bit;
} __aligned(8);

/* On 64-bit hosts, unsigned long and u64 have the same size, so passing
 * a u64 pointer and an unsigned long pointer to find_next_bit() will
 * return the same result, as both point to the same 8-byte area.
 *
 * For 32-bit little-endian hosts, using a u64 pointer or unsigned long
 * pointer also makes no difference. This is because the first iterated
 * unsigned long is composed of bits 0-31 of the u64 and the second unsigned
 * long is composed of bits 32-63 of the u64.
 *
 * However, for 32-bit big-endian hosts, this is not the case. The first
 * iterated unsigned long will be bits 32-63 of the u64, so swap these two
 * ulong values within the u64.
 */
static void swap_ulong_in_u64(u64 *bits, unsigned int nr)
{
#if (BITS_PER_LONG == 32) && defined(__BIG_ENDIAN)
	unsigned int i;

	for (i = 0; i < nr; i++)
		bits[i] = (bits[i] >> 32) | ((u64)(u32)bits[i] << 32);
#endif
}

/**
 * bpf_iter_bits_new() - Initialize a new bits iterator for a given memory area
 * @it: The new bpf_iter_bits to be created
 * @unsafe_ptr__ign: A pointer pointing to a memory area to be iterated over
 * @nr_words: The size of the specified memory area, measured in 8-byte units.
 * The maximum value of @nr_words is @BITS_ITER_NR_WORDS_MAX. This limit may be
 * further reduced by the BPF memory allocator implementation.
 *
 * This function initializes a new bpf_iter_bits structure for iterating over
 * a memory area which is specified by the @unsafe_ptr__ign and @nr_words. It
 * copies the data of the memory area to the newly created bpf_iter_bits @it for
 * subsequent iteration operations.
 *
 * On success, 0 is returned. On failure, ERR is returned.
 */
__bpf_kfunc int
bpf_iter_bits_new(struct bpf_iter_bits *it, const u64 *unsafe_ptr__ign, u32 nr_words)
{
	struct bpf_iter_bits_kern *kit = (void *)it;
	u32 nr_bytes = nr_words * sizeof(u64);
	u32 nr_bits = BYTES_TO_BITS(nr_bytes);
	int err;

	BUILD_BUG_ON(sizeof(struct bpf_iter_bits_kern) != sizeof(struct bpf_iter_bits));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_bits_kern) !=
		     __alignof__(struct bpf_iter_bits));

	kit->nr_bits = 0;
	kit->bits_copy = 0;
	kit->bit = -1;

	if (!unsafe_ptr__ign || !nr_words)
		return -EINVAL;
	if (nr_words > BITS_ITER_NR_WORDS_MAX)
		return -E2BIG;

	/* Optimization for u64 mask */
	if (nr_bits == 64) {
		err = bpf_probe_read_kernel_common(&kit->bits_copy, nr_bytes, unsafe_ptr__ign);
		if (err)
			return -EFAULT;

		swap_ulong_in_u64(&kit->bits_copy, nr_words);

		kit->nr_bits = nr_bits;
		return 0;
	}

	if (bpf_mem_alloc_check_size(false, nr_bytes))
		return -E2BIG;

	/* Fallback to memalloc */
	kit->bits = bpf_mem_alloc(&bpf_global_ma, nr_bytes);
	if (!kit->bits)
		return -ENOMEM;

	err = bpf_probe_read_kernel_common(kit->bits, nr_bytes, unsafe_ptr__ign);
	if (err) {
		bpf_mem_free(&bpf_global_ma, kit->bits);
		return err;
	}

	swap_ulong_in_u64(kit->bits, nr_words);

	kit->nr_bits = nr_bits;
	return 0;
}

/**
 * bpf_iter_bits_next() - Get the next bit in a bpf_iter_bits
 * @it: The bpf_iter_bits to be checked
 *
 * This function returns a pointer to a number representing the value of the
 * next bit in the bits.
 *
 * If there are no further bits available, it returns NULL.
 */
__bpf_kfunc int *bpf_iter_bits_next(struct bpf_iter_bits *it)
{
	struct bpf_iter_bits_kern *kit = (void *)it;
	int bit = kit->bit, nr_bits = kit->nr_bits;
	const void *bits;

	if (!nr_bits || bit >= nr_bits)
		return NULL;

	bits = nr_bits == 64 ? &kit->bits_copy : kit->bits;
	bit = find_next_bit(bits, nr_bits, bit + 1);
	if (bit >= nr_bits) {
		kit->bit = bit;
		return NULL;
	}

	kit->bit = bit;
	return &kit->bit;
}

/**
 * bpf_iter_bits_destroy() - Destroy a bpf_iter_bits
 * @it: The bpf_iter_bits to be destroyed
 *
 * Destroy the resource associated with the bpf_iter_bits.
 */
__bpf_kfunc void bpf_iter_bits_destroy(struct bpf_iter_bits *it)
{
	struct bpf_iter_bits_kern *kit = (void *)it;

	if (kit->nr_bits <= 64)
		return;
	bpf_mem_free(&bpf_global_ma, kit->bits);
}

/**
 * bpf_copy_from_user_str() - Copy a string from an unsafe user address
 * @dst:             Destination address, in kernel space.  This buffer must be
 *                   at least @dst__sz bytes long.
 * @dst__sz:         Maximum number of bytes to copy, includes the trailing NUL.
 * @unsafe_ptr__ign: Source address, in user space.
 * @flags:           The only supported flag is BPF_F_PAD_ZEROS
 *
 * Copies a NUL-terminated string from userspace to BPF space. If user string is
 * too long this will still ensure zero termination in the dst buffer unless
 * buffer size is 0.
 *
 * If BPF_F_PAD_ZEROS flag is set, memset the tail of @dst to 0 on success and
 * memset all of @dst on failure.
 */
__bpf_kfunc int bpf_copy_from_user_str(void *dst, u32 dst__sz, const void __user *unsafe_ptr__ign, u64 flags)
{
	int ret;

	if (unlikely(flags & ~BPF_F_PAD_ZEROS))
		return -EINVAL;

	if (unlikely(!dst__sz))
		return 0;

	ret = strncpy_from_user(dst, unsafe_ptr__ign, dst__sz - 1);
	if (ret < 0) {
		if (flags & BPF_F_PAD_ZEROS)
			memset((char *)dst, 0, dst__sz);

		return ret;
	}

	if (flags & BPF_F_PAD_ZEROS)
		memset((char *)dst + ret, 0, dst__sz - ret);
	else
		((char *)dst)[ret] = '\0';

	return ret + 1;
}

/*
 * Write current task's executable path into @buf at probe-fire time.
 * Companion to gustack: lets the BPF program populate the record's
 * exe_path slot before submitting, eliminating the worker-side
 * lookup race that loses short-lived processes (cat, ls) which exit
 * before the bifrost guest worker drains the ringbuf.
 *
 * Returns bytes written including NUL terminator on success, 0 if
 * the firing context has no usable mm (kthread, exit race), negative
 * errno on buffer too small.
 *
 * Non-sleepable: get_task_mm/d_path/fput/mmput are all atomic-safe.
 */
__bpf_kfunc int bifrost_kfunc_current_exe_path(void *buf, u32 buf__sz)
{
	return bifrost_task_exe_path(current, (char *)buf, buf__sz);
}

/*
 * Forward declaration: the dedup table + helper live further down
 * (alongside the publish path that originally introduced them).
 * Wrapping `bifrost_kfunc_emit_vma_table` with the same dedup check
 * lets us short-circuit the d_path() loop on hot uprobe/kprobe
 * workloads where the same task fires repeatedly.
 */
static bool bifrost_vma_pub_test_and_set(u32 tgid, u32 exec_id);

/*
 * Sentinel n_vmas value the kernel writes when the per-fire dedup
 * check hits. The host's `VmaTable::parse` rejects records with
 * this value via its bounds check (`HDR_SIZE + n_vmas * ENTRY_SIZE
 * > body.len()` overflows), preserving its existing cached table.
 * Backwards-compatible: pre-dedup hosts also reject the sentinel
 * via the same overflow path.
 */
#define BIFROST_VMA_TABLE_DEDUP_SENTINEL 0xFFFFFFFEu

/*
 * Pack the firing process's file-backed VMA table into @buf so the
 * gustack symbolicator on the host can resolve PCs across libraries
 * (libc, ld-musl, vdso) — not just the main exe. The host caches
 * the table by gpid until the next emit.
 *
 * Per-fire dedup: a process's file-backed VMA layout is fixed at
 * exec() time and immutable until the next exec — there's no point
 * shipping the same table through shmem on every gustack fire.
 * Once we've published for a given (tgid, self_exec_id), subsequent
 * fires write a 16-byte sentinel header and skip the d_path() loop.
 * The dedup table keys on `self_exec_id` so an exec() (or a recycled
 * tgid after the previous task exited and a new one took the same
 * pid) correctly invalidates the entry.
 *
 * See `bifrost_emit_vma_table` for wire format.
 */
__bpf_kfunc int bifrost_kfunc_emit_vma_table(void *buf, u32 buf__sz)
{
	struct task_struct *task = current;
	struct bifrost_vma_table_hdr_kern *hdr;

	if (task && !(task->flags & PF_KTHREAD) &&
	    bifrost_vma_pub_test_and_set(task->tgid, task->self_exec_id)) {
		if (!buf || buf__sz < sizeof(*hdr))
			return -EINVAL;
		hdr = (struct bifrost_vma_table_hdr_kern *)buf;
		memset(hdr, 0, sizeof(*hdr));
		hdr->n_vmas = BIFROST_VMA_TABLE_DEDUP_SENTINEL;
		return sizeof(*hdr);
	}
	return bifrost_emit_vma_table(task, (char *)buf, buf__sz);
}

/*
 * Phase 2: SHMEM event ringbuf reserve. Atomic CAS on producer_pos
 * in the SHMEM header; returns a pointer into the data area on
 * success, NULL on full / not-yet-initialized / size-too-large /
 * end-of-buffer wrap. Replaces `bpf_ringbuf_reserve` in the
 * gustack lowering when the SHMEM data plane is active.
 *
 * The `size__k` parameter has the `__k` suffix so the BPF verifier
 * tracks it as a compile-time constant — paired with our verifier
 * patch (special_kfunc_list entry), this lets the verifier type
 * the return as `PTR_TO_MEM` with `mem_size == size__k` so the
 * BPF program can write up to `size__k` bytes into the returned
 * buffer. Without `__k`, the verifier treats the void* return
 * as a scalar and rejects every subsequent store.
 */
/*
 * Internal SHMEM ringbuf reserve, callable from both BPF (via
 * the kfunc wrapper below) and regular kernel context (used by
 * push_agg_snapshot in the bifrost guest module). Same atomic
 * CAS + wraparound logic; just lifted out of the BPF kfunc.
 */
/* W8: per-CPU speculation state.  Sized so the cross-CPU
 * footprint stays bounded.  `active_lane != 0` ⇒ subsequent
 * `bifrost_shmem_reserve_kernel_class` calls route into the
 * per-CPU side buffer instead of the principal sub-ring;
 * `commit()` replays buffered records back through the same
 * reserve path with the lane deactivated. */
#define BIFROST_SPEC_RECORDS_PER_CPU 16
#define BIFROST_SPEC_RECORD_MAX 1024

struct bifrost_spec_state {
	u32 active_lane;
	u32 buffered;
	u32 record_sizes[BIFROST_SPEC_RECORDS_PER_CPU];
	u32 record_classes[BIFROST_SPEC_RECORDS_PER_CPU];
	u8 records[BIFROST_SPEC_RECORDS_PER_CPU][BIFROST_SPEC_RECORD_MAX];
};
DEFINE_PER_CPU(struct bifrost_spec_state, bifrost_spec_state);

/* Class-aware kernel-internal reserve. The BPF-callable kfunc
 * below defaults to PRINCIPAL; other in-kernel call sites
 * (push_agg_snapshot, publish_vma_table, symtab pumps) pass
 * AGG / STKSTR explicitly so the W7 drop summary can attribute
 * which class is overloaded. */
void *bifrost_shmem_reserve_kernel_class(u32 size, unsigned int class)
{
	char *base = READ_ONCE(bifrost_shmem_va);
	struct bifrost_shmem_ringbuf_hdr *hdr;
	struct bifrost_shmem_per_cpu *pc;
	struct bifrost_spec_state *spec;
	u64 aligned, cur, new_pos, cons;
	u64 rb_off, rb_len, off_in_rb;
	u64 per_cpu_len;
	u32 *rec_hdr;
	char *data;
	unsigned int cpu;

	if (!base || !size || size > BIFROST_RB_MAX_RECORD)
		return NULL;

	/* W8: speculation routing.  If the current CPU has an
	 * active speculation lane and the record fits the
	 * per-CPU side buffer, return a pointer into the side
	 * buffer instead of the principal sub-ring.  `commit`
	 * later replays each buffered record back through this
	 * function with `active_lane == 0`. */
	spec = this_cpu_ptr(&bifrost_spec_state);
	if (spec->active_lane != 0
	    && spec->buffered < BIFROST_SPEC_RECORDS_PER_CPU
	    && size + 8 <= BIFROST_SPEC_RECORD_MAX) {
		u8 *rec = spec->records[spec->buffered];
		u32 *spec_hdr = (u32 *)rec;

		spec_hdr[0] = size;
		spec_hdr[1] = 0;
		spec->record_sizes[spec->buffered] = size;
		spec->record_classes[spec->buffered] = class;
		spec->buffered++;
		return rec + 8;
	}
	/* If we're speculating but the buffer is full or the
	 * record is too large, drop into the DBLERR-equivalent
	 * "speculation buffer overflow" class so the user sees
	 * something.  Returning NULL prevents the record from
	 * landing anywhere. */
	if (spec->active_lane != 0) {
		hdr = (struct bifrost_shmem_ringbuf_hdr *)base;
		if (hdr->num_cpus) {
			cpu = smp_processor_id() % hdr->num_cpus;
			atomic64_inc(&hdr->per_cpu[cpu]
					      .dropped_records[BIFROST_DROP_CLASS_DBLERR]);
		}
		return NULL;
	}
	hdr = (struct bifrost_shmem_ringbuf_hdr *)base;
	rb_off = hdr->ringbuf_off;
	rb_len = hdr->ringbuf_len;
	per_cpu_len = hdr->per_cpu_ring_len;
	if (!rb_len || !per_cpu_len || !hdr->num_cpus)
		return NULL;

	cpu = smp_processor_id() % hdr->num_cpus;
	pc = &hdr->per_cpu[cpu];
	data = base + rb_off + (u64)cpu * per_cpu_len;

	aligned = ALIGN(BIFROST_RB_RECORD_HDR + size, 8);

	for (;;) {
		cur = atomic64_read(&pc->producer_pos);
		cons = atomic64_read(&pc->consumer_pos);
		off_in_rb = cur % per_cpu_len;

		if (off_in_rb + aligned > per_cpu_len) {
			u64 pad_size = per_cpu_len - off_in_rb;
			if (cur + pad_size - cons > per_cpu_len) {
				bifrost_shmem_note_drop(hdr, cpu, size, class);
				return NULL;
			}
			new_pos = cur + pad_size;
			if (atomic64_cmpxchg(&pc->producer_pos, cur,
					     new_pos) != cur) {
				cpu_relax();
				continue;
			}
			rec_hdr = (u32 *)(data + off_in_rb);
			rec_hdr[0] = pad_size - BIFROST_RB_RECORD_HDR;
			smp_store_release(
				&rec_hdr[1],
				BIFROST_RB_FLAG_READY | BIFROST_RB_FLAG_PADDING);
			continue;
		}

		if (cur + aligned - cons > per_cpu_len) {
			bifrost_shmem_note_drop(hdr, cpu, size, class);
			return NULL;
		}
		new_pos = cur + aligned;
		if (atomic64_cmpxchg(&pc->producer_pos, cur, new_pos) == cur)
			break;
		cpu_relax();
	}

	rec_hdr = (u32 *)(data + off_in_rb);
	rec_hdr[0] = size;
	WRITE_ONCE(rec_hdr[1], 0); /* flags = busy */
	return (char *)rec_hdr + BIFROST_RB_RECORD_HDR;
}
EXPORT_SYMBOL_GPL(bifrost_shmem_reserve_kernel_class);

/* Backwards-compatible kernel-internal entry: defaults to
 * PRINCIPAL drop attribution. Callers that know which class
 * they're emitting (agg snapshots, VMA tables, symtab pushes)
 * should use `bifrost_shmem_reserve_kernel_class` directly. */
void *bifrost_shmem_reserve_kernel(u32 size)
{
	return bifrost_shmem_reserve_kernel_class(
		size, BIFROST_DROP_CLASS_PRINCIPAL);
}
EXPORT_SYMBOL_GPL(bifrost_shmem_reserve_kernel);

/*
 * BPF kfunc form. Mirrors `bifrost_shmem_reserve_kernel` but
 * with the `__k` suffix on the size arg so the verifier tracks
 * it as a constant — paired with the verifier-side
 * `special_kfunc_list` entry in kernel/bpf/verifier.c, this lets
 * the verifier type the void* return as PTR_TO_MEM with
 * mem_size == size__k so BPF programs can write up to size__k
 * bytes into the buffer.
 */
__bpf_kfunc void *bifrost_kfunc_shmem_reserve(u32 size__k)
{
	return bifrost_shmem_reserve_kernel(size__k);
}

/*
 * Internal SHMEM ringbuf submit (kernel-context form).
 */
void bifrost_shmem_submit_kernel(void *ptr)
{
	u32 *flags;

	if (!ptr)
		return;
	flags = (u32 *)((char *)ptr - 4);
	smp_store_release(flags, BIFROST_RB_FLAG_READY);
}
EXPORT_SYMBOL_GPL(bifrost_shmem_submit_kernel);

/*
 * Mark a previously-reserved record ready. Release-store on the
 * flags field pairs with the consumer's acquire-load so all prior
 * payload writes are visible.
 *
 * The `ptr__ign` arg uses the `__ign` suffix so the BPF verifier
 * doesn't require a typed pointer — submit accepts whatever the
 * companion reserve returned (PTR_TO_MEM after our verifier patch).
 */
__bpf_kfunc void bifrost_kfunc_shmem_submit(void *ptr__ign)
{
	bifrost_shmem_submit_kernel(ptr__ign);
}

/*
 * Phase 3b: VMA-table publish-on-first-fire-per-(tgid, exec_id).
 *
 * Replaces the per-fire VMA-table side-trip emitted by gustack
 * lowering. Internal flow:
 *   1. Compute key = (tgid << 32) | exec_id  (exec_id from
 *      current->self_exec_id — bumps on execve).
 *   2. Linear-probe a small in-module hash table for the key.
 *   3. If found, return 0 (already published — caller skips).
 *   4. Otherwise: reserve a 4096-byte record in the SHMEM ringbuf,
 *      stamp correlation (vmid=0, probe_id=0xFFFFFFFF magic, ktime,
 *      pid_tgid), fill body via bifrost_emit_vma_table, submit.
 *      Insert key into the hash table.
 *
 * Returns 1 on publish, 0 on skip (already seen), negative on
 * out-of-space / hash-table-full.
 *
 * Record size sized for BIFROST_VMA_TABLE_MAX=32: header(16) + 32
 * entries × 32B = 1040 bytes; remaining 3032 bytes hold path strings
 * (~95 B/path average is plenty for /usr/lib/aarch64-linux-gnu/ paths).
 */
#define BIFROST_VMA_PUB_BUCKETS 4096
#define BIFROST_VMA_PUB_PROBE_DEPTH 16
#define BIFROST_VMA_PUB_PROBE_MAGIC 0xFFFFFFFFu
#define BIFROST_VMA_REC_SIZE 4096
#define BIFROST_VMA_REC_BODY_SIZE (BIFROST_VMA_REC_SIZE - 24)

struct bifrost_vma_pub_entry {
	u64 key; /* (tgid << 32) | exec_id; 0 == empty */
};
static struct bifrost_vma_pub_entry
	bifrost_vma_pub_table[BIFROST_VMA_PUB_BUCKETS];
static DEFINE_SPINLOCK(bifrost_vma_pub_lock);

static bool bifrost_vma_pub_test_and_set(u32 tgid, u32 exec_id)
{
	u64 key = ((u64)tgid << 32) | exec_id;
	u32 idx, i;
	bool already_seen = false;
	unsigned long flags;

	if (key == 0)
		key = 1; /* avoid 0 sentinel; not strictly necessary */
	idx = hash_64(key, 12) & (BIFROST_VMA_PUB_BUCKETS - 1);

	spin_lock_irqsave(&bifrost_vma_pub_lock, flags);
	for (i = 0; i < BIFROST_VMA_PUB_PROBE_DEPTH; i++) {
		u32 slot = (idx + i) & (BIFROST_VMA_PUB_BUCKETS - 1);
		if (bifrost_vma_pub_table[slot].key == key) {
			already_seen = true;
			break;
		}
		if (bifrost_vma_pub_table[slot].key == 0) {
			bifrost_vma_pub_table[slot].key = key;
			break;
		}
	}
	/* Probe overflow: treat as not-seen so we re-emit; bounded
	 * extra cost is acceptable vs. losing the VMA table. */
	spin_unlock_irqrestore(&bifrost_vma_pub_lock, flags);
	return already_seen;
}

static void bifrost_vma_pub_clear(u32 tgid, u32 exec_id)
{
	u64 key = ((u64)tgid << 32) | exec_id;
	u32 idx, i;
	unsigned long flags;

	if (key == 0)
		key = 1;
	idx = hash_64(key, 12) & (BIFROST_VMA_PUB_BUCKETS - 1);

	spin_lock_irqsave(&bifrost_vma_pub_lock, flags);
	for (i = 0; i < BIFROST_VMA_PUB_PROBE_DEPTH; i++) {
		u32 slot = (idx + i) & (BIFROST_VMA_PUB_BUCKETS - 1);

		if (bifrost_vma_pub_table[slot].key == key) {
			bifrost_vma_pub_table[slot].key = 0;
			break;
		}
		if (bifrost_vma_pub_table[slot].key == 0)
			break;
	}
	spin_unlock_irqrestore(&bifrost_vma_pub_lock, flags);
}

/*
 * Phase 4 doorbell. The bifrost guest module publishes a
 * `void (*kick_doorbell)(void *priv)` callback + private cookie
 * via `bifrost_set_doorbell_callback`; this kfunc invokes it. The
 * callback does a single virtqueue_kick on the dedicated
 * vq_doorbell — host's vq_doorbell handler signals an EventFd
 * that the SHMEM consumer thread blocks on (kqueue/poll), waking
 * it within ~3-10 µs of this kfunc's return (per HVF spike).
 *
 * Rate-limiting: only fires the doorbell when the consumer has
 * fallen behind by more than `BIFROST_DOORBELL_THRESHOLD_BYTES`
 * bytes (producer_pos / consumer_pos are byte-counted). Sized at
 * 4 KB ≈ 6-8 typical records — long enough that the consumer's
 * brief busy-poll (16 × 100 µs = 1.6 ms) has a chance to drain
 * the queue before we MMIO-trap.
 */
#define BIFROST_DOORBELL_THRESHOLD_BYTES 4096
typedef void (*bifrost_kick_fn_t)(void *priv);
static bifrost_kick_fn_t bifrost_kick_fn __read_mostly;
static void *bifrost_kick_priv __read_mostly;

int bifrost_set_doorbell_callback(bifrost_kick_fn_t fn, void *priv)
{
	WRITE_ONCE(bifrost_kick_priv, priv);
	smp_wmb();
	WRITE_ONCE(bifrost_kick_fn, fn);
	return 0;
}
EXPORT_SYMBOL_GPL(bifrost_set_doorbell_callback);

void bifrost_clear_doorbell_callback(void)
{
	WRITE_ONCE(bifrost_kick_fn, NULL);
	smp_wmb();
	WRITE_ONCE(bifrost_kick_priv, NULL);
}
EXPORT_SYMBOL_GPL(bifrost_clear_doorbell_callback);

__bpf_kfunc void bifrost_kfunc_shmem_kick(void)
{
	char *base = READ_ONCE(bifrost_shmem_va);
	struct bifrost_shmem_ringbuf_hdr *hdr;
	struct bifrost_shmem_per_cpu *pc;
	bifrost_kick_fn_t fn;
	u64 prod, cons;
	unsigned int cpu;

	fn = READ_ONCE(bifrost_kick_fn);
	if (!fn || !base)
		return;
	hdr = (struct bifrost_shmem_ringbuf_hdr *)base;
	if (!hdr->num_cpus)
		return;
	/* W1: only kick when *this CPU's* sub-ring has fallen
	 * meaningfully behind. False negatives (this CPU's consumer
	 * asleep but distance < threshold) are bounded — the
	 * consumer's per-CPU drain loop picks them up on its next
	 * poll cycle. The single-ring layout's threshold (4 KB)
	 * mapped to ~6-8 typical records on a 6 MB ring; on a
	 * per-CPU sub-ring of ~384 KB that's still the right
	 * order-of-magnitude wake threshold. */
	cpu = smp_processor_id() % hdr->num_cpus;
	pc = &hdr->per_cpu[cpu];
	prod = atomic64_read(&pc->producer_pos);
	cons = atomic64_read(&pc->consumer_pos);
	if (prod - cons < BIFROST_DOORBELL_THRESHOLD_BYTES)
		return;
	fn(READ_ONCE(bifrost_kick_priv));
}

__bpf_kfunc int bifrost_kfunc_publish_vma_table(void)
{
	struct task_struct *task = current;
	u64 pid_tgid;
	u32 tgid, exec_id;
	char *base;
	u8 *rec, *body;
	int written;

	if (!task || (task->flags & PF_KTHREAD))
		return 0;
	pid_tgid = ((u64)task->tgid << 32) | (u32)task->pid;
	tgid = task->tgid;
	exec_id = task->self_exec_id;

	base = READ_ONCE(bifrost_shmem_va);
	if (!base)
		return -ENOENT;
	if (bifrost_vma_pub_test_and_set(tgid, exec_id))
		return 0; /* already published */
	rec = bifrost_shmem_reserve_kernel_class(BIFROST_VMA_REC_SIZE,
						  BIFROST_DROP_CLASS_STKSTR);
	if (!rec) {
		bifrost_vma_pub_clear(tgid, exec_id);
		return -ENOSPC;
	}
	/* Correlation header. */
	*(u32 *)(rec + 0) = 0;                                /* vmid */
	*(u32 *)(rec + 4) = BIFROST_VMA_PUB_PROBE_MAGIC;       /* probe_id */
	*(u64 *)(rec + 8) = ktime_get_ns();                    /* gns */
	*(u64 *)(rec + 16) = pid_tgid;                         /* gpid */
	/* Body. */
	body = rec + 24;
	written = bifrost_emit_vma_table(task, (char *)body,
					 BIFROST_VMA_REC_BODY_SIZE);
	if (written < 0) {
		/* Best effort: zero the body and submit anyway so the
		 * host doesn't choke on stale memory. */
		memset(body, 0, BIFROST_VMA_REC_BODY_SIZE);
	}
	bifrost_shmem_submit_kernel(rec);
	return 1;
}

/*
 * W10: walltimestamp(). Returns CLOCK_REALTIME nanoseconds since
 * the Unix epoch — the same clock `date +%s%N` reads. The pre-W10
 * lowering aliased `bpf_ktime_get_boot_ns` which returned monotonic
 * ns since boot, so scripts comparing against absolute wall time
 * silently saw bogus values. `ktime_get_real_ns` is the kernel's
 * canonical "wall-clock now" call and is safe from any context
 * (irq, NMI, preemption disabled).
 */
__bpf_kfunc u64 bifrost_kfunc_walltime_ns(void)
{
	return ktime_get_real_ns();
}

/*
 * W10: vtimestamp().  DTrace's contract is "the total amount
 * of time the current thread has been running on a CPU, minus
 * the time spent in DTrace probe context."  The kernel
 * scheduler already tracks per-task on-CPU runtime accurately
 * in `task_struct.se.sum_exec_runtime` (nanoseconds), updated
 * on every context switch and tick.  Returning this directly
 * gives the user a monotonic per-thread CPU-time clock that
 * advances at thread-scheduling-runtime scale (not wall-clock
 * scale) — exactly the semantic dtrace(1) scripts rely on to
 * separate "wall time" deltas from "thread CPU time" deltas.
 *
 * The "minus probe context" subtraction is an approximation
 * we accept: Bifrost probes complete in microseconds and run
 * with preemption disabled inside the BPF runtime, so the
 * probe-context window is short and not separately tracked by
 * the scheduler accounting.  Two consecutive reads of
 * `vtimestamp` from the same thread bracket the thread's CPU
 * time over the interval — the probe overhead itself is
 * included in the delta, but at single-digit-microsecond cost
 * the noise floor is negligible for any realistic profile
 * workload.
 *
 * Returns 0 if `current` is NULL (idle context shouldn't
 * fire a Bifrost-lowered probe but the guard is cheap).
 */
__bpf_kfunc u64 bifrost_kfunc_vtimestamp_ns(void)
{
	struct task_struct *t = current;

	if (!t)
		return 0;
	return t->se.sum_exec_runtime;
}

/*
 * W10: progenyof(pid). Returns 1 if @target_pid is `current` or
 * any ancestor of `current`, walking up `real_parent` to init.
 *
 * Bounded loop: we cap at BIFROST_PROGENYOF_MAX_DEPTH so a
 * pathological ancestor chain (or a corrupt task_struct under
 * concurrent task tearaway) can't spin the verifier or block
 * forever. PID 1 (init) terminates the chain naturally — if we
 * see real_parent == itself before hitting init, that's the
 * idle/init boundary; we stop and return 0.
 *
 * Compares against `tgid` (the user-visible "process ID"), not
 * the kernel's per-thread `pid`. Matches DTrace semantics where
 * `progenyof(N)` cares about the process tree, not threads.
 */
/*
 * W3: bump the per-CPU `BIFROST_DROP_CLASS_DBLERR` counter for
 * the current CPU when a fault-prone kfunc returns NULL / 0 on
 * an unrecoverable input (NULL pointer, -EFAULT from
 * `strncpy_from_user`, ancestor walk hitting the idle/init
 * boundary).  Surfaces in the host CLI's drop summary as the
 * `dblerr=N` class — the W7 per-class drop taxonomy was already
 * shipping with `dblerr` rendered, just with no producer until
 * now.  Gives users a visible signal that one of their
 * fault-prone kfunc calls (copyin / copyinstr / strchr / strrchr
 * / strstr / strjoin / substr / progenyof) silently no-op'd.
 *
 * Called from the kfunc error paths only; the kfuncs themselves
 * still return the documented sentinel (NULL pointer or 0) so
 * the BPF verifier's KF_RET_NULL contract is preserved and
 * existing scripts continue to gracefully degrade.
 */
static inline void bifrost_kfunc_note_fault(void)
{
	struct bifrost_shmem_ringbuf_hdr *hdr;
	char *base;
	unsigned int cpu;

	base = READ_ONCE(bifrost_shmem_va);
	if (!base)
		return;
	hdr = (struct bifrost_shmem_ringbuf_hdr *)base;
	if (!hdr->num_cpus)
		return;
	cpu = smp_processor_id() % hdr->num_cpus;
	atomic64_inc(
		&hdr->per_cpu[cpu].dropped_records[BIFROST_DROP_CLASS_DBLERR]);
}

#define BIFROST_PROGENYOF_MAX_DEPTH 64
__bpf_kfunc u64 bifrost_kfunc_progenyof(u32 target_pid)
{
	struct task_struct *t = current;
	unsigned int depth;

	if (!t) {
		bifrost_kfunc_note_fault();
		return 0;
	}
	rcu_read_lock();
	for (depth = 0; depth < BIFROST_PROGENYOF_MAX_DEPTH; depth++) {
		struct task_struct *parent;

		if (!t)
			break;
		if ((u32)t->tgid == target_pid) {
			rcu_read_unlock();
			return 1;
		}
		parent = rcu_dereference(t->real_parent);
		if (!parent || parent == t)
			break;
		t = parent;
	}
	rcu_read_unlock();
	return 0;
}

/*
 * W9: strlen(s). DTrace's `strlen(string s)` returns the number
 * of bytes before the first NUL, capped at the on-disk string
 * limit. We bound the read at BIFROST_STR_MAX bytes so the
 * verifier accepts the call from any probe context, and use
 * `bpf_probe_read_user_str` for safe user-space fault handling.
 *
 * Returns 0 if @uaddr is NULL or unreadable, matching DTrace's
 * "no fault, just zero" semantics. Real action-fault routing
 * lives behind W3 (dtrace:::ERROR clauses).
 */
#define BIFROST_STR_MAX 256
__bpf_kfunc u64 bifrost_kfunc_strlen(const char *uaddr)
{
	char buf[BIFROST_STR_MAX];
	long n;

	if (!uaddr) {
		bifrost_kfunc_note_fault();
		return 0;
	}
	n = strncpy_from_user(buf, (const char __user *)uaddr,
			       BIFROST_STR_MAX);
	if (n < 0) {
		bifrost_kfunc_note_fault();
		return 0;
	}
	if (n == BIFROST_STR_MAX)
		n = BIFROST_STR_MAX - 1;
	return (u64)n;
}

/*
 * W9: copyinstr(uaddr). Bounded NUL-terminated user-string copy
 * into a per-CPU scratch buffer; returns a kernel pointer that
 * BPF programs use as a `string` operand to `printf("%s", ...)`.
 *
 * Per-CPU scratch is reused across calls in the same probe — a
 * probe that calls copyinstr twice gets the second result back
 * from the same buffer, overwriting the first. This matches
 * DTrace's "copyinstr scratch is short-lived" contract: callers
 * are expected to use the result immediately (e.g. as a printf
 * argument), not stash it.
 */
DEFINE_PER_CPU(char[BIFROST_STR_MAX], bifrost_copyinstr_scratch);

__bpf_kfunc char *bifrost_kfunc_copyinstr(const char *uaddr)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	long n;

	if (!uaddr) {
		bifrost_kfunc_note_fault();
		buf[0] = '\0';
		return buf;
	}
	n = strncpy_from_user(buf, (const char __user *)uaddr,
			       BIFROST_STR_MAX);
	if (n < 0) {
		bifrost_kfunc_note_fault();
		buf[0] = '\0';
		return buf;
	}
	if (n >= BIFROST_STR_MAX)
		buf[BIFROST_STR_MAX - 1] = '\0';
	return buf;
}

/*
 * W9: strchr(s, c) — first occurrence of byte @needle in
 * user-string @uaddr. Returns a kernel pointer into the per-CPU
 * scratch buffer (the same one `copyinstr` writes into) at the
 * matching offset, or the buffer's NUL slot when @needle is 0
 * and the string has room (matches DTrace's "strchr(s, '\0')
 * returns end-of-string"), or NULL if not found / unreadable.
 *
 * Bound: BIFROST_STR_MAX bytes. Longer haystacks are silently
 * truncated, matching the rest of the W9 string built-ins.
 */
__bpf_kfunc char *bifrost_kfunc_strchr(const char *uaddr, u64 needle)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	char target = (char)(needle & 0xff);
	long n;
	long i;

	if (!uaddr) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	n = strncpy_from_user(buf, (const char __user *)uaddr,
			       BIFROST_STR_MAX);
	if (n < 0) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	if (n >= BIFROST_STR_MAX)
		n = BIFROST_STR_MAX - 1;
	for (i = 0; i < n; i++) {
		if (buf[i] == target)
			return &buf[i];
	}
	/* DTrace's strchr(s, '\0') returns a pointer to the
	 * terminating NUL; copyinstr already wrote it at buf[n]. */
	if (target == '\0')
		return &buf[n];
	return NULL;
}

/*
 * W9: strrchr(s, c) — last occurrence of byte @needle.
 * Same scratch + bound semantics as strchr; iterates from the
 * end backward so the first match wins.
 */
__bpf_kfunc char *bifrost_kfunc_strrchr(const char *uaddr, u64 needle)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	char target = (char)(needle & 0xff);
	long n;
	long i;

	if (!uaddr) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	n = strncpy_from_user(buf, (const char __user *)uaddr,
			       BIFROST_STR_MAX);
	if (n < 0) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	if (n >= BIFROST_STR_MAX)
		n = BIFROST_STR_MAX - 1;
	if (target == '\0')
		return &buf[n];
	for (i = n - 1; i >= 0; i--) {
		if (buf[i] == target)
			return &buf[i];
	}
	return NULL;
}

/*
 * W9: copyin(uaddr, len) — bounded byte copy from user memory
 * into a per-CPU scratch buffer. Unlike copyinstr this does NOT
 * stop at NUL; the requested length is honored up to
 * BIFROST_STR_MAX. Returns a kernel pointer that BPF programs
 * use as a generic byte blob (for tracemem-style emission).
 *
 * Reuses the same per-CPU scratch buffer as copyinstr/strchr/
 * strrchr — callers that interleave the calls in one probe must
 * consume the result before the next call.
 */
__bpf_kfunc void *bifrost_kfunc_copyin(const char *uaddr, u64 len)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	u64 cap = len < BIFROST_STR_MAX ? len : BIFROST_STR_MAX;
	long rc;

	if (!uaddr || cap == 0) {
		bifrost_kfunc_note_fault();
		buf[0] = '\0';
		return buf;
	}
	rc = copy_from_user(buf, (const void __user *)uaddr, cap);
	if (rc != 0) {
		bifrost_kfunc_note_fault();
		/* Best-effort: zero on partial-or-failed copy so the
		 * caller sees a deterministic blob instead of stale
		 * scratch bytes. */
		memset(buf, 0, cap);
	}
	return buf;
}

/*
 * W9 auxiliary scratch — strstr / index / strjoin / substr need
 * a SECOND per-CPU buffer so two user strings can be staged at
 * the same time. Sized to match BIFROST_STR_MAX so the kernel-side
 * search loops stay within a fixed bound the verifier can prove.
 */
DEFINE_PER_CPU(char[BIFROST_STR_MAX], bifrost_copyinstr_scratch_aux);

/*
 * W9: strstr(haystack, needle). Returns a pointer into the
 * primary per-CPU scratch buffer at the first occurrence of
 * `needle` in `haystack`, or NULL if not found / unreadable.
 * Both args are user pointers to NUL-terminated strings.
 *
 * Implementation: O(n*m) byte-wise search after copying both
 * strings into per-CPU scratch. Empty needle returns the start
 * of haystack (matches DTrace semantics).
 */
__bpf_kfunc char *bifrost_kfunc_strstr(const char *uaddr_h,
				       const char *uaddr_n)
{
	char *h = this_cpu_ptr(bifrost_copyinstr_scratch);
	char *n = this_cpu_ptr(bifrost_copyinstr_scratch_aux);
	long hlen, nlen, i, j;

	if (!uaddr_h || !uaddr_n) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	hlen = strncpy_from_user(h, (const char __user *)uaddr_h,
				  BIFROST_STR_MAX);
	if (hlen < 0) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	if (hlen >= BIFROST_STR_MAX)
		hlen = BIFROST_STR_MAX - 1;
	nlen = strncpy_from_user(n, (const char __user *)uaddr_n,
				  BIFROST_STR_MAX);
	if (nlen < 0) {
		bifrost_kfunc_note_fault();
		return NULL;
	}
	if (nlen >= BIFROST_STR_MAX)
		nlen = BIFROST_STR_MAX - 1;
	if (nlen == 0)
		return h;
	if (nlen > hlen)
		return NULL;
	for (i = 0; i <= hlen - nlen; i++) {
		for (j = 0; j < nlen; j++) {
			if (h[i + j] != n[j])
				break;
		}
		if (j == nlen)
			return &h[i];
	}
	return NULL;
}

/*
 * W9: index(haystack, needle). Like `strstr` but returns the
 * zero-based byte offset, or -1 if not found / unreadable.
 * (DTrace returns the offset as an integer scalar, hence the
 * u64 return type bit-packing a signed -1 as 0xFFFFFFFFFFFFFFFF.)
 */
__bpf_kfunc u64 bifrost_kfunc_index(const char *uaddr_h,
				    const char *uaddr_n)
{
	char *p = bifrost_kfunc_strstr(uaddr_h, uaddr_n);
	char *h = this_cpu_ptr(bifrost_copyinstr_scratch);

	if (!p)
		return (u64)-1L;
	return (u64)(p - h);
}

/*
 * W9: strjoin(a, b). Concatenates two user strings into the
 * primary per-CPU scratch buffer. Total length bounded by
 * BIFROST_STR_MAX (the second copy stops early if the first
 * fills the buffer).
 */
__bpf_kfunc char *bifrost_kfunc_strjoin(const char *uaddr_a,
					const char *uaddr_b)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	long alen, blen, room;

	if (!uaddr_a) {
		buf[0] = '\0';
		alen = 0;
	} else {
		alen = strncpy_from_user(buf, (const char __user *)uaddr_a,
					  BIFROST_STR_MAX);
		if (alen < 0)
			alen = 0;
		if (alen >= BIFROST_STR_MAX)
			alen = BIFROST_STR_MAX - 1;
	}
	room = BIFROST_STR_MAX - alen - 1;
	if (uaddr_b && room > 0) {
		blen = strncpy_from_user(buf + alen,
					  (const char __user *)uaddr_b,
					  room + 1);
		if (blen < 0)
			blen = 0;
		if (blen > room)
			blen = room;
		buf[alen + blen] = '\0';
	} else {
		buf[alen] = '\0';
	}
	return buf;
}

/*
 * W9: substr(s, idx, len). Returns a pointer to the primary
 * per-CPU scratch buffer holding `len` bytes of `s` starting at
 * byte offset `idx`. Out-of-range or negative parameters clamp
 * to a zero-length result (matches DTrace's "no fault, just
 * empty" semantics).
 */
__bpf_kfunc char *bifrost_kfunc_substr(const char *uaddr,
				       u64 idx, u64 len)
{
	char *buf = this_cpu_ptr(bifrost_copyinstr_scratch);
	char *aux = this_cpu_ptr(bifrost_copyinstr_scratch_aux);
	long n;
	long start, end, sublen;

	if (!uaddr) {
		buf[0] = '\0';
		return buf;
	}
	n = strncpy_from_user(aux, (const char __user *)uaddr,
			       BIFROST_STR_MAX);
	if (n < 0) {
		buf[0] = '\0';
		return buf;
	}
	if (n >= BIFROST_STR_MAX)
		n = BIFROST_STR_MAX - 1;
	start = (long)idx;
	if (start < 0 || start >= n) {
		buf[0] = '\0';
		return buf;
	}
	sublen = (long)len;
	if (sublen < 0)
		sublen = 0;
	end = start + sublen;
	if (end > n)
		end = n;
	if (end - start >= BIFROST_STR_MAX)
		end = start + BIFROST_STR_MAX - 1;
	memcpy(buf, aux + start, end - start);
	buf[end - start] = '\0';
	return buf;
}

/*
 * W8: speculation lifecycle.  Real DTrace speculation routes
 * record reservations into per-lane side buffers until
 * `commit()` promotes them or `discard()` drops them.  This
 * implementation supports a single active lane per CPU (lane
 * id 1).  A real per-CPU bounded buffer holds up to
 * `BIFROST_SPEC_RECORDS_PER_CPU` records of at most
 * `BIFROST_SPEC_RECORD_MAX` bytes each.
 *
 *   speculation()      Allocate lane 1 on this CPU if no
 *                      active lane.  Returns 0 if already
 *                      speculating; returns 1 on success.
 *   speculate(id)      For id==1, set the per-CPU active
 *                      lane to 1 so subsequent
 *                      `bifrost_shmem_reserve_kernel_class`
 *                      calls route into the per-CPU side
 *                      buffer instead of the principal
 *                      sub-ring.
 *   commit(id)         For id==1, replay every buffered
 *                      record into the principal sub-ring
 *                      via the standard reserve/submit
 *                      path, then deactivate the lane.
 *   discard(id)        For id==1, zero the buffered count
 *                      and deactivate the lane.
 *
 * Per-CPU storage is sized at ~16 KB so the cross-CPU footprint
 * is bounded at `BIFROST_NUM_CPUS_MAX * 16 KB = 256 KB`.
 * Records exceeding `BIFROST_SPEC_RECORD_MAX` or arriving past
 * `BIFROST_SPEC_RECORDS_PER_CPU` are dropped (commit replays
 * only what fit).  See the `struct bifrost_spec_state`
 * declaration above `bifrost_shmem_reserve_kernel_class`.
 */
__bpf_kfunc u64 bifrost_kfunc_speculation(void)
{
	struct bifrost_spec_state *s = this_cpu_ptr(&bifrost_spec_state);

	if (s->active_lane != 0)
		return 0;
	return 1;
}

__bpf_kfunc void bifrost_kfunc_speculate(u64 id)
{
	struct bifrost_spec_state *s = this_cpu_ptr(&bifrost_spec_state);

	if (id == 1 && s->active_lane == 0) {
		s->active_lane = 1;
		s->buffered = 0;
	}
}

__bpf_kfunc void bifrost_kfunc_commit(u64 id)
{
	struct bifrost_spec_state *s = this_cpu_ptr(&bifrost_spec_state);
	u32 i;

	if (id != 1 || s->active_lane != 1)
		return;
	/* Turn off speculation BEFORE replay so the replay calls
	 * route through the principal path. */
	s->active_lane = 0;
	for (i = 0; i < s->buffered; i++) {
		u32 sz = s->record_sizes[i];
		u32 cls = s->record_classes[i];
		void *dst;

		if (sz == 0 || sz > BIFROST_SPEC_RECORD_MAX - 8)
			continue;
		dst = bifrost_shmem_reserve_kernel_class(sz, cls);
		if (dst) {
			memcpy(dst, &s->records[i][8], sz);
			bifrost_shmem_submit_kernel(dst);
		}
	}
	s->buffered = 0;
}

__bpf_kfunc void bifrost_kfunc_discard(u64 id)
{
	struct bifrost_spec_state *s = this_cpu_ptr(&bifrost_spec_state);

	if (id != 1)
		return;
	s->active_lane = 0;
	s->buffered = 0;
}

/*
 * W5a: clear(@agg).  DTrace's `clear()` zeros every entry of
 * an aggregation map.  The `__map` arg suffix routes through
 * the verifier's `KF_ARG_PTR_TO_MAP` path so the BPF program
 * emits `bpf_ld_map_fd(r1, agg_fd); call <kfunc>` and the
 * verifier resolves the agg's fake_fd to a real `struct bpf_map *`
 * at LOAD_PROG time.  Walks every key (PERCPU_ARRAY by integer
 * index; PERCPU_HASH via `map_get_next_key`) and zeroes every
 * per-CPU value slot in place.  Bounded at
 * `BIFROST_CLEAR_MAX_KEYS` so a misconfigured large map can't
 * monopolise the kernel.
 */
#define BIFROST_CLEAR_MAX_KEYS 65536
#define BIFROST_CLEAR_MAX_KEY_SIZE 64

__bpf_kfunc int bifrost_kfunc_clear_agg(struct bpf_map *map__map)
{
	struct bpf_map *map = map__map;
	u32 value_size;
	int cpu;

	if (!map || !map->ops)
		return -EINVAL;
	if (!map->ops->map_lookup_percpu_elem)
		return -EINVAL;
	value_size = map->value_size;
	/* Largest agg slot today is 24 bytes (stddev); cap at 64
	 * so future small additions don't need a recompile, while
	 * a misconfigured map still gets rejected. */
	if (value_size == 0 || value_size > BIFROST_CLEAR_MAX_KEY_SIZE)
		return -EINVAL;

	if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		u32 key;
		u32 max = map->max_entries;

		if (max > BIFROST_CLEAR_MAX_KEYS)
			max = BIFROST_CLEAR_MAX_KEYS;
		for (key = 0; key < max; key++) {
			for_each_possible_cpu(cpu) {
				void *val = map->ops->map_lookup_percpu_elem(
					map, &key, cpu);

				if (val)
					memset(val, 0, value_size);
			}
		}
		return 0;
	}

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH) {
		u8 cur_key[BIFROST_CLEAR_MAX_KEY_SIZE];
		u8 next_key[BIFROST_CLEAR_MAX_KEY_SIZE];
		void *prev = NULL;
		u32 key_size = map->key_size;
		int n;

		if (key_size == 0 || key_size > BIFROST_CLEAR_MAX_KEY_SIZE)
			return -EINVAL;

		for (n = 0; n < BIFROST_CLEAR_MAX_KEYS; n++) {
			int err;

			rcu_read_lock();
			err = map->ops->map_get_next_key(map, prev, next_key);
			rcu_read_unlock();
			if (err == -ENOENT)
				break;
			if (err)
				return err;

			for_each_possible_cpu(cpu) {
				void *val = map->ops->map_lookup_percpu_elem(
					map, next_key, cpu);

				if (val)
					memset(val, 0, value_size);
			}

			memcpy(cur_key, next_key, key_size);
			prev = cur_key;
		}
		return 0;
	}

	return -EINVAL;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(generic_btf_ids)
#ifdef CONFIG_CRASH_DUMP
BTF_ID_FLAGS(func, crash_kexec, KF_DESTRUCTIVE)
#endif
BTF_ID_FLAGS(func, bpf_obj_new_impl, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_percpu_obj_new_impl, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_obj_drop_impl, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_percpu_obj_drop_impl, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_refcount_acquire_impl, KF_ACQUIRE | KF_RET_NULL | KF_RCU)
BTF_ID_FLAGS(func, bpf_list_push_front_impl)
BTF_ID_FLAGS(func, bpf_list_push_back_impl)
BTF_ID_FLAGS(func, bpf_list_pop_front, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_list_pop_back, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_task_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_task_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_rbtree_remove, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_rbtree_add_impl)
BTF_ID_FLAGS(func, bpf_rbtree_first, KF_RET_NULL)

#ifdef CONFIG_CGROUPS
BTF_ID_FLAGS(func, bpf_cgroup_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cgroup_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_cgroup_ancestor, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cgroup_from_id, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_task_under_cgroup, KF_RCU)
BTF_ID_FLAGS(func, bpf_task_get_cgroup1, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
#endif
BTF_ID_FLAGS(func, bpf_task_from_pid, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_throw)
BTF_KFUNCS_END(generic_btf_ids)

static const struct btf_kfunc_id_set generic_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &generic_btf_ids,
};


BTF_ID_LIST(generic_dtor_ids)
BTF_ID(struct, task_struct)
BTF_ID(func, bpf_task_release_dtor)
#ifdef CONFIG_CGROUPS
BTF_ID(struct, cgroup)
BTF_ID(func, bpf_cgroup_release_dtor)
#endif

BTF_KFUNCS_START(common_btf_ids)
BTF_ID_FLAGS(func, bpf_cast_to_kern_ctx)
BTF_ID_FLAGS(func, bpf_rdonly_cast)
BTF_ID_FLAGS(func, bpf_rcu_read_lock)
BTF_ID_FLAGS(func, bpf_rcu_read_unlock)
BTF_ID_FLAGS(func, bpf_dynptr_slice, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_dynptr_slice_rdwr, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_num_new, KF_ITER_NEW)
BTF_ID_FLAGS(func, bpf_iter_num_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_num_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_iter_task_vma_new, KF_ITER_NEW | KF_RCU)
BTF_ID_FLAGS(func, bpf_iter_task_vma_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_task_vma_destroy, KF_ITER_DESTROY)
#ifdef CONFIG_CGROUPS
BTF_ID_FLAGS(func, bpf_iter_css_task_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_css_task_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_css_task_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_iter_css_new, KF_ITER_NEW | KF_TRUSTED_ARGS | KF_RCU_PROTECTED)
BTF_ID_FLAGS(func, bpf_iter_css_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_css_destroy, KF_ITER_DESTROY)
#endif
BTF_ID_FLAGS(func, bpf_iter_task_new, KF_ITER_NEW | KF_TRUSTED_ARGS | KF_RCU_PROTECTED)
BTF_ID_FLAGS(func, bpf_iter_task_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_task_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_dynptr_adjust)
BTF_ID_FLAGS(func, bpf_dynptr_is_null)
BTF_ID_FLAGS(func, bpf_dynptr_is_rdonly)
BTF_ID_FLAGS(func, bpf_dynptr_size)
BTF_ID_FLAGS(func, bpf_dynptr_clone)
BTF_ID_FLAGS(func, bpf_modify_return_test_tp)
BTF_ID_FLAGS(func, bpf_wq_init)
BTF_ID_FLAGS(func, bpf_wq_set_callback_impl)
BTF_ID_FLAGS(func, bpf_wq_start)
BTF_ID_FLAGS(func, bpf_preempt_disable)
BTF_ID_FLAGS(func, bpf_preempt_enable)
BTF_ID_FLAGS(func, bpf_iter_bits_new, KF_ITER_NEW)
BTF_ID_FLAGS(func, bpf_iter_bits_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_bits_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_copy_from_user_str, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bifrost_kfunc_current_exe_path)
BTF_ID_FLAGS(func, bifrost_kfunc_emit_vma_table)
BTF_ID_FLAGS(func, bifrost_kfunc_shmem_reserve, KF_RET_NULL)
BTF_ID_FLAGS(func, bifrost_kfunc_shmem_submit)
BTF_ID_FLAGS(func, bifrost_kfunc_publish_vma_table)
BTF_ID_FLAGS(func, bifrost_kfunc_shmem_kick)
/* W10: real wall-clock + ancestor walk. Both are pure (no
 * side-effects on guest state) — no special KF_* flags needed. */
BTF_ID_FLAGS(func, bifrost_kfunc_walltime_ns)
BTF_ID_FLAGS(func, bifrost_kfunc_vtimestamp_ns)
BTF_ID_FLAGS(func, bifrost_kfunc_progenyof)
/* W9: bounded user-string accessors. KF_SLEEPABLE is NOT set —
 * strncpy_from_user is fault-tolerant via pagefault_disable in
 * the BPF runtime, returning -EFAULT instead of sleeping. */
BTF_ID_FLAGS(func, bifrost_kfunc_strlen)
BTF_ID_FLAGS(func, bifrost_kfunc_copyinstr)
/* W9: strchr/strrchr return a pointer into the per-CPU scratch
 * buffer, or NULL if the byte isn't present. KF_RET_NULL signals
 * the verifier so callers must NULL-check before deref. */
BTF_ID_FLAGS(func, bifrost_kfunc_strchr, KF_RET_NULL)
BTF_ID_FLAGS(func, bifrost_kfunc_strrchr, KF_RET_NULL)
BTF_ID_FLAGS(func, bifrost_kfunc_copyin)
BTF_ID_FLAGS(func, bifrost_kfunc_strstr, KF_RET_NULL)
BTF_ID_FLAGS(func, bifrost_kfunc_index)
BTF_ID_FLAGS(func, bifrost_kfunc_strjoin)
BTF_ID_FLAGS(func, bifrost_kfunc_substr)
/* W8: speculation lifecycle.  Per-CPU `struct bifrost_spec_state`
 * carves a 16-slot × 1 KB side buffer; reserve routes there when
 * `active_lane != 0`; commit replays into the principal sub-ring;
 * discard zeroes the buffer. */
BTF_ID_FLAGS(func, bifrost_kfunc_speculation)
BTF_ID_FLAGS(func, bifrost_kfunc_speculate)
BTF_ID_FLAGS(func, bifrost_kfunc_commit)
BTF_ID_FLAGS(func, bifrost_kfunc_discard)
/* W5a: clear() walks the agg map's per-CPU value slots and zeroes
 * them in place.  `__map` arg suffix routes through the verifier's
 * KF_ARG_PTR_TO_MAP path. */
BTF_ID_FLAGS(func, bifrost_kfunc_clear_agg)
BTF_KFUNCS_END(common_btf_ids)

static const struct btf_kfunc_id_set common_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &common_btf_ids,
};

static int __init kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc generic_dtors[] = {
		{
			.btf_id       = generic_dtor_ids[0],
			.kfunc_btf_id = generic_dtor_ids[1]
		},
#ifdef CONFIG_CGROUPS
		{
			.btf_id       = generic_dtor_ids[2],
			.kfunc_btf_id = generic_dtor_ids[3]
		},
#endif
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &generic_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &generic_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &generic_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &generic_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &generic_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_CGROUP_SKB, &generic_kfunc_set);
	ret = ret ?: register_btf_id_dtor_kfuncs(generic_dtors,
						  ARRAY_SIZE(generic_dtors),
						  THIS_MODULE);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &common_kfunc_set);
}

late_initcall(kfunc_init);

/* Get a pointer to dynptr data up to len bytes for read only access. If
 * the dynptr doesn't have continuous data up to len bytes, return NULL.
 */
const void *__bpf_dynptr_data(const struct bpf_dynptr_kern *ptr, u32 len)
{
	const struct bpf_dynptr *p = (struct bpf_dynptr *)ptr;

	return bpf_dynptr_slice(p, 0, NULL, len);
}

/* Get a pointer to dynptr data up to len bytes for read write access. If
 * the dynptr doesn't have continuous data up to len bytes, or the dynptr
 * is read only, return NULL.
 */
void *__bpf_dynptr_data_rw(const struct bpf_dynptr_kern *ptr, u32 len)
{
	if (__bpf_dynptr_is_rdonly(ptr))
		return NULL;
	return (void *)__bpf_dynptr_data(ptr, len);
}
