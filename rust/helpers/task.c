// SPDX-License-Identifier: GPL-2.0

#include <linux/export.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

struct task_struct *rust_helper_get_current(void)
{
	return current;
}

void rust_helper_get_task_struct(struct task_struct *t)
{
	get_task_struct(t);
}

void rust_helper_put_task_struct(struct task_struct *t)
{
	put_task_struct(t);
}

/*
 * for_each_process() is a macro on init_task->tasks; not callable from
 * Rust directly. This wrapper iterates under rcu_read_lock and invokes
 * the caller's callback for each task. Callback returns nonzero to
 * terminate iteration (e.g., found a match); helper returns the same.
 *
 * Callback runs under RCU — no sleeping. If the caller wants to keep
 * the task alive past iteration, the callback must get_task_struct(p)
 * before returning nonzero.
 */
int rust_helper_for_each_process(int (*cb)(struct task_struct *, void *),
				 void *arg)
{
	struct task_struct *p;
	int ret = 0;

	rcu_read_lock();
	for_each_process(p) {
		if (cb(p, arg)) {
			ret = 1;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}
