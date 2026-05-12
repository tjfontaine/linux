// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/task_helpers.rs
//
// Task-lookup wrapper used by the uprobe-by-symbol attach path.
// The actual task walk happens in C
// (drivers/bifrost/bifrost_helpers.c::bifrost_helper_find_task_by_comm)
// so we can use the kernel's `for_each_process` macro and
// `rcu_read_lock` directly — both are inline-only on the C side.

use kernel::bindings;

unsafe extern "C" {
    /// C helper (drivers/bifrost/bifrost_helpers.c) — wraps
    /// for_each_process under rcu_read_lock. Returns NULL on no
    /// match, otherwise returns a refcounted task that must be
    /// released with `bifrost_helper_put_task_struct`.
    fn bifrost_helper_find_task_by_comm(
        target: *const u8,
        target_len: u32,
    ) -> *mut bindings::task_struct;

    /// Drop the task reference returned by
    /// `bifrost_helper_find_task_by_comm`.
    fn bifrost_helper_put_task_struct(task: *mut bindings::task_struct);
}

/// Walk `for_each_process` looking for a task whose `comm` matches the
/// given basename. Returns the first match with a task ref held; the
/// caller must release it with `put_task_ref`.
///
/// This is the container-aware uprobe-target resolver: comm is the
/// kernel's own truncated-at-15-bytes name for the running task, set
/// at exec() time and visible from any mount namespace.  Once we have
/// the task we can grab its already-loaded exe_file via
/// `get_task_exe_file`, which gives us the actual `struct file *` the
/// kernel mapped — bypassing the need for kern_path's namespace-bound
/// lookup entirely.
///
/// SAFETY: the returned pointer is a kernel task pointer. It remains
/// valid until the caller passes it to `put_task_ref`.
pub(crate) unsafe fn find_task_by_comm(target: &[u8]) -> *mut bindings::task_struct {
    if target.is_empty() {
        return core::ptr::null_mut();
    }
    unsafe { bifrost_helper_find_task_by_comm(target.as_ptr(), target.len() as u32) }
}

/// Release a task reference returned by `find_task_by_comm`.
pub(crate) unsafe fn put_task_ref(task: *mut bindings::task_struct) {
    if task.is_null() {
        return;
    }
    unsafe {
        bifrost_helper_put_task_struct(task);
    }
}
