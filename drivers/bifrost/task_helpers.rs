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
    /// for_each_process under rcu_read_lock.  Returns NULL on no
    /// match.  See the helper file for the locking contract.
    fn bifrost_helper_find_task_by_comm(
        target: *const u8,
        target_len: u32,
    ) -> *mut bindings::task_struct;
}

/// Walk `for_each_process` looking for a task whose `comm` matches the
/// given basename.  Returns the first match (RCU-protected pointer; the
/// caller must hold rcu_read_lock or otherwise guarantee the task is
/// not freed while it dereferences the pointer — typically by using
/// `get_task_exe_file` immediately, which bumps a refcount on its
/// internal state).
///
/// This is the container-aware uprobe-target resolver: comm is the
/// kernel's own truncated-at-15-bytes name for the running task, set
/// at exec() time and visible from any mount namespace.  Once we have
/// the task we can grab its already-loaded exe_file via
/// `get_task_exe_file`, which gives us the actual `struct file *` the
/// kernel mapped — bypassing the need for kern_path's namespace-bound
/// lookup entirely.
///
/// SAFETY: the caller must use the returned pointer under rcu_read_lock
/// or call `get_task_exe_file` immediately to elevate the reference
/// before any other use.
pub(crate) unsafe fn find_task_by_comm(target: &[u8]) -> *mut bindings::task_struct {
    if target.is_empty() {
        return core::ptr::null_mut();
    }
    unsafe {
        bifrost_helper_find_task_by_comm(target.as_ptr(), target.len() as u32)
    }
}
