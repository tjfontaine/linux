// SPDX-License-Identifier: GPL-2.0
// Shared uprobe entry and return handlers.

use kernel::bindings;
use kernel::ffi::c_int;

use crate::run_prog_slot;
use crate::slots::BifrostUprobe;

/// Shared uprobe entry handler.  Recovers the firing slot via
/// container-of on the `consumer` argument: `BifrostUprobe::consumer`
/// is the first field, so the consumer pointer is bit-identical to
/// the wrapper pointer.
pub(crate) unsafe extern "C" fn bifrost_uprobe_handler(
    self_consumer: *mut bindings::uprobe_consumer,
    regs: *mut bindings::pt_regs,
) -> c_int {
    unsafe {
        let bp = self_consumer as *const BifrostUprobe;
        run_prog_slot((*bp).slot as usize, regs);
    }
    0
}

/// Shared uretprobe handler.  pt_regs holds the return value in x0/rax,
/// matching DTrace's `:return` convention.
pub(crate) unsafe extern "C" fn bifrost_uretprobe_handler(
    self_consumer: *mut bindings::uprobe_consumer,
    _func: usize,
    regs: *mut bindings::pt_regs,
) -> c_int {
    unsafe {
        let bp = self_consumer as *const BifrostUprobe;
        run_prog_slot((*bp).slot as usize, regs);
    }
    0
}
