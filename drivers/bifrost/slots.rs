// SPDX-License-Identifier: GPL-2.0
// Heap-backed probe slot table and lease allocation.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use kernel::bindings;
use kernel::prelude::*;

use crate::wire::{MAX_PROBE_SLOTS, PROBE_TYPE_NONE};

/// Initial slot-table capacity allocated at module init.
///
/// **Phase C completion**: the slot table is now a
/// `KVec<KBox<BifrostSlot>>` that grows on demand; there is no hard
/// cap.  The driver pre-allocates `INITIAL_SLOT_HINT` slots to avoid
/// kmalloc churn for typical workloads.
pub(crate) const INITIAL_SLOT_HINT: usize = 8;

/// Compatibility soft cap referenced by the host CLI's preflight check.
/// The driver does not enforce this; `slots_ensure` grows past it on
/// demand.
pub(crate) const MAX_KPROBES: usize = MAX_PROBE_SLOTS;

/// Per-slot uprobe consumer wrapper.  Container-of slot recovery:
/// the kernel uprobe API holds `*mut uprobe_consumer` after register;
/// the shared uprobe handlers cast that pointer back to
/// `*const BifrostUprobe` because `consumer` is first.
#[repr(C)]
pub(crate) struct BifrostUprobe {
    pub(crate) consumer: bindings::uprobe_consumer,
    pub(crate) slot: u32,
}

/// Coalesced per-slot state.  Replaces the older parallel static arrays
/// for program pointers, target names, attach handles, and cleanup state.
#[repr(C)]
pub(crate) struct BifrostSlot {
    /// Probe family discriminant; sentinel `PROBE_TYPE_NONE` means
    /// "slot allocated but never registered."
    pub(crate) probe_type: u8,
    /// 32-byte NUL-padded target name.
    pub(crate) target_name: [u8; 32],
    /// Monotonic lease ID issued at attach time. 0 = no lease.
    pub(crate) lease: u64,
    /// JIT'd eBPF program pointer.
    pub(crate) prog: AtomicPtr<bindings::bpf_prog>,
    /// Uprobe consumer wrapper.
    pub(crate) uprobe: core::mem::MaybeUninit<BifrostUprobe>,
    /// Uprobe registration handle from `uprobe_register`.
    pub(crate) uprobe_handle: *mut bindings::uprobe,
    /// igrab'd inode pinning the uprobe target file.
    pub(crate) uprobe_inode: *mut bindings::inode,
    /// kern_path output.
    pub(crate) uprobe_path: bindings::path,
    /// FBT trampoline link.
    pub(crate) fbt_link: core::mem::MaybeUninit<bindings::bpf_tracing_link>,
    /// True when fbt_link is currently linked to a trampoline.
    pub(crate) fbt_linked: bool,
    /// Raw-tracepoint link.
    pub(crate) rawtp_link: core::mem::MaybeUninit<bindings::bpf_raw_tp_link>,
    /// Cached `bpf_raw_event_map *` for `bpf_put_raw_tracepoint`.
    pub(crate) rawtp_btp: *mut bindings::bpf_raw_event_map,
    /// True when rawtp_link is currently registered.
    pub(crate) rawtp_registered: bool,
}

impl BifrostSlot {
    const fn new() -> Self {
        Self {
            probe_type: PROBE_TYPE_NONE,
            target_name: [0u8; 32],
            lease: 0,
            prog: AtomicPtr::new(core::ptr::null_mut()),
            uprobe: core::mem::MaybeUninit::uninit(),
            uprobe_handle: core::ptr::null_mut(),
            uprobe_inode: core::ptr::null_mut(),
            uprobe_path: bindings::path {
                mnt: core::ptr::null_mut(),
                dentry: core::ptr::null_mut(),
            },
            fbt_link: core::mem::MaybeUninit::uninit(),
            fbt_linked: false,
            rawtp_link: core::mem::MaybeUninit::uninit(),
            rawtp_btp: core::ptr::null_mut(),
            rawtp_registered: false,
        }
    }
}

/// The single per-slot storage.  Heap-allocated via
/// `KVec<KBox<BifrostSlot>>`: KVec reallocations move only Box pointers,
/// not the slot bodies whose addresses are handed to kernel uprobe APIs.
static mut BIFROST_SLOTS_OPT: Option<KVec<KBox<BifrostSlot>>> = None;

/// Counter for the next slot to fill on LOAD_PROG.
pub(crate) static mut BIFROST_NUM_KPROBES: usize = 0;

static BIFROST_NEXT_LEASE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn bifrost_slots_init() -> Result<()> {
    // SAFETY: called exactly once during module init before any worker
    // thread is started; no concurrent access possible.
    unsafe {
        if BIFROST_SLOTS_OPT.is_some() {
            return Ok(());
        }
        let mut v: KVec<KBox<BifrostSlot>> = KVec::with_capacity(INITIAL_SLOT_HINT, GFP_KERNEL)?;
        for _ in 0..INITIAL_SLOT_HINT {
            let b = KBox::new(BifrostSlot::new(), GFP_KERNEL)?;
            v.push(b, GFP_KERNEL)?;
        }
        BIFROST_SLOTS_OPT = Some(v);
    }
    Ok(())
}

/// Ensure the slot table has at least `n` slots, allocating new
/// `KBox<BifrostSlot>` entries as needed.
pub(crate) unsafe fn slots_ensure(n: usize) -> Result<()> {
    unsafe {
        let v = BIFROST_SLOTS_OPT.as_mut().unwrap_unchecked();
        while v.len() < n {
            let b = KBox::new(BifrostSlot::new(), GFP_KERNEL)?;
            v.push(b, GFP_KERNEL)?;
        }
        Ok(())
    }
}

/// Slot-table accessor.  Returns a mutable slice of `KBox` pointers;
/// field access via `slots_mut()[i].field` autoderefs through `KBox`
/// to the underlying `BifrostSlot` body.
///
/// SAFETY: caller must ensure `bifrost_slots_init()` has run.
#[inline]
pub(crate) unsafe fn slots_mut() -> &'static mut [KBox<BifrostSlot>] {
    unsafe { BIFROST_SLOTS_OPT.as_mut().unwrap_unchecked().as_mut_slice() }
}

/// Allocate a fresh non-zero slot lease.
#[inline]
pub(crate) fn slot_lease_new() -> u64 {
    BIFROST_NEXT_LEASE.fetch_add(1, Ordering::AcqRel)
}
