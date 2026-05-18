// SPDX-License-Identifier: GPL-2.0
// Heap-backed probe slot table and lease allocation.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use kernel::bindings;
use kernel::prelude::*;

use crate::wire::{MAX_PROBE_SLOTS, PROBE_TYPE_NONE};

/// Slot-table capacity allocated at module init.
///
/// **Phase L (goal item 4)**: the slot table is now allocated full at
/// init time rather than growing on demand.  `KVec<KBox<BifrostSlot>>`
/// remains the underlying storage, but `KVec::push` is no longer
/// called past `bifrost_slots_init()`.  This closes the IRQ-vs-worker
/// race where the spine could be reallocated on one CPU while an
/// already-attached uprobe was firing `slots_mut()[K]` on another.
///
/// Sizing rationale: `MAX_PROBE_SLOTS = 256`, `sizeof(BifrostSlot)`
/// is small (~200 bytes after padding), so the full table is well
/// under 64 KB pre-allocated at module load.  Slots past the cap
/// are refused with `-ENOSPC` (was: silent grow then later silent
/// truncation through a separate cap check).
pub(crate) const INITIAL_SLOT_HINT: usize = MAX_PROBE_SLOTS;

/// Hard cap on concurrently-attached probe slots.  Pre-allocated at
/// init; `slots_ensure` refuses past this point.  Matches the host
/// CLI's preflight check.
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
    /// Profile-timer perf_event handle (one per-CPU; the MVP opens
    /// CPU 0 only).  Null when no perf_event is registered.
    pub(crate) perf_event: *mut bindings::perf_event,
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
            perf_event: core::ptr::null_mut(),
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

/// Ensure the slot table has at least `n` slots.  Post-init the table
/// is fixed-size at `INITIAL_SLOT_HINT == MAX_PROBE_SLOTS`; this is a
/// pure bounds check that returns `-ENOSPC` when the request exceeds
/// the pre-allocated capacity.  The spine is never reallocated past
/// init, so callers in IRQ context (uprobe handlers) cannot observe
/// torn slice headers.
pub(crate) unsafe fn slots_ensure(n: usize) -> Result<()> {
    unsafe {
        let v = BIFROST_SLOTS_OPT.as_mut().unwrap_unchecked();
        if n > v.len() {
            return Err(Error::from_errno(-(kernel::bindings::ENOSPC as i32)));
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
