// SPDX-License-Identifier: GPL-2.0
// Probe-family attach and cleanup dispatch.

use core::sync::atomic::Ordering;

use kernel::bindings;
use kernel::ffi::{c_char, c_int, c_void};
use kernel::prelude::*;

use crate::path_helpers::path_basename;
use crate::slots::{slot_lease_new, slots_ensure, slots_mut, BIFROST_NUM_KPROBES};
use crate::symtab_snapshot::push_symtab_snapshot_cb;
use crate::task_helpers::TaskRef;
use crate::uprobe_handlers::{bifrost_uprobe_handler, bifrost_uretprobe_handler};
use crate::wire::{
    PROBE_TYPE_FENTRY, PROBE_TYPE_FEXIT, PROBE_TYPE_NONE, PROBE_TYPE_PROFILE_TIMER,
    PROBE_TYPE_TRACEPOINT, PROBE_TYPE_UPROBE, PROBE_TYPE_UPROBE_BY_SYM, PROBE_TYPE_URETPROBE,
    PROBE_TYPE_URETPROBE_BY_SYM, PROBE_TYPE_USDT,
};
use crate::{free_slot_prog, BifrostGuest, BIFROST_TRACING_LINK_OPS};

extern "C" {
    fn bpf_get_raw_tracepoint(name: *const c_char) -> *mut bindings::bpf_raw_event_map;
    fn bpf_put_raw_tracepoint(btp: *mut bindings::bpf_raw_event_map);
    fn perf_event_create_kernel_counter(
        attr: *mut bindings::perf_event_attr,
        cpu: c_int,
        task: *mut bindings::task_struct,
        callback: Option<unsafe extern "C" fn()>,
        context: *mut c_void,
    ) -> *mut bindings::perf_event;
    fn perf_event_release_kernel(event: *mut bindings::perf_event) -> c_int;
    fn perf_event_set_bpf_prog(
        event: *mut bindings::perf_event,
        prog: *mut bindings::bpf_prog,
        bpf_cookie: u64,
    ) -> c_int;
    fn cpu_possible_mask() -> *const bindings::cpumask;
    fn num_online_cpus() -> u32;
    fn bpf_probe_register(
        btp: *mut bindings::bpf_raw_event_map,
        link: *mut bindings::bpf_raw_tp_link,
    ) -> c_int;
    fn bpf_probe_unregister(
        btp: *mut bindings::bpf_raw_event_map,
        link: *mut bindings::bpf_raw_tp_link,
    ) -> c_int;
    fn uprobe_register(
        inode: *mut bindings::inode,
        offset: i64,
        ref_ctr_offset: i64,
        uc: *mut bindings::uprobe_consumer,
    ) -> *mut bindings::uprobe;
    fn uprobe_unregister_nosync(uprobe: *mut bindings::uprobe, uc: *mut bindings::uprobe_consumer);
    fn kern_path(name: *const c_char, flags: core::ffi::c_uint, path: *mut bindings::path)
        -> c_int;
    fn path_put(path: *const bindings::path);
    fn igrab(inode: *mut bindings::inode) -> *mut bindings::inode;
    fn iput(inode: *mut bindings::inode);
    fn get_task_exe_file(task: *mut bindings::task_struct) -> *mut bindings::file;
    fn fput(file: *mut bindings::file);
    fn bifrost_helper_resolve_symbol(
        file: *mut bindings::file,
        symbol_name: *const u8,
        symbol_name_len: u32,
        out_file_offset: *mut u64,
        out_size: *mut u64,
    ) -> c_int;
    fn bifrost_helper_resolve_usdt(
        file: *mut bindings::file,
        provider_name: *const u8,
        provider_name_len: u32,
        probe_name: *const u8,
        probe_name_len: u32,
        out_pc_file_offset: *mut u64,
        out_semaphore_file_offset: *mut u64,
    ) -> c_int;
    fn bifrost_helper_for_each_vma_file(
        task: *mut bindings::task_struct,
        cb: Option<unsafe extern "C" fn(*mut bindings::file, *mut c_void)>,
        ctx: *mut c_void,
    );
}

/// Inputs for `slot_family_attach`, borrowed against the LOAD_PROG
/// worker's stack-resident parse buffer.
pub(crate) struct AttachExt<'a> {
    pub(crate) name_str: &'a str,
    pub(crate) target_name: [u8; 32],
    pub(crate) uprobe_basename: &'a [u8],
    pub(crate) uprobe_symbol: &'a [u8],
    pub(crate) uprobe_provider: &'a [u8],
    pub(crate) uprobe_path_buf: &'a [u8; 257],
    pub(crate) uprobe_file_offset: u64,
}

/// Centralized attach dispatch.  Allocates a fresh slot lease,
/// stores it in `slots_mut()[slot].lease`, then forwards to the
/// per-family attach.  The lease is issued *before* dispatch so a
/// failed attach still has a recorded lease for diagnostics; the
/// cleanup path tolerates `lease == 0` for slots that never got
/// attached.
///
/// Returns 0 on success or a negative errno from the per-family attach.
/// On failure, the JIT'd program stored in the slot is released and the
/// lease is cleared so the worker can report truthful LOAD_PROG status.
pub(crate) unsafe fn slot_family_attach(
    slot: usize,
    probe_type: u8,
    bg: *mut BifrostGuest,
    ext: &AttachExt<'_>,
) -> c_int {
    unsafe {
        // Heap-migration: grow the slot table here so the
        // family-specific attach below can index slot N safely.
        // The LOAD_PROG dispatch already grew before reaching us
        // for the common case; this is the defensive grow that
        // covers any future caller path.
        if slots_ensure(slot + 1).is_err() {
            pr_err!(
                "bifrost_guest: slot table grow to len={} failed in slot_family_attach\n",
                slot + 1
            );
            return -(bindings::ENOMEM as i32);
        }
        slots_mut()[slot].lease = slot_lease_new();
        let rc = match probe_type {
            PROBE_TYPE_FENTRY | PROBE_TYPE_FEXIT => {
                attach_slot_fbt(slot, probe_type, ext.name_str, bg)
            }
            PROBE_TYPE_TRACEPOINT => attach_slot_tracepoint(slot, ext.name_str, bg),
            PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => attach_slot_uprobe(
                slot,
                probe_type,
                ext.name_str,
                ext.uprobe_path_buf,
                ext.uprobe_file_offset,
                bg,
            ),
            PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => attach_slot_uprobe_by_sym(
                slot,
                probe_type,
                ext.uprobe_basename,
                ext.uprobe_symbol,
                bg,
            ),
            PROBE_TYPE_USDT => attach_slot_usdt(
                slot,
                ext.uprobe_basename,
                ext.uprobe_provider,
                ext.uprobe_symbol,
                bg,
            ),
            PROBE_TYPE_PROFILE_TIMER => attach_slot_profile_timer(
                slot,
                ext.uprobe_file_offset, // period_ns is carried in this slot
                                        // by load_prog_parse; see
                                        // `parse_profile_timer_trailer`.
                bg,
            ),
            _ => {
                pr_err!(
                    "bifrost_guest: unsupported probe_type {} for target='{}' slot[{}] — bifrost driver no longer dispatches kprobe (probe_types 0/1)\n",
                    probe_type,
                    ext.name_str,
                    slot
                );
                -(bindings::EINVAL as i32)
            }
        };
        if rc != 0 {
            free_slot_prog(slot);
            slots_mut()[slot].lease = 0;
        }
        rc
    }
}

/// Centralized cleanup dispatch.  Returns true if the slot was a
/// uprobe family member (so the caller can run the batched
/// `uprobe_unregister_sync()` once at the end), false otherwise.
/// Mirrors the cleanup match in `bifrost_remove` line-for-line;
/// adding a new family adds an arm here and a matching attach arm.
pub(crate) unsafe fn slot_family_cleanup(slot: usize, probe_type: u8) -> bool {
    unsafe {
        let had_uprobe = match probe_type {
            PROBE_TYPE_FENTRY | PROBE_TYPE_FEXIT => {
                cleanup_slot_fbt(slot);
                false
            }
            PROBE_TYPE_TRACEPOINT => {
                cleanup_slot_tracepoint(slot);
                false
            }
            PROBE_TYPE_UPROBE
            | PROBE_TYPE_URETPROBE
            | PROBE_TYPE_UPROBE_BY_SYM
            | PROBE_TYPE_URETPROBE_BY_SYM
            | PROBE_TYPE_USDT => cleanup_slot_uprobe(slot),
            PROBE_TYPE_PROFILE_TIMER => {
                cleanup_slot_profile_timer(slot);
                false
            }
            PROBE_TYPE_NONE => false,
            other => {
                pr_err!(
                    "bifrost_guest: cleanup slot[{}]: unknown probe_type {} (kprobe paths retired)\n",
                    slot,
                    other
                );
                false
            }
        };
        // Cleanup never grows; just zero the lease if the slot
        // index is in range.  After the heap migration, the table
        // length covers every attached slot by construction.
        if slot < slots_mut().len() {
            slots_mut()[slot].lease = 0;
        }
        had_uprobe
    }
}

/// Short string label for the family that owns `probe_type`.
/// Used by self-trace emit in a follow-up; today only diagnostic.
#[allow(dead_code)]
fn slot_family_label(probe_type: u8) -> &'static str {
    match probe_type {
        PROBE_TYPE_FENTRY | PROBE_TYPE_FEXIT => "fbt",
        PROBE_TYPE_TRACEPOINT => "tracepoint",
        PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => "uprobe",
        PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => "uprobe_by_sym",
        PROBE_TYPE_USDT => "usdt",
        PROBE_TYPE_PROFILE_TIMER => "profile-timer",
        PROBE_TYPE_NONE => "none",
        _ => "unknown",
    }
}

/// Profile-timer attach.  Opens a single per-CPU
/// (CPU 0 for the MVP) `perf_event` of type PERF_TYPE_SOFTWARE
/// (1) / PERF_COUNT_SW_CPU_CLOCK (0) with the host-supplied
/// `period_ns` sample period, then attaches the JIT'd BPF program
/// via `perf_event_set_bpf_prog`.  The event handle is stashed on
/// the slot so cleanup can release it at detach.
unsafe fn attach_slot_profile_timer(
    slot: usize,
    period_ns: u64,
    bg: *mut BifrostGuest,
) -> c_int {
    unsafe {
        let jitted = slots_mut()[slot].prog.load(Ordering::Acquire);
        if jitted.is_null() {
            pr_err!(
                "bifrost_guest: profile-timer slot[{}]: prog pointer missing — verifier path failed?\n",
                slot,
            );
            return -(bindings::EINVAL as i32);
        }
        if period_ns == 0 {
            pr_err!(
                "bifrost_guest: profile-timer slot[{}]: period_ns=0 rejected (host should encode at least 1ns)\n",
                slot,
            );
            return -(bindings::EINVAL as i32);
        }
        let mut attr = bindings::perf_event_attr::default();
        attr.type_ = 1; // PERF_TYPE_SOFTWARE
        attr.size = core::mem::size_of::<bindings::perf_event_attr>() as u32;
        attr.config = 0; // PERF_COUNT_SW_CPU_CLOCK
        attr.__bindgen_anon_1.sample_period = period_ns;
        // sample_type=0 keeps the perf-event sample record minimal; the BPF
        // program reads its own context (bpf_perf_event_data) — no
        // raw-sample payload needed.
        attr.sample_type = 0;
        // Open per-CPU 0 only for the MVP.  Per-CPU iteration is a
        // follow-up; profile-timer on CPU 0 still fires at the
        // requested period and feeds the same per-CPU SHM ring the
        // tracepoint path uses.
        let event = perf_event_create_kernel_counter(
            &mut attr as *mut _,
            0,                       // cpu = 0
            core::ptr::null_mut(),   // task = NULL (CPU-bound)
            None,                    // callback (NULL → BPF takes the sample)
            core::ptr::null_mut(),   // context
        );
        if (event as usize) >= (-4095isize as usize) {
            // ERR_PTR encoding: returned pointer is in the [-4095, 0)
            // range when the kernel signalled a negative errno.
            let err = -((event as isize) as i32);
            pr_err!(
                "bifrost_guest: profile-timer slot[{}] perf_event_create_kernel_counter failed: {}\n",
                slot,
                err,
            );
            return -err.abs();
        }
        let r = perf_event_set_bpf_prog(event, jitted, 0);
        if r != 0 {
            pr_err!(
                "bifrost_guest: profile-timer slot[{}] perf_event_set_bpf_prog failed: {}\n",
                slot,
                r,
            );
            perf_event_release_kernel(event);
            return r;
        }
        slots_mut()[slot].perf_event = event;
        // Mirror attach_slot_fbt: bump the high-water-mark slot
        // counter so subsequent LOAD_PROGs land in slot+1 instead
        // of clobbering this one.  Without this, the peer
        // ExtraProg::Action's per-fire program overwrites the
        // profile-timer's agg-chain program at slot[0] (or vice
        // versa), depending on LOAD_PROG order.
        BIFROST_NUM_KPROBES = slot + 1;
        (*bg).kprobe_attached = true;
        pr_info!(
            "bifrost_guest: profile-timer slot[{}] attached: period_ns={} cpu=0\n",
            slot,
            period_ns,
        );
        0
    }
}

/// Counterpart to `attach_slot_profile_timer`.  Releases the
/// per-CPU perf_event handle if one was registered.
unsafe fn cleanup_slot_profile_timer(slot: usize) {
    unsafe {
        if slot >= slots_mut().len() {
            return;
        }
        let event = slots_mut()[slot].perf_event;
        if !event.is_null() {
            let _ = perf_event_release_kernel(event);
            slots_mut()[slot].perf_event = core::ptr::null_mut();
        }
    }
}

/// On any error the JIT'd prog is freed and the slot stays
/// unattached (cleanup_slot_fbt then no-ops).
unsafe fn attach_slot_fbt(
    slot: usize,
    probe_type: u8,
    name_str: &str,
    bg: *mut BifrostGuest,
) -> c_int {
    unsafe {
        let kind = if probe_type == PROBE_TYPE_FENTRY {
            "fentry"
        } else {
            "fexit"
        };
        let attach_type: u32 = if probe_type == PROBE_TYPE_FENTRY {
            24 // BPF_TRACE_FENTRY
        } else {
            25 // BPF_TRACE_FEXIT
        };
        let jitted = slots_mut()[slot].prog.load(Ordering::Acquire);
        let tr = if jitted.is_null() || (*jitted).aux.is_null() {
            core::ptr::null_mut()
        } else {
            (*(*jitted).aux).dst_trampoline
        };
        if jitted.is_null() || tr.is_null() {
            pr_err!(
            "bifrost_guest: {} slot[{}] target='{}': dst_trampoline missing — verifier didn't resolve attach target (BTF lookup failed?)\n",
            kind, slot, name_str
        );
            return -(bindings::EINVAL as i32);
        }
        let link_p: *mut bindings::bpf_tracing_link = if (slot as usize) < slots_mut().len() {
            slots_mut()[slot as usize].fbt_link.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        };
        if link_p.is_null() {
            pr_err!("bifrost_guest: {} slot[{}] OOB\n", kind, slot);
            return -(bindings::EINVAL as i32);
        }
        core::ptr::write_bytes(link_p, 0, 1);
        // bpf_link_init takes a const ops ptr.  We pass our static
        // BIFROST_TRACING_LINK_OPS — the link is never exposed via
        // fd, but bpf_link_init derefs ops->dealloc & ops->
        // dealloc_deferred unconditionally so the ops ptr can't be
        // NULL.  Cleanup happens via direct
        // bpf_trampoline_unlink_prog + bpf_trampoline_put in
        // cleanup_slot_fbt.
        bindings::bpf_link_init(
            &mut (*link_p).link.link as *mut bindings::bpf_link,
            2, // BPF_LINK_TYPE_TRACING
            &BIFROST_TRACING_LINK_OPS as *const bindings::bpf_link_ops,
            jitted,
        );
        (*link_p).attach_type = attach_type;
        (*link_p).trampoline = tr;
        (*link_p).tgt_prog = core::ptr::null_mut();
        let lret = bindings::bpf_trampoline_link_prog(
            &mut (*link_p).link as *mut bindings::bpf_tramp_link,
            tr,
            core::ptr::null_mut(),
        );
        if lret == 0 {
            slots_mut()[slot].fbt_linked = true;
            BIFROST_NUM_KPROBES = slot + 1;
            // kprobe_attached is the "any probe attached" master
            // flag that gates cleanup; set it so bifrost_remove walks
            // our trampoline-link cleanup arm.
            (*bg).kprobe_attached = true;
            pr_info!(
                "bifrost_guest: {} slot[{}] linked to trampoline for '{}'\n",
                kind,
                slot,
                name_str
            );
        } else {
            pr_err!(
                "bifrost_guest: {} slot[{}] bpf_trampoline_link_prog failed: {}\n",
                kind,
                slot,
                lret
            );
            return lret;
        }
        0
    }
}

/// Register a JIT'd raw-tracepoint prog by resolving the event
/// name via `bpf_get_raw_tracepoint` and inserting our per-slot
/// `bpf_raw_tp_link` via `bpf_probe_register`.
///
/// `target_name` carries just the tracepoint name (category is
/// implicit — `bpf_get_raw_tracepoint` walks the
/// `__start__bpf_raw_tp[..]` table flat).
///
/// On any error the JIT'd prog is freed and any acquired btp
/// reference is dropped (`bpf_put_raw_tracepoint`) before
/// returning.  Symmetric to cleanup_slot_tracepoint.
unsafe fn attach_slot_tracepoint(slot: usize, name_str: &str, bg: *mut BifrostGuest) -> c_int {
    unsafe {
        let jitted = slots_mut()[slot].prog.load(Ordering::Acquire);
        if jitted.is_null() {
            pr_err!(
                "bifrost_guest: tracepoint slot[{}]: prog NULL after JIT\n",
                slot
            );
            return -(bindings::EINVAL as i32);
        }
        let btp = bpf_get_raw_tracepoint(slots_mut()[slot].target_name.as_ptr() as *const _);
        if btp.is_null() {
            pr_err!(
            "bifrost_guest: tracepoint slot[{}] event '{}' not found in kernel tracepoint table\n",
            slot, name_str
        );
            return -(bindings::ENOENT as i32);
        }
        let link_p: *mut bindings::bpf_raw_tp_link = if (slot as usize) < slots_mut().len() {
            slots_mut()[slot as usize].rawtp_link.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        };
        if link_p.is_null() {
            pr_err!("bifrost_guest: tracepoint slot[{}] OOB\n", slot);
            bpf_put_raw_tracepoint(btp);
            return -(bindings::EINVAL as i32);
        }
        core::ptr::write_bytes(link_p, 0, 1);
        // bpf_link_init: same all-None ops table as the tracing-link
        // case; bpf_link_init derefs ops->dealloc & ops->
        // dealloc_deferred so the ops ptr can't be NULL.
        bindings::bpf_link_init(
            &mut (*link_p).link as *mut bindings::bpf_link,
            9, // BPF_LINK_TYPE_RAW_TRACEPOINT
            &BIFROST_TRACING_LINK_OPS as *const bindings::bpf_link_ops,
            jitted,
        );
        (*link_p).btp = btp;
        let lret = bpf_probe_register(btp, link_p);
        if lret == 0 {
            slots_mut()[slot].rawtp_btp = btp;
            slots_mut()[slot].rawtp_registered = true;
            BIFROST_NUM_KPROBES = slot + 1;
            (*bg).kprobe_attached = true;
            pr_info!(
                "bifrost_guest: tracepoint slot[{}] attached to event '{}'\n",
                slot,
                name_str
            );
        } else {
            pr_err!(
                "bifrost_guest: tracepoint slot[{}] bpf_probe_register failed: {}\n",
                slot,
                lret
            );
            bpf_put_raw_tracepoint(btp);
            return lret;
        }
        0
    }
}

/// Register a kernel-resolved uprobe (PROBE_TYPE_UPROBE_BY_SYM /
/// URETPROBE_BY_SYM).  The CLI ferried only (basename, symbol)
/// in the BFR7 trailer; we walk for_each_process to find a task
/// whose `comm` matches the basename, grab its already-mapped
/// exe_file, parse the ELF symtab for `symbol`, and register the
/// uprobe at the resolved file offset.
///
/// On the way: `bifrost_helper_for_each_vma_file` pushes
/// per-binary function symtabs to the host so the gustack
/// renderer can symbolicate frames without reading any ELF off
/// a host-mirrored rootfs.
///
/// Symmetric to cleanup_slot_uprobe.
unsafe fn attach_slot_uprobe_by_sym(
    slot: usize,
    probe_type: u8,
    basename: &[u8],
    symbol: &[u8],
    bg: *mut BifrostGuest,
) -> c_int {
    unsafe {
        // Defense in depth: caller (slot_family_attach via the
        // LOAD_PROG dispatch) already called slots_ensure(slot+1).
        // This check protects against a misuse from a future caller
        // that forgets the grow step.
        if slot >= slots_mut().len() {
            pr_err!(
                "bifrost_guest: uprobe slot[{}] out of range (len={})\n",
                slot,
                slots_mut().len()
            );
            return -(bindings::EINVAL as i32);
        }
        // Initialize the wrapper's slot field, then expose the consumer
        // pointer for the kernel uprobe API.  The kernel only sees the
        // consumer; our shared handler recovers `slot` via container-of.
        let bp_ptr = slots_mut()[slot].uprobe.as_mut_ptr();
        (*bp_ptr).slot = slot as u32;
        let consumer: *mut bindings::uprobe_consumer = &mut (*bp_ptr).consumer as *mut _;
        if consumer.is_null() {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] consumer ptr null\n",
                slot
            );
            return -(bindings::EINVAL as i32);
        }
        // TaskRef pairs the C-side get_task_struct with a
        // mechanical put_task_struct on drop. Replaces the manual
        // put_task_ref calls that were scattered across each early
        // return.
        let Some(task) = TaskRef::find(basename) else {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] no task with comm '{}'\n",
                slot,
                core::str::from_utf8(basename).unwrap_or("?")
            );
            return -(bindings::ENOENT as i32);
        };
        let exe = get_task_exe_file(task.as_ptr());
        if exe.is_null() {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] task has no exe_file\n",
                slot
            );
            return -(bindings::ENOENT as i32);
        }
        let mut sym_off: u64 = 0;
        let mut sym_size: u64 = 0;
        let rc = bifrost_helper_resolve_symbol(
            exe,
            symbol.as_ptr(),
            symbol.len() as u32,
            &mut sym_off,
            &mut sym_size,
        );
        if rc != 0 {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] resolve '{}' failed: {}\n",
                slot,
                core::str::from_utf8(symbol).unwrap_or("?"),
                rc
            );
            fput(exe);
            return rc;
        }
        pr_info!(
            "bifrost_guest: uprobe-by-sym slot[{}] resolved '{}'+0x{:x} (size={})\n",
            slot,
            core::str::from_utf8(symbol).unwrap_or("?"),
            sym_off,
            sym_size
        );
        // Side-channel: push function symtabs for the firing task's
        // executable VMAs to the host so its gustack renderer can
        // symbolicate frames without reading any ELF off a
        // host-mirrored rootfs.  Walks task->mm's VMAs (sleepable;
        // we're in the worker thread's LOAD_PROG handler, not BPF/
        // kprobe context) and pushes one record per unique vm_file —
        // covers the uprobed binary AND libc/libpthread/vDSO mapped
        // into the same task, so the bottom frames of gustack
        // symbolicate too.
        bifrost_helper_for_each_vma_file(
            task.as_ptr(),
            Some(push_symtab_snapshot_cb),
            core::ptr::null_mut(),
        );
        drop(task);
        let exe_inode = (*exe).f_inode;
        let pinned = igrab(exe_inode);
        fput(exe);
        if pinned.is_null() {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] igrab returned NULL\n",
                slot
            );
            return -(bindings::ENOENT as i32);
        }
        // Reuse the same consumer-build + uprobe_register path used
        // for host-resolved uprobes by dispatching on the *_BY_SYM
        // variants when assigning the handler.
        core::ptr::write_bytes(consumer, 0, 1);
        if probe_type == PROBE_TYPE_URETPROBE_BY_SYM {
            (*consumer).ret_handler = match slot {
                // shared handler — slot recovered via container-of
                _ => Some(bifrost_uretprobe_handler),
            };
        } else {
            (*consumer).handler = match slot {
                // shared handler — slot recovered via container-of
                _ => Some(bifrost_uprobe_handler),
            };
        }
        let handle = uprobe_register(pinned, sym_off as i64, 0, consumer);
        let raw = handle as i64;
        if (-4096..0).contains(&raw) || handle.is_null() {
            pr_err!(
                "bifrost_guest: uprobe-by-sym slot[{}] uprobe_register failed: {}\n",
                slot,
                raw
            );
            iput(pinned);
            return if raw < 0 {
                raw as c_int
            } else {
                -(bindings::EINVAL as i32)
            };
        }
        slots_mut()[slot].uprobe_handle = handle;
        slots_mut()[slot].uprobe_inode = pinned;
        (*bg).kprobe_attached = true;
        BIFROST_NUM_KPROBES = slot + 1;
        let kind = if probe_type == PROBE_TYPE_URETPROBE_BY_SYM {
            "uretprobe"
        } else {
            "uprobe"
        };
        pr_info!(
            "bifrost_guest: {} slot[{}] (by-sym) registered on {}:{} +0x{:x} (sym_size={})\n",
            kind,
            slot,
            core::str::from_utf8(basename).unwrap_or("?"),
            core::str::from_utf8(symbol).unwrap_or("?"),
            sym_off,
            sym_size
        );
        0
    }
}

/// Register a kernel-resolved USDT (PROBE_TYPE_USDT).  The CLI
/// ferried `(basename, sdt_provider, sdt_probe)` in the BFR7
/// trailer; we find the matching task by `comm == basename`, grab
/// its `exe_file`, and call `bifrost_helper_resolve_usdt` to walk
/// `.note.stapsdt`.  Symmetric to attach_slot_uprobe_by_sym but
/// targeting the SDT note section rather than `.symtab`.
///
/// The semaphore offset returned by the helper is non-zero on
/// SystemTap-style USDT probes (postgres-built-with-`--enable-dtrace`,
/// libstapsdt, glibc); we hand it to `uprobe_register` as
/// `ref_ctr_offset` so the kernel atomically increments the per-probe
/// `unsigned short` flag in `.probes` on attach.  Without that the
/// `STAP_PROBE` macro body short-circuits (no consumer registered)
/// and the NOP at `pc` never gets executed.
unsafe fn attach_slot_usdt(
    slot: usize,
    basename: &[u8],
    sdt_provider: &[u8],
    sdt_probe: &[u8],
    bg: *mut BifrostGuest,
) -> c_int {
    unsafe {
        // Defense in depth: caller (slot_family_attach via the
        // LOAD_PROG dispatch) already called slots_ensure(slot+1).
        // This check protects against a misuse from a future caller
        // that forgets the grow step.
        if slot >= slots_mut().len() {
            pr_err!(
                "bifrost_guest: uprobe slot[{}] out of range (len={})\n",
                slot,
                slots_mut().len()
            );
            return -(bindings::EINVAL as i32);
        }
        // Initialize the wrapper's slot field, then expose the consumer
        // pointer for the kernel uprobe API.  The kernel only sees the
        // consumer; our shared handler recovers `slot` via container-of.
        let bp_ptr = slots_mut()[slot].uprobe.as_mut_ptr();
        (*bp_ptr).slot = slot as u32;
        let consumer: *mut bindings::uprobe_consumer = &mut (*bp_ptr).consumer as *mut _;
        if consumer.is_null() {
            pr_err!("bifrost_guest: usdt slot[{}] consumer ptr null\n", slot);
            return -(bindings::EINVAL as i32);
        }
        let mut pc_off: u64 = 0;
        let mut sema_off: u64 = 0;
        let (task, pinned) = if !basename.is_empty() && basename[0] == b'/' {
            let mut path_buf = [0u8; 257];
            if basename.len() > 256 {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] path too long ({} > 256): '{}'\n",
                    slot,
                    basename.len(),
                    core::str::from_utf8(&basename[..256]).unwrap_or("?")
                );
                return -(bindings::EINVAL as i32);
            }
            let len = basename.len();
            path_buf[..len].copy_from_slice(&basename[..len]);
            let file = bindings::filp_open(
                path_buf.as_ptr() as *const c_char,
                bindings::O_RDONLY as c_int,
                0,
            );
            let raw_file = file as isize;
            if (-4096..0).contains(&raw_file) || file.is_null() {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] open path '{}' failed: {}\n",
                    slot,
                    core::str::from_utf8(basename).unwrap_or("?"),
                    raw_file
                );
                return if raw_file < 0 {
                    raw_file as c_int
                } else {
                    -(bindings::ENOENT as i32)
                };
            }
            let rc = bifrost_helper_resolve_usdt(
                file,
                sdt_provider.as_ptr(),
                sdt_provider.len() as u32,
                sdt_probe.as_ptr(),
                sdt_probe.len() as u32,
                &mut pc_off,
                &mut sema_off,
            );
            if rc != 0 {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] path resolve {}:{} on '{}' failed: {}\n",
                    slot,
                    core::str::from_utf8(sdt_provider).unwrap_or("?"),
                    core::str::from_utf8(sdt_probe).unwrap_or("?"),
                    core::str::from_utf8(basename).unwrap_or("?"),
                    rc
                );
                fput(file);
                return rc;
            }
            let pinned = igrab((*file).f_inode);
            fput(file);
            if pinned.is_null() {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] path '{}' inode pin failed\n",
                    slot,
                    core::str::from_utf8(basename).unwrap_or("?")
                );
                return -(bindings::ENOENT as i32);
            }
            (None, pinned)
        } else {
            // TaskRef RAII pairs get_task_struct on the C
            // side with put_task_struct on drop.
            let Some(task_ref) = TaskRef::find(basename) else {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] no task with comm '{}'\n",
                    slot,
                    core::str::from_utf8(basename).unwrap_or("?")
                );
                return -(bindings::ENOENT as i32);
            };
            let exe = get_task_exe_file(task_ref.as_ptr());
            if exe.is_null() {
                pr_err!("bifrost_guest: usdt slot[{}] task has no exe_file\n", slot);
                return -(bindings::ENOENT as i32);
            }
            let rc = bifrost_helper_resolve_usdt(
                exe,
                sdt_provider.as_ptr(),
                sdt_provider.len() as u32,
                sdt_probe.as_ptr(),
                sdt_probe.len() as u32,
                &mut pc_off,
                &mut sema_off,
            );
            if rc != 0 {
                pr_err!(
                    "bifrost_guest: usdt slot[{}] resolve {}:{} failed: {}\n",
                    slot,
                    core::str::from_utf8(sdt_provider).unwrap_or("?"),
                    core::str::from_utf8(sdt_probe).unwrap_or("?"),
                    rc
                );
                fput(exe);
                return rc;
            }
            let exe_inode = (*exe).f_inode;
            let pinned = igrab(exe_inode);
            fput(exe);
            (Some(task_ref), pinned)
        };
        pr_info!(
            "bifrost_guest: usdt slot[{}] resolved {}:{} pc=+0x{:x} sema=+0x{:x}\n",
            slot,
            core::str::from_utf8(sdt_provider).unwrap_or("?"),
            core::str::from_utf8(sdt_probe).unwrap_or("?"),
            pc_off,
            sema_off
        );
        // Push symtabs for the firing task's executable VMAs (same as the
        // by-sym path) so any gustack() in the body symbolicates cleanly.
        if let Some(task) = task.as_ref() {
            bifrost_helper_for_each_vma_file(
                task.as_ptr(),
                Some(push_symtab_snapshot_cb),
                core::ptr::null_mut(),
            );
        }
        // task: Option<TaskRef> drops here at end of block.
        if pinned.is_null() {
            pr_err!("bifrost_guest: usdt slot[{}] igrab returned NULL\n", slot);
            return -(bindings::ENOENT as i32);
        }
        core::ptr::write_bytes(consumer, 0, 1);
        // shared handler — slot recovered via container-of
        (*consumer).handler = Some(bifrost_uprobe_handler);
        let handle = uprobe_register(pinned, pc_off as i64, sema_off as i64, consumer);
        let raw = handle as i64;
        if (-4096..0).contains(&raw) || handle.is_null() {
            pr_err!(
                "bifrost_guest: usdt slot[{}] uprobe_register failed: {}\n",
                slot,
                raw
            );
            iput(pinned);
            return if raw < 0 {
                raw as c_int
            } else {
                -(bindings::EINVAL as i32)
            };
        }
        slots_mut()[slot].uprobe_handle = handle;
        slots_mut()[slot].uprobe_inode = pinned;
        (*bg).kprobe_attached = true;
        BIFROST_NUM_KPROBES = slot + 1;
        pr_info!(
            "bifrost_guest: usdt slot[{}] registered on {}:{}:{} pc=+0x{:x} sema=+0x{:x}\n",
            slot,
            core::str::from_utf8(basename).unwrap_or("?"),
            core::str::from_utf8(sdt_provider).unwrap_or("?"),
            core::str::from_utf8(sdt_probe).unwrap_or("?"),
            pc_off,
            sema_off
        );
        0
    }
}

/// Register a host-resolved uprobe (PROBE_TYPE_UPROBE /
/// URETPROBE).  The CLI ferried (path, file_offset) in the BFR7
/// trailer.  Path resolution is two-stage:
///
///   1. Container-aware exe_file lookup via `find_task_by_comm`
///      → `get_task_exe_file` → `igrab`.  Works for binaries that
///      live only in a container's overlayfs (init's mount ns
///      has no visibility there).
///
///   2. `kern_path` fallback with retry-with-backoff (handles
///      the boot-order race where LOAD_PROG arrives at ~50ms
///      while virtiofs hasn't finished mounting the rootfs yet).
///
/// Storage: when (1) succeeds, kpath stays zero and
/// slots_mut()[slot].uprobe_path is left as the empty path; cleanup
/// branches on dentry.is_null() to skip path_put.  The pinned
/// inode (igrab'd from the file's f_inode) handles lifetime
/// either way.
///
/// Symmetric to cleanup_slot_uprobe.
unsafe fn attach_slot_uprobe(
    slot: usize,
    probe_type: u8,
    name_str: &str,
    uprobe_path_buf: &[u8; 257],
    uprobe_file_offset: u64,
    bg: *mut BifrostGuest,
) -> c_int {
    unsafe {
        // Defense in depth: caller (slot_family_attach via the
        // LOAD_PROG dispatch) already called slots_ensure(slot+1).
        // This check protects against a misuse from a future caller
        // that forgets the grow step.
        if slot >= slots_mut().len() {
            pr_err!(
                "bifrost_guest: uprobe slot[{}] out of range (len={})\n",
                slot,
                slots_mut().len()
            );
            return -(bindings::EINVAL as i32);
        }
        // Initialize the wrapper's slot field, then expose the consumer
        // pointer for the kernel uprobe API.  The kernel only sees the
        // consumer; our shared handler recovers `slot` via container-of.
        let bp_ptr = slots_mut()[slot].uprobe.as_mut_ptr();
        (*bp_ptr).slot = slot as u32;
        let consumer: *mut bindings::uprobe_consumer = &mut (*bp_ptr).consumer as *mut _;
        if consumer.is_null() {
            pr_err!("bifrost_guest: uprobe slot[{}] consumer ptr null\n", slot);
            return -(bindings::EINVAL as i32);
        }
        let mut kpath: bindings::path = bindings::path {
            mnt: core::ptr::null_mut(),
            dentry: core::ptr::null_mut(),
        };
        let mut pinned: *mut bindings::inode = core::ptr::null_mut();
        let mut resolved_via = "<unset>";

        // Stage 1: exe_file via for_each_process.
        // TaskRef releases the task ref on drop, even
        // through the early-break branches inside the chain below.
        let basename = path_basename(uprobe_path_buf);
        if !basename.is_empty() {
            if let Some(task) = TaskRef::find(basename) {
                let exe = get_task_exe_file(task.as_ptr());
                // Drop the task ref before fput on exe — neither
                // depends on the other after exe_file is captured.
                drop(task);
                if !exe.is_null() {
                    let exe_inode = (*exe).f_inode;
                    pinned = igrab(exe_inode);
                    // Drop the file ref — the inode pin (igrab refcount)
                    // is sufficient to keep the inode alive for the
                    // lifetime of the uprobe.
                    fput(exe);
                    if !pinned.is_null() {
                        resolved_via = "exe_file";
                    }
                }
            }
        }

        // Stage 2: kern_path fallback with retry.
        let mut rc: c_int = 0;
        let mut attempts: u32 = 0;
        if pinned.is_null() {
            rc = -2; // -ENOENT
            while attempts < 300 {
                rc = kern_path(
                    uprobe_path_buf.as_ptr() as *const c_char,
                    1, // LOOKUP_FOLLOW
                    &mut kpath,
                );
                if rc == 0 || rc != -2 {
                    break;
                }
                // 100 ms = HZ/10 (HZ=1000 on most modern arm64 builds).
                bindings::schedule_timeout_interruptible(100);
                if bindings::kthread_should_stop() {
                    break;
                }
                attempts += 1;
            }
            if rc == 0 {
                let raw_inode = (*kpath.dentry).d_inode;
                pinned = igrab(raw_inode);
                if pinned.is_null() {
                    path_put(&kpath);
                    kpath.mnt = core::ptr::null_mut();
                    kpath.dentry = core::ptr::null_mut();
                } else {
                    resolved_via = if attempts > 0 {
                        "kern_path (after retries)"
                    } else {
                        "kern_path"
                    };
                }
            }
        }

        if pinned.is_null() {
            pr_err!(
            "bifrost_guest: uprobe slot[{}] path resolution failed for '{}' (kern_path={} after {} retries; no task with matching comm)\n",
            slot,
            core::str::from_utf8(
                &uprobe_path_buf[..uprobe_path_buf
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0)]
            )
            .unwrap_or("?"),
            rc,
            attempts
        );
            return if rc != 0 {
                rc
            } else {
                -(bindings::ENOENT as i32)
            };
        }
        pr_info!(
            "bifrost_guest: uprobe slot[{}] resolved '{}' via {} (attempts={})\n",
            slot,
            core::str::from_utf8(
                &uprobe_path_buf[..uprobe_path_buf.iter().position(|&b| b == 0).unwrap_or(0)]
            )
            .unwrap_or("?"),
            resolved_via,
            attempts
        );
        // Zero the consumer struct, then wire either entry or return
        // handler based on probe_type.
        core::ptr::write_bytes(consumer, 0, 1);
        if probe_type == PROBE_TYPE_URETPROBE {
            (*consumer).ret_handler = match slot {
                // shared handler — slot recovered via container-of
                _ => Some(bifrost_uretprobe_handler),
            };
        } else {
            (*consumer).handler = match slot {
                // shared handler — slot recovered via container-of
                _ => Some(bifrost_uprobe_handler),
            };
        }
        let handle = uprobe_register(
            pinned,
            uprobe_file_offset as i64,
            0, // ref_ctr_offset — only USDT (attach_slot_usdt) uses non-zero
            consumer,
        );
        let raw = handle as i64;
        if (-4096..0).contains(&raw) || handle.is_null() {
            pr_err!(
                "bifrost_guest: uprobe_register slot[{}] failed: {}\n",
                slot,
                raw
            );
            iput(pinned);
            if !kpath.dentry.is_null() {
                path_put(&kpath);
            }
            return if raw < 0 {
                raw as c_int
            } else {
                -(bindings::EINVAL as i32)
            };
        }
        slots_mut()[slot].uprobe_handle = handle;
        slots_mut()[slot].uprobe_inode = pinned;
        slots_mut()[slot].uprobe_path = kpath;
        (*bg).kprobe_attached = true;
        BIFROST_NUM_KPROBES = slot + 1;
        let kind = if probe_type == PROBE_TYPE_URETPROBE {
            "uretprobe"
        } else {
            "uprobe"
        };
        pr_info!(
            "bifrost_guest: {} slot[{}] registered on '{}' +0x{:x} -> {}\n",
            kind,
            slot,
            core::str::from_utf8(
                &uprobe_path_buf[..uprobe_path_buf.iter().position(|&b| b == 0).unwrap_or(0)]
            )
            .unwrap_or("?"),
            uprobe_file_offset,
            name_str
        );
        0
    }
}

/// Tear down an FBT (FENTRY/FEXIT) trampoline link allocated in
/// the per-slot static storage.  Symmetric to the LOAD_PROG arm
/// at line ~600 that calls `bpf_trampoline_get` +
/// `bpf_trampoline_link_prog` — we reverse it via
/// `bpf_trampoline_unlink_prog` + `bpf_trampoline_put`.  The
/// `bpf_link` itself was never exposed via fd, so its refcnt
/// stays at the `bpf_link_init` default (1) and we don't
/// `bpf_link_put`.
unsafe fn cleanup_slot_fbt(s: usize) {
    unsafe {
        if !slots_mut()[s].fbt_linked {
            return;
        }
        let link_p: *mut bindings::bpf_tracing_link = if (s as usize) < slots_mut().len() {
            slots_mut()[s as usize].fbt_link.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        };
        if !link_p.is_null() {
            let tr = (*link_p).trampoline;
            bindings::bpf_trampoline_unlink_prog(
                &mut (*link_p).link as *mut bindings::bpf_tramp_link,
                tr,
                core::ptr::null_mut(),
            );
            if !tr.is_null() {
                bindings::bpf_trampoline_put(tr);
            }
        }
        slots_mut()[s].fbt_linked = false;
    }
}

/// Tear down a raw-tracepoint registration in the per-slot static
/// storage.  Symmetric to the LOAD_PROG arm: unregister the
/// `bpf_raw_tp_link` from the tracepoint via
/// `bpf_probe_unregister`, then drop the module ref taken at
/// register time via `bpf_put_raw_tracepoint`.  The link is
/// static storage (never exposed via fd), refcnt stays at 1 from
/// `bpf_link_init`.
unsafe fn cleanup_slot_tracepoint(s: usize) {
    unsafe {
        if !slots_mut()[s].rawtp_registered {
            return;
        }
        let link_p: *mut bindings::bpf_raw_tp_link = if (s as usize) < slots_mut().len() {
            slots_mut()[s as usize].rawtp_link.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        };
        let btp = slots_mut()[s].rawtp_btp;
        if !link_p.is_null() && !btp.is_null() {
            let _ = bpf_probe_unregister(btp, link_p);
            bpf_put_raw_tracepoint(btp);
        }
        slots_mut()[s].rawtp_btp = core::ptr::null_mut();
        slots_mut()[s].rawtp_registered = false;
    }
}

/// Tear down a uprobe registration (host- or kernel-resolved).
/// Returns `true` if there was an active uprobe handle that we
/// called `uprobe_unregister_nosync` on — the caller batches a
/// single `uprobe_unregister_sync()` after the loop to drain
/// outstanding handlers across all slots in one shot.  We also
/// drop the inode pin (`iput`) and path ref (`path_put`) taken at
/// register time.
unsafe fn cleanup_slot_uprobe(s: usize) -> bool {
    unsafe {
        let mut had_uprobe = false;
        let handle = slots_mut()[s].uprobe_handle;
        let consumer: *mut bindings::uprobe_consumer = if s < slots_mut().len() {
            let bp_ptr = slots_mut()[s].uprobe.as_mut_ptr();
            &mut (*bp_ptr).consumer as *mut _
        } else {
            core::ptr::null_mut()
        };
        if !handle.is_null() && !consumer.is_null() {
            uprobe_unregister_nosync(handle, consumer);
            had_uprobe = true;
        }
        slots_mut()[s].uprobe_handle = core::ptr::null_mut();
        let inode = slots_mut()[s].uprobe_inode;
        if !inode.is_null() {
            iput(inode);
            slots_mut()[s].uprobe_inode = core::ptr::null_mut();
        }
        if !slots_mut()[s].uprobe_path.dentry.is_null() {
            path_put(&slots_mut()[s].uprobe_path);
            slots_mut()[s].uprobe_path = bindings::path {
                mnt: core::ptr::null_mut(),
                dentry: core::ptr::null_mut(),
            };
        }
        had_uprobe
    }
}
