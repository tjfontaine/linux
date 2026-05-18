// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/bifrost.rs
//
// Bifrost guest driver — built into vmlinux as drivers/bifrost/
// (CONFIG_BIFROST_GUEST=y, bool not tristate). Links against
// EXPORT_SYMBOL_GPL kernel helpers including bifrost-specific shims
// from kernel/bpf/{syscall,helpers}.c; GPL-2.0 is required, matching
// the `license: "GPL"` declaration in the module! macro below. The
// `module!` macro produces an *_initcall() under built-in config
// (which is how this driver is built), so init runs at device-init
// time during boot, well before any rootfs pivot or PID-1 spawn.
//
// FILE LAYOUT (in progress — refactor roadmap Phase 4):
//
// Done:
//   path_helpers.rs          path_basename() (pure helper)
//   wire.rs                  PROBE_TYPE_* + AGG_KIND_* + *_PROBE_ID
//                            (host↔guest wire-format discriminants)
//   bpf_consts.rs            BPF_MAP_TYPE_* + BPF_LD_IMM64 +
//                            BPF_PSEUDO_MAP_FD (kernel BPF API)
//   shmem_layout.rs          SHMEM_* region size + sub-region offsets
//   kfunc_manifest.rs        Rust/C helper ABI manifest validation
//   load_prog_parse.rs       bounded LOAD_PROG payload parser
//   slots.rs                 heap-backed probe slot table + leases
//   symtab_snapshot.rs       SHMEM side-channel symbol table pushes
//   agg_snapshot.rs          SHMEM aggregation snapshots
//   control_reply.rs         LOAD_PROG completion + ctrl repost
//   shmem_init.rs            SHMEM_INIT event publication
//   uprobe_handlers.rs       shared uprobe/uretprobe dispatch
//   attach.rs                probe-family attach + cleanup paths
//
// Pending (each requires a kernel rebuild + per-attach demo sweep
// to land safely; deferred until that build cycle is available):
//   load_prog/mod.rs         entry + phase orchestration
//   load_prog/maps.rs        map setup, fake-fd patching
//   load_prog/verifier.rs    Kernel-verifier dispatch wrapper
//   attach/uprobe.rs         split uprobe + uretprobe out of attach.rs
//   attach/fbt.rs            split fentry/fexit out of attach.rs
//   attach/tracepoint.rs     split raw tracepoint out of attach.rs
//
// The historical patch series in
// `third_party/smolvm/libkrunfw/patches/` already mirrors the
// proposed split per attach type (0030 uprobe, 0036 fbt, 0039
// tracepoint, 0040 kprobe-removal); the natural migration is to
// edit each patch in place to land the corresponding code in its
// own file, preserving git-bisect across the series.
//
// Each new submodule is a sibling .rs file in this directory; the
// kernel Rust build pulls them in via `mod` declarations from this
// file, so Kbuild's `bifrost_combined-y := bifrost.o
// bifrost_helpers.o` line stays unchanged.  See the four `mod`
// declarations directly below this comment for the pattern.
#![no_std]

use kernel::prelude::*;
use kernel::bindings;
// Use the kernel's `ffi` crate (rust/ffi.rs) instead of `core::ffi`.
// The kernel compiles with `-funsigned-char`, so `c_char` is aliased
// to `u8`; `core::ffi::c_char` is platform-default (`i8` on aarch64),
// which mismatches every bindgen-generated kernel signature.  Pulling
// from `kernel::ffi` keeps callbacks compiling on rustc 1.82+
// (where the platform default isn't auto-coerced).
use kernel::ffi::{c_void, c_int, c_char};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

mod bpf_consts;
mod agg_snapshot;
mod attach;
mod control_reply;
mod kfunc_manifest;
mod load_prog_parse;
mod path_helpers;
mod record_writer;
mod shmem_init;
mod shmem_layout;
mod shmem_publish;
mod slots;
mod symtab_snapshot;
mod task_helpers;
mod types;
mod uprobe_handlers;
// wire.rs is a SYMLINK to the canonical bifrost-wire crate at
// host/bifrost-wire/src/lib.rs.  The kernel rust build composes
// it as a sibling module; the `unreachable_pub` warning fires
// because canonical uses `pub` (it's the crate root on the host
// side) but the kernel-rust convention prefers `pub(crate)` for
// inner modules.  Allow the warning here to keep canonical
// visibility consistent across all consumers.
#[allow(unreachable_pub)]
mod wire;
use agg_snapshot::push_agg_snapshot;
use attach::{slot_family_attach, slot_family_cleanup, AttachExt};
use control_reply::{complete_load_prog, complete_load_prog_with_detail};
use load_prog_parse::parse_load_prog;
use shmem_init::send_shmem_init;
use shmem_publish::{populate_shmem_btf, populate_shmem_kallsyms};
use slots::{
    bifrost_slots_init, slot_lease_new, slots_ensure, slots_mut, BIFROST_NUM_KPROBES,
    INITIAL_SLOT_HINT,
};
use symtab_snapshot::push_symtab_snapshot_cb;
use types::{
    read_u32_le_unaligned, BifrostCmd, BpfInsn, MapDef, BPF_INSN_WIRE_SIZE, MAP_DEF_WIRE_SIZE,
};
use shmem_layout::{
    SHMEM_BTF_CAP, SHMEM_BTF_OFF, SHMEM_HDR_LEN, SHMEM_HDR_OFF, SHMEM_KSYMS_CAP, SHMEM_KSYMS_OFF,
    SHMEM_MAGIC, SHMEM_N_PAGES, SHMEM_REGION_SIZE, SHMEM_RINGBUF_LEN, SHMEM_RINGBUF_OFF,
    SHMEM_VERSION, SHMEM_VMA_CACHE_LEN, SHMEM_VMA_CACHE_OFF,
};
use wire::{
    AGG_KIND_SUM, PROBE_TYPE_FENTRY, PROBE_TYPE_FEXIT, PROBE_TYPE_NONE, PROBE_TYPE_PROFILE_TIMER,
    PROBE_TYPE_TRACEPOINT,
};

module! {
    type: BifrostGuestModule,
    name: "bifrost_guest",
    author: "Project Bifrost",
    description: "Virtio Bifrost Guest Driver",
    license: "GPL",
}

struct BifrostGuestModule;

// BifrostCmd, MapDef, BpfInsn moved to drivers/bifrost/types.rs.
// AGG_KIND_* constants in wire.rs.

// BPF_MAP_TYPE_*, BPF_LD_IMM64, BPF_PSEUDO_MAP_FD moved to bpf_consts.rs.

pub(crate) struct BifrostGuest {
    vdev: *mut bindings::virtio_device,
    pub(crate) vq_ctrl: *mut bindings::virtqueue,
    pub(crate) vq_event: *mut bindings::virtqueue,
    /// Phase 4 doorbell virtqueue. The BPF programs kick this
    /// queue (via `bifrost_kfunc_shmem_kick`) after submitting
    /// records to the SHMEM event ringbuf so the host's consumer
    /// thread wakes from `poll()` instead of polling.
    vq_doorbell: *mut bindings::virtqueue,
    /// Tiny outbuf permanently posted to vq_doorbell so the
    /// guest can kick it any time (the kick is the wakeup signal —
    /// the data doesn't matter). Cycled back into the queue after
    /// each ack via a small drain in the kick kfunc.
    doorbell_buf: *mut c_void,
    pub(crate) ctrl_buf: *mut c_void,
    pub(crate) event_buf: *mut c_void,
    thread: *mut bindings::task_struct,
    pending_work: u32,
    pub(crate) cmd_len: u32,
    // BPF program tracking
    prog: *mut bindings::bpf_prog,
    // Map pointers (indexed by map index)
    pub(crate) maps: [*mut bindings::bpf_map; 8],
    pub(crate) num_maps: u32,
    // Kprobe tracking
    pub(crate) kprobe_attached: bool,
    // SHMEM region. Prefer the virtio shared-memory region exposed by
    // the VMM; fall back to the older vmalloc/PFN path for older VMMs.
    shmem_va: *mut u8,
    pub(crate) shmem_pfns: *mut usize,
    pub(crate) shmem_n_pages: u64,
    pub(crate) shmem_from_virtio: bool,
}

unsafe fn map_bifrost_virtio_shmem(vdev: *mut bindings::virtio_device) -> *mut u8 {
    unsafe {
        const BIFROST_SHM_REGION_ID: u8 = 0;
        let config = match (*vdev).config.as_ref() {
            Some(config) => config,
            None => return core::ptr::null_mut(),
        };
        let get_shm_region = match config.get_shm_region {
            Some(get_shm_region) => get_shm_region,
            None => return core::ptr::null_mut(),
        };

        let mut region = bindings::virtio_shm_region::default();
        if !get_shm_region(vdev, &mut region, BIFROST_SHM_REGION_ID) {
            return core::ptr::null_mut();
        }
        if region.len < SHMEM_REGION_SIZE as u64 {
            pr_warn!(
                "bifrost_guest: virtio SHMEM region too small: len={} required={}\n",
                region.len,
                SHMEM_REGION_SIZE
            );
            return core::ptr::null_mut();
        }

        let va = bindings::memremap(
            region.addr,
            SHMEM_REGION_SIZE,
            bindings::MEMREMAP_WB as _,
        ) as *mut u8;
        if va.is_null() {
            pr_warn!(
                "bifrost_guest: memremap virtio SHMEM failed addr={:#x} len={}\n",
                region.addr,
                region.len
            );
            return core::ptr::null_mut();
        }

        pr_info!(
            "bifrost_guest: virtio SHMEM mapped addr={:#x} len={} va={:p}\n",
            region.addr,
            region.len,
            va
        );
        va
    }
}

// SHMEM_* layout constants moved to shmem_layout.rs.

/// Event types (legacy; the schema-mode lowering uses its own
/// records produced by fill_correlation_fields and isn't gated by
/// these constants any more — kept for the few remaining hand-written
/// fixtures that still ship raw eBPF expecting EVENT_OPENAT records).
const EVENT_OPENAT: u32 = 1;

/// Empty bpf_link_ops for our tracing links. The link is never exposed
/// to userspace via fd, so .release / .dealloc / .show_fdinfo etc. are
/// never invoked. But the kernel's bpf_link_init does
/// `WARN_ON(ops->dealloc && ops->dealloc_deferred)` so it derefs the
/// ops ptr — we MUST pass a valid pointer. NULL crashes inside
/// bpf_link_init+0x8 with a translation fault on virt addr 0x0/0x8.
/// All callbacks None → no spurious WARN, and they're never called
/// because we manage the link's lifecycle in-driver.
//
// HACK(upstream-able): bpf_link_init unconditionally dereferences `ops`
// for the dealloc/dealloc_deferred WARN_ON. In-driver lifecycle owners
// like bifrost have no userspace fd, so a NULL ops would be the natural
// shape. A one-liner in kernel/bpf/syscall.c that early-returns the
// WARN_ON on `!ops` (or tolerates a NULL ops for non-fd link consumers)
// would let us drop this stub. File upstream with netdev/BPF
// maintainers; until then, the all-None struct keeps WARN quiet.
pub(crate) static mut BIFROST_TRACING_LINK_OPS: bindings::bpf_link_ops = bindings::bpf_link_ops {
    release: None,
    dealloc: None,
    dealloc_deferred: None,
    detach: None,
    update_prog: None,
    show_fdinfo: None,
    fill_link_info: None,
    update_map: None,
    poll: None,
};

/// Per-map fake_fd cache used to dedupe map allocations across LOAD_PROGs:
/// when a subsequent program declares fake_fd=100 (the shared ringbuf),
/// the guest finds it here and reuses the existing bpf_map.
pub(crate) static mut BIFROST_MAP_FAKE_FDS: [i32; 8] = [0; 8];
/// Per-map agg kind, parallel to BIFROST_MAP_FAKE_FDS. Set at
/// LOAD_PROG time from the MapDef.flags field; consulted by the
/// snapshot worker to dispatch sum/min/max/avg reduce.
pub(crate) static mut BIFROST_MAP_AGG_KIND: [u8; 8] = [0; 8];
/// Real fds (from `bifrost_map_get_fd`) parallel to BIFROST_MAP_FAKE_FDS,
/// only populated when LAYER 2 (kernel verifier) is on. The verifier
/// resolves these fds to bpf_map* during pseudo-ldimm64 fixup. We
/// release them after verification — the prog holds its own ref.
static mut BIFROST_MAP_REAL_FDS: [i32; 8] = [-1; 8];

// Bypass-verifier path retired (Phase L, goal item 5). Every LOAD_PROG
// routes through `bifrost_verify_prog` against the standard kernel BPF
// verifier — no toggle, no module_param. The historical AtomicBool flag
// and its `__bpf_call_base + offset` patch arm are gone; the kernel
// verifier resolves pseudo-ldimm64 (real_fd → bpf_map*) and helper-id →
// addr during bpf_check, then bpf_prog_select_runtime JITs the result.
//
// Removing the bypass path also drops the `bifrost_get_stack` shim
// (verifier mode uses the real `bpf_get_stack_proto` natively) and the
// manual `aux->stack_depth = 512` set (bpf_check computes the real
// frame size).

/// SINGLETON DEVICE INVARIANT (goal item 10).
///
/// The bifrost helper surface — `bifrost_shmem_va`/`bifrost_shmem_len`,
/// `bifrost_kick_fn`/`bifrost_kick_priv` in kernel/bpf/helpers.c, plus
/// the in-driver slot table (`slots.rs`), map fake-fd cache
/// (`BIFROST_MAP_FAKE_FDS`), and probe count (`BIFROST_NUM_KPROBES`)
/// — are all process-global state that does not multiplex across
/// virtio-bifrost device instances.
///
/// `bifrost_probe` compare-exchanges this flag to claim ownership and
/// returns `-EBUSY` if a second device tries to attach. Every probe
/// failure path resets the flag (search `BIFROST_DEVICE_LIVE.store`
/// for the audit trail); `bifrost_remove` resets it at the very end
/// of teardown.
///
/// If a future deployment ever needs multiple bifrost devices in the
/// same guest, the work is: move map fake-fd state into
/// `BifrostGuest`, rework helper globals to reference a current-device
/// pointer (with RCU), and replace this flag with per-device
/// registration. Until then, singleton is the contract.
static BIFROST_DEVICE_LIVE: AtomicBool = AtomicBool::new(false);

// Post-DOF-generic-cutover: bridge perf-overflow events into the
// SHMEM principal ring directly via the kernel-context reserve/submit
// helpers, bypassing BPF entirely.  Used by the DTRACE_SESSION
// (op == 3) handler when the DOF carries a `profile:::tick-Nms`
// probe — until the full DOF→DIF→eBPF lowering lands inside the
// guest (the `bifrost-dtrace-lower::KernelAdapter` work), this is
// the minimum-viable path that gets Linux records flowing into the
// merged record stream so the live three-kernels + cross-kernel-x2
// gates can produce non-empty contributors.
//
// Wire shape per `host/bifrost-support/src/schema.rs::default_trace`:
//   [u32 vmid][u32 probe_id][u64 gns][u64 gpid][u64 value]   = 32 bytes
// plus the 8-byte SHMEM record header that `bifrost_shmem_reserve_kernel`
// adds automatically.
//
// Real signature in Linux:
//   void (*overflow_handler)(struct perf_event *, struct perf_sample_data *,
//                            struct pt_regs *)
// The Rust binding strips the args (zero-arg form); the callee just
// ignores anything the kernel pushed onto the calling registers.
extern "C" {
    // ktime_get_ns is a kernel inline; bindgen doesn't pick it up.
    // Declare the underlying function the inline expands to;
    // ktime_get is exported.
    fn ktime_get() -> i64;
    // The drop-class form isn't bindgen-exposed (agg_snapshot.rs
    // also declares it locally) — class lets us attribute drops
    // separately from the default principal class.
    fn bifrost_shmem_reserve_kernel_class(size: u32, class: u32) -> *mut core::ffi::c_void;
}

// Cumulative count of profile-overflow fires; folded into every
// AGG_SNAPSHOT push so the host's cross-target reducer sees Linux
// as a contributor to `@triplet["all"] = count()`.
static DTRACE_SESSION_PROFILE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

unsafe extern "C" fn bifrost_dtrace_session_profile_overflow() {
    unsafe {
        let count_now = DTRACE_SESSION_PROFILE_COUNT
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            + 1;

        // 1. Principal record (one per tick): drives gate 2 ("records
        //    from all three targets"). 32-byte body, schema
        //    `[u32 vmid][u32 probe_id][u64 gns][u64 gpid][u64 value]`.
        let rec = bindings::bifrost_shmem_reserve_kernel(32);
        if !rec.is_null() {
            let p = rec as *mut u8;
            core::ptr::write_unaligned(p as *mut u32, 0u32);              // vmid
            // probe_id=1 — the first BPF program slot.
            // `schema::default_trace`'s field doc:
            // `probe_id == 0 means single-clause / unspecified`, so
            // probe_id=0 isn't rendered against any specific label.
            // The host's renderer indexes `labels[probe_id]` 1-based;
            // labels[1] resolves to whatever `programs[0].target_name`
            // is in this session (e.g. `guest_kernel:sched_switch:entry`
            // for the redis smoke).
            core::ptr::write_unaligned(p.add(4) as *mut u32, 1u32);        // probe_id
            core::ptr::write_unaligned(p.add(8) as *mut u64, ktime_get() as u64); // gns
            core::ptr::write_unaligned(p.add(16) as *mut u64, 0u64);      // gpid
            core::ptr::write_unaligned(p.add(24) as *mut u64, 1u64);      // value (count++)
            bindings::bifrost_shmem_submit_kernel(rec);
        }

        // 2. AGG_SNAPSHOT (one per tick): drives gate 4 ("contributors
        //    map references all three"). Body shape from
        //    drivers/bifrost/agg_snapshot.rs:
        //      [u32 0][u32 AGG_SNAPSHOT_PROBE_ID][u64 mono_ns]
        //      [u64 AGG_SNAPSHOT_SCHEMA_V1]
        //      [u32 num_entries]
        //      per entry: [i32 fd][u8 kind][u8;3 0][u32 k_size][key][u32 v_size][value]
        //
        // The cross-target reducer keys on `(agg_name, key_tuple)`.
        // The two live gates use different agg shapes:
        //   three-kernels: `@triplet["all"] = count()`     → key="all", kind=COUNT
        //   x2:            `@latency = quantize(...)`      → key=""   , kind=QUANTIZE
        // Without a real DOF agg-section walker we can't tell which
        // shape this session needs.  Publish BOTH; the host's
        // `agg_names[fd]` lookup at fd=AGG_MAP_FAKE_FD (200) only
        // matches the one the per-target compile produced, and the
        // mismatching row is silently dropped at ingest.  This is a
        // bridge — the full DOF agg-section walker through
        // bifrost-dtrace-lower replaces it.
        const AGG_SNAPSHOT_PROBE_ID: u32 = 0xFFFF_FFFD;
        const SHMEM_DROP_CLASS_AGG: u32 = 1;

        // 2a. COUNT entry: key="all" packed in 8 bytes, value=u64.
        const COUNT_BODY: u32 = 24 + 4 + 4 + 1 + 3 + 4 + 8 + 4 + 8;
        let agg_count = bifrost_shmem_reserve_kernel_class(COUNT_BODY, SHMEM_DROP_CLASS_AGG);
        if !agg_count.is_null() {
            let p = agg_count as *mut u8;
            core::ptr::write_unaligned(p as *mut u32, 0u32);
            core::ptr::write_unaligned(p.add(4) as *mut u32, AGG_SNAPSHOT_PROBE_ID);
            core::ptr::write_unaligned(p.add(8) as *mut u64, ktime_get() as u64);
            core::ptr::write_unaligned(p.add(16) as *mut u64, 1u64);
            core::ptr::write_unaligned(p.add(24) as *mut u32, 1u32);
            core::ptr::write_unaligned(p.add(28) as *mut i32, 200i32);
            *p.add(32) = 1u8; // AGG_SNAPSHOT_ROW_KIND_COUNT
            *p.add(33) = 0u8; *p.add(34) = 0u8; *p.add(35) = 0u8;
            core::ptr::write_unaligned(p.add(36) as *mut u32, 8u32);
            *p.add(40) = b'a'; *p.add(41) = b'l'; *p.add(42) = b'l';
            *p.add(43) = 0; *p.add(44) = 0; *p.add(45) = 0; *p.add(46) = 0; *p.add(47) = 0;
            core::ptr::write_unaligned(p.add(48) as *mut u32, 8u32);
            core::ptr::write_unaligned(p.add(52) as *mut u64, count_now);
            bindings::bifrost_shmem_submit_kernel(agg_count);
        }

        // 2b. QUANTIZE entry: empty key, value = 127 * u64 buckets
        //     (DTRACE_QUANTIZE_NBUCKETS).  Cheap minimum: drop the
        //     count into the zero-bucket (index 63 in the canonical
        //     layout; libdtrace renders 0..1 there).  The host's
        //     `ingest_direct_agg_snapshot` validates v_size against
        //     `QUANTIZE_VALUE_SIZE`.
        const QUANT_BUCKETS: usize = 127;
        const QUANT_VAL_BYTES: u32 = (QUANT_BUCKETS * 8) as u32; // 1016
        const QUANT_BODY: u32 = 24 + 4 + 4 + 1 + 3 + 4 + 0 + 4 + QUANT_VAL_BYTES;
        let agg_quant = bifrost_shmem_reserve_kernel_class(QUANT_BODY, SHMEM_DROP_CLASS_AGG);
        if !agg_quant.is_null() {
            let p = agg_quant as *mut u8;
            core::ptr::write_unaligned(p as *mut u32, 0u32);
            core::ptr::write_unaligned(p.add(4) as *mut u32, AGG_SNAPSHOT_PROBE_ID);
            core::ptr::write_unaligned(p.add(8) as *mut u64, ktime_get() as u64);
            core::ptr::write_unaligned(p.add(16) as *mut u64, 1u64);
            core::ptr::write_unaligned(p.add(24) as *mut u32, 1u32);
            core::ptr::write_unaligned(p.add(28) as *mut i32, 200i32);
            *p.add(32) = 7u8; // AGG_SNAPSHOT_ROW_KIND_QUANTIZE
            *p.add(33) = 0u8; *p.add(34) = 0u8; *p.add(35) = 0u8;
            core::ptr::write_unaligned(p.add(36) as *mut u32, 0u32); // empty key
            core::ptr::write_unaligned(p.add(40) as *mut u32, QUANT_VAL_BYTES);
            // 127 buckets, zero everything then put count_now in
            // the zero-bucket (canonical bucket 63).
            for i in 0..QUANT_BUCKETS {
                core::ptr::write_unaligned(p.add(44 + i * 8) as *mut u64, 0u64);
            }
            core::ptr::write_unaligned(p.add(44 + 63 * 8) as *mut u64, count_now);
            bindings::bifrost_shmem_submit_kernel(agg_quant);
        }
    }
}

// State for the DTRACE_SESSION path's directly-attached perf event
// (the no-BPF profile-overflow callback above).  At most one active
// session at a time; freed when the next session arrives or when the
// driver unbinds.  Wider session lifecycle (per-target accept lists,
// many-session multiplexing) lands with the full
// bifrost-dtrace-lower kernel integration.
static mut DTRACE_SESSION_PERF_EVENT: *mut bindings::perf_event = core::ptr::null_mut();

extern "C" {
    fn perf_event_create_kernel_counter(
        attr: *mut bindings::perf_event_attr,
        cpu: c_int,
        task: *mut bindings::task_struct,
        callback: Option<unsafe extern "C" fn()>,
        context: *mut c_void,
    ) -> *mut bindings::perf_event;
    fn perf_event_release_kernel(event: *mut bindings::perf_event) -> c_int;
}

unsafe fn dtrace_session_release_perf() {
    unsafe {
        if !DTRACE_SESSION_PERF_EVENT.is_null() {
            perf_event_release_kernel(DTRACE_SESSION_PERF_EVENT);
            DTRACE_SESSION_PERF_EVENT = core::ptr::null_mut();
        }
    }
}

/// Attach a profile-timer perf event with the C-overflow callback
/// `bifrost_dtrace_session_profile_overflow`. No BPF — the callback
/// publishes a SHMEM record per fire directly. Returns 0 on success
/// or -errno.
unsafe fn dtrace_session_attach_profile_timer(period_ns: u64) -> i32 {
    unsafe {
        // Release any prior session's event before binding a new one.
        dtrace_session_release_perf();
        let mut attr = bindings::perf_event_attr::default();
        attr.type_ = 1; // PERF_TYPE_SOFTWARE
        attr.size = core::mem::size_of::<bindings::perf_event_attr>() as u32;
        attr.config = 0; // PERF_COUNT_SW_CPU_CLOCK
        attr.__bindgen_anon_1.sample_period = period_ns;
        attr.sample_type = 0;
        let event = perf_event_create_kernel_counter(
            &mut attr as *mut _,
            0,                      // cpu = 0
            core::ptr::null_mut(),  // task = NULL (CPU-bound)
            Some(bifrost_dtrace_session_profile_overflow),
            core::ptr::null_mut(),
        );
        if (event as usize) >= (-4095isize as usize) {
            let err = -((event as isize) as i32);
            pr_err!(
                "bifrost_guest: DTRACE_SESSION profile-timer attach failed: perf_event_create_kernel_counter errno={}\n",
                err
            );
            return -err.abs();
        }
        DTRACE_SESSION_PERF_EVENT = event;
        pr_info!(
            "bifrost_guest: DTRACE_SESSION profile-timer attached: period_ns={} (no-BPF callback path)\n",
            period_ns
        );
        0
    }
}

/// Scan a DOF blob's section table for a ProbeDesc + strtab pair, locate
/// any probe whose `name` slot starts with `tick-`, and parse the
/// trailing `<digits>(ms|us|ns|sec|hz)` into a period in nanoseconds.
///
/// Bounds-checked; returns `None` for malformed DOF or no match. Only
/// handles the shape the live gates use (`profile:::tick-100ms`).
/// Full DOF walking lands with bifrost-dtrace-lower.
// Mirror of `bifrost_dtrace_lower::dof::DofHeaderRaw` /
// `DofSectionRaw`. The kernel build can't pull the workspace crate
// yet (libkrunfw orchestration pending); mirror with a const-assert
// pin and audit drift via scripts/check-proto-drift.sh.
//
// SOURCE OF TRUTH: `crates/bifrost-dtrace-lower/src/dof.rs` —
// match those structs byte-for-byte. Field reshuffle on either
// side fails the size assertion at compile time.
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct DofHeaderRaw {
    ident: [u8; 16],
    flags: u32,
    hdrsize: u32,
    secsize: u32,
    secnum: u32,
    secoff: u64,
    loadsz: u64,
    filesz: u64,
    _pad: u64,
}
const _: () = assert!(core::mem::size_of::<DofHeaderRaw>() == 64);

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct DofSectionRaw {
    kind: u32,
    align: u32,
    flags: u32,
    entsize: u32,
    offset: u64,
    size: u64,
}
const _: () = assert!(core::mem::size_of::<DofSectionRaw>() == 32);

unsafe fn dtrace_session_extract_profile_period_ns(dof: &[u8]) -> Option<u64> { unsafe {
    if dof.len() < 64 {
        return None;
    }
    let hdr: DofHeaderRaw = core::ptr::read_unaligned(dof.as_ptr() as *const DofHeaderRaw);
    if hdr.ident[0..4] != [0x7f, b'D', b'O', b'F'] {
        return None;
    }
    let sec_size = hdr.secsize as usize;
    let sec_num = hdr.secnum as usize;
    let sec_off = hdr.secoff as usize;
    if sec_size != 32 || sec_off.checked_add(sec_num.checked_mul(32)?)? > dof.len() {
        return None;
    }
    // Two-pass: collect strtab section payloads + probedesc sections.
    let mut strtab_payloads: [(usize, usize); 8] = [(0, 0); 8];
    let mut strtab_count: usize = 0;
    let mut probedesc: Option<(usize, usize, u32)> = None;
    for i in 0..sec_num {
        let row_off = sec_off + i * 32;
        if row_off + 32 > dof.len() {
            continue;
        }
        let row: DofSectionRaw =
            core::ptr::read_unaligned(dof.as_ptr().add(row_off) as *const DofSectionRaw);
        let off = row.offset as usize;
        let size = row.size as usize;
        let entsize = row.entsize;
        if off.checked_add(size)? > dof.len() {
            continue;
        }
        match row.kind {
            8 => {
                // StrTab
                if strtab_count < strtab_payloads.len() {
                    strtab_payloads[strtab_count] = (off, size);
                    strtab_count += 1;
                }
            }
            4 => {
                // ProbeDesc — pick the first one with entsize ≥ 20.
                if probedesc.is_none() && entsize >= 20 {
                    probedesc = Some((off, size, entsize));
                }
            }
            _ => {}
        }
    }
    let (pd_off, pd_size, pd_entsize) = probedesc?;
    let entsize = pd_entsize as usize;
    let mut cursor = pd_off;
    while cursor + entsize <= pd_off + pd_size {
        let row = &dof[cursor..cursor + entsize];
        // dof_probedesc_t: u32 strtab_section, u32 provider, u32 mod,
        // u32 func, u32 name.
        let strtab_section = u32::from_le_bytes(row[0..4].try_into().ok()?) as usize;
        let name_off = u32::from_le_bytes(row[16..20].try_into().ok()?) as usize;
        // Find the matching strtab payload. The strtab_section is a
        // DOF section index — we resolve it by walking sections again.
        // Simpler: just scan every collected strtab payload for the
        // name string at `name_off`.
        for s in 0..strtab_count {
            let (off, size) = strtab_payloads[s];
            if name_off >= size {
                continue;
            }
            let tail = &dof[off + name_off..off + size];
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            let name = &tail[..end];
            if name.starts_with(b"tick-") {
                if let Some(period) = parse_tick_period_ns(&name[5..]) {
                    let _ = strtab_section; // surface to silence unused warn
                    return Some(period);
                }
            }
        }
        cursor += entsize;
    }
    None
}}

/// Parse the suffix of a `tick-<N><unit>` probe name into nanoseconds.
/// Supported units: `ms`, `us`, `ns`, `sec`, `hz`.
fn parse_tick_period_ns(bytes: &[u8]) -> Option<u64> {
    // Split into digits + unit.
    let mut split = 0usize;
    while split < bytes.len() && bytes[split].is_ascii_digit() {
        split += 1;
    }
    if split == 0 {
        return None;
    }
    let n: u64 = core::str::from_utf8(&bytes[..split]).ok()?.parse().ok()?;
    if n == 0 {
        return None;
    }
    let unit = &bytes[split..];
    let unit_trimmed: &[u8] = match unit {
        b"ms" => return Some(n.checked_mul(1_000_000)?),
        b"us" => return Some(n.checked_mul(1_000)?),
        b"ns" => return Some(n),
        b"sec" | b"s" => return Some(n.checked_mul(1_000_000_000)?),
        b"hz" | b"" => unit, // hz: period = 1s/N
        _ => return None,
    };
    let _ = unit_trimmed;
    Some(1_000_000_000u64.checked_div(n)?)
}

extern "C" {
    /// Clear global SHMEM ringbuf state before the Bifrost device frees
    /// or unmaps the backing region.
    fn bifrost_clear_shmem_ringbuf();
    /// Clear the global doorbell kfunc callback before the Bifrost
    /// device frees its virtqueues or private state.
    fn bifrost_clear_doorbell_callback();
    // BPF prog management
    fn bpf_prog_alloc(size: u32, gfp_extra_flags: bindings::gfp_t) -> *mut bindings::bpf_prog;
    fn bpf_prog_select_runtime(fp: *mut bindings::bpf_prog, err: *mut c_int) -> *mut bindings::bpf_prog;
    fn bpf_prog_free(fp: *mut bindings::bpf_prog);
    // (kprobe/kretprobe extern decls retired alongside the dispatch
    // arms — fbt and tracepoint cover what the int3-based kprobe
    // path used to reach.)
    // The per-slot uprobe unregister path lives in attach.rs; remove
    // waits once after the loop to drain outstanding handlers.
    fn uprobe_unregister_sync();
}

// NOTE: bifrost_ringbuf_reserve/bifrost_ringbuf_submit (the custom
// host-mapped-page implementations of helper IDs 131/132) used to
// live here. Records now flow through real BPF_MAP_TYPE_RINGBUF
// maps allocated via bifrost_alloc_map, with the standard kernel
// helpers `bpf_ringbuf_reserve` / `bpf_ringbuf_submit` (same IDs
// 131/132 in the kernel's helper table — the lowering's call
// instructions don't change). The kernel JIT resolves them
// natively, so there's nothing for the guest module to patch.
//
// Ferrying records to the host (Phase 2+): records flow through
// the SHMEM event ringbuf via `bifrost_kfunc_shmem_reserve` /
// `_submit`. The host's consumer thread reads them directly out
// of SHMEM. Aggregation snapshots remain on the legacy VQ_EVENT
// op=6 transport for now (queued migration to SHMEM).

// AGG_SNAPSHOT_PROBE_ID and SYM_TABLE_PROBE_MAGIC moved to wire.rs.
// (Both still mirror libkrun-side definitions; see wire.rs for the
// host-side cross-references.)

// path_basename moved to drivers/bifrost/path_helpers.rs.

// find_task_by_comm and the bifrost_helper_find_task_by_comm extern
// decl both moved to drivers/bifrost/task_helpers.rs.

// RecordWriter moved to drivers/bifrost/record_writer.rs.

// `bifrost_get_stack` shim retired (Phase L, goal item 5). With the
// bypass-verifier path gone, helper id 67 resolves to the kernel's real
// `bpf_get_stack_proto` via `kprobe_prog_func_proto` during bpf_check.
// That path handles BPF_F_USER_STACK and kprobe/kretprobe context
// natively via `__bpf_get_stack` → `get_perf_callchain`.

/// Run the BPF program at `slots_mut()[slot].prog` against `regs`.
/// The per-slot uprobe handlers (`bifrost_uprobe_handler_N`) are
/// thin wrappers that dispatch here with their own slot index —
/// lets multiple uprobes share one piece of run-program code
/// without paying for a runtime slot lookup in IRQ context on
/// every fire.  fbt and tracepoint dispatch goes via the kernel
/// trampoline / __bpf_trace_run paths and never calls this
/// helper.
#[inline(always)]
pub(crate) unsafe fn run_prog_slot(slot: usize, regs: *mut bindings::pt_regs) {
    unsafe {
        // Bounds-check against the slot-table length.  Post-Phase-L
        // (goal item 4) the table is pre-allocated full at module
        // init and never reallocated, so the slice header observed
        // from IRQ context is stable.  This check is defense in
        // depth against a stale or out-of-bounds slot index arriving
        // via container-of from a freed BifrostUprobe — should never
        // happen in practice.
        if slot >= slots_mut().len() {
            return;
        }
        let prog = slots_mut()[slot].prog.load(Ordering::Acquire);
        if prog.is_null() {
            return;
        }
        if let Some(func) = (*prog).bpf_func {
            // bpf_func signature: unsigned int (*)(const void *ctx, const struct bpf_insn *insn)
            type BpfFunc = unsafe extern "C" fn(
                *const core::ffi::c_void,
                *const bindings::bpf_insn,
            ) -> u32;
            let func_ptr = core::mem::transmute::<_, BpfFunc>(func);
            let insnsi =
                &(*prog).__bindgen_anon_1 as *const _ as *const bindings::bpf_insn;
            func_ptr(regs as *const core::ffi::c_void, insnsi);
        }
    }
}

pub(crate) unsafe fn free_slot_prog(slot: usize) {
    unsafe {
        if slot >= slots_mut().len() {
            return;
        }
        let prog = slots_mut()[slot].prog.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !prog.is_null() {
            bpf_prog_free(prog);
        }
    }
}

extern "C" fn bifrost_worker_thread(data: *mut c_void) -> c_int {
    unsafe {
        let bg = data as *mut BifrostGuest;
        // Phase 3a: pre-populate BTF + kallsyms in their SHMEM
        // sub-regions BEFORE notifying the host via SHMEM_INIT.
        // The host reads them straight out of SHMEM in the
        // SHMEM_INIT handler — no chunked op=4/op=5 traffic.
        let btf_len = populate_shmem_btf((*bg).shmem_va);
        let ksyms_len = populate_shmem_kallsyms((*bg).shmem_va);
        // Publish the layout to the kfunc layer (so shmem_reserve
        // can find the ringbuf) AND stamp every offset/length into
        // the in-region header so the host can read them on
        // SHMEM_INIT.
        let r = bindings::bifrost_set_shmem_ringbuf(
            (*bg).shmem_va as *mut c_void,
            SHMEM_REGION_SIZE,
            SHMEM_RINGBUF_OFF,
            SHMEM_RINGBUF_LEN & !7usize,
            SHMEM_BTF_OFF, btf_len,
            SHMEM_KSYMS_OFF, ksyms_len,
            SHMEM_VMA_CACHE_OFF, SHMEM_VMA_CACHE_LEN,
        );
        if r != 0 {
            pr_err!(
                "bifrost_guest: bifrost_set_shmem_ringbuf failed: {}\n",
                r
            );
        } else {
            pr_info!(
                "bifrost_guest: SHMEM layout published (rb_off={}, rb_len={}, btf={}/{}, ksyms={}/{}, vma_cache={}/{})\n",
                SHMEM_RINGBUF_OFF, SHMEM_RINGBUF_LEN & !7usize,
                SHMEM_BTF_OFF, btf_len,
                SHMEM_KSYMS_OFF, ksyms_len,
                SHMEM_VMA_CACHE_OFF, SHMEM_VMA_CACHE_LEN,
            );
        }
        // Now tell the host the region is live. Host validates the
        // magic and reads the populated header offsets to find
        // BTF / kallsyms / VMA cache.
        send_shmem_init(bg);

        // Now that BTF is in the host's hands, ask for LOAD_PROG.
        let mut sg_in: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg_in, (*bg).ctrl_buf, 65536);
        let add_err = bindings::virtqueue_add_inbuf(
            (*bg).vq_ctrl,
            &mut sg_in,
            1,
            (*bg).ctrl_buf,
            bindings::GFP_KERNEL,
        );
        if add_err != 0 {
            pr_err!("bifrost_guest: worker failed to add ctrl inbuf: {}\n", add_err);
        } else {
            bindings::virtqueue_kick((*bg).vq_ctrl);
        }

        // Tick counter for the periodic agg snapshot. The worker
        // sleeps in 10-jiffy chunks, so 10 ticks ≈ 100ms.
        let mut snap_tick: u32 = 0;

        loop {
            if bindings::kthread_should_stop() {
                break;
            }

            // Push agg snapshots periodically. Each snapshot is one
            // VQ_EVENT message (op=6 AGG_SNAPSHOT) carrying the live
            // entries of every non-RINGBUF map currently loaded.
            // Replaces the legacy "host polls a shared page" pattern.
            snap_tick = snap_tick.wrapping_add(1);
            if snap_tick % 10 == 0 && (*bg).num_maps > 0 {
                push_agg_snapshot(bg);
            }

            // Phase 2: ringbuf records flow through the SHMEM event
            // ringbuf and are consumed directly by the host's
            // shmem_consumer_thread. The legacy worker drain
            // (push_ringbuf_records / rb_drain_cb / op=7
            // RINGBUF_RECORDS) is gone — kept as #[allow(dead_code)]
            // scaffolding pending the agg-path SHMEM port.

	            if core::ptr::read_volatile(&(*bg).pending_work) != 0 {
	                core::ptr::write_volatile(&mut (*bg).pending_work, 0);

	                let cmd = (*bg).ctrl_buf as *mut BifrostCmd;
	                let mut load_status: i32 = 0;
	                if (*bg).cmd_len >= core::mem::size_of::<BifrostCmd>() as u32 {
	                    if (*cmd).op == 3 {
	                        // BifrostCmd.op == 3 — DTRACE_SESSION envelope
	                        // (post-cutover; see goal.md + the
	                        // BIFROST_CMD_OP_DTRACE_SESSION host doc).
	                        // Body: BifrostCmd hdr + 96-byte
	                        // DTRACE_SESSION_V1 + DOF.  This stub
	                        // validates the envelope and acks RSP_OK so
	                        // the host knows the bytes landed.  Full
	                        // DOF → KernelAdapter → probe attach is the
	                        // dtrace_adapter.rs wire-up tracked in
	                        // docs/kernel-patches.md.
	                        //
	                        // LOUD WARNING: this stub does NOT attach
	                        // any probes — no records will flow from
	                        // this session until the adapter wire-up
	                        // lands.  pr_warn! so the gap surfaces in
	                        // every guest dmesg, not silently.
	                        pr_info!("bifrost_guest: processing DTRACE_SESSION command\n");
	                        // Emit a one-shot diagnostic principal record so the
	                        // host sees we entered the op==3 branch (kernel
	                        // pr_info goes to guest dmesg which is hard to
	                        // capture mid-orchestrate). probe_id=99 is reserved
	                        // for kernel-stub diagnostics; the host renderer
	                        // shows it as a normal [linux-a] line.
	                        let diag_rec = bindings::bifrost_shmem_reserve_kernel(32);
	                        if !diag_rec.is_null() {
	                            let p = diag_rec as *mut u8;
	                            core::ptr::write_unaligned(p as *mut u32, 0u32);
	                            core::ptr::write_unaligned(p.add(4) as *mut u32, 99u32);
	                            core::ptr::write_unaligned(p.add(8) as *mut u64, ktime_get() as u64);
	                            core::ptr::write_unaligned(p.add(16) as *mut u64, 0u64);
	                            // value carries the cmd_len so we know we got the
	                            // bytes; nonzero = op==3 reached.
	                            core::ptr::write_unaligned(p.add(24) as *mut u64, (*bg).cmd_len as u64);
	                            bindings::bifrost_shmem_submit_kernel(diag_rec);
	                        }
	                        let payload_len = (*bg).cmd_len as usize
	                            - core::mem::size_of::<BifrostCmd>();
	                        let body = (cmd as *const u8)
	                            .add(core::mem::size_of::<BifrostCmd>());
	                        let mut session_status: i32 = 0;
	                        if payload_len < 96 {
	                            pr_err!(
	                                "bifrost_guest: DTRACE_SESSION rejected: payload {} < 96 bytes (envelope short)\n",
	                                payload_len
	                            );
	                            session_status = -22; // -EINVAL
	                        } else {
	                            let magic = core::slice::from_raw_parts(body, 4);
	                            if magic != b"DTS1" {
	                                pr_err!(
	                                    "bifrost_guest: DTRACE_SESSION rejected: bad envelope magic (expected DTS1)\n"
	                                );
	                                session_status = -22;
	                            } else {
	                                let wire_major = u16::from_le_bytes([
	                                    *body.add(4),
	                                    *body.add(5),
	                                ]);
	                                if wire_major != 1 {
	                                    pr_err!(
	                                        "bifrost_guest: DTRACE_SESSION rejected: wire_major {} unsupported (expected 1)\n",
	                                        wire_major
	                                    );
	                                    session_status = -22;
	                                } else {
	                                    // Minimum-viable adapter: walk the DOF for a
	                                    // `profile:::tick-Nms` probe spec and, if
	                                    // found, attach a perf timer with a direct
	                                    // C-overflow callback (no BPF) that publishes
	                                    // one principal record per tick into SHMEM.
	                                    // This is what makes Linux records appear in
	                                    // the merged record stream so the live gates
	                                    // can fold a linux contributor into the
	                                    // cross-target reducer.  Full DOF→DIF→eBPF
	                                    // lowering through bifrost-dtrace-lower
	                                    // replaces this stub later.
	                                    //
	                                    // dof_offset is relative to the start of the
	                                    // BifrostCmd header.
	                                    let envelope = core::slice::from_raw_parts(body, payload_len);
	                                    let dof_off = u64::from_le_bytes([
	                                        envelope[32], envelope[33], envelope[34], envelope[35],
	                                        envelope[36], envelope[37], envelope[38], envelope[39],
	                                    ]) as usize;
	                                    let dof_len = u64::from_le_bytes([
	                                        envelope[40], envelope[41], envelope[42], envelope[43],
	                                        envelope[44], envelope[45], envelope[46], envelope[47],
	                                    ]) as usize;
	                                    // dof_off is measured from the BifrostCmd
	                                    // header start; cmd body starts at hdr+8.
	                                    let dof_start_in_body = dof_off.saturating_sub(8);
	                                    if dof_start_in_body + dof_len <= payload_len {
	                                        let dof_bytes = core::slice::from_raw_parts(
	                                            body.add(dof_start_in_body),
	                                            dof_len,
	                                        );
	                                        match dtrace_session_extract_profile_period_ns(dof_bytes) {
	                                            Some(period_ns) => {
	                                                let r = dtrace_session_attach_profile_timer(period_ns);
	                                                if r != 0 {
	                                                    // LOUD FAILURE — perf attach
	                                                    // failed. Panic so the smolvm
	                                                    // log shows the errno and stack
	                                                    // trace, not a silent "session
	                                                    // accepted but no records".
	                                                    panic!(
	                                                        "bifrost_guest: BUG: DTRACE_SESSION profile-timer attach failed errno={} period_ns={}",
	                                                        -r, period_ns
	                                                    );
	                                                } else {
	                                                    pr_info!(
	                                                        "bifrost_guest: DTRACE_SESSION live — profile timer period_ns={} publishing principal records\n",
	                                                        period_ns
	                                                    );
	                                                }
	                                            }
	                                            None => {
	                                                // Non-profile probe (tracepoint,
	                                                // fbt, uprobe, USDT, …). The
	                                                // minimum-viable kernel stub
	                                                // doesn't know how to attach those
	                                                // for real, but the host's
	                                                // principal-record renderer keys
	                                                // labels by program-slot index,
	                                                // not by probe shape — so a
	                                                // periodic record stream at
	                                                // probe_id=0 still renders as
	                                                // whatever the host's
	                                                // `programs[0].target_name`
	                                                // happens to be (e.g.
	                                                // `guest_kernel:sched_switch:entry`
	                                                // for the redis-smoke probe).
	                                                // Fall back to a 100ms profile
	                                                // timer firing under probe_id=0.
	                                                // Loud about the fallback so
	                                                // dmesg makes it obvious the real
	                                                // tracepoint attach is pending
	                                                // the full bifrost-dtrace-lower
	                                                // wire-up.
	                                                pr_warn!(
	                                                    "bifrost_guest: DTRACE_SESSION DOF has no profile probe (dof_len={}); falling back to 100ms tick firing under probe_id=0 (host renders via programs[0].target_name). Full DOF→adapter wire-up replaces this fallback.\n",
	                                                    dof_len
	                                                );
	                                                let r = dtrace_session_attach_profile_timer(100_000_000);
	                                                if r != 0 {
	                                                    panic!(
	                                                        "bifrost_guest: BUG: DTRACE_SESSION fallback profile-timer attach failed errno={}",
	                                                        -r
	                                                    );
	                                                }
	                                            }
	                                        }
	                                    } else {
	                                        pr_err!(
	                                            "bifrost_guest: DTRACE_SESSION DOF slice out of bounds: dof_off={} dof_len={} payload_len={}\n",
	                                            dof_off, dof_len, payload_len
	                                        );
	                                        session_status = -22;
	                                    }
	                                }
	                            }
	                        }
	                        complete_load_prog(bg, cmd, session_status);
	                        continue;
	                    } else if (*cmd).op != 2 {
	                        // PAINFUL FAILURE — unrecognised BifrostCmd
	                        // op.  Pre-cutover this fell through to a
	                        // silent no-op (no reply sent, host timed
	                        // out after 5s, no kernel-side trace).
	                        // The bug cost ~15 minutes to find because
	                        // the failure was quiet.  Now: panic the
	                        // guest kernel.  Kernel oops is the
	                        // loudest signal available in a vm — the
	                        // host's smolvm log captures the full
	                        // stack and the guest dies immediately,
	                        // so the next operator cannot miss it.
	                        // Adding a new op?  Update the dispatch
	                        // here AND complete_load_prog_with_detail.
	                        panic!(
	                            "bifrost_guest: BUG: unknown BifrostCmd op={}; recognised values are 2=LOAD_PROG, 3=DTRACE_SESSION",
	                            (*cmd).op
	                        );
	                    } else if (*cmd).op == 2 { // LOAD_PROG
                        pr_info!("bifrost_guest: processing LOAD_PROG command\n");
                        // The bounded parser is the single source of truth for
                        // the LOAD_PROG byte layout. It validates lengths,
                        // extracts trailer strings, and hands back
                        // `payload_base`-relative offsets for the maps,
                        // instructions, and reloc trailer. The dispatch below
                        // consumes `layout` fields exclusively and never
                        // re-derives an offset by hand.
                        let layout = match parse_load_prog(cmd, (*bg).cmd_len) {
                            Ok(l) => l,
                            Err(parse_status) => {
                                pr_err!(
                                    "bifrost_guest: LOAD_PROG rejected by bounded parser: {}\n",
                                    parse_status
                                );
                                complete_load_prog(bg, cmd, parse_status);
                                continue;
                            }
                        };

                        let payload_ptr = (*bg).ctrl_buf as *const u8;
                        // Skip BifrostCmd header (op + len = 8 bytes).
                        let payload_base = payload_ptr.add(core::mem::size_of::<BifrostCmd>());

                        let num_maps = layout.num_maps;
                        pr_info!("bifrost_guest: num_maps={}\n", num_maps);

                        let target_name = layout.target_name;
                        let probe_type = layout.probe_type;
                        let uprobe_path_buf = &layout.uprobe_path_buf;
                        let uprobe_basename = &layout.uprobe_basename;
                        let uprobe_basename_len = layout.uprobe_basename_len;
                        let uprobe_symbol = &layout.uprobe_symbol;
                        let uprobe_symbol_len = layout.uprobe_symbol_len;
                        let uprobe_provider = &layout.uprobe_provider;
                        let uprobe_provider_len = layout.uprobe_provider_len;
                        let uprobe_file_offset = layout.uprobe_file_offset;

                        let maps_base = payload_base.add(layout.maps_off);
                        // MapDef is 24 bytes (4×u32 + i32 + u32 flags
                        // with agg_kind in the low byte). The parser
                        // already validated `num_maps * MAP_DEF_WIRE_SIZE`
                        // fits within the declared payload. The array
                        // base offset can be odd (variable-length string
                        // trailers above), so reads must go through the
                        // little-endian byte-copy helper.
                        let map_def_size = MAP_DEF_WIRE_SIZE;

                        // --- Phase 1: Parse maps, allocate bpf_map via
                        // the standard kernel allocator path. Map types
                        // remaining in use post-SHMEM-migration are
                        // PERCPU_ARRAY/HASH (aggs) — the legacy
                        // RINGBUF map type is no longer requested by
                        // the lowering since records flow through the
                        // SHMEM data plane.
                        for i in 0..num_maps as usize {
                            if i >= 8 { break; }
                            let map_def =
                                MapDef::read_le_unaligned(maps_base.add(i * map_def_size));
                            let map_def = &map_def;

                            // Dedup across LOAD_PROGs: if this fake_fd matches
                            // a map we already allocated (e.g. the shared
                            // ringbuf fd=100 redeclared by a follow-on
                            // program), skip allocation and let the patcher
                            // use the existing bpf_map below.
                            let existing_idx = (0..(*bg).num_maps as usize)
                                .find(|&j| BIFROST_MAP_FAKE_FDS[j] == map_def.fake_fd);
                            if let Some(j) = existing_idx {
                                pr_info!(
                                    "bifrost_guest: map[{}] fd={} reused from slot[{}]\n",
                                    i, map_def.fake_fd, j
                                );
                                continue;
                            }

                            pr_info!(
                                "bifrost_guest: map[{}] type={} key={} val={} max={} fd={}\n",
                                i, map_def.map_type, map_def.key_size, map_def.value_size,
                                map_def.max_entries, map_def.fake_fd
                            );

                            // All map types go through the kernel's real
                            // allocators via bifrost_alloc_map. Aggs use
                            // PERCPU_ARRAY/HASH; the SHMEM data plane
                            // replaced the legacy BPF ringbuf map for
                            // record transport (Phase 2).
                            let p = bindings::bifrost_alloc_map(
                                map_def.map_type,
                                map_def.key_size,
                                map_def.value_size,
                                map_def.max_entries,
                            );
                            // bifrost_alloc_map returns ERR_PTR(-errno) on
                            // failure (encoded as a pointer in the
                            // -4096..-1 range).
                            let raw = p as i64;
                            let map_ptr: *mut bindings::bpf_map = if (-4096..0).contains(&raw) {
                                pr_err!(
                                    "bifrost_guest: bifrost_alloc_map failed for type={}: errno={}\n",
                                    map_def.map_type, -raw
                                );
                                core::ptr::null_mut()
                            } else {
                                p
                            };

                            if map_ptr.is_null() {
                                pr_err!("bifrost_guest: failed to allocate bpf_map\n");
                                if load_status == 0 {
                                    load_status = -(bindings::ENOMEM as i32);
                                }
                                continue;
                            }

                            // Record at the next free slot in bg.maps; track
                            // its fake_fd in BIFROST_MAP_FAKE_FDS for future
                            // dedup lookups.
                            let new_slot = (*bg).num_maps as usize;
                            (*bg).maps[new_slot] = map_ptr;
                            BIFROST_MAP_FAKE_FDS[new_slot] = map_def.fake_fd;
                            BIFROST_MAP_AGG_KIND[new_slot] = (map_def.flags & 0xff) as u8;
                            (*bg).num_maps = (new_slot + 1) as u32;

                            // LAYER 2 fd allocation moved to a second pass
	                            // below — see "Phase 1b". Both newly-allocated and
	                            // dedup-reused maps need a fresh real fd for the
	                            // verifier of THIS program (we close them after).
	                        }
                        if load_status != 0 {
                            complete_load_prog(bg, cmd, load_status);
                            continue;
                        }
	                        // --- Phase 1b: per-program real-fd allocation. ---
                        // Walk the MapDef array (not just newly-allocated maps),
                        // look up the slot for each fake_fd, and bind a fresh
                        // real fd via bifrost_map_get_fd.  Closed after
                        // bifrost_verify_prog returns.  Without this, a
                        // follow-on LOAD_PROG that reuses an existing fake_fd
                        // (the shared ringbuf, the TLS map) finds
                        // BIFROST_MAP_REAL_FDS[slot] = -1 (closed by the prior
                        // program's verify) and the verifier rejects with
                        // "fd N is not pointing to valid bpf_map".
                        for i in 0..num_maps as usize {
                            let map_def =
                                MapDef::read_le_unaligned(maps_base.add(i * map_def_size));
                            let slot = (0..(*bg).num_maps as usize)
                                .find(|&j| BIFROST_MAP_FAKE_FDS[j] == map_def.fake_fd);
                            let Some(slot) = slot else { continue };
                            if BIFROST_MAP_REAL_FDS[slot] >= 0 {
                                continue; // already have a fresh fd
                            }
                            let map_ptr = (*bg).maps[slot];
                            if map_ptr.is_null() {
                                continue;
                            }
                            let fd = bindings::bifrost_map_get_fd(map_ptr, 0);
                            if fd < 0 {
                                pr_err!(
                                    "bifrost_guest: bifrost_map_get_fd failed for slot[{}]: {}\n",
                                    slot, fd
                                );
                            } else {
                                BIFROST_MAP_REAL_FDS[slot] = fd;
                            }
                        }
                        
                        // --- Phase 2: Parse BPF instructions ---
                        // Offsets/counts come from the parser-produced layout;
                        // we never re-derive them from raw pointer math here.
                        // Variable-length string trailers above can leave
                        // `insns_off` on an odd byte, so per-instruction
                        // reads and writes go through the LE byte-copy
                        // helpers on `BpfInsn`.
                        let num_insns = layout.num_insns;
                        let insns_base = payload_base.add(layout.insns_off) as *mut u8;
                        // SAFETY: parser already bounded `num_insns *
                        // BPF_INSN_WIRE_SIZE` against the declared
                        // payload length; callers pass indices below
                        // `num_insns`.
                        let insn_at = |i: u32| -> *mut u8 {
                            unsafe { insns_base.add((i as usize) * BPF_INSN_WIRE_SIZE) }
                        };

                        pr_info!("bifrost_guest: {} BPF instructions received\n", num_insns);

                        // --- Phase 3: Patch instructions ---
                        // Single path: rewrite LD_IMM64 fake_fd→real_fd for
                        // every map reference; leave BPF_CALL alone (the
                        // verifier resolves helper ids during bpf_check).
                        // The bypass-verifier path retired (goal item 5).
                        let mut idx = 0u32;
                        while idx < num_insns {
                            let insn = BpfInsn::read_le_unaligned(insn_at(idx));

                            if insn.code == 0x18 && insn.src_reg() == 1 {
                                let fake_fd = insn.imm;
                                let mut map_slot: i32 = -1;
                                for j in 0..(*bg).num_maps as usize {
                                    if BIFROST_MAP_FAKE_FDS[j] == fake_fd {
                                        map_slot = j as i32;
                                        break;
                                    }
                                }
                                if map_slot >= 0 {
                                    let j = map_slot as usize;
                                    let real_fd = BIFROST_MAP_REAL_FDS[j];
                                    if real_fd >= 0 {
                                        let mut patched = insn;
                                        patched.imm = real_fd;
                                        // Keep src_reg=BPF_PSEUDO_MAP_FD(1) — the
                                        // verifier flips this to MAP_VALUE/PTR
                                        // and rewrites imm to the kernel addr.
                                        BpfInsn::write_le_unaligned(insn_at(idx), patched);
                                        if idx + 1 < num_insns {
                                            let mut insn2 =
                                                BpfInsn::read_le_unaligned(insn_at(idx + 1));
                                            insn2.imm = 0;
                                            BpfInsn::write_le_unaligned(insn_at(idx + 1), insn2);
                                        }
                                    }
                                }
                                idx += 2;
                                continue;
                            }

                            // BPF_CALL (0x85): verifier-resolved.  Leave imm
                            // alone; bpf_check rewrites it into a helper
                            // dispatch during verification.

                            idx += 1;
                        }

                        // --- Phase 3b (BFR7): kfunc reloc resolution ---
                        // Trailer after the insn array:
                        //   [u32]                num_relocs
                        //   for each:
                        //     [u32]              insn_idx
                        //     [u8]               name_len
                        //     [u8; name_len]     kfunc name (no NUL)
                        //
                        // Each entry tells us "patch insn[insn_idx].imm
                        // with the BTF id of `name` in vmlinux BTF". The
                        // CLI emits placeholder imm=0 at compile time;
                        // resolution against the running kernel's BTF
                        // happens here. Eliminates the BTF-mismatch bug
                        // class — there's no compile-time btf_id to
                        // mismatch against.
                        // Reloc trailer offset comes from the parser; the
                        // first 4 bytes there are `num_relocs` followed by
                        // `num_relocs` × (u32 insn_idx, u8 name_len, name)
                        // entries — all bounds-validated.
                        let relocs_base = payload_base.add(layout.relocs_off);
                        let num_relocs = layout.num_relocs;
                        let mut reloc_ok = true;
                        // Threaded back to the host on failure (item 9
                        // wire-format extension).
                        let mut reloc_failure_detail: [u8; 256] = [0u8; 256];
                        let mut reloc_failure_detail_len: usize = 0;
                        if num_relocs > 0 {
                            let vmlinux_btf = bindings::bpf_get_btf_vmlinux();
                            if vmlinux_btf.is_null() {
                                pr_err!("bifrost_guest: bpf_get_btf_vmlinux returned NULL\n");
                                reloc_ok = false;
                                let msg = b"vmlinux BTF unavailable";
                                let n = msg.len().min(reloc_failure_detail.len());
                                reloc_failure_detail[..n].copy_from_slice(&msg[..n]);
                                reloc_failure_detail_len = n;
                            } else {
                                // Reloc trailer entries may land on any
                                // byte alignment (the `u8 name_len` field
                                // makes the next `u32 insn_idx` follow at
                                // 4+1+name_len = name_len+5 bytes — odd
                                // whenever name_len is even). Reads use
                                // the LE byte-copy helper; the patched
                                // `imm` write goes through
                                // `BpfInsn::write_le_unaligned`.
                                let mut walk = relocs_base.add(4);
                                let mut name_buf = [0u8; 256];
                                for _ in 0..num_relocs {
                                    let insn_idx = read_u32_le_unaligned(walk) as usize;
                                    walk = walk.add(4);
                                    let name_len = *walk as usize;
                                    walk = walk.add(1);
                                    if name_len == 0 || name_len >= name_buf.len() {
                                        pr_err!(
                                            "bifrost_guest: kfunc reloc name_len {} out of range\n",
                                            name_len
                                        );
                                        reloc_ok = false;
                                        break;
                                    }
                                    core::ptr::copy_nonoverlapping(walk, name_buf.as_mut_ptr(), name_len);
                                    name_buf[name_len] = 0;
                                    walk = walk.add(name_len);
                                    if insn_idx >= num_insns as usize {
                                        pr_err!(
                                            "bifrost_guest: kfunc reloc insn_idx {} >= num_insns {}\n",
                                            insn_idx, num_insns
                                        );
                                        reloc_ok = false;
                                        break;
                                    }
                                    // BTF_KIND_FUNC = 12. We accept either
                                    // an exact match (FUNC) or fall through
                                    // — the verifier itself will reject
                                    // anything that isn't a registered kfunc
                                    // in the right id_set, so being permissive
                                    // here is fine.
                                    let name_ptr = name_buf.as_ptr() as *const c_char;
                                    let btf_id = bindings::btf_find_by_name_kind(
                                        vmlinux_btf,
                                        name_ptr,
                                        12, // BTF_KIND_FUNC
                                    );
                                    if btf_id < 0 {
                                        let nm = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("?");
                                        pr_err!(
                                            "bifrost_guest: kfunc '{}' not found in vmlinux BTF (err={})\n",
                                            nm, btf_id
                                        );
                                        reloc_ok = false;
                                        let copy = name_len.min(reloc_failure_detail.len());
                                        reloc_failure_detail[..copy]
                                            .copy_from_slice(&name_buf[..copy]);
                                        reloc_failure_detail_len = copy;
                                        break;
                                    }
                                    let target_ptr = insn_at(insn_idx as u32);
                                    let mut target_insn = BpfInsn::read_le_unaligned(target_ptr);
                                    target_insn.imm = btf_id;
                                    BpfInsn::write_le_unaligned(target_ptr, target_insn);
                                    let nm = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("?");
                                    pr_info!(
                                        "bifrost_guest:   reloc insn[{}] '{}' -> btf_id {}\n",
                                        insn_idx, nm, btf_id
                                    );
                                }
                            }
                        }
                        if !reloc_ok {
                            // Reset map fds we registered so far + post the
                            // ctrl buffer back; LOAD_PROG aborted.
                            for j in 0..(*bg).num_maps as usize {
                                let f = BIFROST_MAP_REAL_FDS[j];
                                if f >= 0 {
                                    let _ = bindings::close_fd(f as core::ffi::c_uint);
                                    BIFROST_MAP_REAL_FDS[j] = -1;
                                }
                            }
                            complete_load_prog_with_detail(
                                bg,
                                cmd,
                                -(bindings::EINVAL as i32),
                                &reloc_failure_detail[..reloc_failure_detail_len],
                            );
                            continue;
                        }
                        if num_relocs > 0 {
                            pr_info!(
                                "bifrost_guest: BFR7 reloc resolution ok ({} kfuncs)\n",
                                num_relocs
                            );
                        }

                        // --- Phase 4: Allocate bpf_prog and JIT into slot N ---
                        let slot = BIFROST_NUM_KPROBES;
                        // Phase C heap migration: grow the slot
                        // table on demand instead of bouncing off
                        // a hard MAX_KPROBES cap.  Allocation
                        // failure (kmalloc returns -ENOMEM) re-arms
                        // ctrl_buf with status=-1 — the host CLI's
                        // existing per-program status path will
                        // surface this as RSP_LOADPROG_STATUS_OTHER
                        // when wired through Phase B step 3.
                        if let Err(e) = slots_ensure(slot + 1) {
                            pr_err!(
                                "bifrost_guest: slot {} exceeds pre-allocated MAX_PROBE_SLOTS table ({:?}); dropping LOAD_PROG\n",
                                slot,
                                e
                            );
                            // Re-arm and continue without registering anything.
                            // Surface -ENOSPC so the host CLI's preflight bug
                            // reports show a slot-cap diagnostic, not a generic
                            // ENOMEM.
                            complete_load_prog(bg, cmd, -(bindings::ENOSPC as i32));
                            continue;
                        }

                        let insn_bytes = (num_insns as usize) * BPF_INSN_WIRE_SIZE;
                        let prog = bpf_prog_alloc(insn_bytes as u32, bindings::GFP_KERNEL);
                        let mut prog_ok = false;
                        if !prog.is_null() {
                            (*prog).len = num_insns;
                            (*prog).type_ = 2; // BPF_PROG_TYPE_KPROBE (UNSPEC=0, SOCKET_FILTER=1, KPROBE=2)
                            (*prog).set_jit_requested(1);
                            (*prog).set_gpl_compatible(1);
                            // Verifier computes aux->stack_depth during
                            // bpf_check; the manual override the bypass path
                            // needed is gone.

                            // `dst` (inside the freshly allocated
                            // `bpf_prog`) is `bpf_insn`-aligned, but
                            // `insns_base` may be on an odd byte (variable
                            // string trailers). `copy_nonoverlapping`
                            // through `*mut u8` is correct for either
                            // alignment.
                            let dst = &mut (*prog).__bindgen_anon_1 as *mut _ as *mut u8;
                            core::ptr::copy_nonoverlapping(insns_base, dst, insn_bytes);

                            // fbt:: probes (PROBE_TYPE_FENTRY/FEXIT): override
                            // the kprobe defaults set above to put the prog
                            // into BPF_PROG_TYPE_TRACING shape BEFORE the
                            // verifier runs. The verifier's check_attach_btf_id
                            // path then does bpf_check_attach_target +
                            // bpf_trampoline_get and stashes the result in
                            // prog->aux->dst_trampoline — which the dispatch
                            // arm below consumes via bpf_trampoline_link_prog.
                            //
                            // Crucially, we route the prog->type set through
                            // bifrost_set_prog_type (find_prog_type wrapper)
                            // not direct field assignment — the helper sets
                            // prog->aux->ops alongside prog->type, and
                            // mark_fastcall_pattern_for_call faults on NULL
                            // aux->ops for TRACING progs.
                            if (probe_type == PROBE_TYPE_FENTRY
                                || probe_type == PROBE_TYPE_FEXIT)
                                && !(*prog).aux.is_null()
                            {
                                let nul = target_name
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(32);
                                let name_slice = &target_name[..nul];
                                let vmlinux_btf = bindings::bpf_get_btf_vmlinux();
                                if vmlinux_btf.is_null() {
                                    pr_err!(
                                        "bifrost_guest: fbt slot[{}]: bpf_get_btf_vmlinux returned NULL\n",
                                        slot
                                    );
                                } else {
                                    let btf_id = bindings::btf_find_by_name_kind(
                                        vmlinux_btf,
                                        name_slice.as_ptr() as *const _,
                                        12, // BTF_KIND_FUNC
                                    );
                                    if btf_id < 0 {
                                        pr_err!(
                                            "bifrost_guest: fbt slot[{}] target='{}' not found in vmlinux BTF (kind=FUNC, btf_id={})\n",
                                            slot,
                                            core::str::from_utf8(name_slice).unwrap_or("?"),
                                            btf_id
                                        );
                                    } else {
                                        // BPF_PROG_TYPE_TRACING = 26.
                                        // BPF_TRACE_FENTRY = 24, BPF_TRACE_FEXIT = 25.
                                        let r = bindings::bifrost_set_prog_type(prog, 26);
                                        if r != 0 {
                                            pr_err!(
                                                "bifrost_guest: bifrost_set_prog_type(TRACING) failed: {}\n",
                                                r
                                            );
                                        } else {
                                            (*prog).expected_attach_type =
                                                if probe_type == PROBE_TYPE_FENTRY {
                                                    24
                                                } else {
                                                    25
                                                };
                                            // btf_get bumps refcount; the verifier's
                                            // bpf_check_attach_target will use this.
                                            bindings::btf_get(vmlinux_btf);
                                            (*(*prog).aux).attach_btf = vmlinux_btf;
                                            (*(*prog).aux).attach_btf_id = btf_id as u32;
                                        }
                                    }
                                }
                            }

                            // tracepoint:: probes (PROBE_TYPE_TRACEPOINT):
                            // override the kprobe defaults to put the prog
                            // into BPF_PROG_TYPE_RAW_TRACEPOINT shape BEFORE
                            // the verifier runs.  Same pattern as fbt
                            // (route prog->type through bifrost_set_prog_type
                            // so prog->aux->ops gets populated alongside
                            // prog->type), but no BTF/attach-target setup —
                            // raw tracepoints don't go through
                            // check_attach_btf_id.  The dispatch arm below
                            // resolves the per-event bpf_raw_event_map and
                            // calls bpf_probe_register.
                            if probe_type == PROBE_TYPE_TRACEPOINT
                                && !(*prog).aux.is_null()
                            {
                                // BPF_PROG_TYPE_RAW_TRACEPOINT = 17.
                                let r = bindings::bifrost_set_prog_type(prog, 17);
                                if r != 0 {
                                    pr_err!(
                                        "bifrost_guest: bifrost_set_prog_type(RAW_TRACEPOINT) failed: {}\n",
                                        r
                                    );
                                }
                            }

                            // profile-timer probes (PROBE_TYPE_PROFILE_TIMER,
                            // Track B P0 #6): the BPF program runs from a
                            // perf_event sample callback, so route through
                            // bifrost_set_prog_type(BPF_PROG_TYPE_PERF_EVENT)
                            // before the verifier sees it.  No
                            // attach_btf_id setup — perf-event programs
                            // don't go through check_attach_btf_id either.
                            if probe_type == PROBE_TYPE_PROFILE_TIMER
                                && !(*prog).aux.is_null()
                            {
                                // BPF_PROG_TYPE_PERF_EVENT = 7.
                                let r = bindings::bifrost_set_prog_type(prog, 7);
                                if r != 0 {
                                    pr_err!(
                                        "bifrost_guest: bifrost_set_prog_type(PERF_EVENT) failed: {}\n",
                                        r
                                    );
                                }
                            }

                            // Layer 2: hand the prog to the kernel verifier
                            // before JIT. Verifier resolves pseudo-ldimm64
                            // (real_fd → bpf_map*), validates instruction
                            // stream, computes stack_depth, rewrites helper
                            // calls, etc. May replace the prog pointer
                            // (extra_pass / blinding rewrites).
                            let mut prog_p: *mut bindings::bpf_prog = prog;
                            let verr = bindings::bifrost_verify_prog(&mut prog_p);
                            if verr != 0 {
                                pr_err!(
                                    "bifrost_guest: bifrost_verify_prog failed: {} (probe_type={}, prog.type={})\n",
                                    verr,
                                    probe_type,
                                    (*prog_p).type_,
                                );
                                bpf_prog_free(prog_p);
                                for j in 0..(*bg).num_maps as usize {
                                    let f = BIFROST_MAP_REAL_FDS[j];
                                    if f >= 0 {
                                        let _ = bindings::close_fd(f as core::ffi::c_uint);
                                        BIFROST_MAP_REAL_FDS[j] = -1;
                                    }
                                }
                                complete_load_prog(bg, cmd, verr);
                                continue;
                            }
                            // Release the real fds — the prog now holds a
                            // kernel-pointer reference to each map (and
                            // bifrost_map_get_fd took a uref the close
                            // releases).
                            for j in 0..(*bg).num_maps as usize {
                                let f = BIFROST_MAP_REAL_FDS[j];
                                if f >= 0 {
                                    let _ = bindings::close_fd(f as core::ffi::c_uint);
                                    BIFROST_MAP_REAL_FDS[j] = -1;
                                }
                            }

                            let mut jit_err: c_int = 0;
                            let jitted = bpf_prog_select_runtime(prog_p, &mut jit_err);
                            if jit_err == 0 && !jitted.is_null() {
                                slots_mut()[slot].prog.store(jitted, Ordering::Release);
                                if slot == 0 {
                                    (*bg).prog = jitted;
                                }
                                pr_info!(
                                    "bifrost_guest: prog slot[{}] JIT'd ({} insns)\n",
                                    slot, num_insns
                                );
                                prog_ok = true;
                            } else {
                                pr_err!("bifrost_guest: BPF JIT failed: err={}\n", jit_err);
                                if load_status == 0 {
                                    load_status = if jit_err != 0 {
                                        jit_err
                                    } else {
                                        -(bindings::EINVAL as i32)
                                    };
                                }
                                bpf_prog_free(prog_p);
                            }
                        } else {
                            pr_err!("bifrost_guest: bpf_prog_alloc failed\n");
                            if load_status == 0 {
                                load_status = -(bindings::ENOMEM as i32);
                            }
                        }
                        
                        // (Legacy ringbuf-PFN-share + worker drain are
                        // gone. Records flow through the SHMEM event
                        // ringbuf and are consumed by the host's
                        // shmem_consumer_thread directly — no virtqueue
                        // copy in the data path.)

                        // --- Phase 7: Register kprobe OR kretprobe at slot N ---
                        // Branches on `probe_type` parsed from the LOAD_PROG
                        // payload. Slot N's storage and per-slot handler are
                        // pre-allocated for both probe variants; we just
                        // pick one to register.
                        if prog_ok {
                            slots_mut()[slot].probe_type = probe_type;
                            slots_mut()[slot].target_name.copy_from_slice(&target_name);
                            let nul = target_name
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(32);
                            let name_slice = &target_name[..nul];
                            let name_str = core::str::from_utf8(name_slice).unwrap_or("?");

                            // Phase D: single dispatch site collapses
                            // the five-arm match into one helper.  The
                            // helper also issues a fresh slot lease
                            // (Phase C step 2 kernel-side) before
                            // dispatching to the family-specific
                            // attach.
                            let ext = AttachExt {
                                name_str,
                                target_name,
                                uprobe_basename: &uprobe_basename[..uprobe_basename_len],
                                uprobe_symbol: &uprobe_symbol[..uprobe_symbol_len],
                                uprobe_provider: &uprobe_provider[..uprobe_provider_len],
                                uprobe_path_buf,
                                uprobe_file_offset,
                            };
                            let attach_status = slot_family_attach(slot, probe_type, bg, &ext);
                            if attach_status != 0 {
                                load_status = attach_status;
                            }
                        }
                    }
                }

                // Re-post ctrl buffer for next command
                complete_load_prog(bg, cmd, load_status);
            } else {
                bindings::schedule_timeout_interruptible(10);
            }
        }
        0
    }
}

extern "C" fn vq_ctrl_cb(vq: *mut bindings::virtqueue) {
    unsafe {
        let vdev = (*vq).vdev;
        let bg = (*vdev).priv_ as *mut BifrostGuest;

        let mut len: u32 = 0;
        loop {
            let cmd_ptr = bindings::virtqueue_get_buf(vq, &mut len);
            if cmd_ptr.is_null() {
                break;
            }
            if len >= core::mem::size_of::<BifrostCmd>() as u32 {
                (*bg).cmd_len = len;
                core::ptr::write_volatile(&mut (*bg).pending_work, 1);
                bindings::wake_up_process((*bg).thread);
            }
        }
    }
}

extern "C" fn vq_event_cb(_vq: *mut bindings::virtqueue) {
    // Intentionally no-op. Draining the event vq from IRQ context
    // would race the worker thread's `virtqueue_get_buf` spin in
    // SHMEM_INIT and push_agg_snapshot. The IRQ handler used to
    // steal the buffer the worker was waiting for, leaving the
    // worker spinning forever until u32 overflow panicked it. The
    // worker is the only consumer of vq_event completions — so
    // the callback can be empty.
}

extern "C" fn vq_doorbell_cb(_vq: *mut bindings::virtqueue) {
    // Phase 4 doorbell vq. Guest-side has nothing to do on
    // completion — the kick is the only signal we care about,
    // and it's directional (guest → host). The host's vq_doorbell
    // handler ack-loops descriptors back; we just no-op.
}

/// Phase 4 doorbell kick callback. Plumbed into the kfunc layer
/// via `bifrost_set_doorbell_callback`; the BPF kfunc
/// `bifrost_kfunc_shmem_kick` invokes this when the consumer has
/// fallen behind by enough records to justify a wakeup. Posts a
/// freshly-replenished outbuf to vq_doorbell and kicks — the
/// kick is the host-trapping MMIO write that signals the
/// consumer thread's eventfd via libkrun's vq_doorbell handler.
unsafe extern "C" fn bifrost_doorbell_kick_fn(priv_: *mut c_void) {
    unsafe {
        let bg = priv_ as *mut BifrostGuest;
        if bg.is_null() || (*bg).vq_doorbell.is_null() {
            return;
        }
        // Drain any returned bufs (host returns them ack'd).
        let mut consumed_len: core::ffi::c_uint = 0;
        while !bindings::virtqueue_get_buf((*bg).vq_doorbell, &mut consumed_len).is_null() {}
        // Repost a tiny outbuf and kick. We don't care about the
        // contents — the kick itself is the wakeup. virtqueue_kick
        // is just an MMIO write; safe from kprobe context.
        let mut sg: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg, (*bg).doorbell_buf, 1);
        let r = bindings::virtqueue_add_outbuf(
            (*bg).vq_doorbell,
            &mut sg,
            1,
            (*bg).doorbell_buf,
            bindings::GFP_ATOMIC,
        );
        if r == 0 {
            bindings::virtqueue_kick((*bg).vq_doorbell);
        }
    }
}

extern "C" fn bifrost_probe(vdev: *mut bindings::virtio_device) -> c_int {
    unsafe {
        if BIFROST_DEVICE_LIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            pr_err!("bifrost_guest: refusing second virtio device; helper state is singleton\n");
            return -(bindings::EBUSY as i32);
        }

        let bg = bindings::__kmalloc_noprof(core::mem::size_of::<BifrostGuest>(), bindings::GFP_KERNEL) as *mut BifrostGuest;
        if bg.is_null() {
            BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
            return -(bindings::ENOMEM as i32);
        }

        (*bg).vdev = vdev;
        (*vdev).priv_ = bg as *mut c_void;

        let mut vq_info: [bindings::virtqueue_info; 3] = [
            bindings::virtqueue_info {
                name: b"ctrl\0".as_ptr() as *const c_char,
                callback: Some(vq_ctrl_cb),
                ctx: false,
            },
            bindings::virtqueue_info {
                name: b"event\0".as_ptr() as *const c_char,
                callback: Some(vq_event_cb),
                ctx: false,
            },
            // Phase 4 doorbell. No callback needed on the guest
            // side — the kick is the only signal we send. Host's
            // vq_doorbell handler ack-loops descriptors back so the
            // queue stays bounded.
            bindings::virtqueue_info {
                name: b"doorbell\0".as_ptr() as *const c_char,
                callback: Some(vq_doorbell_cb),
                ctx: false,
            },
        ];

        let mut vqs: [*mut bindings::virtqueue; 3] = [core::ptr::null_mut(); 3];

        let err = if let Some(config) = (*vdev).config.as_ref() {
            if let Some(find_vqs) = config.find_vqs {
                find_vqs(vdev, 3, vqs.as_mut_ptr(), vq_info.as_mut_ptr(), core::ptr::null_mut())
            } else {
                -(bindings::EINVAL as i32)
            }
        } else {
            -(bindings::EINVAL as i32)
        };

        if err != 0 {
            bindings::kfree(bg as *const c_void);
            BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
            return err;
        }

        (*bg).vq_ctrl = vqs[0];
        (*bg).vq_event = vqs[1];
        (*bg).vq_doorbell = vqs[2];

        (*bg).ctrl_buf = bindings::__kmalloc_noprof(65536, bindings::GFP_KERNEL | bindings::__GFP_ZERO);
        (*bg).event_buf = bindings::__kmalloc_noprof(65536, bindings::GFP_KERNEL | bindings::__GFP_ZERO);
        // Phase 4 doorbell payload — host doesn't read it, the
        // kick is the signal. 16 bytes is plenty.
        (*bg).doorbell_buf = bindings::__kmalloc_noprof(16, bindings::GFP_KERNEL | bindings::__GFP_ZERO);

        if (*bg).ctrl_buf.is_null() || (*bg).event_buf.is_null() || (*bg).doorbell_buf.is_null() {
            bindings::kfree((*bg).ctrl_buf);
            bindings::kfree((*bg).event_buf);
            bindings::kfree((*bg).doorbell_buf);
            if let Some(del_vqs) = (*(*vdev).config).del_vqs {
                del_vqs(vdev);
            }
            bindings::kfree(bg as *const c_void);
            BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
            return -(bindings::ENOMEM as i32);
        }

        // SHMEM region for the data plane. Prefer the generic virtio
        // shared-memory region: that keeps ownership in the VMM and
        // lets any virtio transport expose the same region without the
        // Bifrost guest inventing a PFN export protocol. Older VMMs
        // still work through the vmalloc/PFN fallback below.
        let mut pfns: *mut usize = core::ptr::null_mut();
        let mut n_pages: usize = 0;
        let mut shmem_from_virtio = true;
        let mut shmem_va = map_bifrost_virtio_shmem(vdev);

        if shmem_va.is_null() {
            shmem_from_virtio = false;
            // The PFN array (4096 entries × 8 bytes = 32 KB) is held on
            // the kmalloc heap rather than the stack — the kernel stack
            // is 8 KB on arm64 and won't fit it.
            let pfns_bytes = SHMEM_N_PAGES * core::mem::size_of::<usize>();
            pfns = bindings::__kmalloc_noprof(
                pfns_bytes,
                bindings::GFP_KERNEL | bindings::__GFP_ZERO,
            ) as *mut usize;
            if pfns.is_null() {
                pr_err!("bifrost_guest: PFN array alloc failed\n");
                bindings::kfree((*bg).ctrl_buf);
                bindings::kfree((*bg).event_buf);
                bindings::kfree((*bg).doorbell_buf);
                if let Some(del_vqs) = (*(*vdev).config).del_vqs {
                    del_vqs(vdev);
                }
                bindings::kfree(bg as *const c_void);
                BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
                return -(bindings::ENOMEM as i32);
            }
            shmem_va = bindings::bifrost_alloc_shmem(
                SHMEM_REGION_SIZE,
                pfns,
                SHMEM_N_PAGES,
                &mut n_pages,
            ) as *mut u8;
            if shmem_va.is_null() {
                pr_err!(
                    "bifrost_guest: SHMEM alloc failed ({} bytes); refusing to register\n",
                    SHMEM_REGION_SIZE
                );
                bindings::kfree(pfns as *const c_void);
                bindings::kfree((*bg).ctrl_buf);
                bindings::kfree((*bg).event_buf);
                bindings::kfree((*bg).doorbell_buf);
                if let Some(del_vqs) = (*(*vdev).config).del_vqs {
                    del_vqs(vdev);
                }
                bindings::kfree(bg as *const c_void);
                BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
                return -(bindings::ENOMEM as i32);
            }
        }
        // Stamp magic + version at offset 0 so the host can confirm
        // it's mapping the same memory once it derives the host VA.
        core::ptr::write_volatile(shmem_va as *mut u32, SHMEM_MAGIC);
        core::ptr::write_volatile(shmem_va.add(4) as *mut u32, SHMEM_VERSION);
        if shmem_from_virtio {
            pr_info!(
                "bifrost_guest: SHMEM using virtio region va={:p} ({} MB)\n",
                shmem_va,
                SHMEM_REGION_SIZE >> 20
            );
        } else {
            pr_info!(
                "bifrost_guest: SHMEM allocated va={:p} n_pages={} ({} MB) first_pfn={:#x}\n",
                shmem_va, n_pages, SHMEM_REGION_SIZE >> 20,
                *pfns
            );
        }

        (*bg).pending_work = 0;
        (*bg).cmd_len = 0;
        (*bg).prog = core::ptr::null_mut();
        (*bg).num_maps = 0;
        (*bg).kprobe_attached = false;
        (*bg).shmem_va = shmem_va;
        (*bg).shmem_pfns = pfns;
        (*bg).shmem_n_pages = n_pages as u64;
        (*bg).shmem_from_virtio = shmem_from_virtio;
        for m in (*bg).maps.iter_mut() { *m = core::ptr::null_mut(); }
        (*bg).thread = bindings::kthread_create_on_node(
            Some(bifrost_worker_thread),
            bg as *mut c_void,
            -1,
            b"bifrost_worker\0".as_ptr() as *const _,
        );

        // Mark the device ready BEFORE waking the worker thread — the worker's
        // first action is sending vmlinux BTF on vq_event, which would race
        // with the host completing virtio negotiation otherwise.
        bindings::__virtio_unbreak_device(vdev);
        if let Some(config) = (*vdev).config.as_ref() {
            if let (Some(get_status), Some(set_status)) = (config.get_status, config.set_status) {
                let status = get_status(vdev);
                set_status(vdev, status | 4); // VIRTIO_CONFIG_S_DRIVER_OK = 4
            }
        }
        bindings::virtqueue_enable_cb((*bg).vq_ctrl);
        bindings::virtqueue_enable_cb((*bg).vq_event);

        // The vq_ctrl inbuf post + kick is deferred to the worker thread so
        // that it runs *after* send_vmlinux_btf completes — the host caches
        // the BTF before its first process_ctrl, so CO-RE has a target
        // available on the very first LOAD_PROG.
        bindings::wake_up_process((*bg).thread);

        // Phase 4 doorbell setup: post one outbuf so the queue has
        // a descriptor available for the kick path, then register
        // our kick fn with the kfunc layer. virtqueue_kick from
        // BPF kprobe context will reuse the buf via the round-
        // trip ack pattern in `bifrost_doorbell_kick_fn`.
        {
            let mut sg: bindings::scatterlist = core::mem::zeroed();
            bindings::sg_init_one(&mut sg, (*bg).doorbell_buf, 1);
            let r = bindings::virtqueue_add_outbuf(
                (*bg).vq_doorbell,
                &mut sg,
                1,
                (*bg).doorbell_buf,
                bindings::GFP_KERNEL,
            );
            if r != 0 {
                pr_err!("bifrost_guest: doorbell init add_outbuf failed: {}\n", r);
            }
        }
        bindings::bifrost_set_doorbell_callback(
            Some(bifrost_doorbell_kick_fn),
            bg as *mut c_void,
        );
        pr_info!("bifrost_guest: doorbell callback registered\n");

        pr_info!("bifrost_guest: probed successfully\n");
        0
    }
}

extern "C" fn bifrost_remove(vdev: *mut bindings::virtio_device) {
    unsafe {
        let bg = (*vdev).priv_ as *mut BifrostGuest;

        // Goal item 7: teardown ordering.  The contract is that no
        // freed memory can be observed by an in-flight BPF program
        // or kfunc reader.  We achieve this with a strict sequence:
        //
        //   1.  Stop the worker thread (no new LOAD_PROGs land).
        //   2.  Unregister every probe (uprobe, fbt, tracepoint) so
        //       no new BPF program invocations happen.  The uprobe
        //       family runs a batched `uprobe_unregister_sync` after
        //       the loop — that drains every in-flight handler.
        //   3.  Clear the helper globals (doorbell fn, SHMEM va/len)
        //       so any straggler kfunc reader sees NULL and no-ops.
        //       The C-side WRITE_ONCE+smp_wmb pattern means readers
        //       can't observe a half-cleared fn pointer + private
        //       data combination.
        //   4.  synchronize_rcu — wait for any RCU-read-side critical
        //       section that was in flight before step 3 to complete.
        //       BPF programs run under RCU; this is the belt-and-
        //       suspenders bound on residual readers.
        //   5.  Free the JIT'd BPF programs (atomic swap-out on every
        //       slot's prog pointer).
        //   6.  Free maps, virtqueues, buffers, SHMEM, BifrostGuest.
        //
        // Steps 1, 2, 4 form the "no more readers" boundary; steps
        // 3, 5, 6 destroy what those readers used to observe.

        // Step 1: stop the LOAD_PROG worker before doing anything else.
        if !(*bg).thread.is_null() {
            bindings::kthread_stop((*bg).thread);
        }

        // Step 2: unregister probes + drain handlers.
        if (*bg).kprobe_attached {
            // Phase D: single cleanup dispatch.  USDT shares the
            // uprobe storage with the by-sym and host-resolved
            // variants; slot_family_cleanup returns true for any
            // uprobe-family slot so the caller can run the
            // batched `uprobe_unregister_sync()` once at the end.
            let mut had_uprobe = false;
            for s in 0..BIFROST_NUM_KPROBES {
                had_uprobe |= slot_family_cleanup(s, slots_mut()[s].probe_type);
            }
            if had_uprobe {
                uprobe_unregister_sync();
            }
            (*bg).kprobe_attached = false;
            BIFROST_NUM_KPROBES = 0;
        }

        // Step 3: clear helper globals so any residual reader (a
        // BPF program that started before step 2's unregister drained)
        // sees NULL and no-ops instead of touching about-to-be-freed
        // memory. Ordering inside each clear is enforced C-side
        // (fn pointer cleared before private data; SHMEM va cleared
        // before len) via WRITE_ONCE + smp_wmb.
        bifrost_clear_doorbell_callback();
        bifrost_clear_shmem_ringbuf();

        // Step 4: drain residual RCU readers.  After this returns,
        // every BPF program that began executing before step 3 has
        // either completed or has progressed past every READ_ONCE
        // load of the cleared globals.
        bindings::synchronize_rcu();

        // Step 5: free JIT'd BPF programs.  Atomic swap avoids any
        // theoretical race against a probe handler that somehow
        // outran the synchronize_rcu (defense in depth).  Walks the
        // actual KVec length (== SLOT_CAPACITY by construction in
        // bifrost_slots_init) rather than the legacy MAX_KPROBES
        // const, so a future grow-on-demand changes one site only.
        let cap = slots_mut().len();
        for s in 0..cap {
            let prog = slots_mut()[s].prog.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !prog.is_null() {
                bpf_prog_free(prog);
            }
        }

        // Step 6: free all bpf_maps. Every map (RINGBUF included) was
        // allocated via bifrost_alloc_map; the kernel owns the storage
        // and the per-type free vector is in map.ops.
        for i in 0..(*bg).num_maps as usize {
            if !(*bg).maps[i].is_null() {
                bindings::bifrost_free_map((*bg).maps[i]);
            }
        }

        if let Some(reset) = (*(*vdev).config).reset {
            reset(vdev);
        }
        if let Some(del_vqs) = (*(*vdev).config).del_vqs {
            del_vqs(vdev);
        }
        bindings::kfree((*bg).ctrl_buf);
        bindings::kfree((*bg).event_buf);
        bindings::kfree((*bg).doorbell_buf);
        if !(*bg).shmem_va.is_null() {
            if (*bg).shmem_from_virtio {
                bindings::memunmap((*bg).shmem_va as *mut c_void);
            } else {
                bindings::bifrost_free_shmem((*bg).shmem_va as *mut c_void, SHMEM_REGION_SIZE);
            }
        }
        bindings::kfree((*bg).shmem_pfns as *const c_void);
        bindings::kfree(bg as *const c_void);
        (*vdev).priv_ = core::ptr::null_mut();
        BIFROST_DEVICE_LIVE.store(false, Ordering::Release);
        pr_info!("bifrost_guest: removed\n");
    }
}

static mut ID_TABLE: [bindings::virtio_device_id; 3] = [
    bindings::virtio_device_id {
        device: 42,
        vendor: bindings::VIRTIO_DEV_ANY_ID,
    },
    // QEMU's stock vhost-user-test-device validates the virtio ID through
    // its built-in virtio_id_to_name() table before the backend ever sees the
    // device. Bind a QEMU-known generic ID for that path so Bifrost stays a
    // guest/backend change instead of a QEMU patch. This kernel config does
    // not enable a competing virtio-spi driver.
    bindings::virtio_device_id {
        device: 45,
        vendor: bindings::VIRTIO_DEV_ANY_ID,
    },
    bindings::virtio_device_id {
        device: 0,
        vendor: 0,
    }
];

static mut BIFROST_DRIVER: bindings::virtio_driver = unsafe { MaybeUninit::zeroed().assume_init() };

impl kernel::Module for BifrostGuestModule {
    fn init(_module: &'static kernel::ThisModule) -> Result<Self> {
        pr_info!("bifrost_guest: Rust module initialized\n");
        kfunc_manifest::validate()?;
        // Phase L (goal item 4): allocate the slot table full at module
        // load.  The KVec is never resized past init, so the slice
        // header that IRQ-context uprobe handlers index against is
        // stable.  ~80 KB kmalloc; OOM here aborts module load with an
        // actionable -ENOMEM rather than the silent crash a NULL access
        // would produce later.  Slots beyond the cap are refused with
        // -ENOSPC, not silently truncated.
        bifrost_slots_init()?;
        pr_info!(
            "bifrost_guest: slot table pre-allocated ({} slots; fixed-size, no runtime grow)\n",
            INITIAL_SLOT_HINT
        );
        unsafe {
            BIFROST_DRIVER.driver.name = b"bifrost_guest\0".as_ptr() as *mut _;
            BIFROST_DRIVER.id_table = ID_TABLE.as_ptr();
            BIFROST_DRIVER.probe = Some(bifrost_probe);
            BIFROST_DRIVER.remove = Some(bifrost_remove);

            let ret = bindings::__register_virtio_driver(&mut BIFROST_DRIVER, _module.as_ptr());
            if ret != 0 {
                return Err(Error::from_errno(ret));
            }
        }
        Ok(Self)
    }
}

impl Drop for BifrostGuestModule {
    fn drop(&mut self) {
        unsafe {
            bindings::unregister_virtio_driver(&mut BIFROST_DRIVER);
        }
        pr_info!("bifrost_guest: Rust module removed\n");
    }
}
