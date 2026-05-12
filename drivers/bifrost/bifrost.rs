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
//
// Pending (each requires a kernel rebuild + per-attach demo sweep
// to land safely; deferred until that build cycle is available):
//   load_prog/mod.rs         entry + phase orchestration
//   load_prog/maps.rs        map setup, fake-fd patching
//   load_prog/verifier.rs    BIFROST_USE_VERIFIER path
//   attach/mod.rs            dispatch on probe_type
//   attach/uprobe.rs         uprobe + uretprobe (file + symbol variants)
//   attach/fbt.rs            fentry/fexit (BPF trampoline)
//   attach/tracepoint.rs     raw tracepoint
//   cleanup.rs               per-handle teardown, atomic prog swap
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
mod kfunc_manifest;
mod load_prog_parse;
mod path_helpers;
mod record_writer;
mod shmem_layout;
mod shmem_publish;
mod slots;
mod symtab_snapshot;
mod task_helpers;
mod types;
// wire.rs is a SYMLINK to the canonical bifrost-wire crate at
// host/bifrost-wire/src/lib.rs.  The kernel rust build composes
// it as a sibling module; the `unreachable_pub` warning fires
// because canonical uses `pub` (it's the crate root on the host
// side) but the kernel-rust convention prefers `pub(crate)` for
// inner modules.  Allow the warning here to keep canonical
// visibility consistent across all consumers.
#[allow(unreachable_pub)]
mod wire;
use bpf_consts::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF};
use load_prog_parse::validate_load_prog_cmd;
use path_helpers::path_basename;
use record_writer::RecordWriter;
use shmem_publish::{populate_shmem_btf, populate_shmem_kallsyms};
use slots::{
    bifrost_slots_init, slot_lease_new, slots_ensure, slots_mut, BifrostUprobe,
    BIFROST_NUM_KPROBES, INITIAL_SLOT_HINT,
};
use symtab_snapshot::push_symtab_snapshot_cb;
use task_helpers::{find_task_by_comm, put_task_ref};
use types::{BifrostCmd, BpfInsn, MapDef};
use shmem_layout::{
    SHMEM_BTF_CAP, SHMEM_BTF_OFF, SHMEM_HDR_LEN, SHMEM_HDR_OFF, SHMEM_KSYMS_CAP, SHMEM_KSYMS_OFF,
    SHMEM_MAGIC, SHMEM_N_PAGES, SHMEM_REGION_SIZE, SHMEM_RINGBUF_LEN, SHMEM_RINGBUF_OFF,
    SHMEM_VERSION, SHMEM_VMA_CACHE_LEN, SHMEM_VMA_CACHE_OFF,
};
use wire::{
    AGG_KIND_AVG, AGG_KIND_MAX, AGG_KIND_MIN, AGG_KIND_SUM, AGG_SNAPSHOT_PROBE_ID,
    PROBE_TYPE_FENTRY, PROBE_TYPE_FEXIT, PROBE_TYPE_NONE, PROBE_TYPE_TRACEPOINT, PROBE_TYPE_UPROBE,
    PROBE_TYPE_UPROBE_BY_SYM, PROBE_TYPE_URETPROBE, PROBE_TYPE_URETPROBE_BY_SYM, PROBE_TYPE_USDT,
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

struct BifrostGuest {
    vdev: *mut bindings::virtio_device,
    vq_ctrl: *mut bindings::virtqueue,
    vq_event: *mut bindings::virtqueue,
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
    ctrl_buf: *mut c_void,
    event_buf: *mut c_void,
    thread: *mut bindings::task_struct,
    pending_work: u32,
    cmd_len: u32,
    // BPF program tracking
    prog: *mut bindings::bpf_prog,
    // Map pointers (indexed by map index)
    maps: [*mut bindings::bpf_map; 8],
    num_maps: u32,
    // Kprobe tracking
    kprobe_attached: bool,
    // SHMEM region. Prefer the virtio shared-memory region exposed by
    // the VMM; fall back to the older vmalloc/PFN path for older VMMs.
    shmem_va: *mut u8,
    shmem_pfns: *mut usize,
    shmem_n_pages: u64,
    shmem_from_virtio: bool,
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
static mut BIFROST_TRACING_LINK_OPS: bindings::bpf_link_ops = bindings::bpf_link_ops {
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
static mut BIFROST_MAP_FAKE_FDS: [i32; 8] = [0; 8];
/// Per-map agg kind, parallel to BIFROST_MAP_FAKE_FDS. Set at
/// LOAD_PROG time from the MapDef.flags field; consulted by the
/// snapshot worker to dispatch sum/min/max/avg reduce.
static mut BIFROST_MAP_AGG_KIND: [u8; 8] = [0; 8];
/// Real fds (from `bifrost_map_get_fd`) parallel to BIFROST_MAP_FAKE_FDS,
/// only populated when LAYER 2 (kernel verifier) is on. The verifier
/// resolves these fds to bpf_map* during pseudo-ldimm64 fixup. We
/// release them after verification — the prog holds its own ref.
static mut BIFROST_MAP_REAL_FDS: [i32; 8] = [-1; 8];

/// LAYER 2 — when true, route every LOAD_PROG through the kernel
/// verifier (`bifrost_verify_prog`). When false, fall back to the
/// hand-patched bypass-verifier path (resolves fake_fds to map ptrs
/// inline, helper ids to `__bpf_call_base + offset`, and manually
/// sets aux->stack_depth before bpf_prog_select_runtime).
///
/// Implemented as an atomic so `module_param` can flip it at runtime
/// (with `modprobe bifrost_guest use_verifier=1` or via sysfs) without
/// rebuilding. Default off until the path is proven; flip to default-on
/// once layer-2 demos pass.
pub static BIFROST_USE_VERIFIER: AtomicBool = AtomicBool::new(true);

/// The current helper surface is intentionally singleton: SHMEM
/// reserve/submit and the doorbell kfunc are published through global
/// kernel/bpf helper state. Reject a second virtio-bifrost device
/// rather than sharing slots, map fake-fd caches, and callback private
/// data across devices.
static BIFROST_DEVICE_LIVE: AtomicBool = AtomicBool::new(false);

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
    // A4 — Uprobes. uprobe_register pins an inode + offset and writes a
    // breakpoint into the binary's text page; subsequent user-mode hits
    // call our consumer's handler. Unregister is two-step: nosync to
    // remove the consumer, then a single sync to wait for outstanding
    // handlers to drain. CONFIG_UPROBES=y is set in the build script.
    fn uprobe_register(
        inode: *mut bindings::inode,
        offset: i64,
        ref_ctr_offset: i64,
        uc: *mut bindings::uprobe_consumer,
    ) -> *mut bindings::uprobe;
    fn uprobe_unregister_nosync(
        uprobe: *mut bindings::uprobe,
        uc: *mut bindings::uprobe_consumer,
    );
    fn uprobe_unregister_sync();
    // Path resolution (resolves a guest-visible path to a struct path
    // we can dereference for the inode). LOOKUP_FOLLOW=1 follows
    // symlinks; bare basenames + dynamic linker symlinks resolve fine.
    fn kern_path(
        name: *const c_char,
        flags: core::ffi::c_uint,
        path: *mut bindings::path,
    ) -> c_int;
    fn path_put(path: *const bindings::path);
    // Inode lifecycle — igrab pins (refcount++), iput releases. We hold
    // the pin for the lifetime of the uprobe registration; otherwise
    // the kernel could evict the inode out from under us.
    fn igrab(inode: *mut bindings::inode) -> *mut bindings::inode;
    fn iput(inode: *mut bindings::inode);
    // Container-aware fallback path resolution: walk the task list,
    // find a process whose comm matches the requested binary basename,
    // and grab its already-loaded exe_file. The kernel resolved the
    // exe_file at exec() time *inside the target task's mount
    // namespace*, so this works for binaries that live only in a
    // container's overlayfs (which `kern_path` running in init's mount
    // namespace cannot see).
    //
    // Both functions are defined in kernel/fork.c. Not EXPORT_SYMBOL'd
    // for modules, but bifrost-guest is built in-tree (CONFIG_BIFROST=y)
    // so it links directly without an export list.
    fn get_task_exe_file(task: *mut bindings::task_struct) -> *mut bindings::file;
    fn fput(file: *mut bindings::file);
    // bifrost_helper_find_task_by_comm extern decl moved to
    // drivers/bifrost/task_helpers.rs alongside find_task_by_comm.
    /// C helper — resolves a symbol name in the ELF symbol table of
    /// `file` (a task's exe_file) to its file offset.  Returns 0 on
    /// success and writes the offset/size to the out pointers; a
    /// negative errno on failure.  Only ELF64 LE / ET_DYN today;
    /// see drivers/bifrost/bifrost_helpers.c for the full contract.
    fn bifrost_helper_resolve_symbol(
        file: *mut bindings::file,
        symbol_name: *const u8,
        symbol_name_len: u32,
        out_file_offset: *mut u64,
        out_size: *mut u64,
    ) -> c_int;
    /// C helper — sister to bifrost_helper_resolve_symbol but for
    /// USDT (`.note.stapsdt`) probes.  Walks the section to find the
    /// first entry matching `(provider_name, probe_name)` and
    /// resolves both the probe pc and its `.probes` semaphore via
    /// PT_LOAD vaddr→file_offset translation.  Returns 0 on success
    /// and writes both offsets via the out pointers; the semaphore
    /// offset is 0 when the probe doesn't use one.  Negative errno
    /// on failure (`-ENOENT` if the section / entry isn't present).
    fn bifrost_helper_resolve_usdt(
        file: *mut bindings::file,
        provider_name: *const u8,
        provider_name_len: u32,
        probe_name: *const u8,
        probe_name_len: u32,
        out_pc_file_offset: *mut u64,
        out_semaphore_file_offset: *mut u64,
    ) -> c_int;
    /// C helper — walk `task->mm`'s file-backed executable VMAs and
    /// invoke `cb(file, ctx)` for each unique `vm_file`.  Used by the
    /// uprobe register path to push symtabs for every binary the
    /// firing task has mapped, not just the one we put a uprobe on
    /// (so libc / libpthread / vDSO frames in gustack output
    /// symbolicate too).  Sleepable (does mmap_read_lock + d_path
    /// inside the cb's downstream calls); must not be called from
    /// kprobe / BPF context.
    fn bifrost_helper_for_each_vma_file(
        task: *mut bindings::task_struct,
        cb: Option<unsafe extern "C" fn(*mut bindings::file, *mut c_void)>,
        ctx: *mut c_void,
    );
    // Timing
    fn ktime_get_mono_fast_ns() -> u64;
    // libc strlen — needed in the kallsyms walker callback to size each
    // symbol name without scanning twice.
    fn strlen(s: *const c_char) -> usize;
    // Raw tracepoint attach.  Resolve the per-event bpf_raw_event_map
    // by name (kernel walks __start__bpf_raw_tp[..] + module list);
    // register a bpf_raw_tp_link wrapping the prog so per-event
    // dispatch enters via btp->bpf_func → __bpf_trace_run → prog.
    // Symmetric unregister pairs with bpf_put_raw_tracepoint to drop
    // the module ref taken by the lookup.
    fn bpf_get_raw_tracepoint(name: *const c_char) -> *mut bindings::bpf_raw_event_map;
    fn bpf_put_raw_tracepoint(btp: *mut bindings::bpf_raw_event_map);
    fn bpf_probe_register(
        btp: *mut bindings::bpf_raw_event_map,
        link: *mut bindings::bpf_raw_tp_link,
    ) -> c_int;
    fn bpf_probe_unregister(
        btp: *mut bindings::bpf_raw_event_map,
        link: *mut bindings::bpf_raw_tp_link,
    ) -> c_int;
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

/// Pack a snapshot of every non-RINGBUF map's live entries into the
/// SHMEM event ringbuf. Replaces the legacy VQ_EVENT op=6
/// AGG_SNAPSHOT virtqueue path.
///
/// On-wire body (after the standard 24-byte correlation header
/// vmid/probe_id=AGG_SNAPSHOT_PROBE_ID/gns/gpid):
///
///   [u32 num_entries]
///   for each entry:
///     [i32 fake_fd]    (map's fake_fd from LOAD_PROG)
///     [u32 key_size]   (key length in bytes; 0..=MAX_KEY_BYTES)
///     [u8 * key_size]  (raw key bytes — multi-key composites
///                       carry their full byte width here)
///     [u64 value]
///
/// Length-prefixed keys carry full multi-key composites without
/// the legacy u64-truncation that collapsed `[execname, pid]`
/// down to just the execname's first 8 bytes.  Worst-case entry
/// is i32 + u32 + 32 bytes (max 4-key composite at 8 bytes per
/// chunk) + u64 = 48 bytes; cap 2048 entries → ~99 KB body.
/// Record max remains 64 KB so we cap entries at a slightly
/// lower count to stay safely below.
///
/// Iterates each map via `bifrost_map_lookup_sum_u64` for
/// PERCPU_ARRAY/HASH (sums per-cpu) or
/// `bifrost_map_get_next_key` for HASH-shaped maps.
unsafe fn push_agg_snapshot(bg: *mut BifrostGuest) {
    let _ = bg; // bg held for symmetry; the SHMEM region is module-static.
    unsafe {
        // Reserve worst-case sized record up-front.
        const HDR_BYTES: usize = 24; // correlation header
        const NUM_ENTRIES_BYTES: usize = 4;
        // Worst-case per-entry: i32 fd + u32 key_size + 32 byte
        // key (max 4-key composite at 8 bytes/chunk) + u64 value
        // = 48 bytes.  Cap MAX_ENTRIES so HDR + n*48 stays under
        // the 64 KB record max.
        const MAX_KEY_BYTES: usize = 32;
        const MAX_ENTRY_BYTES: usize = 4 + 4 + MAX_KEY_BYTES + 8;
        const MAX_ENTRIES: usize = 1024;
        const MAX_BODY: usize = HDR_BYTES + NUM_ENTRIES_BYTES + MAX_ENTRIES * MAX_ENTRY_BYTES;

        let rec = bindings::bifrost_shmem_reserve_kernel(MAX_BODY as u32) as *mut u8;
        if rec.is_null() {
            // Producer full or SHMEM not yet published. Drop this
            // snapshot — next tick will retry.
            return;
        }

        let mut writer = RecordWriter::new(rec, MAX_BODY);

        // Correlation header.
        writer.write_u32(0); // vmid
        writer.write_u32(AGG_SNAPSHOT_PROBE_ID);
        writer.write_u64(bindings::ktime_get_mono_fast_ns());
        writer.write_u64(0); // gpid

        // num_entries placeholder (overwritten at end).
        let n_off = writer.off;
        writer.write_u32(0);

        let mut packed: usize = 0;
        for i in 0..(*bg).num_maps as usize {
            if packed >= MAX_ENTRIES {
                break;
            }
            let map = (*bg).maps[i];
            if map.is_null() {
                continue;
            }
            let fd = BIFROST_MAP_FAKE_FDS[i];
            let agg_kind = BIFROST_MAP_AGG_KIND[i];
            let mt = (*map).map_type;
            // RINGBUF storage is host-mapped — skip it.
            if mt == BPF_MAP_TYPE_RINGBUF {
                continue;
            }
            // Internal maps (thread-local storage at fake_fd=300+) carry
            // implementation state, not user-visible aggregations.
            if fd >= 300 {
                continue;
            }
            let key_size = (*map).key_size as usize;

            // Per-cpu reduce closure: dispatches sum/min/max/avg
            // based on the agg_kind we stamped at LOAD_PROG time.
            let reduce = |k_ptr: *const core::ffi::c_void, out: *mut u64| -> i32 {
                match agg_kind {
                    AGG_KIND_MIN => bindings::bifrost_map_lookup_min_u64(map, k_ptr, out),
                    AGG_KIND_MAX => bindings::bifrost_map_lookup_max_u64(map, k_ptr, out),
                    AGG_KIND_AVG => bindings::bifrost_map_lookup_avg_u64(map, k_ptr, out),
                    _            => bindings::bifrost_map_lookup_sum_u64(map, k_ptr, out),
                }
            };

            if mt == BPF_MAP_TYPE_ARRAY || mt == BPF_MAP_TYPE_PERCPU_ARRAY {
                let max = (*map).max_entries;
                for k in 0..max {
                    if packed >= MAX_ENTRIES {
                        break;
                    }
                    let k32: u32 = k;
                    let mut v: u64 = 0;
                    let rc = reduce(
                        &k32 as *const u32 as *const core::ffi::c_void,
                        &mut v as *mut u64,
                    );
                    if rc != 0 || v == 0 {
                        continue; // -ENOENT or all-zero across CPUs
                    }
                    // ARRAY-shaped maps key on a u32 index.  Length-
                    // prefixed write: [fd][key_size=4][key bytes][value].
                    let chk = writer.off;
                    let k_bytes = k32.to_le_bytes();
                    if !writer.write_i32(fd)
                        || !writer.write_u32(4)
                        || !writer.write_bytes(&k_bytes)
                        || !writer.write_u64(v)
                    {
                        writer.off = chk;
                        break;
                    }
                    packed += 1;
                }
            } else {
                // HASH-shaped: iterate via get_next_key.
                let mut cur_key = [0u8; 32];
                let mut next_key = [0u8; 32];
                let mut have_cur = false;
                loop {
                    if packed >= MAX_ENTRIES {
                        break;
                    }
                    let from = if have_cur {
                        cur_key.as_ptr() as *mut core::ffi::c_void
                    } else {
                        core::ptr::null_mut()
                    };
                    let rc = bindings::bifrost_map_get_next_key(
                        map,
                        from,
                        next_key.as_mut_ptr() as *mut core::ffi::c_void,
                    );
                    if rc != 0 {
                        break; // -ENOENT = no more keys
                    }
                    let mut v: u64 = 0;
                    let rc_lookup = reduce(
                        next_key.as_ptr() as *const core::ffi::c_void,
                        &mut v as *mut u64,
                    );
                    if rc_lookup != 0 {
                        cur_key.copy_from_slice(&next_key);
                        have_cur = true;
                        continue;
                    }
                    if v != 0 {
                        // Length-prefixed write: [fd][key_size][key
                        // bytes][value].  Multi-key composites carry
                        // their full byte width — no truncation.
                        let kb = core::cmp::min(key_size, MAX_KEY_BYTES);
                        let chk = writer.off;
                        if !writer.write_i32(fd)
                            || !writer.write_u32(kb as u32)
                            || !writer.write_bytes(&next_key[..kb])
                            || !writer.write_u64(v)
                        {
                            writer.off = chk;
                            break;
                        }
                        packed += 1;
                    }
                    cur_key.copy_from_slice(&next_key);
                    have_cur = true;
                }
            }
        }

        // Stamp real num_entries.
        writer.poke_u32(n_off, packed as u32);

        bindings::bifrost_shmem_submit_kernel(rec as *mut c_void);
    }
}

// BPF_MAP_TYPE_ARRAY / BPF_MAP_TYPE_PERCPU_ARRAY moved to bpf_consts.rs.


/// Stand-in for bpf_get_stack (helper id 67). bpf_base_func_proto in
/// our libkrunfw build dereferences prog->expected_attach_type for
/// this case, and our resolver hands it NULL, so the kernel's proto
/// crashes. Delegate to `bifrost_stack_walk` — a kernel-side shim
/// (kernel/bpf/helpers.c) wrapping the arm64 unwinder
/// (`stack_trace_save_regs` → `arch_stack_walk`) which handles
/// kprobe context, IRQ stacks, and the kretprobe trampoline correctly.
///
/// Args follow the eBPF helper ABI emitted by `lower_action_into`:
///   r1 = ctx (pt_regs *), r2 = buf, r3 = size, r4 = flags.
/// Bypass-verifier-only kernel-stack helper. Verifier mode (the
/// default) skips this entirely — the kernel's
/// `kprobe_prog_func_proto` resolves helper id 67 to the real
/// `bpf_get_stack_proto`, which already handles BPF_F_USER_STACK
/// natively via `__bpf_get_stack` → `get_perf_callchain`. This
/// shim only runs in bypass mode and only for kernel-stack walks.
unsafe extern "C" fn bifrost_get_stack(
    ctx: *mut core::ffi::c_void,
    buf: *mut core::ffi::c_void,
    size: u32,
    _flags: u64,
) -> i64 {
    unsafe {
        if ctx.is_null() || buf.is_null() {
            return -1;
        }
        let nr_entries = (size / 8) as core::ffi::c_uint;
        let written = bindings::bifrost_stack_walk(
            ctx as *mut bindings::pt_regs,
            buf as *mut usize,
            nr_entries,
            0,
        );
        (written as i64) * 8
    }
}

/// Run the BPF program at `slots_mut()[slot].prog` against `regs`.
/// The per-slot uprobe handlers (`bifrost_uprobe_handler_N`) are
/// thin wrappers that dispatch here with their own slot index —
/// lets multiple uprobes share one piece of run-program code
/// without paying for a runtime slot lookup in IRQ context on
/// every fire.  fbt and tracepoint dispatch goes via the kernel
/// trampoline / __bpf_trace_run paths and never calls this
/// helper.
#[inline(always)]
unsafe fn run_prog_slot(slot: usize, regs: *mut bindings::pt_regs) {
    unsafe {
        // Bounds-check against the live slot-table length, not
        // the legacy MAX_KPROBES constant.  After the heap
        // migration the table grows on demand; this check
        // protects against a stale or out-of-bounds slot index
        // arriving via container-of from a freed BifrostUprobe
        // (defense in depth — should never happen in practice).
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

// A4 — Per-slot uprobe entry handlers. Signature matches struct
// uprobe_consumer::handler — pt_regs at the user-mode probe site has
// the function arguments in x0..x7 (arm64) or rdi/rsi/rdx/rcx/r8/r9
// (x86_64). The lowered eBPF reads these via the existing pt_regs
// helpers; nothing in the lowering needs to change.
/// Shared uprobe entry handler.  Recovers the firing slot via
/// container-of on the `consumer` argument: `BifrostUprobe::consumer`
/// is the first field, so the consumer pointer is bit-identical to
/// the wrapper pointer.  Replaces the retired N hand-rolled
/// per-slot handler functions; growing MAX_KPROBES is now a single
/// number bump with no new handler functions, no new match arms.
unsafe extern "C" fn bifrost_uprobe_handler(
    self_consumer: *mut bindings::uprobe_consumer,
    regs: *mut bindings::pt_regs,
) -> c_int {
    unsafe {
        let bp = self_consumer as *const BifrostUprobe;
        run_prog_slot((*bp).slot as usize, regs);
    }
    0
}

/// Shared uretprobe (return-probe) handler.  The kernel's signature
/// has an extra `func` argument (entry PC of the probed function);
/// pt_regs holds the return value in x0/rax which matches DTrace's
/// `:return` convention.  Same container-of slot-recovery as the
/// entry handler above.
unsafe extern "C" fn bifrost_uretprobe_handler(
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


unsafe fn load_prog_seq(cmd: *const BifrostCmd, cmd_len: u32) -> u64 {
    unsafe {
        const CMD_HDR: usize = core::mem::size_of::<BifrostCmd>();
        const SEQ_LEN: usize = core::mem::size_of::<u64>();

        if cmd.is_null() || (cmd_len as usize) < CMD_HDR + SEQ_LEN {
            return 0;
        }
        let cmd_len = cmd_len as usize;
        let declared_seq_off = CMD_HDR.saturating_add((*cmd).len as usize);
        let seq_off = if declared_seq_off + SEQ_LEN <= cmd_len {
            declared_seq_off
        } else {
            cmd_len - SEQ_LEN
        };
        core::ptr::read_unaligned((cmd as *const u8).add(seq_off) as *const u64)
    }
}

unsafe fn send_load_prog_status(bg: *mut BifrostGuest, seq: u64, status: i32) {
    unsafe {
        const OP_LOAD_PROG_STATUS: u32 = 9;
        let event_buf = (*bg).event_buf as *mut u8;
        core::ptr::copy_nonoverlapping(
            &OP_LOAD_PROG_STATUS as *const u32 as *const u8,
            event_buf,
            4,
        );
        core::ptr::copy_nonoverlapping(
            &seq as *const u64 as *const u8,
            event_buf.add(4),
            8,
        );
        core::ptr::copy_nonoverlapping(
            &status as *const i32 as *const u8,
            event_buf.add(12),
            4,
        );

        let mut sg: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg, (*bg).event_buf, 16);
        let add_err = bindings::virtqueue_add_outbuf(
            (*bg).vq_event,
            &mut sg,
            1,
            (*bg).event_buf,
            bindings::GFP_KERNEL,
        );
        if add_err != 0 {
            pr_err!("bifrost_guest: LOAD_PROG status event add failed: {}\n", add_err);
            return;
        }
        bindings::virtqueue_kick((*bg).vq_event);

        let mut consumed_len: core::ffi::c_uint = 0;
        let mut spins: u32 = 0;
        loop {
            let ret = bindings::virtqueue_get_buf((*bg).vq_event, &mut consumed_len);
            if !ret.is_null() {
                break;
            }
            core::hint::spin_loop();
            spins += 1;
            if spins % 1024 == 0 {
                bindings::__cond_resched();
            }
        }
    }
}

unsafe fn repost_ctrl_buffer(bg: *mut BifrostGuest) {
    unsafe {
        let mut sg_in: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg_in, (*bg).ctrl_buf, 65536);
        bindings::virtqueue_add_inbuf(
            (*bg).vq_ctrl,
            &mut sg_in,
            1,
            (*bg).ctrl_buf,
            bindings::GFP_KERNEL,
        );
        bindings::virtqueue_kick((*bg).vq_ctrl);
    }
}

unsafe fn complete_load_prog(bg: *mut BifrostGuest, cmd: *const BifrostCmd, status: i32) {
    unsafe {
        if !cmd.is_null() && (*cmd).op == 2 {
            let seq = load_prog_seq(cmd, (*bg).cmd_len);
            send_load_prog_status(bg, seq, status);
        }
        repost_ctrl_buffer(bg);
    }
}

unsafe fn free_slot_prog(slot: usize) {
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

/// One-shot SHMEM_INIT message to the host. For the generic virtio
/// SHM path this is a 24-byte readiness notification (`n_pages=0`);
/// the host already owns the region and maps it through the VMM's
/// virtio-shm metadata. For older VMMs, the fallback carries the
/// per-page PFN array so libkrun can derive host VAs from guest RAM.
///
/// Wire format:
///   [u32 op=8][u32 region_size][u32 n_pages][u32 magic]
///   [u32 version][u32 reserved]
///   [u64 pfns × n_pages]
///
/// Total: 24 bytes for virtio SHM, or 24 + n_pages × 8 for PFN SHM.
/// The fallback remains 32 792 bytes for a 16 MB region.
unsafe fn send_shmem_init(bg: *mut BifrostGuest) {
    unsafe {
        const OP_SHMEM_INIT: u32 = 8;
        let event_buf = (*bg).event_buf as *mut u8;
        let region_size = SHMEM_REGION_SIZE as u32;
        let n_pages = (*bg).shmem_n_pages as u32;

        // Header.
        core::ptr::copy_nonoverlapping(
            &OP_SHMEM_INIT as *const u32 as *const u8,
            event_buf,
            4,
        );
        core::ptr::copy_nonoverlapping(
            &region_size as *const u32 as *const u8,
            event_buf.add(4),
            4,
        );
        core::ptr::copy_nonoverlapping(
            &n_pages as *const u32 as *const u8,
            event_buf.add(8),
            4,
        );
        core::ptr::copy_nonoverlapping(
            &SHMEM_MAGIC as *const u32 as *const u8,
            event_buf.add(12),
            4,
        );
        core::ptr::copy_nonoverlapping(
            &SHMEM_VERSION as *const u32 as *const u8,
            event_buf.add(16),
            4,
        );
        let reserved: u32 = if (*bg).shmem_from_virtio { 1 } else { 0 };
        core::ptr::copy_nonoverlapping(
            &reserved as *const u32 as *const u8,
            event_buf.add(20),
            4,
        );

        if n_pages != 0 {
            // PFN array — usize on the kernel side, marshalled as u64.
            // arm64 kernel is 64-bit so usize == u64; cast is a no-op
            // but the explicit type keeps the wire format CPU-agnostic.
            let pfns_dst = event_buf.add(24) as *mut u64;
            for i in 0..(n_pages as usize) {
                *pfns_dst.add(i) = *((*bg).shmem_pfns).add(i) as u64;
            }
        }

        let total_len = 24 + (n_pages as usize) * 8;
        let mut sg: bindings::scatterlist = core::mem::zeroed();
        bindings::sg_init_one(&mut sg, (*bg).event_buf, total_len as u32);
        bindings::virtqueue_add_outbuf(
            (*bg).vq_event,
            &mut sg,
            1,
            (*bg).event_buf,
            bindings::GFP_KERNEL,
        );
        bindings::virtqueue_kick((*bg).vq_event);

        // Spin for ack (host returns the buffer once it has mapped
        // and validated the region). Same yield pattern as
        // send_vmlinux_btf so RCU stalls don't trip on slow hosts.
        let mut consumed_len: core::ffi::c_uint = 0;
        let mut spins: u32 = 0;
        loop {
            let ret = bindings::virtqueue_get_buf((*bg).vq_event, &mut consumed_len);
            if !ret.is_null() {
                break;
            }
            core::hint::spin_loop();
            spins += 1;
            if spins % 1024 == 0 {
                bindings::__cond_resched();
            }
        }
        pr_info!(
            "bifrost_guest: SHMEM_INIT sent ({} bytes, {} pfns, virtio_shm={}) and acked\n",
            total_len, n_pages, (*bg).shmem_from_virtio
        );
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
	                    if (*cmd).op == 2 { // LOAD_PROG
                        pr_info!("bifrost_guest: processing LOAD_PROG command\n");
                        let parse_status = validate_load_prog_cmd(cmd, (*bg).cmd_len);
                        if parse_status != 0 {
                            pr_err!(
                                "bifrost_guest: LOAD_PROG rejected by bounded parser: {}\n",
                                parse_status
                            );
                            complete_load_prog(bg, cmd, parse_status);
                            continue;
                        }
                        
                        // LOAD_PROG payload layout:
                        //   [0..4]   op: u32 = 2
                        //   [4..8]   len: u32
                        //   [8..12]  num_maps: u32
                        //   [12..44] target_name: [u8; 32]
                        //   [44..48] flags: u32 (low byte = probe_type)
                        //   [48..48+num_maps*24]  MapDef array
                        //   [..+4]   num_insns: u32
                        //   [..+num_insns*8]  BPF instructions
                        let payload_ptr = (*bg).ctrl_buf as *const u8;
                        let payload_base = payload_ptr.add(8); // skip op(4) + len(4)

                        let num_maps = *(payload_base as *const u32);
                        pr_info!("bifrost_guest: num_maps={}\n", num_maps);

                        // Extract target_name (32 bytes)
                        let mut target_name = [0u8; 32];
                        core::ptr::copy_nonoverlapping(payload_base.add(4), target_name.as_mut_ptr(), 32);

                        // Probe-type flags (32 bits; only low byte used).
                        let flags = *(payload_base.add(4 + 32) as *const u32);
                        let probe_type: u8 = (flags & 0xff) as u8;

                        // A4 — Uprobe trailer.  Three shapes by probe_type:
                        //
                        //   2/3 (host-resolved):
                        //     u32 path_len, path_bytes, u64 file_offset
                        //
                        //   4/5 (kernel-resolved):
                        //     u32 bn_len, basename_bytes,
                        //     u32 sym_len, symbol_bytes
                        //   The driver looks up the matching task by comm
                        //   (basename), grabs its exe_file, parses the ELF
                        //   symbol table to find `symbol`'s file offset,
                        //   then registers the uprobe.  No host rootfs
                        //   mirror needed.
                        //
                        //   9 (USDT, kernel-resolved):
                        //     u32 bn_len, basename_bytes,
                        //     u32 prov_len, sdt_provider_bytes,
                        //     u32 probe_len, sdt_probe_bytes
                        //   Same task→exe_file path as 4/5; the driver
                        //   walks `.note.stapsdt` (rather than `.symtab`)
                        //   to find the matching `(provider, probe)`,
                        //   then registers a uprobe at the recorded
                        //   pc + ref_ctr_offset.  bifrost_helper_resolve_usdt
                        //   does the in-kernel ELF walk.
                        //
                        // 0/1 (kprobe/kretprobe) carry no trailer.
                        let mut uprobe_path_buf: [u8; 257] = [0u8; 257];
                        let mut uprobe_basename: [u8; 65] = [0u8; 65];
                        let mut uprobe_basename_len: usize = 0;
                        let mut uprobe_symbol: [u8; 257] = [0u8; 257];
                        let mut uprobe_symbol_len: usize = 0;
                        let mut uprobe_provider: [u8; 65] = [0u8; 65];
                        let mut uprobe_provider_len: usize = 0;
                        let mut uprobe_file_offset: u64 = 0;
                        let mut trailer_bytes: usize = 0;
                        let mut malformed_trailer = false;
                        if probe_type == PROBE_TYPE_UPROBE
                            || probe_type == PROBE_TYPE_URETPROBE
                        {
                            let trailer_start = payload_base.add(4 + 32 + 4);
                            let path_len =
                                *(trailer_start as *const u32) as usize;
                            if path_len > 256 {
                                pr_err!(
                                    "bifrost_guest: LOAD_PROG uprobe path_len {} > 256\n",
                                    path_len
                                );
                                malformed_trailer = true;
                            } else {
                                core::ptr::copy_nonoverlapping(
                                    trailer_start.add(4),
                                    uprobe_path_buf.as_mut_ptr(),
                                    path_len,
                                );
                                uprobe_path_buf[path_len] = 0;
                                uprobe_file_offset = *(trailer_start
                                    .add(4 + path_len)
                                    as *const u64);
                                trailer_bytes = 4 + path_len + 8;
                            }
                        } else if probe_type == PROBE_TYPE_USDT {
                            // Trailer: u32 bn_len ++ bn ++ u32 prov_len ++
                            // prov ++ u32 probe_len ++ probe.  Three
                            // length-prefixed strings; mirrors 4/5 with an
                            // extra (provider) field.
                            let trailer_start = payload_base.add(4 + 32 + 4);
                            let bn_len =
                                *(trailer_start as *const u32) as usize;
                            if bn_len == 0 || bn_len > 64 {
                                pr_err!(
                                    "bifrost_guest: LOAD_PROG usdt bn_len {} out of range\n",
                                    bn_len
                                );
                                malformed_trailer = true;
                            } else {
                                core::ptr::copy_nonoverlapping(
                                    trailer_start.add(4),
                                    uprobe_basename.as_mut_ptr(),
                                    bn_len,
                                );
                                uprobe_basename[bn_len] = 0;
                                uprobe_basename_len = bn_len;
                                let prov_field = trailer_start.add(4 + bn_len);
                                let prov_len =
                                    *(prov_field as *const u32) as usize;
                                if prov_len == 0 || prov_len > 64 {
                                    pr_err!(
                                        "bifrost_guest: LOAD_PROG usdt prov_len {} out of range\n",
                                        prov_len
                                    );
                                    malformed_trailer = true;
                                } else {
                                    core::ptr::copy_nonoverlapping(
                                        prov_field.add(4),
                                        uprobe_provider.as_mut_ptr(),
                                        prov_len,
                                    );
                                    uprobe_provider[prov_len] = 0;
                                    uprobe_provider_len = prov_len;
                                    let probe_field =
                                        prov_field.add(4 + prov_len);
                                    let probe_len =
                                        *(probe_field as *const u32) as usize;
                                    if probe_len == 0 || probe_len > 256 {
                                        pr_err!(
                                            "bifrost_guest: LOAD_PROG usdt probe_len {} out of range\n",
                                            probe_len
                                        );
                                        malformed_trailer = true;
                                    } else {
                                        core::ptr::copy_nonoverlapping(
                                            probe_field.add(4),
                                            uprobe_symbol.as_mut_ptr(),
                                            probe_len,
                                        );
                                        uprobe_symbol[probe_len] = 0;
                                        uprobe_symbol_len = probe_len;
                                        trailer_bytes = 4 + bn_len + 4 + prov_len + 4 + probe_len;
                                    }
                                }
                            }
                        } else if probe_type == PROBE_TYPE_UPROBE_BY_SYM
                            || probe_type == PROBE_TYPE_URETPROBE_BY_SYM
                        {
                            let trailer_start = payload_base.add(4 + 32 + 4);
                            let bn_len =
                                *(trailer_start as *const u32) as usize;
                            if bn_len == 0 || bn_len > 64 {
                                pr_err!(
                                    "bifrost_guest: LOAD_PROG uprobe-by-sym bn_len {} out of range\n",
                                    bn_len
                                );
                                malformed_trailer = true;
                            } else {
                                core::ptr::copy_nonoverlapping(
                                    trailer_start.add(4),
                                    uprobe_basename.as_mut_ptr(),
                                    bn_len,
                                );
                                uprobe_basename[bn_len] = 0;
                                uprobe_basename_len = bn_len;
                                let sym_field = trailer_start.add(4 + bn_len);
                                let sym_len =
                                    *(sym_field as *const u32) as usize;
                                if sym_len == 0 || sym_len > 256 {
                                    pr_err!(
                                        "bifrost_guest: LOAD_PROG uprobe-by-sym sym_len {} out of range\n",
                                        sym_len
                                    );
                                    malformed_trailer = true;
                                } else {
                                    core::ptr::copy_nonoverlapping(
                                        sym_field.add(4),
                                        uprobe_symbol.as_mut_ptr(),
                                        sym_len,
                                    );
                                    uprobe_symbol[sym_len] = 0;
                                    uprobe_symbol_len = sym_len;
                                    trailer_bytes = 4 + bn_len + 4 + sym_len;
                                }
                            }
                        }
                        if malformed_trailer {
                            // Skip processing this command; re-post and
                            // continue.  Falling through with bad lengths
                            // would corrupt the maps/insns offsets.
                            complete_load_prog(bg, cmd, -(bindings::EINVAL as i32));
                            continue;
                        }

                        let maps_base = payload_base.add(4 + 32 + 4 + trailer_bytes);
                        // MapDef bumped to 24 bytes with appended u32 flags
                        // (low byte = agg_kind for snapshot-worker dispatch).
                        let map_def_size = 24usize;
                        
                        // --- Phase 1: Parse maps, allocate bpf_map via
                        // the standard kernel allocator path. Map types
                        // remaining in use post-SHMEM-migration are
                        // PERCPU_ARRAY/HASH (aggs) — the legacy
                        // RINGBUF map type is no longer requested by
                        // the lowering since records flow through the
                        // SHMEM data plane.
                        for i in 0..num_maps as usize {
                            if i >= 8 { break; }
                            let map_def = &*(maps_base.add(i * map_def_size) as *const MapDef);

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
                        // Layer 2 only. Walk the MapDef array (not just newly-
                        // allocated maps), look up the slot for each fake_fd,
                        // and bind a fresh real fd via bifrost_map_get_fd.
                        // Closed after bifrost_verify_prog returns. Without
                        // this, a follow-on LOAD_PROG that reuses an existing
                        // fake_fd (the shared ringbuf, the TLS map) finds
                        // BIFROST_MAP_REAL_FDS[slot] = -1 (closed by the prior
                        // program's verify) and the verifier rejects with
                        // "fd N is not pointing to valid bpf_map".
                        if BIFROST_USE_VERIFIER.load(core::sync::atomic::Ordering::Relaxed) {
                            for i in 0..num_maps as usize {
                                let map_def = &*(maps_base.add(i * map_def_size) as *const MapDef);
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
                                    pr_info!(
                                        "bifrost_guest: layer2 map[{}] (fake_fd={}) real fd={}\n",
                                        slot, map_def.fake_fd, fd
                                    );
                                }
                            }
                        }
                        
                        // --- Phase 2: Parse BPF instructions ---
                        let insns_header = maps_base.add(num_maps as usize * map_def_size);
                        let num_insns = *(insns_header as *const u32);
                        let insns_base = insns_header.add(4) as *mut BpfInsn;
                        
                        pr_info!("bifrost_guest: {} BPF instructions received\n", num_insns);
                        
                        // --- Phase 3: Patch instructions ---
                        // Two paths:
                        //  - Layer-2 (verifier on): rewrite LD_IMM64 with the
                        //    map's REAL fd; leave BPF_CALL alone (verifier
                        //    resolves helper ids during bpf_check).
                        //  - Bypass-verifier (verifier off): resolve fake_fd →
                        //    bpf_map* (clear src_reg) and helper_id → offset
                        //    inline so the JIT can lower without bpf_check.
                        let use_verifier = BIFROST_USE_VERIFIER.load(core::sync::atomic::Ordering::Relaxed);
                        pr_info!("bifrost_guest: Phase 3 starting (use_verifier={})\n", use_verifier);
                        let bpf_call_base = bindings::__bpf_call_base as *const () as u64;
                        let mut idx = 0u32;
                        while idx < num_insns {
                            let insn = &mut *insns_base.add(idx as usize);

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
                                    let map_ptr = (*bg).maps[j];
                                    if use_verifier {
                                        let real_fd = BIFROST_MAP_REAL_FDS[j];
                                        if real_fd >= 0 {
                                            insn.imm = real_fd;
                                            // Keep src_reg=BPF_PSEUDO_MAP_FD(1) — the
                                            // verifier flips this to MAP_VALUE/PTR
                                            // and rewrites imm to the kernel addr.
                                            if idx + 1 < num_insns {
                                                let insn2 = &mut *insns_base.add((idx + 1) as usize);
                                                insn2.imm = 0;
                                            }
                                            pr_info!(
                                                "bifrost_guest: layer2 ldimm64[{}] fake_fd={} -> real_fd={}\n",
                                                idx, fake_fd, real_fd
                                            );
                                        }
                                    } else if !map_ptr.is_null() {
                                        let addr = map_ptr as u64;
                                        insn.imm = addr as i32;
                                        insn.set_src_reg(0);
                                        if idx + 1 < num_insns {
                                            let insn2 = &mut *insns_base.add((idx + 1) as usize);
                                            insn2.imm = (addr >> 32) as i32;
                                        }
                                        pr_info!(
                                            "bifrost_guest: patched insn[{}] fd={} -> map=0x{:x}\n",
                                            idx, fake_fd, addr
                                        );
                                    }
                                }
                                idx += 2;
                                continue;
                            }

                            if insn.code == 0x85 && insn.src_reg() == 0 {
                                let helper_id = insn.imm;
                                if use_verifier {
                                    // Verifier resolves helper ids; leave
                                    // imm alone (it already holds the id).
                                    let _ = helper_id;
                                } else {
                                    let helper_addr: u64 = match helper_id {
                                        67 => bifrost_get_stack as *const () as u64,
                                        _ => {
                                            // Bypass-verifier path — `prog` not yet constructed.
                                            // Safe to pass NULL because all helpers we lower in
                                            // this path live in bpf_base_func_proto's first
                                            // switch (no CAP_BPF gate).
                                            let proto = bindings::bifrost_get_func_proto(
                                                helper_id as bindings::bpf_func_id,
                                                core::ptr::null(),
                                            );
                                            if proto.is_null() {
                                                0
                                            } else {
                                                (*proto).func.map(|f| f as *const () as u64).unwrap_or(0)
                                            }
                                        }
                                    };
                                    if helper_addr != 0 {
                                        let offset = helper_addr.wrapping_sub(bpf_call_base) as i32;
                                        insn.imm = offset;
                                        pr_info!(
                                            "bifrost_guest: patched insn[{}] helper {} -> 0x{:x} (offset {})\n",
                                            idx, helper_id, helper_addr, offset
                                        );
                                    } else {
                                        pr_err!("bifrost_guest: no proto for helper {}\n", helper_id);
                                    }
                                }
                            }

                            idx += 1;
                        }
                        pr_info!("bifrost_guest: Phase 3 finished\n");

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
                        let relocs_base = (insns_base as *const u8).add((num_insns as usize) * 8);
                        let num_relocs = *(relocs_base as *const u32);
                        let mut reloc_ok = true;
                        if num_relocs > 0 {
                            let vmlinux_btf = bindings::bpf_get_btf_vmlinux();
                            if vmlinux_btf.is_null() {
                                pr_err!("bifrost_guest: bpf_get_btf_vmlinux returned NULL\n");
                                reloc_ok = false;
                            } else {
                                let mut walk = relocs_base.add(4);
                                let mut name_buf = [0u8; 256];
                                for _ in 0..num_relocs {
                                    let insn_idx = *(walk as *const u32) as usize;
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
                                        break;
                                    }
                                    let target_insn = &mut *insns_base.add(insn_idx);
                                    target_insn.imm = btf_id;
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
                            complete_load_prog(bg, cmd, -(bindings::EINVAL as i32));
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
                                "bifrost_guest: slot table grow to len={} failed ({:?}); dropping LOAD_PROG\n",
                                slot + 1,
                                e
                            );
                            // Re-arm and continue without registering anything.
                            complete_load_prog(bg, cmd, -(bindings::ENOMEM as i32));
                            continue;
                        }

                        let insn_bytes = (num_insns as usize) * 8;
                        let prog = bpf_prog_alloc(insn_bytes as u32, bindings::GFP_KERNEL);
                        let mut prog_ok = false;
                        if !prog.is_null() {
                            (*prog).len = num_insns;
                            (*prog).type_ = 2; // BPF_PROG_TYPE_KPROBE (UNSPEC=0, SOCKET_FILTER=1, KPROBE=2)
                            (*prog).set_jit_requested(1);
                            (*prog).set_gpl_compatible(1);
                            if !use_verifier && !(*prog).aux.is_null() {
                                // Bypass path needs stack_depth set manually
                                // since the verifier (which would normally
                                // compute it) is skipped. See memory note
                                // build_jit_stack_depth.md.
                                (*(*prog).aux).stack_depth = 512;
                            }

                            let dst = &mut (*prog).__bindgen_anon_1 as *mut _ as *mut u8;
                            core::ptr::copy_nonoverlapping(
                                insns_base as *const u8,
                                dst,
                                insn_bytes,
                            );

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

                            // Layer 2: hand the prog to the kernel verifier
                            // before JIT. Verifier resolves pseudo-ldimm64
                            // (real_fd → bpf_map*), validates instruction
                            // stream, computes stack_depth, rewrites helper
                            // calls, etc. May replace the prog pointer
                            // (extra_pass / blinding rewrites).
                            let mut prog_p: *mut bindings::bpf_prog = prog;
                            if use_verifier {
                                let verr = bindings::bifrost_verify_prog(&mut prog_p);
                                if verr != 0 {
                                    pr_err!(
                                        "bifrost_guest: bifrost_verify_prog failed: {}\n",
                                        verr
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
                                pr_info!("bifrost_guest: bifrost_verify_prog ok\n");
                                // Release the real fds — the prog now holds
                                // a kernel-pointer reference to each map
                                // (and bifrost_map_get_fd took a uref the
                                // close releases).
                                for j in 0..(*bg).num_maps as usize {
                                    let f = BIFROST_MAP_REAL_FDS[j];
                                    if f >= 0 {
                                        let _ = bindings::close_fd(f as core::ffi::c_uint);
                                        BIFROST_MAP_REAL_FDS[j] = -1;
                                    }
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
                                uprobe_path_buf: &uprobe_path_buf,
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

// Per-slot attach + cleanup arms.  Each pair of helpers
// (attach_slot_<kind> + cleanup_slot_<kind>) handles ONE
// probe-type's teardown / register-and-attach for a single slot
// index.  The dispatch loop in the LOAD_PROG worker calls the
// attach side; bifrost_remove calls the cleanup side.  Splitting
// each arm out keeps both flows readable (each block was 100+
// lines deeply nested in a 1300-line worker body) and gives
// reviewers a single place to audit reverse-order discipline:
// every refcount the attach arm acquires, the cleanup arm drops.

/// Register a JIT'd FBT (FENTRY/FEXIT) prog by linking it into
/// the BPF trampoline the verifier resolved for us.
///
/// The verifier's `check_attach_btf_id` path populated
/// `prog->aux->dst_trampoline` (via `bpf_check_attach_target` +
/// `bpf_trampoline_get`) when we set `type=TRACING +
/// attach_btf_id` and routed through `bifrost_set_prog_type`
/// before `bifrost_verify_prog`.  We:
///   1. Init a per-slot `bpf_tracing_link`
///   2. Point it at the JIT'd prog + dst_trampoline
///   3. `bpf_trampoline_link_prog` inserts the link into the
///      trampoline's hlist — the next call into the target
///      function hits the trampoline and runs our prog.
///
// =====================================================================
// Probe-family dispatch (Phase D).
//
// Today's `match probe_type` happens at three sites:
//   - LOAD_PROG attach loop (line ~1842): selects which
//     `attach_slot_*` to call.
//   - bifrost_remove cleanup (line ~2948): selects which
//     `cleanup_slot_*` to call.
//   - host CLI wrapper builder (host/bifrost/src/cli/wrapper.rs):
//     selects which trailer shape to emit.
//
// The three matches are coupled — adding a new probe family means
// editing all three plus the wire-format const + the per-family
// register/unregister paths.  Phase D collapses the kernel-side two
// matches into single dispatch helpers with a single arm per
// family.  Adding a new family is one new arm in three places
// (slot_family_attach / _cleanup / _label) plus a new
// attach_slot_<family> + cleanup_slot_<family>.  No more parallel
// match arms drifting out of sync.
//
// Note: this is the kernel-rust-friendly shape — `match`-based
// dispatch rather than `&'static dyn AttachOps`.  Kernel-rust
// supports `dyn Trait` but the existing driver uses no dyn, so
// staying with concrete dispatch keeps the add-one-family delta
// tighter and the codegen friendlier.

/// Inputs for `slot_family_attach` — the union of arguments every
/// `attach_slot_*` function needs.  Each family pulls only the
/// fields it cares about.  Borrowed by `'a` against the LOAD_PROG
/// worker's stack-resident parse buffer.
struct AttachExt<'a> {
    name_str: &'a str,
    target_name: [u8; 32],
    uprobe_basename: &'a [u8],
    uprobe_symbol: &'a [u8],
    uprobe_provider: &'a [u8],
    uprobe_path_buf: &'a [u8; 257],
    uprobe_file_offset: u64,
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
unsafe fn slot_family_attach(
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
            pr_err!("bifrost_guest: slot table grow to len={} failed in slot_family_attach\n", slot + 1);
            return -(bindings::ENOMEM as i32);
        }
        slots_mut()[slot].lease = slot_lease_new();
        let rc = match probe_type {
            PROBE_TYPE_FENTRY | PROBE_TYPE_FEXIT => {
                attach_slot_fbt(slot, probe_type, ext.name_str, bg)
            }
            PROBE_TYPE_TRACEPOINT => {
                attach_slot_tracepoint(slot, ext.name_str, bg)
            }
            PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => {
                attach_slot_uprobe(
                    slot,
                    probe_type,
                    ext.name_str,
                    ext.uprobe_path_buf,
                    ext.uprobe_file_offset,
                    bg,
                )
            }
            PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => {
                attach_slot_uprobe_by_sym(
                    slot,
                    probe_type,
                    ext.uprobe_basename,
                    ext.uprobe_symbol,
                    bg,
                )
            }
            PROBE_TYPE_USDT => {
                attach_slot_usdt(
                    slot,
                    ext.uprobe_basename,
                    ext.uprobe_provider,
                    ext.uprobe_symbol,
                    bg,
                )
            }
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
unsafe fn slot_family_cleanup(slot: usize, probe_type: u8) -> bool {
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
/// Used by Phase H emit in a follow-up; today only diagnostic.
#[allow(dead_code)]
fn slot_family_label(probe_type: u8) -> &'static str {
    match probe_type {
        PROBE_TYPE_FENTRY | PROBE_TYPE_FEXIT => "fbt",
        PROBE_TYPE_TRACEPOINT => "tracepoint",
        PROBE_TYPE_UPROBE | PROBE_TYPE_URETPROBE => "uprobe",
        PROBE_TYPE_UPROBE_BY_SYM | PROBE_TYPE_URETPROBE_BY_SYM => "uprobe_by_sym",
        PROBE_TYPE_USDT => "usdt",
        PROBE_TYPE_NONE => "none",
        _ => "unknown",
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
    } else { core::ptr::null_mut() };
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
            kind, slot, name_str
        );
    } else {
        pr_err!(
            "bifrost_guest: {} slot[{}] bpf_trampoline_link_prog failed: {}\n",
            kind, slot, lret
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
    } else { core::ptr::null_mut() };
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
            slot, name_str
        );
    } else {
        pr_err!(
            "bifrost_guest: tracepoint slot[{}] bpf_probe_register failed: {}\n",
            slot, lret
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
        pr_err!("bifrost_guest: uprobe slot[{}] out of range (len={})\n", slot, slots_mut().len());
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
    let task = find_task_by_comm(basename);
    if task.is_null() {
        pr_err!(
            "bifrost_guest: uprobe-by-sym slot[{}] no task with comm '{}'\n",
            slot,
            core::str::from_utf8(basename).unwrap_or("?")
        );
        return -(bindings::ENOENT as i32);
    }
    let exe = get_task_exe_file(task);
    if exe.is_null() {
        pr_err!(
            "bifrost_guest: uprobe-by-sym slot[{}] task has no exe_file\n",
            slot
        );
        put_task_ref(task);
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
        put_task_ref(task);
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
        task,
        Some(push_symtab_snapshot_cb),
        core::ptr::null_mut(),
    );
    put_task_ref(task);
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
            slot, raw
        );
        iput(pinned);
        return if raw < 0 { raw as c_int } else { -(bindings::EINVAL as i32) };
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
        pr_err!("bifrost_guest: uprobe slot[{}] out of range (len={})\n", slot, slots_mut().len());
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
            return if raw_file < 0 { raw_file as c_int } else { -(bindings::ENOENT as i32) };
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
        (core::ptr::null_mut(), pinned)
    } else {
        let task = find_task_by_comm(basename);
        if task.is_null() {
            pr_err!(
                "bifrost_guest: usdt slot[{}] no task with comm '{}'\n",
                slot,
                core::str::from_utf8(basename).unwrap_or("?")
            );
            return -(bindings::ENOENT as i32);
        }
        let exe = get_task_exe_file(task);
        if exe.is_null() {
            pr_err!("bifrost_guest: usdt slot[{}] task has no exe_file\n", slot);
            put_task_ref(task);
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
            put_task_ref(task);
            return rc;
        }
        let exe_inode = (*exe).f_inode;
        let pinned = igrab(exe_inode);
        fput(exe);
        (task, pinned)
    };
    pr_info!(
        "bifrost_guest: usdt slot[{}] resolved {}:{} pc=+0x{:x} sema=+0x{:x}\n",
        slot,
        core::str::from_utf8(sdt_provider).unwrap_or("?"),
        core::str::from_utf8(sdt_probe).unwrap_or("?"),
        pc_off, sema_off
    );
    // Push symtabs for the firing task's executable VMAs (same as the
    // by-sym path) so any gustack() in the body symbolicates cleanly.
    if !task.is_null() {
        bifrost_helper_for_each_vma_file(
            task,
            Some(push_symtab_snapshot_cb),
            core::ptr::null_mut(),
        );
        put_task_ref(task);
    }
    if pinned.is_null() {
        pr_err!("bifrost_guest: usdt slot[{}] igrab returned NULL\n", slot);
        return -(bindings::ENOENT as i32);
    }
    core::ptr::write_bytes(consumer, 0, 1);
// shared handler — slot recovered via container-of
    (*consumer).handler = Some(bifrost_uprobe_handler);
    let handle = uprobe_register(
        pinned,
        pc_off as i64,
        sema_off as i64,
        consumer,
    );
    let raw = handle as i64;
    if (-4096..0).contains(&raw) || handle.is_null() {
        pr_err!(
            "bifrost_guest: usdt slot[{}] uprobe_register failed: {}\n",
            slot, raw
        );
        iput(pinned);
        return if raw < 0 { raw as c_int } else { -(bindings::EINVAL as i32) };
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
        pc_off, sema_off
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
        pr_err!("bifrost_guest: uprobe slot[{}] out of range (len={})\n", slot, slots_mut().len());
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
    let basename = path_basename(uprobe_path_buf);
    if !basename.is_empty() {
        let task = find_task_by_comm(basename);
        if !task.is_null() {
            let exe = get_task_exe_file(task);
            put_task_ref(task);
            if !exe.is_null() {
                let exe_inode = (*exe).f_inode;
                pinned = igrab(exe_inode);
                // Drop the file ref — the inode pin (igrab
                // refcount) is sufficient to keep the inode
                // alive for the lifetime of the uprobe.
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
        return if rc != 0 { rc } else { -(bindings::ENOENT as i32) };
    }
    pr_info!(
        "bifrost_guest: uprobe slot[{}] resolved '{}' via {} (attempts={})\n",
        slot,
        core::str::from_utf8(
            &uprobe_path_buf[..uprobe_path_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0)]
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
            slot, raw
        );
        iput(pinned);
        if !kpath.dentry.is_null() {
            path_put(&kpath);
        }
        return if raw < 0 { raw as c_int } else { -(bindings::EINVAL as i32) };
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
            &uprobe_path_buf[..uprobe_path_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(0)]
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
    } else { core::ptr::null_mut() };
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
    } else { core::ptr::null_mut() };
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

extern "C" fn bifrost_remove(vdev: *mut bindings::virtio_device) {
    unsafe {
        let bg = (*vdev).priv_ as *mut BifrostGuest;
        if !(*bg).thread.is_null() {
            bindings::kthread_stop((*bg).thread);
        }
        bifrost_clear_doorbell_callback();
        bifrost_clear_shmem_ringbuf();

        // Unregister all probes first (before freeing memory they reference).
        // Per-slot teardown lives in `cleanup_slot_*` helpers above; this
        // loop just dispatches by probe_type.  Uprobe slots accumulate a
        // had_uprobe flag so we can run a single batched
        // `uprobe_unregister_sync()` at the end (drains outstanding
        // handlers across the whole module before bpf_prog_free).
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
        // Free BPF programs in all loaded slots. Atomic swap avoids
        // racing the per-slot probe handler (uprobe consumer / fbt
        // trampoline / raw tracepoint dispatch) if it ever fires
        // after the unregister call but before the bpf_prog_free.
        // Walk the actual KVec length (== SLOT_CAPACITY by construction
        // in bifrost_slots_init) rather than the legacy MAX_KPROBES
        // const, so a future grow-on-demand changes one site only.
        let cap = slots_mut().len();
        for s in 0..cap {
            let prog = slots_mut()[s].prog.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !prog.is_null() {
                bpf_prog_free(prog);
            }
        }

        // Free all bpf_maps. Every map (RINGBUF included) was allocated
        // via bifrost_alloc_map; the kernel owns the storage and the
        // per-type free vector is in map.ops.
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

static mut ID_TABLE: [bindings::virtio_device_id; 2] = [
    bindings::virtio_device_id {
        device: 42,
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
        // Phase C heap migration: allocate the slot table before
        // any virtio probe path can touch it.  ~80 KB kmalloc;
        // OOM here aborts module load with an actionable -ENOMEM
        // rather than the silent crash a NULL access would
        // produce later.
        bifrost_slots_init()?;
        pr_info!(
            "bifrost_guest: slot table heap-backed (initial={} slots, grows on demand via slots_ensure; was [BifrostSlot; MAX_KPROBES=8] static array)\n",
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
