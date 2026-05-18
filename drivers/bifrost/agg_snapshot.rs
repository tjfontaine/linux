// SPDX-License-Identifier: GPL-2.0
// SHMEM snapshots for aggregation maps.

use kernel::bindings;
use kernel::ffi::c_void;

use crate::bpf_consts::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF};
use crate::record_writer::RecordWriter;
use crate::wire::{
    AGG_KIND_AVG, AGG_KIND_MAX, AGG_KIND_MIN, AGG_KIND_QUANTIZE, AGG_KIND_STDDEV,
    AGG_SNAPSHOT_PROBE_ID, AGG_SNAPSHOT_ROW_KIND_AVG, AGG_SNAPSHOT_ROW_KIND_MAX,
    AGG_SNAPSHOT_ROW_KIND_MIN, AGG_SNAPSHOT_ROW_KIND_QUANTIZE, AGG_SNAPSHOT_ROW_KIND_STDDEV,
    AGG_SNAPSHOT_ROW_KIND_SUM, AGG_SNAPSHOT_ROW_KIND_UNKNOWN, AGG_SNAPSHOT_SCHEMA_V1,
    DTRACE_QUANTIZE_NBUCKETS, QUANTIZE_VALUE_SIZE, SHMEM_DROP_CLASS_AGG,
};

/// Translate the kernel-internal per-map agg-kind flag to the
/// canonical AGG_SNAPSHOT_ROW_KIND_* discriminant stamped into
/// every wire row under schema v1.  The Linux side currently has
/// no QUANTIZE / LQUANTIZE / LLQUANTIZE aggregator, so unknown
/// kinds surface as UNKNOWN — the host marks the row and
/// continues.  Today's BPF programs only use SUM / MIN / MAX /
/// AVG / STDDEV; COUNT is folded into SUM with a constant +1
/// increment.
fn agg_snapshot_row_kind(agg_kind_u8: u8) -> u8 {
    match agg_kind_u8 {
        // AGG_KIND_SUM = 0 from wire.rs
        0 => AGG_SNAPSHOT_ROW_KIND_SUM,
        AGG_KIND_MIN => AGG_SNAPSHOT_ROW_KIND_MIN,
        AGG_KIND_MAX => AGG_SNAPSHOT_ROW_KIND_MAX,
        AGG_KIND_AVG => AGG_SNAPSHOT_ROW_KIND_AVG,
        AGG_KIND_STDDEV => AGG_SNAPSHOT_ROW_KIND_STDDEV,
        AGG_KIND_QUANTIZE => AGG_SNAPSHOT_ROW_KIND_QUANTIZE,
        _ => AGG_SNAPSHOT_ROW_KIND_UNKNOWN,
    }
}
use crate::{BifrostGuest, BIFROST_MAP_AGG_KIND, BIFROST_MAP_FAKE_FDS};

extern "C" {
    /// W7: class-aware kernel-internal reserve. Mirrors
    /// `bifrost_shmem_reserve_kernel` but attributes drops to the
    /// caller-supplied class so the host CLI can report which
    /// workload class (PRINCIPAL / AGG / STKSTR / DBLERR) is
    /// overloaded.
    fn bifrost_shmem_reserve_kernel_class(size: u32, class: u32) -> *mut c_void;
}

/// Pack a snapshot of every non-RINGBUF map's live entries into the
/// SHMEM event ringbuf. Replaces the legacy VQ_EVENT op=6
/// AGG_SNAPSHOT virtqueue path.
pub(crate) unsafe fn push_agg_snapshot(bg: *mut BifrostGuest) {
    unsafe {
        const HDR_BYTES: usize = 24;
        const NUM_ENTRIES_BYTES: usize = 4;
        const MAX_KEY_BYTES: usize = 32;
        // PER_ROW_VAL_CAP: max bytes a single row's value slot can
        // carry on the wire.  Symmetric with FreeBSD's
        // DTRACE_BIFROST_AGG_VAL_MAX = 1024 — wide enough for a
        // full 127-bucket quantize array (8 *
        // DTRACE_QUANTIZE_NBUCKETS = 1016, rounded up to 1024 for
        // headroom).  Today's BPF aggregators only write 8 bytes
        // (COUNT / SUM / MIN / MAX / AVG) or 24 bytes (STDDEV
        // triple); a future quantize-on-Linux aggregator can land
        // here without a wire bump in lockstep.  The host's
        // `ingest_agg_snapshot` decoder caps at 4096, so 1024 fits.
        const PER_ROW_VAL_CAP: usize = 1024;
        const MAX_ENTRY_BYTES: usize = 4 + 4 + MAX_KEY_BYTES + 4 + PER_ROW_VAL_CAP;
        // MAX_ENTRIES is bounded by `bifrost_shmem_reserve_kernel_
        // class`'s per-record cap of 65 536 bytes:
        //   (65 536 - 28) / (4 + 4 + 32 + 4 + 1024) = 61 entries.
        // Round to 60 to leave a safety byte or two.  In practice
        // most BPF aggregators emit 8-byte scalar values, but the
        // reservation has to be sized for the worst case because
        // pack_row doesn't know the value shapes ahead of time
        // until it walks the per-CPU agg maps.  60 quantize-shaped
        // rows is more than any real demo emits per snapshot; the
        // earlier 960 figure was computed against the old 24-byte
        // value cap and never reflected an actual demo working set.
        // If a future session genuinely needs >60 rows, the AGG
        // drop counter surfaces the overflow via the bifrost-wire
        // SHMEM_DROP_CLASS_AGG bucket.
        const MAX_ENTRIES: usize = 60;
        const MAX_BODY: usize = HDR_BYTES + NUM_ENTRIES_BYTES + MAX_ENTRIES * MAX_ENTRY_BYTES;

        let rec = bifrost_shmem_reserve_kernel_class(MAX_BODY as u32, SHMEM_DROP_CLASS_AGG)
            as *mut u8;
        if rec.is_null() {
            return;
        }

        let mut writer = RecordWriter::new(rec, MAX_BODY);
        writer.write_u32(0);
        writer.write_u32(AGG_SNAPSHOT_PROBE_ID);
        writer.write_u64(bindings::ktime_get_mono_fast_ns());
        // Schema v1: the previously-reserved u64 at sub-header
        // offset 16 now carries the wire format schema version.  Any
        // host decoder built before this commit will see a non-zero
        // value here and fall back to the legacy path; the new
        // decoder reads the kind byte stamped into each row.
        writer.write_u64(AGG_SNAPSHOT_SCHEMA_V1);

        let n_off = writer.off;
        writer.write_u32(0);

        // Helper: pack one (fd, kind, key, value) row into the
        // writer.  Returns true on success, false on out-of-space
        // (caller rolls back).  STDDEV writes 24 value bytes; the
        // scalar shapes (SUM / MIN / MAX / AVG) write 8.  Every row
        // carries the canonical AGG_SNAPSHOT_ROW_KIND_* tag so the
        // host never has to scan source to recover the agg kind.
        let mut packed: usize = 0;
        let mut pack_row = |writer: &mut RecordWriter,
                            fd: i32,
                            agg_kind: u8,
                            map: *mut bindings::bpf_map,
                            k_ptr: *const core::ffi::c_void,
                            k_size: u32,
                            k_bytes: &[u8]|
         -> bool {
            let chk = writer.off;
            let kind = agg_snapshot_row_kind(agg_kind);
            let ok = match agg_kind {
                AGG_KIND_QUANTIZE => {
                    // Track B P0 #7: walk the per-CPU
                    // QUANTIZE_VALUE_SIZE byte bucket array, sum
                    // bucket-wise across CPUs, and emit ONE row
                    // with the full array as the value.  Matches
                    // FreeBSD libdtrace's wire shape so the host's
                    // CrossTargetAggReducer folds both kernels'
                    // contributions into one histogram cell.
                    let n = DTRACE_QUANTIZE_NBUCKETS;
                    let mut buckets: [u64; DTRACE_QUANTIZE_NBUCKETS] =
                        [0u64; DTRACE_QUANTIZE_NBUCKETS];
                    let rc = bindings::bifrost_map_lookup_quantize_buckets(
                        map,
                        k_ptr,
                        buckets.as_mut_ptr(),
                        n as u32,
                    );
                    if rc != 0 {
                        return false;
                    }
                    // Skip rows with no fires at all (saves wire
                    // bytes when a quantize agg was declared but
                    // the probe never matched on this CPU).
                    let any = buckets.iter().any(|&v| v != 0);
                    if !any {
                        return false;
                    }
                    let mut wrote = writer.write_i32(fd)
                        && writer.write_bytes(&[kind, 0, 0, 0])
                        && writer.write_u32(k_size)
                        && writer.write_bytes(k_bytes)
                        && writer.write_u32(QUANTIZE_VALUE_SIZE);
                    for i in 0..n {
                        wrote = wrote && writer.write_u64(buckets[i]);
                    }
                    wrote
                }
                AGG_KIND_STDDEV => {
                    let mut n: u64 = 0;
                    let mut sum: u64 = 0;
                    let mut sum_sq: u64 = 0;
                    let rc = bindings::bifrost_map_lookup_stddev_u64(
                        map,
                        k_ptr,
                        &mut n as *mut u64,
                        &mut sum as *mut u64,
                        &mut sum_sq as *mut u64,
                    );
                    if rc != 0 || n == 0 {
                        return false;
                    }
                    writer.write_i32(fd)
                        && writer.write_bytes(&[kind, 0, 0, 0])
                        && writer.write_u32(k_size)
                        && writer.write_bytes(k_bytes)
                        && writer.write_u32(24)
                        && writer.write_u64(n)
                        && writer.write_u64(sum)
                        && writer.write_u64(sum_sq)
                }
                _ => {
                    let mut v: u64 = 0;
                    let rc = match agg_kind {
                        AGG_KIND_MIN => bindings::bifrost_map_lookup_min_u64(map, k_ptr, &mut v),
                        AGG_KIND_MAX => bindings::bifrost_map_lookup_max_u64(map, k_ptr, &mut v),
                        AGG_KIND_AVG => bindings::bifrost_map_lookup_avg_u64(map, k_ptr, &mut v),
                        _ => bindings::bifrost_map_lookup_sum_u64(map, k_ptr, &mut v),
                    };
                    if rc != 0 || v == 0 {
                        return false;
                    }
                    writer.write_i32(fd)
                        && writer.write_bytes(&[kind, 0, 0, 0])
                        && writer.write_u32(k_size)
                        && writer.write_bytes(k_bytes)
                        && writer.write_u32(8)
                        && writer.write_u64(v)
                }
            };
            if !ok {
                writer.off = chk;
            }
            ok
        };

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
            if mt == BPF_MAP_TYPE_RINGBUF || fd >= 300 {
                continue;
            }
            let key_size = (*map).key_size as usize;

            if mt == BPF_MAP_TYPE_ARRAY || mt == BPF_MAP_TYPE_PERCPU_ARRAY {
                let max = (*map).max_entries;
                for k in 0..max {
                    if packed >= MAX_ENTRIES {
                        break;
                    }
                    let k32: u32 = k;
                    let k_bytes = k32.to_le_bytes();
                    // Track B P0 #7: AGG_KIND_QUANTIZE on a
                    // PERCPU_ARRAY[1] represents an unkeyed
                    // `@latency = quantize(...)`.  The map index
                    // 0 is an internal lookup detail, not a
                    // user-visible key — emit k_size=0 on the
                    // wire so the host's CrossTargetAggReducer
                    // keys this row identically to FreeBSD's
                    // libdtrace-emitted empty-key quantize row
                    // and folds both into one histogram cell.
                    let (k_size, k_slice): (u32, &[u8]) = if agg_kind == AGG_KIND_QUANTIZE {
                        (0, &[][..])
                    } else {
                        (4, &k_bytes[..])
                    };
                    if pack_row(
                        &mut writer,
                        fd,
                        agg_kind,
                        map,
                        &k32 as *const u32 as *const core::ffi::c_void,
                        k_size,
                        k_slice,
                    ) {
                        packed += 1;
                    }
                }
            } else {
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
                        break;
                    }
                    let kb = core::cmp::min(key_size, MAX_KEY_BYTES);
                    if pack_row(
                        &mut writer,
                        fd,
                        agg_kind,
                        map,
                        next_key.as_ptr() as *const core::ffi::c_void,
                        kb as u32,
                        &next_key[..kb],
                    ) {
                        packed += 1;
                    }
                    cur_key.copy_from_slice(&next_key);
                    have_cur = true;
                }
            }
        }

        writer.poke_u32(n_off, packed as u32);
        bindings::bifrost_shmem_submit_kernel(rec as *mut c_void);
    }
}
