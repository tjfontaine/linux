// SPDX-License-Identifier: GPL-2.0
// SHMEM snapshots for aggregation maps.

use kernel::bindings;
use kernel::ffi::c_void;

use crate::bpf_consts::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF};
use crate::record_writer::RecordWriter;
use crate::wire::{
    AGG_KIND_AVG, AGG_KIND_MAX, AGG_KIND_MIN, AGG_KIND_STDDEV, AGG_SNAPSHOT_PROBE_ID,
};
use crate::{BifrostGuest, BIFROST_MAP_AGG_KIND, BIFROST_MAP_FAKE_FDS};

/// Pack a snapshot of every non-RINGBUF map's live entries into the
/// SHMEM event ringbuf. Replaces the legacy VQ_EVENT op=6
/// AGG_SNAPSHOT virtqueue path.
pub(crate) unsafe fn push_agg_snapshot(bg: *mut BifrostGuest) {
    unsafe {
        const HDR_BYTES: usize = 24;
        const NUM_ENTRIES_BYTES: usize = 4;
        const MAX_KEY_BYTES: usize = 32;
        // W5: per-row v_size header (u32) plus payload up to 24
        // bytes (STDDEV triple) — sum/min/max/avg use 8.
        const MAX_VAL_BYTES: usize = 24;
        const MAX_ENTRY_BYTES: usize = 4 + 4 + MAX_KEY_BYTES + 4 + MAX_VAL_BYTES;
        // BIFROST_RB_MAX_RECORD is 65 536; subtract the snapshot
        // header + entry-count u32 (28 bytes) and divide by the
        // worst-case per-row size (68 bytes after the W5
        // v_size + 24-byte STDDEV value extension) → 963 entries
        // per snapshot. Round down to 960 for a clean number.
        const MAX_ENTRIES: usize = 960;
        const MAX_BODY: usize = HDR_BYTES + NUM_ENTRIES_BYTES + MAX_ENTRIES * MAX_ENTRY_BYTES;

        let rec = bindings::bifrost_shmem_reserve_kernel(MAX_BODY as u32) as *mut u8;
        if rec.is_null() {
            return;
        }

        let mut writer = RecordWriter::new(rec, MAX_BODY);
        writer.write_u32(0);
        writer.write_u32(AGG_SNAPSHOT_PROBE_ID);
        writer.write_u64(bindings::ktime_get_mono_fast_ns());
        writer.write_u64(0);

        let n_off = writer.off;
        writer.write_u32(0);

        // Helper: pack one (fd, key, value) row into the writer.
        // Returns true on success, false on out-of-space (caller
        // rolls back). STDDEV writes 24 bytes, others 8.
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
            let ok = match agg_kind {
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
                    if pack_row(
                        &mut writer,
                        fd,
                        agg_kind,
                        map,
                        &k32 as *const u32 as *const core::ffi::c_void,
                        4,
                        &k_bytes,
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
