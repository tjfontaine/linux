// SPDX-License-Identifier: GPL-2.0
// SHMEM snapshots for aggregation maps.

use kernel::bindings;
use kernel::ffi::c_void;

use crate::bpf_consts::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF};
use crate::record_writer::RecordWriter;
use crate::wire::{AGG_KIND_AVG, AGG_KIND_MAX, AGG_KIND_MIN, AGG_SNAPSHOT_PROBE_ID};
use crate::{BifrostGuest, BIFROST_MAP_AGG_KIND, BIFROST_MAP_FAKE_FDS};

/// Pack a snapshot of every non-RINGBUF map's live entries into the
/// SHMEM event ringbuf. Replaces the legacy VQ_EVENT op=6
/// AGG_SNAPSHOT virtqueue path.
pub(crate) unsafe fn push_agg_snapshot(bg: *mut BifrostGuest) {
    unsafe {
        const HDR_BYTES: usize = 24;
        const NUM_ENTRIES_BYTES: usize = 4;
        const MAX_KEY_BYTES: usize = 32;
        const MAX_ENTRY_BYTES: usize = 4 + 4 + MAX_KEY_BYTES + 8;
        const MAX_ENTRIES: usize = 1024;
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
            if mt == BPF_MAP_TYPE_RINGBUF || fd >= 300 {
                continue;
            }
            let key_size = (*map).key_size as usize;

            let reduce = |k_ptr: *const core::ffi::c_void, out: *mut u64| -> i32 {
                match agg_kind {
                    AGG_KIND_MIN => bindings::bifrost_map_lookup_min_u64(map, k_ptr, out),
                    AGG_KIND_MAX => bindings::bifrost_map_lookup_max_u64(map, k_ptr, out),
                    AGG_KIND_AVG => bindings::bifrost_map_lookup_avg_u64(map, k_ptr, out),
                    _ => bindings::bifrost_map_lookup_sum_u64(map, k_ptr, out),
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
                        continue;
                    }
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

        writer.poke_u32(n_off, packed as u32);
        bindings::bifrost_shmem_submit_kernel(rec as *mut c_void);
    }
}
