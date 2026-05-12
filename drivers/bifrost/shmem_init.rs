// SPDX-License-Identifier: GPL-2.0
// One-shot SHMEM_INIT notification sent over the event virtqueue.

use kernel::bindings;
use kernel::prelude::*;

use crate::shmem_layout::{SHMEM_MAGIC, SHMEM_REGION_SIZE, SHMEM_VERSION};
use crate::BifrostGuest;

/// One-shot SHMEM_INIT message to the host. For the generic virtio
/// SHM path this is a 24-byte readiness notification (`n_pages=0`);
/// the host already owns the region and maps it through the VMM's
/// virtio-shm metadata. For older VMMs, the fallback carries the
/// per-page PFN array so libkrun can derive host VAs from guest RAM.
pub(crate) unsafe fn send_shmem_init(bg: *mut BifrostGuest) {
    unsafe {
        const OP_SHMEM_INIT: u32 = 8;
        let event_buf = (*bg).event_buf as *mut u8;
        let region_size = SHMEM_REGION_SIZE as u32;
        let n_pages = (*bg).shmem_n_pages as u32;

        core::ptr::copy_nonoverlapping(&OP_SHMEM_INIT as *const u32 as *const u8, event_buf, 4);
        core::ptr::copy_nonoverlapping(
            &region_size as *const u32 as *const u8,
            event_buf.add(4),
            4,
        );
        core::ptr::copy_nonoverlapping(&n_pages as *const u32 as *const u8, event_buf.add(8), 4);
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
        core::ptr::copy_nonoverlapping(&reserved as *const u32 as *const u8, event_buf.add(20), 4);

        if n_pages != 0 {
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
            total_len,
            n_pages,
            (*bg).shmem_from_virtio
        );
    }
}
