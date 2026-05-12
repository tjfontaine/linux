// SPDX-License-Identifier: GPL-2.0
// drivers/bifrost/shmem_publish.rs
//
// Helpers that publish vmlinux BTF and kallsyms into the SHMEM
// region's BTF/KSYMS sub-regions, so the host's libkrun-side
// renderer can symbolicate gustack/gstack frames without ever
// reading vmlinux off a host-mirrored rootfs.
//
// The original `populate_shmem_btf` / `populate_shmem_kallsyms`
// took `*mut BifrostGuest` for `shmem_va` access; here we take
// `*mut u8` directly (the caller passes `(*bg).shmem_va`), which
// keeps this module decoupled from the parent crate's main state
// struct.

use kernel::bindings;
use kernel::ffi::{c_char, c_int, c_void};
use kernel::pr_err;
use kernel::pr_info;

use super::shmem_layout::{SHMEM_BTF_CAP, SHMEM_BTF_OFF, SHMEM_KSYMS_CAP, SHMEM_KSYMS_OFF};

unsafe extern "C" {
    fn strlen(s: *const c_char) -> usize;
}

/// Phase 3a: copy vmlinux BTF straight into the SHMEM BTF
/// sub-region. Replaces the chunked op=4 SEND_BTF transport.
/// Returns the actual byte count copied (0 if BTF unavailable
/// or oversized).
///
/// SAFETY: `shmem_va` must point to the base of a SHMEM region
/// large enough to cover `SHMEM_BTF_OFF + SHMEM_BTF_CAP`.
pub(crate) unsafe fn populate_shmem_btf(shmem_va: *mut u8) -> usize {
    unsafe {
        let mut size: usize = 0;
        let btf_start = bindings::bifrost_btf_data(&mut size as *mut usize) as *const u8;
        if btf_start.is_null() || size == 0 {
            pr_err!("bifrost_guest: vmlinux BTF unavailable\n");
            return 0;
        }
        if size > SHMEM_BTF_CAP {
            pr_err!(
                "bifrost_guest: vmlinux BTF too large ({} > {} cap)\n",
                size,
                SHMEM_BTF_CAP
            );
            return 0;
        }
        let dst = shmem_va.add(SHMEM_BTF_OFF);
        core::ptr::copy_nonoverlapping(btf_start, dst, size);
        pr_info!(
            "bifrost_guest: BTF placed at SHMEM offset {} ({} bytes)\n",
            SHMEM_BTF_OFF,
            size
        );
        size
    }
}

/// Phase 3a: walk kallsyms and pack records into the SHMEM
/// kallsyms sub-region. Replaces the chunked op=5 SEND_KSYMS
/// transport. Wire format matches the legacy (op=5 stream): a
/// sequence of `[u64 addr][u8 name_len][u8; name_len]` records.
/// Returns total bytes written.
///
/// SAFETY: `shmem_va` must point to the base of a SHMEM region
/// large enough to cover `SHMEM_KSYMS_OFF + SHMEM_KSYMS_CAP`.
pub(crate) unsafe fn populate_shmem_kallsyms(shmem_va: *mut u8) -> usize {
    unsafe {
        let mut acc = ShmemKsymsAccum {
            buf: shmem_va.add(SHMEM_KSYMS_OFF),
            cap: SHMEM_KSYMS_CAP,
            pos: 0,
            overflow: false,
        };
        bindings::bifrost_walk_kallsyms(
            Some(shmem_ksyms_cb),
            &mut acc as *mut ShmemKsymsAccum as *mut c_void,
        );
        if acc.overflow {
            pr_err!(
                "bifrost_guest: kallsyms truncated at {} bytes ({} cap)\n",
                acc.pos,
                SHMEM_KSYMS_CAP
            );
        }
        pr_info!(
            "bifrost_guest: kallsyms placed at SHMEM offset {} ({} bytes)\n",
            SHMEM_KSYMS_OFF,
            acc.pos
        );
        acc.pos
    }
}

struct ShmemKsymsAccum {
    buf: *mut u8,
    cap: usize,
    pos: usize,
    overflow: bool,
}

unsafe extern "C" fn shmem_ksyms_cb(data: *mut c_void, name: *const c_char, addr: usize) -> c_int {
    unsafe {
        let acc = data as *mut ShmemKsymsAccum;
        if (*acc).overflow || name.is_null() {
            return 0;
        }
        let name_len = strlen(name);
        if name_len == 0 || name_len > 255 {
            return 0;
        }
        let needed = 8 + 1 + name_len;
        if (*acc).pos + needed > (*acc).cap {
            (*acc).overflow = true;
            return 0;
        }
        let addr_u64 = addr as u64;
        core::ptr::copy_nonoverlapping(
            &addr_u64 as *const u64 as *const u8,
            (*acc).buf.add((*acc).pos),
            8,
        );
        (*acc).pos += 8;
        *(*acc).buf.add((*acc).pos) = name_len as u8;
        (*acc).pos += 1;
        core::ptr::copy_nonoverlapping(name as *const u8, (*acc).buf.add((*acc).pos), name_len);
        (*acc).pos += name_len;
        0
    }
}
