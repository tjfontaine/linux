// SPDX-License-Identifier: GPL-2.0
/*
 * bifrost_helpers.c — small C shims used by the in-tree Rust bifrost
 * driver for things that bindgen can't synthesize cleanly (inline
 * symbols, RCU primitives, kernel macros, ELF parsing).
 */

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/*
 * Walk the task list looking for the first task whose `comm` matches
 * the given basename.  Returns the matching task_struct *, or NULL.
 * Caller must NOT dereference the returned task pointer outside of an
 * RCU read-side critical section unless they pin it themselves
 * (typically via get_task_exe_file, which task_locks internally).
 *
 * `target` may be up to TASK_COMM_LEN-1 (15) bytes — longer prefixes
 * are truncated to match the kernel's own comm storage.
 *
 * The walk runs under rcu_read_lock; the result pointer is briefly
 * valid after rcu_read_unlock thanks to the RCU grace-period
 * guarantee, but the caller is expected to immediately call a
 * task-pinning helper (get_task_exe_file et al.) that elevates the
 * reference count before doing anything else with the pointer.
 */
struct task_struct *bifrost_helper_find_task_by_comm(
	const unsigned char *target,
	unsigned int target_len)
{
	struct task_struct *g, *p, *result = NULL;
	unsigned int n = target_len;
	/* Log every distinct comm we walk past on a failed lookup so
	 * the host CLI's dmesg can see what the kernel actually has
	 * (debug aid for symlink/multicall/PR_SET_NAME mismatches).
	 * Capped at 64 lines to avoid log spam. */
	unsigned int comms_logged = 0;

	if (n > 15)
		n = 15;
	if (n == 0)
		return NULL;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		const char *comm = p->comm;
		unsigned int i;
		bool eq = true;

		for (i = 0; i < n; i++) {
			if ((unsigned char)comm[i] != target[i]) {
				eq = false;
				break;
			}
		}
		if (eq && (n == 15 || comm[n] == '\0' ||
			   comm[n] == ' ' || comm[n] == ':')) {
			result = p;
			break;
		}
	}
	rcu_read_unlock();

	if (!result) {
		/* Diagnostic: list every comm so we can see what task names
		 * actually exist when the lookup fails.  Held under
		 * tasklist_lock for a stable iteration. */
		printk(KERN_INFO
		       "bifrost_guest: find_task_by_comm('%.*s') miss; walking tasks:\n",
		       (int)n, target);
		rcu_read_lock();
		for_each_process_thread(g, p) {
			/* Skip kernel threads (PF_KTHREAD) — they outnumber
			 * user tasks on a quiet box and crowd out the
			 * task we actually care about. */
			if (p->flags & 0x00200000 /* PF_KTHREAD */)
				continue;
			if (comms_logged >= 64)
				break;
			printk(KERN_INFO "  pid=%d comm='%.16s'\n",
			       p->pid, p->comm);
			comms_logged++;
		}
		rcu_read_unlock();
	}
	return result;
}
EXPORT_SYMBOL_GPL(bifrost_helper_find_task_by_comm);

/*
 * Read `count` bytes from `file` at `pos` into `buf`.  Thin wrapper
 * around kernel_read() that retries short reads until it has the
 * full buffer or hits EOF/error.  Returns 0 on full success,
 * negative errno otherwise.
 */
static int bifrost_read_full(struct file *file, void *buf,
			     size_t count, loff_t pos)
{
	ssize_t got;
	size_t total = 0;
	loff_t p = pos;

	while (total < count) {
		got = kernel_read(file, (char *)buf + total,
				  count - total, &p);
		if (got < 0)
			return (int)got;
		if (got == 0)
			return -EINVAL; /* short read */
		total += got;
	}
	return 0;
}

/*
 * Resolve `symbol_name` in the ELF symbol table of `file` and write
 * its file offset to `*out_file_offset`.  Optionally writes symbol
 * size to `*out_size` when not NULL.
 *
 * Mirrors host/bifrost/src/elf_syms.rs but runs in the kernel against
 * the actual file the running process has mapped (file = task's
 * exe_file).  This is the kernel-resolved uprobe path: the host CLI
 * sends just (basename, symbol_name) in the BFR7 trailer; the driver
 * looks up the matching task by comm, grabs its exe_file, walks
 * .symtab → .strtab to find the symbol's `st_value`, and registers
 * the uprobe on that (inode, offset) pair.  No host-side rootfs
 * mirror needed.
 *
 * Constraints (matching the host parser):
 *   - ELF64 little-endian only (arm64 / x86_64).
 *   - ET_DYN binaries (PIE executables / shared objects).  ET_EXEC
 *     would need PT_LOAD-vaddr translation; deferred until a real
 *     non-PIE target shows up.
 *   - Falls back to .dynsym/.dynstr when .symtab is stripped.
 *
 * Returns 0 on success, negative errno otherwise.
 */
int bifrost_helper_resolve_symbol(struct file *file,
				  const char *symbol_name,
				  unsigned int symbol_name_len,
				  unsigned long long *out_file_offset,
				  unsigned long long *out_size)
{
	unsigned char ehdr[64];
	int rc;
	unsigned short e_type;
	unsigned long long e_shoff;
	unsigned short e_shentsize, e_shnum, e_shstrndx;
	void *shdrs = NULL;
	void *symtab = NULL;
	void *strtab = NULL;
	unsigned long long symtab_off = 0, symtab_size = 0;
	unsigned long long strtab_off = 0, strtab_size = 0;
	int ret = -ENOENT;
	unsigned int i;
	int found_dynsym_idx = -1;
	int found_symtab_idx = -1;
	int found_dynstr_idx = -1;
	int found_strtab_idx = -1;

	if (!file || !symbol_name || symbol_name_len == 0)
		return -EINVAL;

	/* ELF header: 64 bytes. */
	rc = bifrost_read_full(file, ehdr, sizeof(ehdr), 0);
	if (rc)
		return rc;
	if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
		return -ENOEXEC;
	if (ehdr[4] != 2 /* ELFCLASS64 */ || ehdr[5] != 1 /* ELFDATA2LSB */)
		return -ENOEXEC;

	/* e_type @ 16 (u16); e_shoff @ 40 (u64); e_shentsize @ 58 (u16);
	 * e_shnum @ 60 (u16); e_shstrndx @ 62 (u16).
	 */
	memcpy(&e_type, ehdr + 16, 2);
	memcpy(&e_shoff, ehdr + 40, 8);
	memcpy(&e_shentsize, ehdr + 58, 2);
	memcpy(&e_shnum, ehdr + 60, 2);
	memcpy(&e_shstrndx, ehdr + 62, 2);

	if (e_type != 3 /* ET_DYN */)
		return -ENOSYS;
	if (e_shentsize != 64 || e_shnum == 0 || e_shnum > 4096)
		return -EINVAL;

	/* Section headers — typically <16 KB but cap at 1 MB. */
	{
		size_t shdrs_bytes = (size_t)e_shentsize * e_shnum;
		if (shdrs_bytes > 1024 * 1024) {
			ret = -EINVAL;
			goto out;
		}
		shdrs = kmalloc(shdrs_bytes, GFP_KERNEL);
		if (!shdrs) {
			ret = -ENOMEM;
			goto out;
		}
		rc = bifrost_read_full(file, shdrs, shdrs_bytes,
				       (loff_t)e_shoff);
		if (rc) {
			ret = rc;
			goto out;
		}
	}

	/* Walk section headers, find SYMTAB and DYNSYM (and remember
	 * their linked STRTABs).  Section header layout (ELF64):
	 *   sh_name  : u32 @ 0
	 *   sh_type  : u32 @ 4
	 *   sh_flags : u64 @ 8
	 *   sh_addr  : u64 @ 16
	 *   sh_offset: u64 @ 24
	 *   sh_size  : u64 @ 32
	 *   sh_link  : u32 @ 40
	 */
	for (i = 0; i < e_shnum; i++) {
		const unsigned char *sh = (const unsigned char *)shdrs + i * 64;
		unsigned int sh_type, sh_link;
		memcpy(&sh_type, sh + 4, 4);
		memcpy(&sh_link, sh + 40, 4);
		if (sh_type == 2 /* SHT_SYMTAB */) {
			found_symtab_idx = i;
			found_strtab_idx = (int)sh_link;
		} else if (sh_type == 11 /* SHT_DYNSYM */ &&
			   found_dynsym_idx < 0) {
			found_dynsym_idx = i;
			found_dynstr_idx = (int)sh_link;
		}
	}

	/* Prefer .symtab; fall back to .dynsym for stripped binaries. */
	{
		int sidx = found_symtab_idx >= 0 ?
				found_symtab_idx : found_dynsym_idx;
		int stidx = found_symtab_idx >= 0 ?
				found_strtab_idx : found_dynstr_idx;
		const unsigned char *sh;
		if (sidx < 0 || stidx < 0 || (unsigned)stidx >= e_shnum) {
			ret = -ENOENT;
			goto out;
		}
		sh = (const unsigned char *)shdrs + sidx * 64;
		memcpy(&symtab_off, sh + 24, 8);
		memcpy(&symtab_size, sh + 32, 8);
		sh = (const unsigned char *)shdrs + stidx * 64;
		memcpy(&strtab_off, sh + 24, 8);
		memcpy(&strtab_size, sh + 32, 8);
	}

	if (symtab_size == 0 || strtab_size == 0)
		goto out;
	/* Symtab cap: 16 MB.  Strtab cap: 16 MB. */
	if (symtab_size > 16 * 1024 * 1024 ||
	    strtab_size > 16 * 1024 * 1024) {
		ret = -EINVAL;
		goto out;
	}

	symtab = vmalloc(symtab_size);
	strtab = vmalloc(strtab_size);
	if (!symtab || !strtab) {
		ret = -ENOMEM;
		goto out;
	}
	rc = bifrost_read_full(file, symtab, symtab_size,
			       (loff_t)symtab_off);
	if (rc) {
		ret = rc;
		goto out;
	}
	rc = bifrost_read_full(file, strtab, strtab_size,
			       (loff_t)strtab_off);
	if (rc) {
		ret = rc;
		goto out;
	}

	/* Iterate symbols (ELF64_Sym is 24 bytes):
	 *   st_name  : u32 @ 0
	 *   st_info  : u8  @ 4 (low nibble = type)
	 *   st_other : u8  @ 5
	 *   st_shndx : u16 @ 6
	 *   st_value : u64 @ 8
	 *   st_size  : u64 @ 16
	 */
	{
		size_t n = (size_t)symtab_size / 24;
		for (i = 0; i < n; i++) {
			const unsigned char *sym =
				(const unsigned char *)symtab + i * 24;
			unsigned int st_name;
			unsigned char st_info, st_type;
			unsigned long long st_value, st_size;
			const char *name;
			size_t name_max;

			memcpy(&st_name, sym + 0, 4);
			st_info = sym[4];
			st_type = st_info & 0x0f;
			memcpy(&st_value, sym + 8, 8);
			memcpy(&st_size, sym + 16, 8);

			/* STT_FUNC=2 or STT_GNU_IFUNC=10. */
			if (st_type != 2 && st_type != 10)
				continue;
			if (st_value == 0)
				continue;
			if ((unsigned long long)st_name >= strtab_size)
				continue;
			name = (const char *)strtab + st_name;
			name_max = strtab_size - st_name;
			if (strnlen(name, name_max) != symbol_name_len)
				continue;
			if (memcmp(name, symbol_name, symbol_name_len) != 0)
				continue;
			/* Match.  For ET_DYN, st_value IS the file offset. */
			*out_file_offset = st_value;
			if (out_size)
				*out_size = st_size;
			ret = 0;
			goto out;
		}
	}

	/* Symbol not found. */
	ret = -ENOENT;

out:
	kfree(shdrs);
	if (symtab)
		vfree(symtab);
	if (strtab)
		vfree(strtab);
	return ret;
}
EXPORT_SYMBOL_GPL(bifrost_helper_resolve_symbol);

/*
 * bifrost_helper_resolve_usdt — Resolve a USDT (.note.stapsdt) probe
 * by (provider, name) within `file` to its file-offset position and
 * the file-offset of its `.probes` semaphore.  Mirror of
 * bifrost_helper_resolve_symbol but for SystemTap-compatible USDT
 * probes (the `--enable-dtrace` build of postgres / systemtap-sdt
 * macros / libstapsdt).
 *
 * Each `.note.stapsdt` entry records:
 *   u64 pc        — link-time virtual address of the NOP instruction
 *   u64 base      — link-time vaddr of `.stapsdt.base` (prelink hint;
 *                   ignored — PIE binaries are not prelinked)
 *   u64 semaphore — link-time vaddr of an unsigned-short flag in
 *                   `.probes`; the probe body short-circuits when
 *                   the flag is 0 (no consumer attached).  The kernel
 *                   atomically increments this u16 on uprobe attach
 *                   when ref_ctr_offset is non-zero.
 *   nul-terminated provider, probe name, argument descriptor
 *
 * Both pc and semaphore are virtual addresses.  Translating each to
 * a file offset requires the PT_LOAD segment that covers the
 * address: file_offset = vaddr - p_vaddr + p_offset.  The text
 * PT_LOAD typically has p_vaddr == p_offset == 0 so pc translates
 * directly, but the data PT_LOAD differs by the alignment padding,
 * so the semaphore translation is genuinely non-trivial.
 *
 * Returns 0 on success, negative errno otherwise.  On success
 * *out_pc_file_offset and *out_semaphore_file_offset are populated
 * (the latter is 0 when the probe has no semaphore).
 */
int bifrost_helper_resolve_usdt(struct file *file,
				const char *provider_name,
				unsigned int provider_name_len,
				const char *probe_name,
				unsigned int probe_name_len,
				unsigned long long *out_pc_file_offset,
				unsigned long long *out_semaphore_file_offset)
{
	unsigned char ehdr[64];
	int rc;
	unsigned short e_type;
	unsigned long long e_phoff, e_shoff;
	unsigned short e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
	void *phdrs = NULL;
	void *shdrs = NULL;
	void *shstr = NULL;
	void *notes = NULL;
	unsigned long long shstr_off = 0, shstr_size = 0;
	unsigned long long notes_off = 0, notes_size = 0;
	int ret = -ENOENT;
	unsigned int i;
	int found_note_idx = -1;

	if (!file || !provider_name || !probe_name)
		return -EINVAL;
	if (provider_name_len == 0 || probe_name_len == 0)
		return -EINVAL;
	if (!out_pc_file_offset || !out_semaphore_file_offset)
		return -EINVAL;

	/* ELF header. */
	rc = bifrost_read_full(file, ehdr, sizeof(ehdr), 0);
	if (rc)
		return rc;
	if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F')
		return -ENOEXEC;
	if (ehdr[4] != 2 || ehdr[5] != 1)
		return -ENOEXEC;

	memcpy(&e_type, ehdr + 16, 2);
	memcpy(&e_phoff, ehdr + 32, 8);
	memcpy(&e_shoff, ehdr + 40, 8);
	memcpy(&e_phentsize, ehdr + 54, 2);
	memcpy(&e_phnum, ehdr + 56, 2);
	memcpy(&e_shentsize, ehdr + 58, 2);
	memcpy(&e_shnum, ehdr + 60, 2);
	memcpy(&e_shstrndx, ehdr + 62, 2);

	if (e_type != 3 /* ET_DYN */)
		return -ENOSYS;
	if (e_phentsize != 56 || e_shentsize != 64)
		return -EINVAL;
	if (e_shnum == 0 || e_shnum > 4096 || e_shstrndx >= e_shnum)
		return -EINVAL;

	/* Read program headers (for vaddr→file_offset translation). */
	if (e_phnum > 0 && e_phnum <= 64) {
		size_t phdrs_bytes = (size_t)e_phentsize * e_phnum;
		phdrs = kmalloc(phdrs_bytes, GFP_KERNEL);
		if (!phdrs) {
			ret = -ENOMEM;
			goto out;
		}
		rc = bifrost_read_full(file, phdrs, phdrs_bytes,
				       (loff_t)e_phoff);
		if (rc) {
			ret = rc;
			goto out;
		}
	}

	/* Read section headers. */
	{
		size_t shdrs_bytes = (size_t)e_shentsize * e_shnum;
		if (shdrs_bytes > 1024 * 1024) {
			ret = -EINVAL;
			goto out;
		}
		shdrs = kmalloc(shdrs_bytes, GFP_KERNEL);
		if (!shdrs) {
			ret = -ENOMEM;
			goto out;
		}
		rc = bifrost_read_full(file, shdrs, shdrs_bytes,
				       (loff_t)e_shoff);
		if (rc) {
			ret = rc;
			goto out;
		}
	}

	/* Read shstrtab so we can resolve section names. */
	{
		const unsigned char *sh =
			(const unsigned char *)shdrs + e_shstrndx * 64;
		memcpy(&shstr_off, sh + 24, 8);
		memcpy(&shstr_size, sh + 32, 8);
	}
	if (shstr_size == 0 || shstr_size > 1024 * 1024) {
		ret = -EINVAL;
		goto out;
	}
	shstr = vmalloc(shstr_size);
	if (!shstr) {
		ret = -ENOMEM;
		goto out;
	}
	rc = bifrost_read_full(file, shstr, shstr_size, (loff_t)shstr_off);
	if (rc) {
		ret = rc;
		goto out;
	}

	/* Find the `.note.stapsdt` section by name (SHT_NOTE = 7). */
	for (i = 0; i < e_shnum; i++) {
		const unsigned char *sh = (const unsigned char *)shdrs + i * 64;
		unsigned int sh_name, sh_type;
		const char *name;
		size_t name_max;
		memcpy(&sh_name, sh + 0, 4);
		memcpy(&sh_type, sh + 4, 4);
		if (sh_type != 7)
			continue;
		if ((unsigned long long)sh_name >= shstr_size)
			continue;
		name = (const char *)shstr + sh_name;
		name_max = (size_t)shstr_size - sh_name;
		if (strnlen(name, name_max) != strlen(".note.stapsdt"))
			continue;
		if (memcmp(name, ".note.stapsdt", strlen(".note.stapsdt")) != 0)
			continue;
		found_note_idx = (int)i;
		break;
	}
	if (found_note_idx < 0)
		goto out;

	{
		const unsigned char *sh =
			(const unsigned char *)shdrs + found_note_idx * 64;
		memcpy(&notes_off, sh + 24, 8);
		memcpy(&notes_size, sh + 32, 8);
	}
	if (notes_size == 0 || notes_size > 4 * 1024 * 1024) {
		ret = -EINVAL;
		goto out;
	}
	notes = vmalloc(notes_size);
	if (!notes) {
		ret = -ENOMEM;
		goto out;
	}
	rc = bifrost_read_full(file, notes, notes_size, (loff_t)notes_off);
	if (rc) {
		ret = rc;
		goto out;
	}

	/*
	 * Walk Elf_Note entries.  Each:
	 *   u32 n_namesz | u32 n_descsz | u32 n_type | name (padded to 4)
	 *   | desc (padded to 4)
	 * Provider must be "stapsdt\0" (n_namesz == 8) and n_type == 3
	 * (NT_STAPSDT).  desc layout: u64 pc | u64 base | u64 sema |
	 * provider\0 | name\0 | args\0.
	 */
	{
		size_t end = (size_t)notes_size;
		size_t p = 0;
		while (p + 12 <= end) {
			unsigned int namesz, descsz, ntype;
			size_t name_start, name_end, desc_start, desc_end, next;
			memcpy(&namesz, (const unsigned char *)notes + p + 0, 4);
			memcpy(&descsz, (const unsigned char *)notes + p + 4, 4);
			memcpy(&ntype,  (const unsigned char *)notes + p + 8, 4);
			name_start = p + 12;
			if (name_start > end ||
			    namesz > end - name_start)
				break;
			name_end = name_start + namesz;
			desc_start = name_end + ((4 - (namesz & 3)) & 3);
			if (desc_start > end || descsz > end - desc_start)
				break;
			desc_end = desc_start + descsz;
			next = desc_end + ((4 - (descsz & 3)) & 3);
			if (next > end)
				break;

			if (ntype == 3 && namesz >= 8 && descsz >= 24 &&
			    memcmp((const unsigned char *)notes + name_start,
				   "stapsdt", 7) == 0 &&
			    *((const unsigned char *)notes + name_start + 7) == 0) {
				const unsigned char *d =
					(const unsigned char *)notes + desc_start;
				unsigned long long pc, sema;
				const char *prov, *probe;
				size_t prov_max, probe_max, prov_actual, probe_actual;
				memcpy(&pc,   d + 0,  8);
				/* d + 8 is `base`; ignored (prelink only). */
				memcpy(&sema, d + 16, 8);
				prov = (const char *)(d + 24);
				prov_max = desc_end - (desc_start + 24);
				prov_actual = strnlen(prov, prov_max);
				if (prov_actual >= prov_max)
					goto skip_note;
				probe = prov + prov_actual + 1;
				probe_max = prov_max - (prov_actual + 1);
				probe_actual = strnlen(probe, probe_max);
				if (probe_actual >= probe_max)
					goto skip_note;
				if (prov_actual == provider_name_len &&
				    memcmp(prov, provider_name, provider_name_len) == 0 &&
				    probe_actual == probe_name_len &&
				    memcmp(probe, probe_name, probe_name_len) == 0) {
					/*
					 * Translate pc and sema vaddrs to
					 * file offsets via PT_LOAD.  pc is
					 * in the text segment (typically
					 * p_vaddr == p_offset == 0) but the
					 * data segment differs by alignment
					 * padding, so do the lookup.
					 */
					unsigned long long pc_off = pc;
					unsigned long long sema_off = 0;
					int xlated_pc = (pc == 0);
					int xlated_sema = (sema == 0);
					unsigned int j;
					for (j = 0; phdrs && j < e_phnum; j++) {
						const unsigned char *ph =
							(const unsigned char *)phdrs + j * 56;
						unsigned int p_type;
						unsigned long long p_offset;
						unsigned long long p_vaddr;
						unsigned long long p_memsz;
						memcpy(&p_type, ph + 0, 4);
						if (p_type != 1 /* PT_LOAD */)
							continue;
						memcpy(&p_offset, ph + 8, 8);
						memcpy(&p_vaddr, ph + 16, 8);
						memcpy(&p_memsz, ph + 40, 8);
						if (!xlated_pc &&
						    pc >= p_vaddr &&
						    pc < p_vaddr + p_memsz) {
							pc_off = pc - p_vaddr + p_offset;
							xlated_pc = 1;
						}
						if (!xlated_sema && sema != 0 &&
						    sema >= p_vaddr &&
						    sema < p_vaddr + p_memsz) {
							sema_off = sema - p_vaddr + p_offset;
							xlated_sema = 1;
						}
					}
					if (!xlated_pc) {
						ret = -EINVAL;
						goto out;
					}
					*out_pc_file_offset = pc_off;
					*out_semaphore_file_offset = sema_off;
					ret = 0;
					goto out;
				}
			}
		skip_note:
			p = next;
		}
	}

	ret = -ENOENT;

out:
	kfree(phdrs);
	kfree(shdrs);
	if (shstr)
		vfree(shstr);
	if (notes)
		vfree(notes);
	return ret;
}
EXPORT_SYMBOL_GPL(bifrost_helper_resolve_usdt);

/*
 * Pack the ELF function symbol table of `file` into `buf` for the
 * gustack symbolicator on the host.  Wire format mirrors the
 * `bifrost_emit_vma_table` shape — a small header with offsets into
 * a trailing strings region, then a flat array of fixed-size
 * entries:
 *
 *   struct bifrost_symtab_hdr {
 *       u32 path_off;       // offset of the binary path in strings[]
 *       u32 path_len;       // length (excluding terminating NUL)
 *       u32 n_syms;
 *       u32 strings_off;    // start of strings region within @buf
 *       u32 strings_len;    // bytes of valid strings data
 *       u32 reserved;
 *   };
 *   struct bifrost_symtab_entry {
 *       u64 st_value;       // file offset (ET_DYN convention)
 *       u64 st_size;
 *       u32 name_off;       // offset into strings[] (NOT @buf!)
 *       u32 reserved;
 *   };
 *
 * Function symbols only (STT_FUNC, STT_GNU_IFUNC).  Symbols with
 * st_value == 0 or empty name are skipped.  Truncates with -EOVERFLOW
 * if the output won't fit; the caller decides whether to drop or
 * split across multiple side-channel records.
 *
 * `path` is the d_path() output the caller already resolved off
 * `file->f_path`; we just copy it into the strings region so the
 * host can key its symbol cache by path string (matching the path
 * field already shipped in the per-task VMA table).
 *
 * Returns: total bytes written on success (≥ sizeof hdr), -errno
 * otherwise.  No host-side fallback to read the ELF off any
 * mirrored rootfs is needed once this lands — symbolication runs
 * entirely off what the guest kernel already has open.
 */
struct bifrost_symtab_hdr_kern {
	unsigned int path_off;
	unsigned int path_len;
	unsigned int n_syms;
	unsigned int strings_off;
	unsigned int strings_len;
	unsigned int reserved;
};
struct bifrost_symtab_entry_kern {
	unsigned long long st_value;
	unsigned long long st_size;
	unsigned int name_off;
	unsigned int reserved;
};
int bifrost_helper_emit_symtab(struct file *file,
			       const char *path,
			       unsigned int path_len,
			       char *buf,
			       unsigned int buf_size,
			       unsigned int sym_idx_start,
			       unsigned int *sym_idx_next)
{
	unsigned char ehdr[64];
	int rc;
	unsigned short e_type;
	unsigned long long e_shoff;
	unsigned short e_shentsize, e_shnum;
	void *shdrs = NULL;
	void *symtab = NULL;
	void *strtab = NULL;
	unsigned long long symtab_off = 0, symtab_size = 0;
	unsigned long long strtab_off = 0, strtab_size = 0;
	int ret = -ENOENT;
	unsigned int i;
	int found_dynsym_idx = -1;
	int found_symtab_idx = -1;
	int found_dynstr_idx = -1;
	int found_strtab_idx = -1;
	struct bifrost_symtab_hdr_kern *hdr;
	struct bifrost_symtab_entry_kern *entries;
	char *strings_base;
	unsigned int entries_off, strings_off, strings_pos;
	unsigned int strings_avail;
	/* Hard caps so a malformed or pathologically-large symtab can't
	 * overflow buf_size or our SHM record. */
	const unsigned int MAX_SYMS = 4000;
	unsigned int n = 0;

	if (!file || !buf || !path || path_len == 0)
		return -EINVAL;
	if (buf_size < sizeof(*hdr) + sizeof(*entries) + path_len + 1)
		return -EINVAL;

	rc = bifrost_read_full(file, ehdr, sizeof(ehdr), 0);
	if (rc)
		return rc;
	if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' ||
	    ehdr[3] != 'F')
		return -ENOEXEC;
	if (ehdr[4] != 2 /* ELFCLASS64 */ ||
	    ehdr[5] != 1 /* ELFDATA2LSB */)
		return -ENOEXEC;
	memcpy(&e_type, ehdr + 16, 2);
	memcpy(&e_shoff, ehdr + 40, 8);
	memcpy(&e_shentsize, ehdr + 58, 2);
	memcpy(&e_shnum, ehdr + 60, 2);
	if (e_type != 3 /* ET_DYN */)
		return -ENOSYS;
	if (e_shentsize != 64 || e_shnum == 0 || e_shnum > 4096)
		return -EINVAL;

	{
		size_t shdrs_bytes = (size_t)e_shentsize * e_shnum;
		if (shdrs_bytes > 1024 * 1024) {
			ret = -EINVAL;
			goto out;
		}
		shdrs = kmalloc(shdrs_bytes, GFP_KERNEL);
		if (!shdrs) {
			ret = -ENOMEM;
			goto out;
		}
		rc = bifrost_read_full(file, shdrs, shdrs_bytes,
				       (loff_t)e_shoff);
		if (rc) {
			ret = rc;
			goto out;
		}
	}

	for (i = 0; i < e_shnum; i++) {
		const unsigned char *sh = (const unsigned char *)shdrs + i * 64;
		unsigned int sh_type, sh_link;
		memcpy(&sh_type, sh + 4, 4);
		memcpy(&sh_link, sh + 40, 4);
		if (sh_type == 2 /* SHT_SYMTAB */) {
			found_symtab_idx = i;
			found_strtab_idx = (int)sh_link;
		} else if (sh_type == 11 /* SHT_DYNSYM */ &&
			   found_dynsym_idx < 0) {
			found_dynsym_idx = i;
			found_dynstr_idx = (int)sh_link;
		}
	}

	{
		int sidx = found_symtab_idx >= 0 ?
				found_symtab_idx : found_dynsym_idx;
		int stidx = found_symtab_idx >= 0 ?
				found_strtab_idx : found_dynstr_idx;
		const unsigned char *sh;
		if (sidx < 0 || stidx < 0 || (unsigned)stidx >= e_shnum) {
			ret = -ENOENT;
			goto out;
		}
		sh = (const unsigned char *)shdrs + sidx * 64;
		memcpy(&symtab_off, sh + 24, 8);
		memcpy(&symtab_size, sh + 32, 8);
		sh = (const unsigned char *)shdrs + stidx * 64;
		memcpy(&strtab_off, sh + 24, 8);
		memcpy(&strtab_size, sh + 32, 8);
	}

	if (symtab_size == 0 || strtab_size == 0)
		goto out;
	if (symtab_size > 16 * 1024 * 1024 ||
	    strtab_size > 16 * 1024 * 1024) {
		ret = -EINVAL;
		goto out;
	}

	symtab = vmalloc(symtab_size);
	strtab = vmalloc(strtab_size);
	if (!symtab || !strtab) {
		ret = -ENOMEM;
		goto out;
	}
	rc = bifrost_read_full(file, symtab, symtab_size,
			       (loff_t)symtab_off);
	if (rc) {
		ret = rc;
		goto out;
	}
	rc = bifrost_read_full(file, strtab, strtab_size,
			       (loff_t)strtab_off);
	if (rc) {
		ret = rc;
		goto out;
	}

	/* Lay out the output buffer.  entries[] follows the header;
	 * strings[] follows entries[].  We don't know n_syms in
	 * advance, so reserve worst-case entries space (or whatever
	 * fits) and grow strings into the tail. */
	hdr = (struct bifrost_symtab_hdr_kern *)buf;
	entries_off = sizeof(*hdr);
	/* Reserve at least STRINGS_RESERVE bytes for the strings
	 * region (path + symbol names) — without this, MAX_SYMS=4000
	 * entries × 24 bytes consumes the whole 64 KB record body
	 * and the path-write fails immediately with -EOVERFLOW.
	 * Empirically: libc has ~3000 STT_FUNC symbols averaging
	 * 14-byte names, so ~50 KB of strings; we cap entries below
	 * to leave space.  Names that don't fit get truncated by the
	 * `strings_pos + name_len + 1 > strings_avail` check inside
	 * the symbol-walk loop. */
	{
		const unsigned int STRINGS_RESERVE = 32 * 1024;
		unsigned int budget;
		unsigned int max_entries_by_buf;
		unsigned int max_entries;

		if (buf_size <= entries_off + STRINGS_RESERVE) {
			ret = -EINVAL;
			goto out;
		}
		budget = buf_size - entries_off - STRINGS_RESERVE;
		max_entries_by_buf = budget / sizeof(*entries);
		max_entries = max_entries_by_buf < MAX_SYMS
			? max_entries_by_buf : MAX_SYMS;
		strings_off = entries_off + max_entries * sizeof(*entries);
		if (strings_off > buf_size) {
			ret = -EINVAL;
			goto out;
		}
		strings_avail = buf_size - strings_off;
	}
	entries = (struct bifrost_symtab_entry_kern *)(buf + entries_off);
	strings_base = buf + strings_off;
	strings_pos = 0;

	memset(hdr, 0, sizeof(*hdr));
	hdr->strings_off = strings_off;

	/* The binary path goes first in strings[] so its offset is
	 * stable (zero) regardless of how many symbols we end up
	 * packing.  Append a trailing NUL for C-string safety on
	 * the host side. */
	if (path_len + 1 > strings_avail) {
		ret = -EOVERFLOW;
		goto out;
	}
	memcpy(strings_base, path, path_len);
	strings_base[path_len] = '\0';
	hdr->path_off = 0;
	hdr->path_len = path_len;
	strings_pos = path_len + 1;

	{
		/* Cap n at the number of entry slots actually available
		 * given the strings reservation we computed above
		 * (`strings_off - entries_off` is exactly that). */
		unsigned int max_entries =
			(strings_off - entries_off) / sizeof(*entries);
		size_t nsym = (size_t)symtab_size / 24;
		/* Resume from the caller-provided index — multi-record
		 * splits feed `sym_idx_next` from the previous record's
		 * out param back in here.  On overflow (n >= max_entries
		 * or strings_pos + name_len + 1 > strings_avail), set
		 * `*sym_idx_next = i` so the next call resumes at the
		 * symbol we couldn't pack.  When the full symtab fits,
		 * we fall out of the loop with i == nsym and set
		 * `*sym_idx_next = 0` to signal "done".
		 *
		 * Bounds: sym_idx_start may be ≥ nsym if the caller
		 * loops past the end (defensive); treat that as "done"
		 * with zero entries written. */
		i = sym_idx_start;
		if (i >= nsym) {
			if (sym_idx_next)
				*sym_idx_next = 0;
		} else for (; i < nsym; i++) {
			const unsigned char *sym =
				(const unsigned char *)symtab + i * 24;
			unsigned int st_name;
			unsigned char st_info, st_type;
			unsigned long long st_value, st_size;
			const char *name;
			size_t name_len, name_max;

			if (n >= max_entries) {
				if (sym_idx_next)
					*sym_idx_next = i;
				break;
			}

			memcpy(&st_name, sym + 0, 4);
			st_info = sym[4];
			st_type = st_info & 0x0f;
			memcpy(&st_value, sym + 8, 8);
			memcpy(&st_size, sym + 16, 8);

			if (st_type != 2 /* STT_FUNC */ &&
			    st_type != 10 /* STT_GNU_IFUNC */)
				continue;
			if (st_value == 0)
				continue;
			if ((unsigned long long)st_name >= strtab_size)
				continue;
			name = (const char *)strtab + st_name;
			name_max = strtab_size - st_name;
			name_len = strnlen(name, name_max);
			if (name_len == 0)
				continue;

			if (strings_pos + name_len + 1 > strings_avail) {
				if (sym_idx_next)
					*sym_idx_next = i;
				break;
			}

			entries[n].st_value = st_value;
			entries[n].st_size = st_size;
			entries[n].name_off = strings_pos;
			entries[n].reserved = 0;
			memcpy(strings_base + strings_pos, name, name_len);
			strings_base[strings_pos + name_len] = '\0';
			strings_pos += name_len + 1;
			n++;
		}
		/* Loop exited cleanly (i == nsym) — no break taken,
		 * `*sym_idx_next` not yet set; signal "done". */
		if (i >= nsym && sym_idx_next)
			*sym_idx_next = 0;
	}

	hdr->n_syms = n;
	hdr->strings_len = strings_pos;
	ret = (int)(strings_off + strings_pos);

out:
	kfree(shdrs);
	if (symtab)
		vfree(symtab);
	if (strtab)
		vfree(strtab);
	return ret;
}
EXPORT_SYMBOL_GPL(bifrost_helper_emit_symtab);

/*
 * Convenience wrapper: resolve the binary path via d_path on
 * `file->f_path` and emit the symtab record body in one call.
 * Layout of the returned buffer matches `bifrost_helper_emit_symtab`
 * (the path is the first entry in strings[]).
 *
 * d_path may return early if the path doesn't fit in the buffer
 * we hand it; we use a small kmalloc'd scratch (PATH_MAX-ish) so
 * the strings region in @buf doesn't have to absorb the worst-
 * case path.  Returns total bytes written (>= sizeof header) on
 * success, negative errno otherwise.
 */
int bifrost_helper_emit_symtab_for_file(struct file *file,
					char *buf,
					unsigned int buf_size,
					unsigned int sym_idx_start,
					unsigned int *sym_idx_next)
{
	char *scratch = NULL;
	const char *resolved;
	unsigned int path_len;
	int ret;

	if (!file || !buf)
		return -EINVAL;

	scratch = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	resolved = d_path(&file->f_path, scratch, PATH_MAX);
	if (IS_ERR(resolved)) {
		ret = (int)PTR_ERR(resolved);
		goto out;
	}
	path_len = (unsigned int)strlen(resolved);
	if (path_len == 0) {
		ret = -ENOENT;
		goto out;
	}
	ret = bifrost_helper_emit_symtab(file, resolved, path_len,
					 buf, buf_size,
					 sym_idx_start, sym_idx_next);
out:
	kfree(scratch);
	return ret;
}
EXPORT_SYMBOL_GPL(bifrost_helper_emit_symtab_for_file);

/*
 * Walk `task->mm`'s file-backed VMAs and invoke `cb(file, ctx)` for
 * each unique executable VMA file.  Caller-provided ctx threads
 * through whatever state the callback needs (in practice the Rust
 * driver's push_symtab_snapshot, which doesn't need extra state and
 * passes ctx == NULL).
 *
 * Dedup is by `struct file *` pointer — if the same binary maps
 * multiple executable VMAs (text + data + ...), only the first one
 * fires the callback.  Bounded at BIFROST_VMA_FILE_MAX so a runaway
 * mm doesn't churn the SHM ring.
 *
 * Skips VMAs:
 *   - without vm_file (anonymous, [stack], [heap])
 *   - without VM_EXEC (data sections — caller wants symtabs for
 *     things it'd actually walk in a backtrace)
 *   - already seen via the dedup table
 *
 * Locking: takes mmap_read_lock (NOT trylock — caller is expected
 * to be in a sleepable context, e.g. the bifrost worker thread or
 * the uprobe register path, not BPF/kprobe).
 */
#define BIFROST_VMA_FILE_MAX 32
typedef void (*bifrost_vma_file_cb_t)(struct file *file, void *ctx);

void bifrost_helper_for_each_vma_file(struct task_struct *task,
				      bifrost_vma_file_cb_t cb,
				      void *ctx)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	if (!task || !cb)
		return;
	if (task->flags & 0x00200000 /* PF_KTHREAD */)
		return;

	mm = get_task_mm(task);
	if (!mm)
		return;

	mmap_read_lock(mm);
	{
		/* `seen` / `n_seen` / `i` are kept in this inner scope
		 * deliberately — declared at function top, gcc 16
		 * + the kernel's -Werror=unused-variable spuriously
		 * fires (the for_each_vma macro expansion creates an
		 * intermediate scope the analysis can't see through).
		 * Keeping the dedup state co-located with the loop
		 * also reads better. */
		struct file *seen[BIFROST_VMA_FILE_MAX];
		unsigned int n_seen = 0;
		VMA_ITERATOR(vmi, mm, 0);
		for_each_vma(vmi, vma) {
			struct file *f;
			bool dup = false;
			unsigned int i;

			if (n_seen >= BIFROST_VMA_FILE_MAX)
				break;
			if (!(vma->vm_flags & VM_EXEC))
				continue;
			f = vma->vm_file;
			if (!f)
				continue;
			for (i = 0; i < n_seen; i++) {
				if (seen[i] == f) {
					dup = true;
					break;
				}
			}
			if (dup)
				continue;
			seen[n_seen++] = f;
			/* The cb is invoked while we still hold
			 * mmap_read_lock; the file pointer is therefore
			 * pinned for the duration of the call (the VMA
			 * holds an implicit ref on vm_file).  The Rust
			 * callback reads from the file via kernel_read
			 * (sleepable) which is fine under
			 * mmap_read_lock — we're not in atomic context. */
			cb(f, ctx);
		}
	}
	mmap_read_unlock(mm);
	mmput(mm);
}
EXPORT_SYMBOL_GPL(bifrost_helper_for_each_vma_file);

/*
 * Phase K — kfunc manifest.  Names and canonical C signatures of
 * every bifrost_helper_* exported from this file, in the same order
 * that the Rust extern decls appear in drivers/bifrost/bifrost.rs.
 *
 * Why: the Rust ↔ C boundary is an implicit ABI today.  A silent
 * signature change on this side (e.g. adding a parameter, changing
 * a return type from int to long) would compile cleanly on the C
 * side and the Rust extern decl would silently disagree, producing
 * UB at runtime.  The manifest makes the contract explicit:
 *
 *   1. This file lists every kfunc + its canonical signature string.
 *   2. drivers/bifrost/bifrost.rs lists the same names + the same
 *      signature strings (as bytes) in the BIFROST_KFUNC_EXPECTED
 *      array.
 *   3. bifrost_kfunc_manifest_hash() returns a djb2 hash of the
 *      concatenated (name, sig) pairs.  At module init the Rust
 *      side computes the same hash from BIFROST_KFUNC_EXPECTED;
 *      a mismatch refuses module load with a named pr_err.
 *   4. scripts/check-kfunc-manifest.sh diffs the two manifests at
 *      build time so the runtime check never fires in a clean tree.
 *
 * Adding a new kfunc: append to BIFROST_KFUNC_MANIFEST here AND to
 * BIFROST_KFUNC_EXPECTED in bifrost.rs.  Order matters — both
 * sides hash in array order.
 *
 * Changing a signature: update the sig string in both places.  The
 * djb2 will change; module init will refuse to load until both
 * sides agree.
 */
struct bifrost_kfunc_decl {
	const char *name;
	const char *sig;
};

static const struct bifrost_kfunc_decl BIFROST_KFUNC_MANIFEST[] = {
	{
		"bifrost_helper_find_task_by_comm",
		"struct task_struct *(const unsigned char *, unsigned int)",
	},
	{
		"bifrost_helper_resolve_symbol",
		"int (struct file *, const u8 *, u32, u64 *, u64 *)",
	},
	{
		"bifrost_helper_resolve_usdt",
		"int (struct file *, const u8 *, u32, const u8 *, u32, u64 *, u64 *)",
	},
	{
		"bifrost_helper_emit_symtab",
		"int (struct file *, u8 *, u32, u32, u32 *)",
	},
	{
		"bifrost_helper_emit_symtab_for_file",
		"int (struct file *, u8 *, u32, u32, u32 *)",
	},
	{
		"bifrost_helper_for_each_vma_file",
		"void (struct task_struct *, void (*)(struct file *, void *), void *)",
	},
};

#define BIFROST_KFUNC_MANIFEST_LEN \
	(sizeof(BIFROST_KFUNC_MANIFEST) / sizeof(BIFROST_KFUNC_MANIFEST[0]))

/*
 * djb2 (Bernstein) string hash — same algorithm both sides agree on.
 * h = 5381; for each byte b: h = (h * 33) + b.  Wraps mod 2^32.  Not
 * cryptographic; it's a fingerprint, not a defense against forgery.
 * Stable across compilers (no UB on overflow under -fwrapv / Rust's
 * `wrapping_*`).
 */
static u32 bifrost_djb2(const char *s)
{
	u32 h = 5381;
	unsigned char c;

	while ((c = (unsigned char)*s++) != 0)
		h = (h * 33u) + c;
	return h;
}

/*
 * Hash the entire manifest.  Format mixed in is "<name>\0<sig>\0" per
 * entry — two NULs as field separators so a benign rename doesn't
 * collide with a benign signature change.  Rust side hashes the
 * same way.
 */
u32 bifrost_kfunc_manifest_hash(void)
{
	u32 h = 5381;
	size_t i;

	for (i = 0; i < BIFROST_KFUNC_MANIFEST_LEN; i++) {
		const char *p;

		for (p = BIFROST_KFUNC_MANIFEST[i].name; *p; p++)
			h = (h * 33u) + (unsigned char)*p;
		h = (h * 33u); /* trailing NUL */
		for (p = BIFROST_KFUNC_MANIFEST[i].sig; *p; p++)
			h = (h * 33u) + (unsigned char)*p;
		h = (h * 33u); /* trailing NUL */
	}
	return h;
}
EXPORT_SYMBOL_GPL(bifrost_kfunc_manifest_hash);

/*
 * Number of entries in the manifest, exposed so the Rust side can
 * confirm it knows about the same number of kfuncs.  A length
 * mismatch surfaces independently of the hash so the diagnostic
 * names the specific failure mode.
 */
u32 bifrost_kfunc_manifest_len(void)
{
	return (u32)BIFROST_KFUNC_MANIFEST_LEN;
}
EXPORT_SYMBOL_GPL(bifrost_kfunc_manifest_len);
