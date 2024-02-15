// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRU (Field-Replaceable Unit) Memory Poison Manager
 *
 * Copyright (c) 2024, Advanced Micro Devices, Inc.
 * All Rights Reserved.
 *
 * Authors:
 *	Naveen Krishna Chatradhi <naveenkrishna.chatradhi@amd.com>
 *	Muralidhara M K <muralidhara.mk@amd.com>
 *	Yazen Ghannam <Yazen.Ghannam@amd.com>
 *
 * Implementation notes, assumptions, and limitations:
 *
 * - FRU memory poison section and memory poison descriptor definitions are not yet
 *   included in the UEFI specification. So they are defined here. Afterwards, they
 *   may be moved to linux/cper.h, if appropriate.
 *
 * - Platforms based on AMD MI300 systems will be the first to use these structures.
 *   There are a number of assumptions made here that will need to be generalized
 *   to support other platforms.
 *
 *   AMD MI300-based platform(s) assumptions:
 *   - Memory errors are reported through x86 MCA.
 *   - The entire DRAM row containing a memory error should be retired.
 *   - There will be (1) FRU memory poison section per CPER.
 *   - The FRU will be the CPU package (processor socket).
 *   - The default number of memory poison descriptor entries should be (8).
 *   - The platform will use ACPI ERST for persistent storage.
 *   - All FRU records should be saved to persistent storage. Module init will
 *     fail if any FRU record is not successfully written.
 *
 * - Boot time memory retirement may occur later than ideal due to dependencies
 *   on other libraries and drivers. This leaves a gap where bad memory may be
 *   accessed during early boot stages.
 *
 * - Enough memory should be pre-allocated for each FRU record to be able to hold
 *   the expected number of descriptor entries. This, mostly empty, record is
 *   written to storage during init time. Subsequent writes to the same record
 *   should allow the Platform to update the stored record in-place. Otherwise,
 *   if the record is extended, then the Platform may need to perform costly memory
 *   management operations on the storage. For example, the Platform may spend time
 *   in Firmware copying and invalidating memory on a relatively slow SPI ROM.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cper.h>
#include <linux/ras.h>
#include <linux/cpu.h>

#include <acpi/apei.h>

#include <asm/cpu_device_id.h>
#include <asm/mce.h>

/* Validation Bits */
#define FMP_VALID_ARCH_TYPE		BIT_ULL(0)
#define FMP_VALID_ARCH			BIT_ULL(1)
#define FMP_VALID_ID_TYPE		BIT_ULL(2)
#define FMP_VALID_ID			BIT_ULL(3)
#define FMP_VALID_LIST_ENTRIES		BIT_ULL(4)
#define FMP_VALID_LIST			BIT_ULL(5)

/* FRU Architecture Types */
#define FMP_ARCH_TYPE_X86_CPUID_1_EAX	0

/* FRU ID Types */
#define FMP_ID_TYPE_X86_PPIN		0

/* FRU Memory Poison Section */
struct cper_sec_fru_mem_poison {
	u32 checksum;
	u64 validation_bits;
	u32 fru_arch_type;
	u64 fru_arch;
	u32 fru_id_type;
	u64 fru_id;
	u32 nr_entries;
} __packed;

/* FRU Descriptor ID Types */
#define FPD_HW_ID_TYPE_MCA_IPID		0

/* FRU Descriptor Address Types */
#define FPD_ADDR_TYPE_MCA_ADDR		0

/* Memory Poison Descriptor */
struct cper_fru_poison_desc {
	u64 timestamp;
	u32 hw_id_type;
	u64 hw_id;
	u32 addr_type;
	u64 addr;
} __packed;

/* Collection of headers and sections for easy pointer use. */
struct fru_rec {
	struct cper_record_header	hdr;
	struct cper_section_descriptor	sec_desc;
	struct cper_sec_fru_mem_poison	fmp;
	struct cper_fru_poison_desc	entries[];
} __packed;

/*
 * Pointers to the complete CPER record of each FRU.
 *
 * Memory allocation will include padded space for descriptor entries.
 */
static struct fru_rec **fru_records;

#define CPER_CREATOR_FMP						\
	GUID_INIT(0xcd5c2993, 0xf4b2, 0x41b2, 0xb5, 0xd4, 0xf9, 0xc3,	\
		  0xa0, 0x33, 0x08, 0x75)

#define CPER_SECTION_TYPE_FMP						\
	GUID_INIT(0x5e4706c1, 0x5356, 0x48c6, 0x93, 0x0b, 0x52, 0xf2,	\
		  0x12, 0x0a, 0x44, 0x58)

/**
 * DOC: fru_poison_entries (byte)
 * Maximum number of descriptor entries possible for each FRU.
 *
 * Values between '1' and '255' are valid.
 * No input or '0' will default to FMPM_DEFAULT_MAX_NR_ENTRIES.
 */
static u8 max_nr_entries;
module_param(max_nr_entries, byte, 0644);
MODULE_PARM_DESC(max_nr_entries,
		 "Maximum number of memory poison descriptor entries per FRU");

#define FMPM_DEFAULT_MAX_NR_ENTRIES	8

/* Maximum number of FRUs in the system. */
static unsigned int max_nr_fru;

/* Total length of record including headers and list of descriptor entries. */
static size_t max_rec_len;

/*
 * Protect the local records cache in fru_records and prevent concurrent
 * writes to storage. This is only needed after init once notifier block
 * registration is done.
 */
static DEFINE_MUTEX(fmpm_update_mutex);

#define for_each_fru(i, rec) \
	for (i = 0; rec = fru_records[i], i < max_nr_fru; i++)

static inline u32 get_fmp_len(struct fru_rec *rec)
{
	return rec->sec_desc.section_length - sizeof(struct cper_section_descriptor);
}

static struct fru_rec *get_fru_record(u64 fru_id)
{
	struct fru_rec *rec;
	unsigned int i;

	for_each_fru(i, rec) {
		if (rec->fmp.fru_id == fru_id)
			return rec;
	}

	pr_debug("Record not found for FRU 0x%016llx", fru_id);
	return NULL;
}

/*
 * Sum up all bytes within the FRU Memory Poison Section including the Memory
 * Poison Descriptor entries.
 */
static u32 do_fmp_checksum(struct cper_sec_fru_mem_poison *fmp, u32 len)
{
	u32 checksum = 0;
	u8 *buf, *end;

	buf = (u8 *)fmp;
	end = buf + len;

	while (buf < end)
		checksum += (u8)(*(buf++));

	return checksum;
}

static int update_record_on_storage(struct fru_rec *rec)
{
	u32 len, checksum;
	int ret;

	/* Calculate a new checksum. */
	len = get_fmp_len(rec);

	/* Get the current total. */
	checksum = do_fmp_checksum(&rec->fmp, len);

	/* Subtract the current checksum from total. */
	checksum -= rec->fmp.checksum;

	/* Use the complement value. */
	rec->fmp.checksum = -checksum;

	pr_debug("Writing to storage");

	ret = erst_write(&rec->hdr);
	if (ret)
		pr_warn("Storage update failed for FRU 0x%016llx", rec->fmp.fru_id);

	return ret;
}

static bool rec_has_valid_entries(struct fru_rec *rec)
{
	if (!(rec->fmp.validation_bits & FMP_VALID_LIST_ENTRIES))
		return false;

	if (!(rec->fmp.validation_bits & FMP_VALID_LIST))
		return false;

	return true;
}

static bool fpds_equal(struct cper_fru_poison_desc *old, struct cper_fru_poison_desc *new)
{
	/*
	 * Ignore timestamp field.
	 * The same physical error may be reported multiple times due to stuck bits, etc.
	 *
	 * Also, order the checks from most->least likely to fail to shortcut the code.
	 */
	if (old->addr != new->addr)
		return false;

	if (old->hw_id != new->hw_id)
		return false;

	if (old->addr_type != new->addr_type)
		return false;

	if (old->hw_id_type != new->hw_id_type)
		return false;

	return true;
}

static bool rec_has_fpd(struct fru_rec *rec, struct cper_fru_poison_desc *fpd)
{
	unsigned int i;

	for (i = 0; i < rec->fmp.nr_entries; i++) {
		struct cper_fru_poison_desc *fpd_i = &rec->entries[i];

		if (fpds_equal(fpd_i, fpd)) {
			pr_debug("Found duplicate record");
			return true;
		}
	}

	return false;
}

static void update_fru_record(struct fru_rec *rec, struct mce *m)
{
	struct cper_sec_fru_mem_poison *fmp = &rec->fmp;
	struct cper_fru_poison_desc fpd, *fpd_dest;
	u32 entry = 0;

	mutex_lock(&fmpm_update_mutex);

	memset(&fpd, 0, sizeof(struct cper_fru_poison_desc));

	fpd.timestamp	= m->time;
	fpd.hw_id_type = FPD_HW_ID_TYPE_MCA_IPID;
	fpd.hw_id	= m->ipid;
	fpd.addr_type	= FPD_ADDR_TYPE_MCA_ADDR;
	fpd.addr	= m->addr;

	/* This is the first entry, so just save it. */
	if (!rec_has_valid_entries(rec))
		goto save_fpd;

	/* Ignore already recorded errors. */
	if (rec_has_fpd(rec, &fpd))
		goto out_unlock;

	if (rec->fmp.nr_entries >= max_nr_entries) {
		pr_warn("Exceeded number of entries for FRU 0x%016llx", rec->fmp.fru_id);
		goto out_unlock;
	}

	entry  = fmp->nr_entries;

save_fpd:
	fpd_dest  = &rec->entries[entry];
	memcpy(fpd_dest, &fpd, sizeof(struct cper_fru_poison_desc));

	fmp->nr_entries		 = entry + 1;
	fmp->validation_bits	|= FMP_VALID_LIST_ENTRIES;
	fmp->validation_bits	|= FMP_VALID_LIST;

	pr_debug("Updated FRU 0x%016llx Entry #%u", fmp->fru_id, entry);

	update_record_on_storage(rec);

out_unlock:
	mutex_unlock(&fmpm_update_mutex);
}

static void retire_dram_row(u64 addr, u64 id, u32 cpu)
{
	struct atl_err a_err;

	memset(&a_err, 0, sizeof(struct atl_err));

	a_err.addr = addr;
	a_err.ipid = id;
	a_err.cpu  = cpu;

	amd_retire_dram_row(&a_err);
}

static int fru_mem_poison_handler(struct notifier_block *nb, unsigned long val, void *data)
{
	struct mce *m = (struct mce *)data;
	struct fru_rec *rec;

	if (!mce_is_memory_error(m))
		return NOTIFY_DONE;

	retire_dram_row(m->addr, m->ipid, m->extcpu);

	/*
	 * An invalid FRU ID should not happen on real errors. But it
	 * could happen from software error injection, etc.
	 */
	rec = get_fru_record(m->ppin);
	if (!rec)
		return NOTIFY_DONE;

	update_fru_record(rec, m);

	return NOTIFY_OK;
}

static struct notifier_block fru_mem_poison_nb = {
	.notifier_call  = fru_mem_poison_handler,
	.priority	= MCE_PRIO_LOWEST,
};

static void retire_mem_fmp(struct fru_rec *rec, u32 nr_entries)
{
	struct cper_sec_fru_mem_poison *fmp = &rec->fmp;
	unsigned int i, cpu;

	for (i = 0; i < nr_entries; i++) {
		struct cper_fru_poison_desc *fpd = &rec->entries[i];
		int err_cpu = -1;

		if (fpd->hw_id_type != FPD_HW_ID_TYPE_MCA_IPID)
			continue;

		if (fpd->addr_type != FPD_ADDR_TYPE_MCA_ADDR)
			continue;

		cpus_read_lock();
		for_each_online_cpu(cpu) {
			if (topology_ppin(cpu) == fmp->fru_id) {
				err_cpu = cpu;
				break;
			}
		}
		cpus_read_unlock();

		if (err_cpu < 0)
			continue;

		retire_dram_row(fpd->addr, fpd->hw_id, err_cpu);
	}
}

static void retire_mem_records(void)
{
	struct cper_sec_fru_mem_poison *fmp;
	struct fru_rec *rec;
	unsigned int i;

	for_each_fru(i, rec) {
		fmp = &rec->fmp;

		if (!rec_has_valid_entries(rec))
			continue;

		retire_mem_fmp(rec, fmp->nr_entries);
	}
}

/* Set the CPER Record Header and CPER Section Descriptor fields. */
static void set_rec_fields(struct fru_rec *rec)
{
	struct cper_section_descriptor	*sec_desc = &rec->sec_desc;
	struct cper_record_header	*hdr	  = &rec->hdr;

	memcpy(hdr->signature, CPER_SIG_RECORD, CPER_SIG_SIZE);
	hdr->revision			= CPER_RECORD_REV;
	hdr->signature_end		= CPER_SIG_END;

	/*
	 * Currently, it is assumed that there is one FRU Memory Poison
	 * section per CPER. But this may change for other implementations.
	 */
	hdr->section_count		= 1;

	/* The logged errors are recoverable. Otherwise, they'd never make it here. */
	hdr->error_severity		= CPER_SEV_RECOVERABLE;

	hdr->validation_bits		= 0;
	hdr->record_length		= max_rec_len;
	hdr->creator_id			= CPER_CREATOR_FMP;
	hdr->notification_type		= CPER_NOTIFY_MCE;
	hdr->record_id			= cper_next_record_id();
	hdr->flags			= CPER_HW_ERROR_FLAGS_PREVERR;

	sec_desc->section_offset	= sizeof(struct cper_record_header);
	sec_desc->section_length	= max_rec_len - sizeof(struct cper_record_header);
	sec_desc->revision		= CPER_SEC_REV;
	sec_desc->validation_bits	= 0;
	sec_desc->flags			= CPER_SEC_PRIMARY;
	sec_desc->section_type		= CPER_SECTION_TYPE_FMP;
	sec_desc->section_severity	= CPER_SEV_RECOVERABLE;
}

static int save_new_records(void)
{
	struct fru_rec *rec;
	unsigned int i;
	int ret = 0;

	for_each_fru(i, rec) {
		if (rec->hdr.record_length)
			continue;

		set_rec_fields(rec);

		ret = update_record_on_storage(rec);
		if (ret)
			break;
	}

	return ret;
}

static bool fmp_is_valid(struct fru_rec *rec)
{
	struct cper_sec_fru_mem_poison *fmp = &rec->fmp;
	u32 len = get_fmp_len(rec);

	if (!fmp)
		return false;

	if (!len)
		return false;

	/* Checksum must sum to zero for the entire section. */
	if (do_fmp_checksum(fmp, len))
		return false;

	if (!(fmp->validation_bits & FMP_VALID_ARCH_TYPE))
		return false;

	if (fmp->fru_arch_type != FMP_ARCH_TYPE_X86_CPUID_1_EAX)
		return false;

	if (!(fmp->validation_bits & FMP_VALID_ARCH))
		return false;

	if (fmp->fru_arch != cpuid_eax(1))
		return false;

	if (!(fmp->validation_bits & FMP_VALID_ID_TYPE))
		return false;

	if (fmp->fru_id_type != FMP_ID_TYPE_X86_PPIN)
		return false;

	if (!(fmp->validation_bits & FMP_VALID_ID))
		return false;

	return true;
}

static bool valid_record(struct fru_rec *old)
{
	struct fru_rec *new;
	size_t len;

	if (!fmp_is_valid(old)) {
		pr_debug("Ignoring invalid record");
		return false;
	}

	new = get_fru_record(old->fmp.fru_id);
	if (!new) {
		pr_debug("Ignoring record for absent FRU");
		return false;
	}

	/* Records larger than max_rec_len were skipped earlier. */
	len = min(max_rec_len, old->hdr.record_length);

	/* Restore the record */
	memcpy(new, old, len);

	return true;
}

/*
 * Fetch saved records from persistent storage.
 *
 * For each found record:
 * - If it was not created by this module, then ignore it.
 * - If it is valid, then copy its data to the local cache.
 * - If it is not valid, then erase it.
 */
static int get_saved_records(void)
{
	struct fru_rec *old;
	u64 record_id;
	int ret, pos;
	ssize_t len;

	/*
	 * Assume saved records match current max size.
	 *
	 * However, this may not be true depending on module parameters.
	 */
	old = kmalloc(max_rec_len, GFP_KERNEL);
	if (!old) {
		ret = -ENOMEM;
		goto out;
	}

	ret = erst_get_record_id_begin(&pos);
	if (ret < 0)
		goto out_end;

	while (!erst_get_record_id_next(&pos, &record_id)) {
		if (record_id == APEI_ERST_INVALID_RECORD_ID)
			goto out_end;
		/*
		 * Make sure to clear temporary buffer between reads to avoid
		 * leftover data from records of various sizes.
		 */
		memset(old, 0, max_rec_len);

		len = erst_read_record(record_id, &old->hdr, max_rec_len,
				       sizeof(struct fru_rec), &CPER_CREATOR_FMP);
		if (len < 0)
			continue;

		if (!valid_record(old))
			erst_clear(record_id);
	}

out_end:
	erst_get_record_id_end();
	kfree(old);
out:
	return ret;
}

static void set_fmp_fields(struct fru_rec *rec, unsigned int cpu)
{
	struct cper_sec_fru_mem_poison *fmp = &rec->fmp;

	fmp->fru_arch_type    = FMP_ARCH_TYPE_X86_CPUID_1_EAX;
	fmp->validation_bits |= FMP_VALID_ARCH_TYPE;

	/* Assume all CPUs in the system have the same value for now. */
	fmp->fru_arch	      = cpuid_eax(1);
	fmp->validation_bits |= FMP_VALID_ARCH;

	fmp->fru_id_type      = FMP_ID_TYPE_X86_PPIN;
	fmp->validation_bits |= FMP_VALID_ID_TYPE;

	fmp->fru_id	      = topology_ppin(cpu);
	fmp->validation_bits |= FMP_VALID_ID;
}

static int init_fmps(void)
{
	struct fru_rec *rec;
	unsigned int i, cpu;
	int ret = 0;

	cpus_read_lock();
	for_each_fru(i, rec) {
		int fru_cpu = -1;

		for_each_online_cpu(cpu) {
			if (topology_physical_package_id(cpu) == i) {
				fru_cpu = cpu;
				break;
			}
		}

		if (fru_cpu < 0) {
			pr_debug("Failed to find matching CPU for FRU #%u", i);
			ret = -ENODEV;
			goto out_unlock;
		}

		set_fmp_fields(rec, fru_cpu);
	}

out_unlock:
	cpus_read_unlock();
	return ret;
}

static int get_system_info(void)
{
	/* Only load on MI300A systems for now. */
	if (!(boot_cpu_data.x86_model >= 0x90 &&
	      boot_cpu_data.x86_model <= 0x9f))
		return -ENODEV;

	if (!cpu_feature_enabled(X86_FEATURE_AMD_PPIN)) {
		pr_debug("PPIN feature not available");
		return -ENODEV;
	}

	/* Use CPU Package (Socket) as FRU for MI300 systems. */
	max_nr_fru = topology_max_packages();
	if (!max_nr_fru)
		return -ENODEV;

	if (!max_nr_entries)
		max_nr_entries = FMPM_DEFAULT_MAX_NR_ENTRIES;

	max_rec_len  = sizeof(struct fru_rec);
	max_rec_len += sizeof(struct cper_fru_poison_desc) * max_nr_entries;

	pr_debug("max_nr_fru=%u max_nr_entries=%u, max_rec_len=%lu",
		 max_nr_fru, max_nr_entries, max_rec_len);
	return 0;
}

static void free_records(void)
{
	struct fru_rec *rec;
	int i;

	for_each_fru(i, rec)
		kfree(rec);

	kfree(fru_records);
}

static int allocate_records(void)
{
	int i, ret = 0;

	fru_records = kcalloc(max_nr_fru, sizeof(struct fru_rec *), GFP_KERNEL);
	if (!fru_records) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < max_nr_fru; i++) {
		fru_records[i] = kzalloc(max_rec_len, GFP_KERNEL);
		if (!fru_records[i]) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	return ret;

out_free:
	for (; i >= 0; i--)
		kfree(fru_records[i]);

	kfree(fru_records);
out:
	return ret;
}

static const struct x86_cpu_id fmpm_cpuids[] = {
	X86_MATCH_VENDOR_FAM(AMD, 0x19, NULL),
	{ }
};
MODULE_DEVICE_TABLE(x86cpu, fmpm_cpuids);

static int __init fru_mem_poison_init(void)
{
	int ret;

	if (!x86_match_cpu(fmpm_cpuids)) {
		ret = -ENODEV;
		goto out;
	}

	if (erst_disable) {
		pr_debug("ERST not available");
		ret = -ENODEV;
		goto out;
	}

	ret = get_system_info();
	if (ret)
		goto out;

	ret = allocate_records();
	if (ret)
		goto out;

	ret = init_fmps();
	if (ret)
		goto out_free;

	ret = get_saved_records();
	if (ret)
		goto out_free;

	ret = save_new_records();
	if (ret)
		goto out_free;

	retire_mem_records();

	mce_register_decode_chain(&fru_mem_poison_nb);

	pr_info("FRU Memory Poison Manager initialized");
	return 0;

out_free:
	free_records();
out:
	return ret;
}

static void __exit fru_mem_poison_exit(void)
{
	mce_unregister_decode_chain(&fru_mem_poison_nb);
	free_records();
}

module_init(fru_mem_poison_init);
module_exit(fru_mem_poison_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FRU Memory Poison Manager");
