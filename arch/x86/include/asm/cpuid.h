/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CPUID-related helpers/definitions
 */

#ifndef _ASM_X86_CPUID_H
#define _ASM_X86_CPUID_H

#include <asm/string.h>

struct cpuinfo_x86;

struct cpuid_regs {
	u32 eax, ebx, ecx, edx;
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX,
	CPUID_ECX,
	CPUID_EDX,
};

enum cpuid_leafs
{
	CPUID_1_EDX		= 0,
	CPUID_8000_0001_EDX,
	CPUID_8086_0001_EDX,
	CPUID_LNX_1,
	CPUID_1_ECX,
	CPUID_C000_0001_EDX,
	CPUID_8000_0001_ECX,
	CPUID_LNX_2,
	CPUID_LNX_3,
	CPUID_7_0_EBX,
	CPUID_D_1_EAX,
	CPUID_LNX_4,
	CPUID_7_1_EAX,
	CPUID_8000_0008_EBX,
	CPUID_6_EAX,
	CPUID_8000_000A_EDX,
	CPUID_7_ECX,
	CPUID_8000_0007_EBX,
	CPUID_7_EDX,
	CPUID_8000_001F_EAX,
};

/*
 * All CPUID functions
 */
struct func_1 {
	/* EDX */
	union {
		struct {
		u32	fpu	  : 1, vme	 : 1, de	  : 1, pse	: 1,
			tsc	  : 1, msr	 : 1, pae	  : 1, mce	: 1,

			cx8	  : 1, apic	 : 1, __rsv2	  : 1, sep	: 1,
			mtrr	  : 1, pge	 : 1, mca	  : 1, cmov	: 1,

			pat	  : 1, pse36	 : 1, psn	  : 1, clfsh	: 1,
			__rsv3	  : 1, ds	 : 1, acpi	  : 1, mmx	: 1,

			fxsr	  : 1, sse	 : 1, sse2	  : 1, ss	: 1,
			htt	  : 1, tm	 : 1, __rsv4	  : 1, pbe	: 1;
		};
		u32 edx;
	} __packed;
};

struct cpuid_info {
	struct func_1 f1;
};

extern struct cpuid_info cpuid_info;
u32 *get_boot_cpu_cap_word(u16 bit);
u32 *get_ap_cap_word(struct cpuinfo_x86 *c, u16 bit);

#ifdef CONFIG_X86_32
extern int have_cpuid_p(void);
#else
static inline int have_cpuid_p(void)
{
	return 1;
}
#endif
static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

#define native_cpuid_reg(reg)					\
static inline unsigned int native_cpuid_##reg(unsigned int op)	\
{								\
	unsigned int eax = op, ebx, ecx = 0, edx;		\
								\
	native_cpuid(&eax, &ebx, &ecx, &edx);			\
								\
	return reg;						\
}

/*
 * Native CPUID functions returning a single datum.
 */
native_cpuid_reg(eax)
native_cpuid_reg(ebx)
native_cpuid_reg(ecx)
native_cpuid_reg(edx)

#ifdef CONFIG_PARAVIRT_XXL
#include <asm/paravirt.h>
#else
#define __cpuid			native_cpuid
#endif

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	__cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return eax;
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ebx;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ecx;
}

static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return edx;
}

static __always_inline bool cpuid_function_is_indexed(u32 function)
{
	switch (function) {
	case 4:
	case 7:
	case 0xb:
	case 0xd:
	case 0xf:
	case 0x10:
	case 0x12:
	case 0x14:
	case 0x17:
	case 0x18:
	case 0x1d:
	case 0x1e:
	case 0x1f:
	case 0x8000001d:
		return true;
	}

	return false;
}

#define for_each_possible_hypervisor_cpuid_base(function) \
	for (function = 0x40000000; function < 0x40010000; function += 0x100)

static inline uint32_t hypervisor_cpuid_base(const char *sig, uint32_t leaves)
{
	uint32_t base, eax, signature[3];

	for_each_possible_hypervisor_cpuid_base(base) {
		cpuid(base, &eax, &signature[0], &signature[1], &signature[2]);

		if (!memcmp(sig, signature, 12) &&
		    (leaves == 0 || ((eax - base) >= leaves)))
			return base;
	}

	return 0;
}

void cpuid_read_leafs(void);

#endif /* _ASM_X86_CPUID_H */
