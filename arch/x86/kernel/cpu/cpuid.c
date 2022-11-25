#include <asm/cpuid.h>
#include <asm/percpu.h>
#include <asm/processor.h>

struct cpuid_info cpuid_info;
EXPORT_SYMBOL_GPL(cpuid_info);

/* Return a pointer to the capability word containing the feature bit. */
static u32 * __get_cap_word(struct cpuinfo_x86 *c, u16 bit)
{
	int cap_word = bit >> 5;

	if (WARN_ON_ONCE(cap_word > NCAPINTS))
		return 0;

	switch (cap_word) {
	case CPUID_1_EDX:
		return &cpuid_info.f1.edx;
		break;
	default:
		return &c->x86_capability[cap_word];
		break;
	}

	return 0;
}

u32 * noinstr get_boot_cpu_cap_word(u16 bit)
{
	return __get_cap_word(&boot_cpu_data, bit);
}
EXPORT_SYMBOL_GPL(get_boot_cpu_cap_word);

u32 * noinstr get_ap_cap_word(struct cpuinfo_x86 *c, u16 bit)
{
	return __get_cap_word(c, bit);
}
EXPORT_SYMBOL_GPL(get_ap_cap_word);

void cpuid_read_leafs(void)
{
	cpuid_info.f1.edx = cpuid_edx(1);
}
