#include "xpf.h"

static uint64_t xpf_sptm_find_arm_vm_init(void) {
	PFStringMetric *unsupportedMemMetric = pfmetric_string_init("Unsupported memory configuration %lx @%s:%d");
	__block uint64_t unsupportedMemAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, unsupportedMemMetric, ^(uint64_t vmaddr, bool *stop) {
		unsupportedMemAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(unsupportedMemMetric);
	XPF_ASSERT(unsupportedMemAddr);

	__block uint64_t arm_init_mid = 0;
	PFXrefMetric *unsupportedMemXrefMetric = pfmetric_xref_init(unsupportedMemAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, unsupportedMemXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		arm_init_mid = vmaddr;
		*stop = true;
	});
	pfmetric_free(unsupportedMemXrefMetric);
	XPF_ASSERT(arm_init_mid);

	uint64_t ret = pfsec_find_function_start(gXPF.kernelTextSection, arm_init_mid);
	return ret;
}

static uint64_t xpf_find_arm_vm_init(void)
{
	PFStringMetric *contiguousHintMetric = pfmetric_string_init("use_contiguous_hint");
	__block uint64_t contiguousHintAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, contiguousHintMetric, ^(uint64_t vmaddr, bool *stop) {
		contiguousHintAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(contiguousHintMetric);
	XPF_ASSERT(contiguousHintAddr);

	__block uint64_t arm_init_mid = 0;
	PFXrefMetric *contiguousHintXrefMetric = pfmetric_xref_init(contiguousHintAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, contiguousHintXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		arm_init_mid = vmaddr;
		*stop = true;
	});
	pfmetric_free(contiguousHintXrefMetric);
	XPF_ASSERT(arm_init_mid);

	return pfsec_find_function_start(gXPF.kernelTextSection, arm_init_mid);
}

static uint64_t xpf_find_arm_vm_init_reference(uint32_t n)
{
	uint64_t arm_vm_init = xpf_item_resolve("kernelSymbol.arm_vm_init");
	XPF_ASSERT(arm_vm_init);

	uint32_t strAny = 0, strAnyMask = 0;
	arm64_gen_str_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &strAny, &strAnyMask);

	uint64_t toCheck = arm_vm_init;
	uint64_t strAddr = 0;
	for (int i = 0; i < n; i++) {
		strAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 0x20, strAny, strAnyMask);
		toCheck = strAddr + 4;
	}

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, strAddr);
}

static uint64_t xpf_find_pmap_bootstrap(void)
{
	__block uint64_t pmap_asid_plru_stringAddr = 0;
	PFStringMetric *asidPlruMetric = pfmetric_string_init("pmap_asid_plru");
	pfmetric_run(gXPF.kernelStringSection, asidPlruMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_asid_plru_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(asidPlruMetric);
	XPF_ASSERT(pmap_asid_plru_stringAddr);

	__block uint64_t pmap_bootstrap = 0;
	PFXrefMetric *asidPlruXrefMetric = pfmetric_xref_init(pmap_asid_plru_stringAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, asidPlruXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_bootstrap = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(asidPlruXrefMetric);
	return pmap_bootstrap;
}

static uint64_t xpf_find_pointer_mask_symbol(uint32_t n)
{
	uint64_t pmap_bootstrap = xpf_item_resolve("kernelSymbol.pmap_bootstrap");
	XPF_ASSERT(pmap_bootstrap);

	uint32_t ldrQ0AnyInst = 0, ldrQ0AnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_Q(0), ARM64_REG_ANY, OPT_UINT64_NONE, &ldrQ0AnyInst, &ldrQ0AnyMask);

	uint64_t ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, pmap_bootstrap, 0x100, ldrQ0AnyInst, ldrQ0AnyMask);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrAddr);
}

static uint64_t xpf_find_pointer_mask(void)
{
	uint64_t pointer_mask_symbol = xpf_item_resolve("kernelSymbol.pointer_mask");
	XPF_ASSERT(pointer_mask_symbol);

	uint64_t pointer_mask = pfsec_read64(gXPF.kernelConstSection, pointer_mask_symbol);
	if (pointer_mask != 0xffffff8000000000 && pointer_mask != 0xffff800000000000 && pointer_mask != 0xffffffc000000000) {
		xpf_set_error("xpf_find_pointer_mask error: Unexpected PAC mask: 0x%llx", pointer_mask);
		return 0;
	}
	return pointer_mask;
}

static uint64_t xpf_find_T1SZ_BOOT(void)
{
	// for T1SZ_BOOT, count how many bits in the pointer_mask are set
	uint64_t pointer_mask = xpf_item_resolve("kernelConstant.pointer_mask");
	uint64_t T1SZ_BOOT = 0;
	for (uint64_t i = 64; i > 0; i--) {
		if (pointer_mask & (1ULL << (i - 1))) {
			T1SZ_BOOT++;
		}
	}
	return T1SZ_BOOT;
}

static uint64_t xpf_find_ARM_TT_L1_INDEX_MASK(void)
{
	uint64_t T1SZ_BOOT = xpf_item_resolve("kernelConstant.T1SZ_BOOT");
	switch (T1SZ_BOOT) {
		case 17:
		return 0x00007ff000000000ULL;
		case 25:
		return 0x0000007000000000ULL;
		case 26:
		return 0x0000003fc0000000ULL;
		default:
		xpf_set_error("ARM_TT_L1_INDEX_MASK: Unexpected T1SZ_BOOT??? (%llu)", T1SZ_BOOT);
		return 0;
	}
}

static uint64_t xpf_find_PT_INDEX_MAX(void)
{
	// return 0x4343434343434343;
	PFSection *textSection = (gXPF.kernelIsArm64e && !gXPF.isSPTMDevice) ? gXPF.kernelPPLTextSection : gXPF.kernelTextSection;

	PFStringMetric *stringMetric = pfmetric_string_init("%s: out of PTD entries and for some reason didn't allocate more %d %p");
	__block uint64_t stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t xrefAddr = 0;
	pfmetric_run(textSection, xrefMetric, ^(uint64_t vmaddr, bool *stop){
		xrefAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	XPF_ASSERT(xrefAddr);

	uint32_t movnAny0Inst = 0, movnAny0Mask = 0;
	arm64_gen_mov_imm('n', ARM64_REG_ANY, OPT_UINT64(0), OPT_UINT64(0), &movnAny0Inst, &movnAny0Mask);
	uint64_t movAddr = pfsec_find_prev_inst(textSection, xrefAddr, 100, movnAny0Inst, movnAny0Mask);
	XPF_ASSERT(movAddr);

	arm64_register movReg;
	int r = arm64_dec_mov_imm(pfsec_read32(textSection, movAddr), &movReg, NULL, NULL, NULL);

	uint32_t strInst = 0, strMask = 0;
	arm64_gen_str_imm(0, LDR_STR_TYPE_UNSIGNED, movReg, ARM64_REG_ANY, OPT_UINT64_NONE, &strInst, &strMask);
	uint32_t ret = gXPF.kernelIsArm64e ? 0xd65f0fff : 0xd65f03c0;

	// We need to count all "str [movReg], ?" instructions until we hit a RET(AB), then we have the PT_INDEX_MAX
	// Apparently the first one is an STP :( so we start with 1
	uint64_t PT_INDEX_MAX = 1;
	for (int i = 0; i < 100; i++) {
		uint32_t inst = pfsec_read32(textSection, movAddr + (i * 4));
		if ((inst & strMask) == strInst) {
			PT_INDEX_MAX++;
		}
		else if (inst == ret) {
			break;
		}
	}
	return PT_INDEX_MAX;
}

static uint64_t xpf_find_phystokv(void)
{
	uint64_t arm_vm_init = xpf_item_resolve("kernelSymbol.arm_vm_init");
	XPF_ASSERT(arm_vm_init);

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);

	// On ARM_LARGE_MEMORY kernels, the second bl is phystokv
	uint32_t n = gXPF.kernelBase == 0xfffffe0007004000 ? 2 : 1;

	uint64_t blAddr = arm_vm_init;
	for (uint32_t i = 0; i < n; i++) {
		blAddr = pfsec_find_next_inst(gXPF.kernelTextSection, blAddr + 4, 0, blAny, blAnyMask);
	}

	uint64_t phystokv = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, blAddr), blAddr, &phystokv, NULL);
	return phystokv;
}

/*static uint64_t xpf_find_gVirtSize(void)
{
	return 0;
}*/

static uint64_t xpf_find_ptov_table(void)
{
	uint64_t phystokv = xpf_item_resolve("kernelSymbol.phystokv");
	XPF_ASSERT(phystokv);

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);

	// Second ldr in phytokv references ptov_table
	uint64_t toCheck = phystokv;
	uint64_t ldrAddr = 0;
	for (int i = 0; i < 2; i++) {
		ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 20, ldrAny, ldrAnyMask);
		toCheck = ldrAddr + 4;
	}
	XPF_ASSERT(ldrAddr);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrAddr);
}

static uint64_t xpf_find_start_first_cpu(void)
{
	uint64_t start_first_cpu = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, gXPF.kernelEntry), gXPF.kernelEntry, &start_first_cpu, NULL);
	return start_first_cpu;
}

static uint64_t xpf_find_cpu_ttep(void)
{
    if (gXPF.isSPTMDevice) {
		uint64_t pmap_bootstrap = xpf_item_resolve("kernelSymbol.pmap_bootstrap");

		// search ADRP xN, #cpu_ttep@PAGE;
		uint32_t inst[] = {
			0x90000000, // adrp xN, #0x...
			0xf9400000, // ldr xN, [xN, #0x...]
			0xa9000000, // stp xN, xN, [xN]
		};
		uint32_t mask[] = {
			0x9F000000,
			0xFFC00000,
			0xFFFF8000,
		};
		
		PFPatternMetric *metric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
		__block uint64_t adrpAddr = 0;
		pfmetric_run_in_range(gXPF.kernelTextSection, pmap_bootstrap, -1, metric, ^(uint64_t vmaddr, bool *stop){
			adrpAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(metric);

		uint64_t ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
		printf("cpu_ttep found? 0x%llx\n", ret);
		return ret;
    }
	uint64_t start_first_cpu = xpf_item_resolve("kernelSymbol.start_first_cpu");

	uint32_t cbzX21Any = 0, cbzX21AnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_X(21), OPT_UINT64_NONE, &cbzX21Any, &cbzX21AnyMask);

	uint64_t cpu_ttep_pre = pfsec_find_next_inst(gXPF.kernelTextSection, start_first_cpu, 0, cbzX21Any, cbzX21AnyMask);
	XPF_ASSERT(cpu_ttep_pre);

	uint64_t addAddr = cpu_ttep_pre + 8;
	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, addAddr);
}

static uint64_t xpf_find_kernel_el(void)
{
	uint64_t start_first_cpu = xpf_item_resolve("kernelSymbol.start_first_cpu");

	uint32_t inst = pfsec_read32(gXPF.kernelTextSection, start_first_cpu + 16);
	if (inst == 0xd5384240 /* msr x0, CurrentEL */) {
		return 2;
	}

	return 1;
}

static uint64_t xpf_find_fatal_error_fmt(void)
{
	PFSection *textSec = (gXPF.kernelAMFITextSection ?: gXPF.kernelTextSection);
	PFSection *stringSec = (gXPF.kernelAMFIStringSection ?: gXPF.kernelStringSection);
	if (!gXPF.kernelIsArm64e && !gXPF.kernelIsFileset) {
		textSec = gXPF.kernelPLKTextSection;
		stringSec = gXPF.kernelPrelinkTextSection;
	}

	PFStringMetric *amfiErrorMetric = pfmetric_string_init("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.\n");
	__block uint64_t amfiErrorAddr = 0;
	pfmetric_run(stringSec, amfiErrorMetric, ^(uint64_t vmaddr, bool *stop) {
		amfiErrorAddr = vmaddr;
		*stop = true;
	});

	if (!amfiErrorAddr) {
		textSec = gXPF.kernelTextSection;
		stringSec = gXPF.kernelStringSection;
		
		pfmetric_run(stringSec, amfiErrorMetric, ^(uint64_t vmaddr, bool *stop) {
			amfiErrorAddr = vmaddr;
			*stop = true;
		});
	}
	pfmetric_free(amfiErrorMetric);
	XPF_ASSERT(amfiErrorAddr);

	__block uint64_t fatal_error_fmt = 0;
	PFXrefMetric *amfiErrorXrefMetric = pfmetric_xref_init(amfiErrorAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(textSec, amfiErrorXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		fatal_error_fmt = pfsec_find_function_start(textSec, vmaddr);
		*stop = true;
	});
	pfmetric_free(amfiErrorXrefMetric);
	return fatal_error_fmt;
}

static uint64_t xpf_find_kalloc_data_external(void)
{
	PFSection *sec = (gXPF.kernelAMFITextSection ?: gXPF.kernelTextSection);
	if (!gXPF.kernelIsArm64e && !gXPF.kernelIsFileset) {
		sec = gXPF.kernelPLKTextSection;
	}

	uint64_t fatal_error_fmt = xpf_item_resolve("kernelSymbol.fatal_error_fmt");
	XPF_ASSERT(fatal_error_fmt);

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);
	uint64_t kallocDataExternalBlAddr = pfsec_find_next_inst(sec, fatal_error_fmt, 20, blAny, blAnyMask);
	if (!kallocDataExternalBlAddr) {
		sec = gXPF.kernelTextSection;
		kallocDataExternalBlAddr = pfsec_find_next_inst(sec, fatal_error_fmt, 20, blAny, blAnyMask);
	}
	XPF_ASSERT(kallocDataExternalBlAddr);

	uint32_t kallocDataExternalBl = pfsec_read32(sec, kallocDataExternalBlAddr);

	uint64_t kallocDataExternal = 0;
	arm64_dec_b_l(kallocDataExternalBl, kallocDataExternalBlAddr, &kallocDataExternal, NULL);
	XPF_ASSERT(kallocDataExternal);

	return pfsec_arm64_resolve_stub(sec, kallocDataExternal);
}

static uint64_t xpf_find_kfree_data_external(void)
{
	PFSection *sec = (gXPF.kernelAMFITextSection ?: gXPF.kernelTextSection);
	if (!gXPF.kernelIsArm64e && !gXPF.kernelIsFileset) {
		sec = gXPF.kernelPLKTextSection;
	}

	uint64_t fatal_error_fmt = xpf_item_resolve("kernelSymbol.fatal_error_fmt");
	XPF_ASSERT(fatal_error_fmt);

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);

	uint32_t ret = gXPF.kernelIsArm64e ? 0xd65f0fff : 0xd65f03c0;
	uint64_t fatal_error_fmt_end = pfsec_find_next_inst(sec, fatal_error_fmt, 0, ret, 0xffffffff);
	if (!fatal_error_fmt_end) {
		sec = gXPF.kernelTextSection;
		fatal_error_fmt_end = pfsec_find_next_inst(sec, fatal_error_fmt, 0, ret, 0xffffffff);
	}
	XPF_ASSERT(fatal_error_fmt_end);

	uint32_t movW1_0x400_Inst = 0, movW1_0x400_InstMask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_W(1), OPT_UINT64(0x400), OPT_UINT64(0), &movW1_0x400_Inst, &movW1_0x400_InstMask);
	uint64_t kfree_data_external_pre = pfsec_find_prev_inst(sec, fatal_error_fmt_end, 25, movW1_0x400_Inst, movW1_0x400_InstMask);

	uint64_t kfree_data_external = 0;
	int decRet = arm64_dec_b_l(pfsec_read32(sec, kfree_data_external_pre+4), kfree_data_external_pre+4, &kfree_data_external, NULL);
	XPF_ASSERT(decRet == 0);

	return pfsec_arm64_resolve_stub(sec, kfree_data_external);
}

static uint64_t xpf_find_allproc(void)
{
	PFStringMetric *shutdownwaitMetric = pfmetric_string_init("shutdownwait");
	XPF_ASSERT(shutdownwaitMetric);

	__block uint64_t shutdownwaitString = 0;
	pfmetric_run(gXPF.kernelStringSection, shutdownwaitMetric, ^(uint64_t vmaddr, bool *stop) {
		shutdownwaitString = vmaddr;
		*stop = true;
	});
	pfmetric_free(shutdownwaitMetric);
	XPF_ASSERT(shutdownwaitString);

	PFXrefMetric *shutdownwaitXrefMetric = pfmetric_xref_init(shutdownwaitString, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t beforeLdrAddr = 0;
	pfmetric_run(gXPF.kernelTextSection, shutdownwaitXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		beforeLdrAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(shutdownwaitXrefMetric);
	XPF_ASSERT(beforeLdrAddr);

	arm64_register destinationReg;
	int decRet = arm64_dec_add_imm(pfsec_read32(gXPF.kernelTextSection, beforeLdrAddr), &destinationReg, NULL, NULL);
	XPF_ASSERT(decRet == 0);

	if (ARM64_REG_GET_NUM(destinationReg) != 3) {
		// If the string is not loaded into x3, we need to advance until the mov x3, <target>

		uint32_t targetInsn = 0, targetMask = 0;
		arm64_gen_mov_reg(ARM64_REG_X(3), destinationReg, &targetInsn, &targetMask);

		uint64_t curAddr = beforeLdrAddr;
		for (int i = 0; i < 200; i++) {
			uint32_t curInsn = pfsec_read32(gXPF.kernelTextSection, curAddr);

			if ((curInsn & targetMask) == targetInsn) {
				beforeLdrAddr = curAddr;
				break;
			}

			// If we find an unconditional branch, follow it
			uint64_t bTarget = 0;
			bool isBl = false;
			if (arm64_dec_b_l(curInsn, curAddr, &bTarget, &isBl) == 0) {
				if (!isBl) {
					curAddr = bTarget;
					continue;
				}
			}

			curAddr += 4;
		}
	}

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);

	uint64_t ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, beforeLdrAddr, 20, ldrAny, ldrAnyMask);
	XPF_ASSERT(ldrAddr);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrAddr);
}

static uint64_t xpf_find_task_crashinfo_release_ref(void)
{
	uint32_t movzW0_0 = 0, movzW0_0Mask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_W(0), OPT_UINT64(0), OPT_UINT64(0), &movzW0_0, &movzW0_0Mask);

	PFStringMetric *corpseReleasedMetric = pfmetric_string_init("Corpse released, count at %d\n");
	__block uint64_t corpseReleasedStringAddr = 0;
	pfmetric_run(gXPF.kernelOSLogSection, corpseReleasedMetric, ^(uint64_t vmaddr, bool *stop){
		corpseReleasedStringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(corpseReleasedMetric);

	if (!corpseReleasedStringAddr) {
		// iOS 14 does not have the above log string
		corpseReleasedMetric = pfmetric_string_init("\"corpse in flight count over-release\"");
		pfmetric_run(gXPF.kernelStringSection, corpseReleasedMetric, ^(uint64_t vmaddr, bool *stop){
			corpseReleasedStringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(corpseReleasedMetric);
		XPF_ASSERT(corpseReleasedStringAddr);

		// iOS 14 also does not have the movz after this panic, so we look for a ret instruction before (as task_crashinfo_release_ref should be the first xref).
		PFXrefMetric *corseReleasedXrefMetric = pfmetric_xref_init(corpseReleasedStringAddr, XREF_TYPE_MASK_REFERENCE);
		__block uint64_t task_crashinfo_release_ref = 0;
		pfmetric_run(gXPF.kernelTextSection, corseReleasedXrefMetric, ^(uint64_t vmaddr, bool *stop) {
			if (pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 20, 0xd65f03c0, 0xffffffff)) {
				task_crashinfo_release_ref = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
				*stop = true;
			}
		});
		pfmetric_free(corseReleasedXrefMetric);

		return task_crashinfo_release_ref;
	}

	PFXrefMetric *corseReleasedXrefMetric = pfmetric_xref_init(corpseReleasedStringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t task_crashinfo_release_ref = 0;
	pfmetric_run(gXPF.kernelTextSection, corseReleasedXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		if (pfsec_find_next_inst(gXPF.kernelTextSection, vmaddr, 20, movzW0_0, movzW0_0Mask)) {
			task_crashinfo_release_ref = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
			*stop = true;
		}
	});
	pfmetric_free(corseReleasedXrefMetric);

	return task_crashinfo_release_ref;
}

static uint64_t xpf_find_task_collect_crash_info(void)
{
	uint64_t task_crashinfo_release_ref = xpf_item_resolve("kernelSymbol.task_crashinfo_release_ref");
	XPF_ASSERT(task_crashinfo_release_ref);

	uint32_t movzW1_0x4000 = 0x52880001, movzW1_0x4000Mask = 0xffffffff;
	__block uint64_t task_collect_crash_info = 0;
	PFXrefMetric *task_crashinfo_release_refXrefMetric = pfmetric_xref_init(task_crashinfo_release_ref, XREF_TYPE_MASK_CALL);
	pfmetric_run(gXPF.kernelTextSection, task_crashinfo_release_refXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		if (pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 0x50, movzW1_0x4000, movzW1_0x4000Mask)) {
			task_collect_crash_info = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
			*stop = true;
		}
	});

	if (!task_collect_crash_info) {
		// On iOS 18, this call is followed by a mov w??, #0
		pfmetric_run(gXPF.kernelTextSection, task_crashinfo_release_refXrefMetric, ^(uint64_t vmaddr, bool *stop) {
			uint64_t imm = 0;
			arm64_register reg;
			if (arm64_dec_mov_imm(pfsec_read32(gXPF.kernelTextSection, vmaddr + 4), &reg, &imm, NULL, NULL) == 0) {
				if (imm == 0 && ARM64_REG_IS_W(reg)) {
					task_collect_crash_info = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
					*stop = true;
				}
			}
		});
	}

	pfmetric_free(task_crashinfo_release_refXrefMetric);
	XPF_ASSERT(task_collect_crash_info);

	// Handle outlining on iOS 18.4+
	// Bit hacky, but with a bit of wishful thinking it might stay like this
	PFXrefMetric *task_collect_crash_infoOutlineMetric = pfmetric_xref_init(task_collect_crash_info, XREF_TYPE_MASK_JUMP);
	pfmetric_run(gXPF.kernelTextSection, task_collect_crash_infoOutlineMetric, ^(uint64_t vmaddr, bool *stop) {
		if ((vmaddr < task_collect_crash_info) && (vmaddr >= (task_collect_crash_info - (5 * sizeof(uint32_t))))) {
			task_collect_crash_info = vmaddr - (2 * sizeof(uint32_t));
			*stop = true;
		}
	});
	pfmetric_free(task_collect_crash_infoOutlineMetric);

	return task_collect_crash_info;
}

static uint64_t xpf_find_task_itk_space(void)
{
	__block uint64_t task_collect_crash_info = xpf_item_resolve("kernelSymbol.task_collect_crash_info");

	uint32_t movzW2_1 = 0, movzW2_1Mask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_W(2), OPT_UINT64(1), OPT_UINT64(0), &movzW2_1, &movzW2_1Mask);

	__block uint64_t itk_space = 0;
	PFXrefMetric *task_collect_crash_infoXrefMetric = pfmetric_xref_init(task_collect_crash_info, XREF_TYPE_MASK_CALL);
	__block uint64_t task_collect_crash_infoXref = 0;

	pfmetric_run(gXPF.kernelTextSection, task_collect_crash_infoXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		if ((pfsec_read32(gXPF.kernelTextSection, vmaddr - 4) & movzW2_1Mask) != movzW2_1) return;

		task_collect_crash_infoXref = vmaddr;
		*stop = true;
	});
	pfmetric_free(task_collect_crash_infoXrefMetric);

	XPF_ASSERT(task_collect_crash_infoXref);

	// At vmaddr + 4 there is a CBZ to some other place
	// At that place, the next CBZ leads to the place where the actual reference we want is

	uint64_t cbz1Addr = task_collect_crash_infoXref + 4;
	bool isCbnz = false;
	uint64_t target1 = 0;
	int decRet = arm64_dec_cb_n_z(pfsec_read32(gXPF.kernelTextSection, cbz1Addr), cbz1Addr, &isCbnz, NULL, &target1);
	XPF_ASSERT(decRet == 0);
	if (isCbnz) {
		// If this is not a cbz and rather a cbnz, treat the instruction after it as the cbz target
		target1 = cbz1Addr + 4;
	}

	uint32_t cbzAnyInst = 0, cbzAnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL_NONE, ARM64_REG_ANY, OPT_UINT64_NONE, &cbzAnyInst, &cbzAnyMask);

	uint64_t cbz2Addr = pfsec_find_next_inst(gXPF.kernelTextSection, target1, 0x20, cbzAnyInst, cbzAnyMask);

	uint64_t target2 = 0;
	decRet = arm64_dec_cb_n_z(pfsec_read32(gXPF.kernelTextSection, cbz2Addr), cbz2Addr, &isCbnz, NULL, &target2);
	XPF_ASSERT(decRet == 0);

	if (isCbnz) {
		// If this is not a cbz and rather a cbnz, treat the instruction after it as the cbz target
		target2 = cbz2Addr + 4;
	}

	uint32_t ldrAnyInst = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAnyInst, &ldrAnyMask);

	// At this place, the first ldr that doesn't read from SP has the reference we want
	uint64_t ldrAddr = target2;
	uint64_t ldrEndAddr = ldrAddr + (20 * sizeof(uint32_t));
	while (true) {
		ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, ldrAddr, (ldrEndAddr - ldrAddr) / 4, ldrAnyInst, ldrAnyMask);
		arm64_register addrReg;
		uint64_t imm = 0;
		arm64_dec_ldr_imm(pfsec_read32(gXPF.kernelTextSection, ldrAddr), NULL, &addrReg, &imm, NULL, NULL);
		if (ARM64_REG_GET_NUM(addrReg) != ARM64_REG_NUM_SP) {
			itk_space = imm;
			break;
		}
		ldrAddr += 4;
	}

	return itk_space;
}

static uint64_t xpf_find_vm_reference(uint32_t idx)
{
	uint32_t inst = 0x120a6d28; // and w8, w9, #0xffc3ffff
	PFPatternMetric *patternMetric = pfmetric_pattern_init(&inst, NULL, sizeof(inst), sizeof(uint32_t));

	__block uint64_t andAddr = 0;
	pfmetric_run(gXPF.kernelTextSection, patternMetric, ^(uint64_t vmaddr, bool *stop) {
		andAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(patternMetric);

	if (!andAddr) {
		inst = 0x120a6d08; // and w8, w8, #0xffc3ffff (iOS 17)
		patternMetric = pfmetric_pattern_init(&inst, NULL, sizeof(inst), sizeof(uint32_t));
		pfmetric_run(gXPF.kernelTextSection, patternMetric, ^(uint64_t vmaddr, bool *stop) {
			andAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(patternMetric);
	}

	XPF_ASSERT(andAddr);

	uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);
	uint64_t toCheck = andAddr;
	uint64_t ldrAddr = 0;
	for (int i = 0; i < idx; i++) {
		ldrAddr = pfsec_find_next_inst(gXPF.kernelTextSection, toCheck, 20, ldrAny, ldrAnyMask);
		toCheck = ldrAddr + 4;
	}

	XPF_ASSERT(ldrAddr);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrAddr);;
}

static uint64_t xpf_find_vm_map_pmap(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("userspace has control access to a kernel map %p through task %p @%s:%d");
	__block uint64_t stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);

	if (!stringAddr) {
		// Slightly different on iOS 14
		stringMetric = pfmetric_string_init("\"userspace has control access to a \" \"kernel map %p through task %p\"");
		pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
			stringAddr = vmaddr;
			*stop = true;
		});
	}

	XPF_ASSERT(stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t xrefAddr = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		xrefAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(xrefMetric);

	XPF_ASSERT(xrefAddr);

	uint32_t inst[2] = { 0 };
	uint32_t mask[2] = { 0 };
	arm64_gen_ldr_imm(0, gXPF.kernelIsArm64e ? LDR_STR_TYPE_PRE_INDEX : LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &inst[0], &mask[0]);
	if (gXPF.kernelIsArm64e) {
		arm64_gen_cb_n_z(OPT_BOOL_NONE, ARM64_REG_ANY, OPT_UINT64_NONE, &inst[1], &mask[1]);
	}

	__block uint64_t vm_map_pmap = 0;
	PFPatternMetric *patternMetric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	pfmetric_run_in_range(gXPF.kernelTextSection, xrefAddr, xrefAddr - (100 * sizeof(uint32_t)), patternMetric, ^(uint64_t vmaddr, bool *stop) {
		if (arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, vmaddr - 4), vmaddr - 4, NULL, NULL, NULL) != 0) {
			arm64_dec_ldr_imm(pfsec_read32(gXPF.kernelTextSection, vmaddr), NULL, NULL, &vm_map_pmap, NULL, NULL);
			*stop = true;
		}
	});
	pfmetric_free(patternMetric);

	return vm_map_pmap;
}

static uint64_t xpf_find_proc_struct_size(void)
{
	if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
		// iOS >=16
		PFStringMetric *procTaskStringMetric = pfmetric_string_init("proc_task");
		__block uint64_t procTaskStringAddr = 0;
		pfmetric_run(gXPF.kernelStringSection, procTaskStringMetric, ^(uint64_t vmaddr, bool *stop) {
			procTaskStringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(procTaskStringMetric);
		XPF_ASSERT(procTaskStringAddr);

		PFXrefMetric *procTaskXrefMetric = pfmetric_xref_init(procTaskStringAddr, XREF_TYPE_MASK_REFERENCE);
		__block uint64_t procTaskStringXref = 0;
		pfmetric_run(gXPF.kernelTextSection, procTaskXrefMetric, ^(uint64_t vmaddr, bool *stop) {
			procTaskStringXref = vmaddr;
			*stop = true;
		});
		pfmetric_free(procTaskXrefMetric);
		XPF_ASSERT(procTaskStringXref);

		uint32_t ldrAnyInst = 0, ldrAnyMask = 0;
		arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAnyInst, &ldrAnyMask);
		uint64_t ldrAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, procTaskStringXref, 0x20, ldrAnyInst, ldrAnyMask);
		XPF_ASSERT(ldrAddr);
		
		uint64_t proc_struct_sizeAddr = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrAddr);
		return pfsec_read64(gXPF.kernelDataSection, proc_struct_sizeAddr);
	}
	else {
		// iOS <=15

		PFStringMetric *procStringMetric = pfmetric_string_init("proc");
		__block uint64_t procStringAddr = 0;
		pfmetric_run(gXPF.kernelStringSection, procStringMetric, ^(uint64_t vmaddr, bool *stop) {
			procStringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(procStringMetric);
		XPF_ASSERT(procStringAddr);

		uint64_t mask = 0x0000ffffffffffff;
		PFPatternMetric *patternMetric = pfmetric_pattern_init(&procStringAddr, &mask, sizeof(procStringAddr), sizeof(uint64_t));
		__block uint64_t proc_struct_size = 0;
		pfmetric_run(gXPF.kernelBootdataInit, patternMetric, ^(uint64_t vmaddr, bool *stop) {
			uint64_t candidate = pfsec_read64(gXPF.kernelBootdataInit, vmaddr + 8);
			if (candidate != 0) {
				proc_struct_size = candidate;
				*stop = true;
			}
		});

		return proc_struct_size;
	}
}

static uint64_t xpf_find_perfmon_dev_open(void)
{
	PFStringMetric *perfmonMetric = pfmetric_string_init("perfmon: attempt to open unsupported source: 0x%x @%s:%d");
	__block uint64_t perfmonString = 0;
	pfmetric_run(gXPF.kernelStringSection, perfmonMetric, ^(uint64_t vmaddr, bool *stop) {
		perfmonString = vmaddr;
		*stop = true;
	});
	pfmetric_free(perfmonMetric);
	XPF_ASSERT(perfmonString);

	PFXrefMetric *perfmonXrefMetric = pfmetric_xref_init(perfmonString, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t perfmonXref = 0;
	pfmetric_run(gXPF.kernelTextSection, perfmonXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		perfmonXref = vmaddr;
		*stop = true;
	});
	pfmetric_free(perfmonXrefMetric);
	XPF_ASSERT(perfmonXref);

	return pfsec_find_function_start(gXPF.kernelTextSection, perfmonXref);
}

static uint64_t xpf_find_perfmon_devices(void)
{
	uint64_t perfmon_dev_open = xpf_item_resolve("kernelSymbol.perfmon_dev_open");
	XPF_ASSERT(perfmon_dev_open);

	uint32_t movWAny_0x28Inst = 0, movWAny_0x28Mask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64(0x28), OPT_UINT64_NONE, &movWAny_0x28Inst, &movWAny_0x28Mask);

	// The "add" of the "adrp, add" we want is either one instruction before this or three after it
	uint64_t movAddr = pfsec_find_next_inst(gXPF.kernelTextSection, perfmon_dev_open, 0, movWAny_0x28Inst, movWAny_0x28Mask);
	XPF_ASSERT(movAddr);

	uint64_t perfmon_devices = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, movAddr - 4);
	if (!perfmon_devices) {
		perfmon_devices = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, movAddr + 12);
	}
	
	return perfmon_devices;
}

static uint64_t xpf_find_vn_kqfilter(void)
{
	PFStringMetric *invalidKnoteMetric = pfmetric_string_init("Invalid knote filter on a vnode! @%s:%d");
	__block uint64_t invalidKnoteString = 0;
	pfmetric_run(gXPF.kernelStringSection, invalidKnoteMetric, ^(uint64_t vmaddr, bool *stop) {
		invalidKnoteString = vmaddr;
		*stop = true;
	});
	pfmetric_free(invalidKnoteMetric);
	XPF_ASSERT(invalidKnoteString);

	PFXrefMetric *invalidKnoteXrefMetric = pfmetric_xref_init(invalidKnoteString, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t invalidKnoteXref = 0;
	pfmetric_run(gXPF.kernelTextSection, invalidKnoteXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		invalidKnoteXref = vmaddr;
		*stop = true;
	});
	pfmetric_free(invalidKnoteXrefMetric);
	XPF_ASSERT(invalidKnoteXref);

	uint64_t ref_start = pfsec_find_function_start(gXPF.kernelTextSection, invalidKnoteXref);
	XPF_ASSERT(ref_start);

	return pfsec_find_function_start(gXPF.kernelTextSection, ref_start - 0x4);
}

static uint64_t xpf_find_cdevsw(void)
{
	uint64_t vn_kqfilter = xpf_item_resolve("kernelSymbol.vn_kqfilter");
	XPF_ASSERT(vn_kqfilter);

	uint32_t movW2Inst = 0, movW2Mask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_W(2), OPT_UINT64(0x20), OPT_UINT64(0), &movW2Inst, &movW2Mask);
	uint64_t before_bl_spec_kqfilterAddr = pfsec_find_next_inst(gXPF.kernelTextSection, vn_kqfilter, 100, movW2Inst, movW2Mask);
	XPF_ASSERT(before_bl_spec_kqfilterAddr);
	uint64_t bl_spec_kqfilterAddr = before_bl_spec_kqfilterAddr + 4;

	uint64_t spec_kqfilter = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, bl_spec_kqfilterAddr), bl_spec_kqfilterAddr, &spec_kqfilter, NULL);

	uint32_t movW10_0x70 = 0, mov10_0x70Mask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_W(10), OPT_UINT64(0x70), OPT_UINT64(0), &movW10_0x70, &mov10_0x70Mask);
	uint64_t movAddr = pfsec_find_next_inst(gXPF.kernelTextSection, spec_kqfilter, 0, movW10_0x70, mov10_0x70Mask);
	XPF_ASSERT(movAddr);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, movAddr + 0x8);
}

static uint64_t xpf_find_proc_apply_sandbox(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("Sandbox failed to revoke host port (%d) for pid %d");
	__block uint64_t sandboxFailedStringAddr = 0;
	pfmetric_run(gXPF.kernelOSLogSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
		sandboxFailedStringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(sandboxFailedStringAddr);

	__block uint64_t proc_apply_sandbox = 0;
	PFXrefMetric *xrefMetric = pfmetric_xref_init(sandboxFailedStringAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop){
		proc_apply_sandbox = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);

	return proc_apply_sandbox;
}

static uint64_t xpf_find_mac_label_set(void)
{
	uint64_t proc_apply_sandbox = xpf_item_resolve("kernelSymbol.proc_apply_sandbox");

	uint32_t blAnyInst = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAnyInst, &blAnyMask);

	uint64_t firstBLAddr = pfsec_find_next_inst(gXPF.kernelTextSection, proc_apply_sandbox, 100, blAnyInst, blAnyMask);
	XPF_ASSERT(firstBLAddr);
	uint64_t secondBLAddr = pfsec_find_next_inst(gXPF.kernelTextSection, firstBLAddr+4, 100, blAnyInst, blAnyMask);
	XPF_ASSERT(secondBLAddr);

	uint64_t mac_label_set = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, secondBLAddr), secondBLAddr, &mac_label_set, NULL);
	return mac_label_set;
}

static uint64_t xpf_find_proc_get_syscall_filter_mask_size(void)
{
	PFSection *textSec = (gXPF.kernelSandboxTextSection ?: gXPF.kernelTextSection);
	PFSection *stringSec = (gXPF.kernelSandboxStringSection ?: gXPF.kernelStringSection);
	if (!gXPF.kernelIsArm64e && !gXPF.kernelIsFileset) {
		textSec = gXPF.kernelPLKTextSection;
		stringSec = gXPF.kernelPrelinkTextSection;
	}

	PFStringMetric *stringMetric = pfmetric_string_init("\"invalid # of syscalls from xnu\" @%s:%d");
	__block uint64_t syscallMasksStringAddr = 0;
	pfmetric_run(stringSec, stringMetric, ^(uint64_t vmaddr, bool *stop) {
		syscallMasksStringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);

	if (!syscallMasksStringAddr) {
		// iOS 15.0 betas 1-3
		stringMetric = pfmetric_string_init("\"invalid # of syscalls from xnu!\" @%s:%d");
		pfmetric_run(stringSec, stringMetric, ^(uint64_t vmaddr, bool *stop) {
			syscallMasksStringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(stringMetric);
	}

	if (!syscallMasksStringAddr && gXPF.kernelStringSection && !gXPF.kernelSandboxStringSection) {
		// On A11 15.x it is in kernelStringSection, on A10 and A9 it is not, on 16.x it is not
		stringMetric = pfmetric_string_init("\"invalid # of syscalls from xnu\" @%s:%d");
		pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
			syscallMasksStringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(stringMetric);

		if (!syscallMasksStringAddr) {
			// iOS 15.0 betas 1-3
			stringMetric = pfmetric_string_init("\"invalid # of syscalls from xnu!\" @%s:%d");
			pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
				syscallMasksStringAddr = vmaddr;
				*stop = true;
			});
			pfmetric_free(stringMetric);
		}

		if (syscallMasksStringAddr) {
			textSec = gXPF.kernelTextSection;
			stringSec = gXPF.kernelStringSection;
		}
	}
	XPF_ASSERT(syscallMasksStringAddr);

	PFXrefMetric *stringXrefMetric = pfmetric_xref_init(syscallMasksStringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t invalidSyscallLogRefAddr = 0;
	pfmetric_run(textSec, stringXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		invalidSyscallLogRefAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringXrefMetric);
	XPF_ASSERT(invalidSyscallLogRefAddr);

	uint32_t adrpAnyInst = 0, adrpAnyMask = 0;
	arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_ANY, &adrpAnyInst, &adrpAnyMask);
	uint64_t prevAdrpAddr = pfsec_find_prev_inst(textSec, invalidSyscallLogRefAddr-8, 20, adrpAnyInst, adrpAnyMask);
	XPF_ASSERT(prevAdrpAddr);

	PFXrefMetric *logBranchXrefMetric = pfmetric_xref_init(prevAdrpAddr, XREF_TYPE_MASK_JUMP);
	__block uint64_t logBranchXrefAddr = 0;
	pfmetric_run(textSec, logBranchXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		logBranchXrefAddr = vmaddr;
		*stop = false;
	});
	pfmetric_free(logBranchXrefMetric);
	XPF_ASSERT(logBranchXrefAddr);

	uint32_t blAnyInst = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAnyInst, &blAnyMask);
	uint64_t blAddr = pfsec_find_prev_inst(textSec, logBranchXrefAddr, 100, blAnyInst, blAnyMask);
	XPF_ASSERT(blAddr);
	uint64_t proc_get_syscall_filter_mask_size = 0;
	arm64_dec_b_l(pfsec_read32(textSec, blAddr), blAddr, &proc_get_syscall_filter_mask_size, NULL);
	
	return pfsec_arm64_resolve_stub(textSec, proc_get_syscall_filter_mask_size);
}

static uint64_t xpf_find_nsysent(void)
{
	uint64_t proc_get_syscall_filter_mask_size = xpf_item_resolve("kernelSymbol.proc_get_syscall_filter_mask_size");
	XPF_ASSERT(proc_get_syscall_filter_mask_size);

	uint32_t movAnyInst = 0, movAnyMask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64_NONE, OPT_UINT64_NONE, &movAnyInst, &movAnyMask);
	uint64_t mov1Addr = pfsec_find_next_inst(gXPF.kernelTextSection, proc_get_syscall_filter_mask_size, 20, movAnyInst, movAnyMask);
	XPF_ASSERT(mov1Addr);
	uint64_t mov2Addr = pfsec_find_next_inst(gXPF.kernelTextSection, mov1Addr+4, 10, movAnyInst, movAnyMask);
	XPF_ASSERT(mov2Addr);

	uint64_t imm = 0;
	arm64_dec_mov_imm(pfsec_read32(gXPF.kernelTextSection, mov2Addr), NULL, &imm, NULL, NULL);
	return imm;
}

static uint64_t xpf_find_mach_trap_count(void)
{
	uint64_t proc_get_syscall_filter_mask_size = xpf_item_resolve("kernelSymbol.proc_get_syscall_filter_mask_size");
	XPF_ASSERT(proc_get_syscall_filter_mask_size);

	uint32_t movAnyInst = 0, movAnyMask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64_NONE, OPT_UINT64_NONE, &movAnyInst, &movAnyMask);
	uint64_t movAddr = pfsec_find_next_inst(gXPF.kernelTextSection, proc_get_syscall_filter_mask_size, 20, movAnyInst, movAnyMask);
	XPF_ASSERT(movAddr);

	uint64_t imm = 0;
	arm64_dec_mov_imm(pfsec_read32(gXPF.kernelTextSection, movAddr), NULL, &imm, NULL, NULL);
	return imm;
}

static uint64_t xpf_find_mach_kobj_count(void)
{
	uint64_t proc_get_syscall_filter_mask_size = xpf_item_resolve("kernelSymbol.proc_get_syscall_filter_mask_size");
	XPF_ASSERT(proc_get_syscall_filter_mask_size);

	uint32_t ldrswInst = 0, ldrswMask = 0;
	arm64_gen_ldrs_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrswInst, &ldrswMask);
	uint64_t ldrswAddr = pfsec_find_next_inst(gXPF.kernelTextSection, proc_get_syscall_filter_mask_size, 40, ldrswInst, ldrswMask);
	XPF_ASSERT(ldrswAddr);
	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, ldrswAddr);
}

static uint64_t xpf_find_developer_mode_enabled(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("Just like pineapple on pizza, this task/thread port doesn't belong here. @%s:%d");
	__block uint64_t stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(stringAddr);

	PFXrefMetric *stringXrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t stringXrefAddr = 0;
	pfmetric_run(gXPF.kernelTextSection, stringXrefMetric, ^(uint64_t vmaddr, bool *stop){
		stringXrefAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringXrefMetric);
	XPF_ASSERT(stringXrefAddr);

	uint32_t adrpAnyInst = 0, adrpAnyMask = 0;
	arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_REG_ANY, &adrpAnyInst, &adrpAnyMask);
	uint64_t branchTarget = pfsec_find_prev_inst(gXPF.kernelTextSection, stringXrefAddr - 4, 20, adrpAnyInst, adrpAnyMask);
	XPF_ASSERT(branchTarget);

	PFXrefMetric *branchXrefMetric = pfmetric_xref_init(branchTarget, XREF_TYPE_MASK_JUMP);
	__block uint64_t branchTarget2 = 0;
	pfmetric_run(gXPF.kernelTextSection, branchXrefMetric, ^(uint64_t vmaddr, bool *stop){
		branchTarget2 = vmaddr;
		*stop = true;
	});
	pfmetric_free(branchXrefMetric);

	__block uint64_t afterRefAddr = 0;
	if (branchTarget2) {
		PFXrefMetric *branchXrefMetric2 = pfmetric_xref_init(branchTarget2, XREF_TYPE_MASK_JUMP);
		
		pfmetric_run(gXPF.kernelTextSection, branchXrefMetric2, ^(uint64_t vmaddr, bool *stop){
			afterRefAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(branchXrefMetric2);
		if (!afterRefAddr) {
			afterRefAddr = branchTarget2;
		}
	}
	else {
		afterRefAddr = branchTarget;
	}

	XPF_ASSERT(afterRefAddr);

	uint32_t ldrLitAnyInst = 0, ldrLitAnyMask = 0;
	arm64_gen_ldr_lit(ARM64_REG_ANY, OPT_UINT64_NONE, OPT_UINT64_NONE, &ldrLitAnyInst, &ldrLitAnyMask);

	__block uint64_t developer_mode_candidate = 0;
	uint64_t ldrLitAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, afterRefAddr, 25, ldrLitAnyInst, ldrLitAnyMask);
	uint64_t adrpAddAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, afterRefAddr, 50, adrpAnyInst, adrpAnyMask);
	XPF_ASSERT(ldrLitAddr || adrpAddAddr);
	// Depending on the version, developer_mode_storage can either be loaded via adrp+add+ldrb or just via a literal ldr
	
	// Literal ldr:
	// arm64 16.4, 16.5, 16.6, potentially later versions aswell
	// adrp+add:
	// everything else

	// If we find an adrp+add closer than an ldr literal, we need to take that instead
	// This is because there is a false positive ldr literal on 16.0 arm64 right before the adrp+add
	if (!adrpAddAddr || ldrLitAddr > adrpAddAddr) {
		arm64_dec_ldr_lit(pfsec_read32(gXPF.kernelTextSection, ldrLitAddr), ldrLitAddr, &developer_mode_candidate, NULL);
	}
	else {
		developer_mode_candidate = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddAddr + 4);
	}

	__block uint64_t developer_mode_enabled = false;
	if (pfsec_contains_vmaddr(gXPF.kernelDataConstSection, developer_mode_candidate)) {
		// developer_mode_candidate is developer_mode_enabled
		developer_mode_enabled = developer_mode_candidate;
	}
	else {
		// developer_mode_candidate is developer_mode_storage
		PFXrefMetric *storageXref = pfmetric_xref_init(developer_mode_candidate, XREF_TYPE_MASK_POINTER);
		pfmetric_run(gXPF.kernelDataConstSection, storageXref, ^(uint64_t vmaddr, bool *stop) {
			developer_mode_enabled = vmaddr;
			*stop = true;
		});
		pfmetric_free(storageXref);
	}

	return developer_mode_enabled;
}

static uint64_t xpf_find_str_x8_x0_gadget(void)
{
	uint32_t inst[] = (uint32_t[]){
		0x00000000, // str x8, [x0]
		0xd65f03c0  // ret
	};
	arm64_gen_str_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_X(8), ARM64_REG_X(0), OPT_UINT64(0), &inst[0], NULL);

	PFPatternMetric *metric = pfmetric_pattern_init(inst, NULL, sizeof(inst), sizeof(uint32_t));
	__block uint64_t str_x8_x0_gadget = 0;
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		str_x8_x0_gadget = vmaddr;
		*stop = true;
	});
	pfmetric_free(metric);
	return str_x8_x0_gadget;
}

static uint64_t xpf_find_exception_return(void)
{
	uint32_t inst[] = (uint32_t[]){
		0xd5034fdf, // msr daifset, #0xf
		0xd538d083, // mrs x3, tpidr_el1
		0x910002bf  // mov sp, x21
	};

	PFPatternMetric *metric = pfmetric_pattern_init(inst, NULL, sizeof(inst), sizeof(uint32_t));
	__block uint64_t exception_return = 0;
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop){
		exception_return = vmaddr;
		*stop = true;
	});
	pfmetric_free(metric);
	return exception_return;
}

static uint64_t xpf_find_kcall_return(void)
{
	uint32_t inst[] = (uint32_t[]){
		0xf9000260, // str x0, [x19]
		0xa9417bfd, // ldp x29, x30, [sp, #0x10]
		0xa8c24ff4, // ldp x20, x19, [sp], #0x20
		0xd65f03c0, // ret
	};

	PFPatternMetric *metric = pfmetric_pattern_init(inst, NULL, sizeof(inst), sizeof(uint32_t));
	__block uint64_t kcall_return = 0;
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop){
		kcall_return = vmaddr;
		*stop = true;
	});
	return kcall_return;
}

static uint64_t xpf_find_thread_machine_CpuDatap(void)
{
	__block uint64_t stringAddr = 0;
	PFStringMetric *stringMetric = pfmetric_string_init("kernel_debug_early_end() not call on boot processor @%s:%d");
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);

	if (!stringAddr) {
		stringMetric = pfmetric_string_init("\"kernel_debug_early_end() not call on boot processor\"");
		pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
			stringAddr = vmaddr;
			*stop = true;
		});
		pfmetric_free(stringMetric);
	}

	XPF_ASSERT(stringAddr);

	__block uint64_t panicBranch = 0;
	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		if (strcmp(gXPF.darwinVersion, "21.0.0") < 0) {
			// On iOS 14 the branch xref is to the adrp before the panic call 
			panicBranch = vmaddr - (sizeof(uint32_t));
		} else {
			panicBranch = vmaddr - (5 * sizeof(uint32_t));
		}
		*stop = true;
	});
	pfmetric_free(xrefMetric);

	XPF_ASSERT(panicBranch);

	__block uint64_t machine_CpuDatap = 0;
	PFXrefMetric *panicBranchXrefMetric = pfmetric_xref_init(panicBranch, XREF_TYPE_MASK_JUMP);
	pfmetric_run(gXPF.kernelTextSection, panicBranchXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		uint64_t msrTPIDR_EL1Addr = pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 50, 0xd538d080, 0xffffffe0);
		arm64_register threadReg = ARM64_REG_X(pfsec_read32(gXPF.kernelTextSection, msrTPIDR_EL1Addr) & 0x1f);

		uint32_t ldrInst = 0, ldrMask = 0;
		arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, threadReg, OPT_UINT64_NONE, &ldrInst, &ldrMask);

		uint64_t ldr1Addr = pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 50, ldrInst, ldrMask);
		uint64_t ldr2Addr = pfsec_find_prev_inst(gXPF.kernelTextSection, ldr1Addr, 50, ldrInst, ldrMask);
	
		uint32_t readLdrInst = pfsec_read32(gXPF.kernelTextSection, ldr1Addr);
		arm64_dec_ldr_imm(readLdrInst, NULL, NULL, &machine_CpuDatap, NULL, NULL);
		if (machine_CpuDatap == 0) {
			readLdrInst = pfsec_read32(gXPF.kernelTextSection, ldr2Addr);
			arm64_dec_ldr_imm(readLdrInst, NULL, NULL, &machine_CpuDatap, NULL, NULL);
		}
		*stop = true;
	});
	pfmetric_free(panicBranchXrefMetric);

	return machine_CpuDatap;
}

static uint64_t xpf_find_thread_machine_kstackptr(void)
{
	__block uint64_t stringAddr = 0;
	PFStringMetric *stringMetric = pfmetric_string_init("Invalid kernel stack pointer (probable corruption).");
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop) {
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(stringAddr);

	__block uint64_t machine_kstackptr = 0;
	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		uint64_t msrTPIDR_EL1Addr = pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 50, 0xd538d080, 0xffffffe0);
		arm64_register threadReg = ARM64_REG_X(pfsec_read32(gXPF.kernelTextSection, msrTPIDR_EL1Addr) & 0x1f);

		uint32_t ldrInst = 0, ldrMask = 0;
		arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, threadReg, OPT_UINT64_NONE, &ldrInst, &ldrMask);
	
		uint64_t ldrAddr = pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 50, ldrInst, ldrMask);
		uint32_t readLdrInst = pfsec_read32(gXPF.kernelTextSection, ldrAddr);
		arm64_dec_ldr_imm(readLdrInst, NULL, NULL, &machine_kstackptr, NULL, NULL);

		*stop = true;
	});
	pfmetric_free(xrefMetric);

	return machine_kstackptr;
}

static uint64_t xpf_find_thread_machine_contextData(void)
{
	uint32_t inst[3] = {
		0xd5184100, // msr sp_el0, x0
		0xa8c107e0, // ldp x0, x1, [sp], #0x10
		0xd50040bf, // msr spsel, #0
	};
	uint32_t mask[3] = {
		0xffffffff,
		0xffffffff,
		0xffffffff,
	};

	__block uint64_t machine_contextData = 0;
	PFPatternMetric *patternMetric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	pfmetric_run(gXPF.kernelTextSection, patternMetric, ^(uint64_t vmaddr, bool *stop) {
		uint16_t imm = 0;
		arm64_dec_add_imm(pfsec_read32(gXPF.kernelTextSection, vmaddr - 12), NULL, NULL, &imm);
		machine_contextData = imm;
		*stop = true;
	});
	pfmetric_free(patternMetric);

	return machine_contextData;
}

// actually, function finding name is `_LowResetVectorBase`
static uint64_t xpf_find_iorvbar(void)
{
	uint32_t inst[1] = {
		0xd510109f, // msr OSLAR_EL1, xzr
	};
	uint32_t mask[1] = {
		0xffffffff,
	};

	__block uint64_t iorvbar = 0;
	PFPatternMetric *patternMetric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	pfmetric_run(gXPF.kernelTextSection, patternMetric, ^(uint64_t vmaddr, bool *stop) {
		// IORVBAR is always page-aligned, and the instruction we look for is always at an offset of +0x400
		if ((vmaddr & 0x3FFF) == 0x400) {
			iorvbar = vmaddr & ~0x3FFF;
			*stop = true;
		}
	});
	return iorvbar;
}

void xpf_common_init(void)
{
	xpf_item_register("kernelSymbol.start_first_cpu", xpf_find_start_first_cpu, NULL);
	xpf_item_register("kernelConstant.kernel_el", xpf_find_kernel_el, NULL);
	xpf_item_register("kernelSymbol.cpu_ttep", xpf_find_cpu_ttep, NULL);
	xpf_item_register("kernelSymbol.fatal_error_fmt", xpf_find_fatal_error_fmt, NULL);
	xpf_item_register("kernelSymbol.kalloc_data_external", xpf_find_kalloc_data_external, NULL);
	xpf_item_register("kernelSymbol.kfree_data_external", xpf_find_kfree_data_external, NULL);
	xpf_item_register("kernelSymbol.allproc", xpf_find_allproc, NULL);

	if(gXPF.isSPTMDevice)
		xpf_item_register("kernelSymbol.arm_vm_init", xpf_sptm_find_arm_vm_init, NULL);
	else
		xpf_item_register("kernelSymbol.arm_vm_init", xpf_find_arm_vm_init, NULL);

	xpf_item_register("kernelSymbol.phystokv", xpf_find_phystokv, NULL);

	xpf_item_register("kernelSymbol.gVirtBase", xpf_find_arm_vm_init_reference, (void*)(uint32_t)1);
	xpf_item_register("kernelSymbol.gPhysBase", xpf_find_arm_vm_init_reference, (void*)(uint32_t)2);
	xpf_item_register("kernelSymbol.gPhysSize", xpf_find_arm_vm_init_reference, (void*)(uint32_t)5);
	xpf_item_register("kernelSymbol.ptov_table", xpf_find_ptov_table, NULL);

	xpf_item_register("kernelSymbol.pmap_bootstrap", xpf_find_pmap_bootstrap, NULL);
	xpf_item_register("kernelSymbol.pointer_mask", xpf_find_pointer_mask_symbol, NULL);
	xpf_item_register("kernelConstant.pointer_mask", xpf_find_pointer_mask, NULL);
	xpf_item_register("kernelConstant.T1SZ_BOOT", xpf_find_T1SZ_BOOT, NULL);
	xpf_item_register("kernelConstant.ARM_TT_L1_INDEX_MASK", xpf_find_ARM_TT_L1_INDEX_MASK, NULL);

	xpf_item_register("kernelConstant.PT_INDEX_MAX", xpf_find_PT_INDEX_MAX, NULL);

	xpf_item_register("kernelSymbol.vm_page_array_beginning_addr", xpf_find_vm_reference, (void *)(uint32_t)1);
	xpf_item_register("kernelSymbol.vm_page_array_ending_addr", xpf_find_vm_reference, (void *)(uint32_t)2);
	xpf_item_register("kernelSymbol.vm_first_phys_ppnum", xpf_find_vm_reference, (void *)(uint32_t)3);

	xpf_item_register("kernelSymbol.task_crashinfo_release_ref", xpf_find_task_crashinfo_release_ref, NULL);
	xpf_item_register("kernelSymbol.task_collect_crash_info", xpf_find_task_collect_crash_info, NULL);
	xpf_item_register("kernelStruct.task.itk_space", xpf_find_task_itk_space, NULL);

	xpf_item_register("kernelStruct.vm_map.pmap", xpf_find_vm_map_pmap, NULL);
	xpf_item_register("kernelStruct.proc.struct_size", xpf_find_proc_struct_size, NULL);

	xpf_item_register("kernelSymbol.perfmon_dev_open", xpf_find_perfmon_dev_open, NULL);
	xpf_item_register("kernelSymbol.perfmon_devices", xpf_find_perfmon_devices, NULL);
	xpf_item_register("kernelSymbol.vn_kqfilter", xpf_find_vn_kqfilter, NULL);
	xpf_item_register("kernelSymbol.cdevsw", xpf_find_cdevsw, NULL);

	xpf_item_register("kernelSymbol.proc_apply_sandbox", xpf_find_proc_apply_sandbox, NULL);
	xpf_item_register("kernelSymbol.mac_label_set", xpf_find_mac_label_set, NULL);

	xpf_item_register("kernelSymbol.proc_get_syscall_filter_mask_size", xpf_find_proc_get_syscall_filter_mask_size, NULL);
	xpf_item_register("kernelConstant.nsysent", xpf_find_nsysent, NULL);
	xpf_item_register("kernelConstant.mach_trap_count", xpf_find_mach_trap_count, NULL);
	xpf_item_register("kernelSymbol.mach_kobj_count", xpf_find_mach_kobj_count, NULL);

	xpf_item_register("kernelSymbol.developer_mode_enabled", xpf_find_developer_mode_enabled, NULL);

	xpf_item_register("kernelGadget.str_x8_x0", xpf_find_str_x8_x0_gadget, NULL);
	xpf_item_register("kernelSymbol.exception_return", xpf_find_exception_return, NULL);
	xpf_item_register("kernelGadget.kcall_return", xpf_find_kcall_return, NULL);

	xpf_item_register("kernelStruct.thread.machine_CpuDatap", xpf_find_thread_machine_CpuDatap, NULL);
	xpf_item_register("kernelStruct.thread.machine_kstackptr", xpf_find_thread_machine_kstackptr, NULL);
	xpf_item_register("kernelStruct.thread.machine_contextData", xpf_find_thread_machine_contextData, NULL);

	if(!gXPF.isSPTMDevice)
		xpf_item_register("kernelSymbol.iorvbar", xpf_find_iorvbar, NULL);
}
