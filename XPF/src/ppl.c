#import "ppl.h"
#import "xpf.h"
#include <choma/arm64.h>
#include <choma/PatchFinder.h>

static uint64_t xpf_find_ppl_dispatch_section(void)
{
	uint32_t bAny = 0, bAnyMask = 0, movX15Any = 0, movX15AnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE, &bAny, &bAnyMask);
	arm64_gen_mov_imm('z', ARM64_REG_X(15), OPT_UINT64_NONE, OPT_UINT64(0), &movX15Any, &movX15AnyMask);

	uint32_t pplCallerInst[] = {
		movX15Any,
		bAny,
		movX15Any,
		bAny,
	};
	uint32_t pplCallerMask[] = {
		movX15AnyMask,
		bAnyMask,
		movX15AnyMask,
		bAnyMask,
	};

	__block uint64_t ppl_dispatch_section = 0;
	PFPatternMetric *metric = pfmetric_pattern_init(pplCallerInst,pplCallerMask,sizeof(pplCallerInst), sizeof(uint32_t));
	pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t vmaddr, bool *stop) {
		ppl_dispatch_section = vmaddr;
		*stop = true;
	});
	pfmetric_free(metric);
	return ppl_dispatch_section;
}

static uint64_t xpf_find_ppl_enter(void)
{
	uint64_t ppl_dispatch_section = xpf_item_resolve("kernelSymbol.ppl_dispatch_section");
	XPF_ASSERT(ppl_dispatch_section);
	__block uint64_t ppl_enter = 0;
	arm64_dec_b_l(pfsec_read32(gXPF.kernelTextSection, ppl_dispatch_section+4), ppl_dispatch_section+4, &ppl_enter, NULL);
	return ppl_enter;
}

static uint64_t xpf_find_ppl_bootstrap_dispatch(void)
{
	uint64_t ppl_enter = xpf_item_resolve("kernelSymbol.ppl_enter");
	XPF_ASSERT(ppl_enter);

	uint32_t cbzAny = 0, cbzAnyMask = 0;
	arm64_gen_cb_n_z(OPT_BOOL(false), ARM64_REG_ANY, OPT_UINT64_NONE, &cbzAny, &cbzAnyMask);

	uint64_t cbzPPLDispatchAddr = pfsec_find_next_inst(gXPF.kernelTextSection, ppl_enter, 30, cbzAny, cbzAnyMask);
	if (cbzPPLDispatchAddr) {
		uint64_t ppl_bootstrap_dispatch = 0;
		arm64_dec_cb_n_z(pfsec_read32(gXPF.kernelTextSection, cbzPPLDispatchAddr), cbzPPLDispatchAddr, NULL, NULL, &ppl_bootstrap_dispatch);
		return ppl_bootstrap_dispatch;
	}
	else {
		uint32_t bCondAnyInst = 0, bCondAnyMask = 0;
		arm64_gen_b_c_cond(OPT_BOOL(false), OPT_UINT64_NONE, OPT_UINT64_NONE, ARM64_COND_ANY, &bCondAnyInst, &bCondAnyMask);
		uint64_t bcondPPLDispatchAddr = pfsec_find_next_inst(gXPF.kernelTextSection, ppl_enter, 30, bCondAnyInst, bCondAnyMask);
		XPF_ASSERT(bcondPPLDispatchAddr);

		uint64_t ppl_bootstrap_dispatch = 0;
		arm64_dec_b_c_cond(pfsec_read32(gXPF.kernelTextSection, bcondPPLDispatchAddr), bcondPPLDispatchAddr, &ppl_bootstrap_dispatch, NULL, NULL);
		return ppl_bootstrap_dispatch;
	}
}

static uint64_t xpf_find_ppl_handler_table(void)
{
	uint64_t ppl_bootstrap_dispatch = xpf_item_resolve("kernelSymbol.ppl_bootstrap_dispatch");
	XPF_ASSERT(ppl_bootstrap_dispatch);

	uint32_t addAny = 0, addAnyMask = 0;
	arm64_gen_add_imm(ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &addAny, &addAnyMask);

	uint64_t addAddr = pfsec_find_next_inst(gXPF.kernelTextSection, ppl_bootstrap_dispatch, 30, addAny, addAnyMask);
	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, addAddr);
}

static uint64_t xpf_find_ppl_routine(uint32_t idx)
{
	uint64_t ppl_handler_table = xpf_item_resolve("kernelSymbol.ppl_handler_table");
	XPF_ASSERT(ppl_handler_table);
	return pfsec_read_pointer(gXPF.kernelDataConstSection, ppl_handler_table + (sizeof(uint64_t) * idx));
}

static uint64_t xpf_find_ppl_dispatch_func(uint32_t idx)
{
	uint64_t ppl_dispatch_section = xpf_item_resolve("kernelSymbol.ppl_dispatch_section");
	XPF_ASSERT(ppl_dispatch_section);

	uint32_t movToFind = 0, movMaskToFind = 0;
	arm64_gen_mov_imm('z', ARM64_REG_X(15), OPT_UINT64(idx), OPT_UINT64(0), &movToFind, &movMaskToFind);

	return pfsec_find_next_inst(gXPF.kernelTextSection, ppl_dispatch_section, 1000, movToFind, movMaskToFind);
}

static uint64_t xpf_find_pmap_image4_trust_caches(void)
{
	uint64_t pmap_lookup_in_loaded_trust_caches_internal = xpf_item_resolve("kernelSymbol.pmap_lookup_in_loaded_trust_caches_internal");
	XPF_ASSERT(pmap_lookup_in_loaded_trust_caches_internal);

	uint32_t ldrLitAny = 0, ldrLitAnyMask = 0;
	arm64_gen_ldr_lit(ARM64_REG_ANY, OPT_UINT64_NONE, OPT_UINT64_NONE, &ldrLitAny, &ldrLitAnyMask);
	uint64_t ldrLitAddr = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_lookup_in_loaded_trust_caches_internal, 20, ldrLitAny, ldrLitAnyMask);
	if (ldrLitAddr) {
		uint64_t ldrTarget = 0;
		arm64_dec_ldr_lit(pfsec_read32(gXPF.kernelPPLTextSection, ldrLitAddr), ldrLitAddr, &ldrTarget, NULL);
		return ldrTarget;
	}

	/*uint32_t ldrAny = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAny, &ldrAnyMask);
	uint64_t ldrAddr = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_lookup_in_loaded_trust_caches_internal, 20, ldrAny, ldrAnyMask);
	if (ldrAddr) {
		uint32_t ldrInst = pfsec_read32(gXPF.kernelPPLTextSection, ldrAddr);
		arm64_register reg;
		uint64_t ldrImm = 0;
		arm64_dec_ldr_imm(ldrInst, NULL, &reg, &ldrImm, NULL);
		uint32_t adrpInst = 0, adrpInstAny = 0;
		arm64_gen_adr_p(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, reg, &adrpInst, &adrpInstAny);
		uint64_t adrpAddr = pfsec_find_prev_inst(gXPF.kernelPPLTextSection, ldrAddr, 20, adrpInst, adrpInstAny);
		if (adrpAddr) {
			uint32_t adrpInst = pfsec_read32(gXPF.kernelPPLTextSection, adrpAddr);
			uint64_t adrpTarget = 0;
			arm64_dec_adr_p(adrpInst, adrpAddr, &adrpTarget, NULL, NULL);
			return adrpTarget + ldrImm;
		}
	}*/

	return 0;
}

static uint64_t xpf_find_pmap_query_trust_cache_safe(void)
{
	uint64_t pmap_lookup_in_loaded_trust_caches_internal = xpf_item_resolve("kernelSymbol.pmap_lookup_in_loaded_trust_caches_internal");
	XPF_ASSERT(pmap_lookup_in_loaded_trust_caches_internal);

	uint32_t blAny = 0, blAnyMask = 0;
	arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &blAny, &blAnyMask);

	uint64_t blAddr = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_lookup_in_loaded_trust_caches_internal, 30, blAny, blAnyMask);
	XPF_ASSERT(blAddr);

	uint32_t blInst = pfsec_read32(gXPF.kernelPPLTextSection, blAddr);

	uint64_t pmap_query_trust_cache_safe = 0;
	arm64_dec_b_l(blInst, blAddr, &pmap_query_trust_cache_safe, NULL);
	return pmap_query_trust_cache_safe;
}

static uint64_t xpf_find_ppl_trust_cache_rt(void)
{
	uint64_t pmap_query_trust_cache_safe = xpf_item_resolve("kernelSymbol.pmap_query_trust_cache_safe");
	XPF_ASSERT(pmap_query_trust_cache_safe);

	uint32_t pacMovInst = 0, pacMovMask = 0;
	arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64(0x6653), OPT_UINT64(0), &pacMovInst, &pacMovMask);
	uint64_t pacMovAddr = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_query_trust_cache_safe, 50, pacMovInst, pacMovMask);
	XPF_ASSERT(pacMovAddr);

	uint32_t addX0AnyInst = 0, addX0AnyMask = 0;
	arm64_gen_add_imm(ARM64_REG_X(0), ARM64_REG_ANY, OPT_UINT64_NONE, &addX0AnyInst, &addX0AnyMask);
	uint64_t ppl_trust_cache_rt_refAddr = pfsec_find_prev_inst(gXPF.kernelPPLTextSection, pacMovAddr, 10, addX0AnyInst, addX0AnyMask);

	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelPPLTextSection, ppl_trust_cache_rt_refAddr);
}

static uint64_t xpf_find_load_static_trust_cache(void)
{
	PFStringMetric *trustcacheSegmentIsZeroMetric = pfmetric_string_init("trust cache segment is zero length but trust caches are available: %u @%s:%d");
	__block uint64_t trustcacheSegmentIsZeroAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, trustcacheSegmentIsZeroMetric, ^(uint64_t vmaddr, bool *stop) {
		trustcacheSegmentIsZeroAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(trustcacheSegmentIsZeroMetric);
	XPF_ASSERT(trustcacheSegmentIsZeroAddr);

	__block uint64_t load_static_trust_cache_mid = 0;
	PFXrefMetric *trustcacheSegmentIsZeroXrefMetric = pfmetric_xref_init(trustcacheSegmentIsZeroAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, trustcacheSegmentIsZeroXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		load_static_trust_cache_mid = vmaddr;
		*stop = true;
	});
	pfmetric_free(trustcacheSegmentIsZeroXrefMetric);
	XPF_ASSERT(load_static_trust_cache_mid);

	uint64_t ret = pfsec_find_function_start(gXPF.kernelTextSection, load_static_trust_cache_mid);
	printf("load_static_trust_cache found? 0x%llx\n", ret);
	return ret;
}

static uint64_t xpf_find_sptm_trust_cache_rt(void)
{
	uint64_t load_static_trust_cache = xpf_item_resolve("kernelSymbol.load_static_trust_cache");
	XPF_ASSERT(load_static_trust_cache);

	// search ADRP xN, #_trust_cache_rt@PAGE;
	uint32_t inst[] = {
		0x90000000, // adrp xN, #0x...
		0xf9400000, // ldr xN, [xN, #0x...]
		0xB4000000, // cbz xN, loc_...
	};
	uint32_t mask[] = {
		0x9F000000,
		0xFFC00000,
		0xFF000000,
	};

	PFPatternMetric *metric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	__block uint64_t adrpAddr = 0;
	pfmetric_run_in_range(gXPF.kernelTextSection, load_static_trust_cache, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(metric);

	uint64_t ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
	printf("trust_cache_rt found? 0x%llx\n", ret);
	return ret;
}

static uint64_t xpf_find_pmap_pin_kernel_pages(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_pin_kernel_pages");
	__block uint64_t pmap_pin_kernel_pages_stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		pmap_pin_kernel_pages_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(pmap_pin_kernel_pages_stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_pin_kernel_pages_stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_pin_kernel_pages = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_pin_kernel_pages = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	XPF_ASSERT(pmap_pin_kernel_pages);

	return pmap_pin_kernel_pages;
}

static uint64_t xpf_find_pmap_pin_kernel_pages_reference(uint32_t idx)
{
	uint64_t pmap_pin_kernel_pages = xpf_item_resolve("kernelSymbol.pmap_pin_kernel_pages");
	XPF_ASSERT(pmap_pin_kernel_pages);

	uint32_t ldrAnyInst = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAnyInst, &ldrAnyMask);

	__block uint64_t ref = 0;
	__block uint32_t f = 0;
	PFPatternMetric *metric = pfmetric_pattern_init(&ldrAnyInst, &ldrAnyMask, sizeof(ldrAnyInst), sizeof(uint32_t));
	pfmetric_run_in_range(gXPF.kernelTextSection, pmap_pin_kernel_pages, -1, metric, ^(uint64_t vmaddr, bool *stop) {
		arm64_register destinationReg;
		arm64_dec_ldr_imm(pfsec_read32(gXPF.kernelTextSection, vmaddr), &destinationReg, NULL, NULL, NULL, NULL);
		// On some kernels there is one additional ldr before the ones we're looking for
		// As this always loads into x0 and the other ones don't, we can filter it out based on that metric
		if (ARM64_REG_GET_NUM(destinationReg) != 0) {
			if (f == idx) {
				ref = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, vmaddr);
				*stop = true;
			}
			f++;
		}
	});

	return ref;
}

static uint64_t xpf_find_phys_attribute_clear_with_flush_range(void) {
	__block uint64_t phys_attribute_clear_stringAddr = 0;
	PFStringMetric *physAttributeMetric = pfmetric_string_init("phys_attribute_clear(%#010x,%#010x,%#010x,%p,%p): invalid options @%s:%d");
	pfmetric_run(gXPF.kernelStringSection, physAttributeMetric, ^(uint64_t vmaddr, bool *stop) {
		phys_attribute_clear_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(physAttributeMetric);
	XPF_ASSERT(phys_attribute_clear_stringAddr);

	__block uint64_t phys_attribute_clear_with_flush_range = 0;
	PFXrefMetric *physAttributeXrefMetric = pfmetric_xref_init(phys_attribute_clear_stringAddr, XREF_TYPE_MASK_REFERENCE);
	pfmetric_run(gXPF.kernelTextSection, physAttributeXrefMetric, ^(uint64_t vmaddr, bool *stop) {
		phys_attribute_clear_with_flush_range = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(physAttributeXrefMetric);
	printf("phys_attribute_clear_with_flush_range found? 0x%llx\n", phys_attribute_clear_with_flush_range);
	return phys_attribute_clear_with_flush_range;
}

static uint64_t xpf_find_phys_attribute_clear_with_flush_range_reference(uint32_t idx)
{
	uint64_t phys_attribute_clear_with_flush_range = xpf_item_resolve("kernelSymbol.phys_attribute_clear_with_flush_range");
	XPF_ASSERT(phys_attribute_clear_with_flush_range);

	uint32_t inst[] = {
		0x90000000, // adrp xN, #0x...
		0xf9400000, // ldr xN, [xN, #0x...]
	};
	uint32_t mask[] = {
		0x9F000000,
		0xFFC00000,
	};

	// find vm_first_phys from 1st adrp
	uint64_t ret = 0;
	PFPatternMetric *metric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	__block uint64_t adrpAddr = 0;
	pfmetric_run_in_range(gXPF.kernelTextSection, phys_attribute_clear_with_flush_range, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});
	if(idx == 0) {
		ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
		printf("vm_first_phys found? 0x%llx\n", ret);
	}

	// find vm_last_phys from 2nd adrp
	pfmetric_run_in_range(gXPF.kernelTextSection, adrpAddr+8, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});
	if(idx == 1) {
		ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
		printf("vm_last_phys found? 0x%llx\n", ret);
	}

	// find pp_attr_table from 3rd adrp
	pfmetric_run_in_range(gXPF.kernelTextSection, adrpAddr+8, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});
	if(idx == 2) {
		ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
		printf("pp_attr_table found? 0x%llx\n", ret);
	}

	pfmetric_free(metric);

	return ret;
}

static uint64_t xpf_find_pmap_enter_pv(void)
{
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_enter_pv");
	XPF_ASSERT(stringMetric);

	__block uint64_t pmap_enter_pv_stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		pmap_enter_pv_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(pmap_enter_pv_stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_enter_pv_stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_enter_pv = 0;
	pfmetric_run(gXPF.kernelPPLTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_enter_pv = pfsec_find_function_start(gXPF.kernelPPLTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);

	return pmap_enter_pv;
}

static uint64_t xpf_sptm_find_pv_head_table(void)
{
	//find `pte_update_wiredcnt` by xref "pmap %p (pte %p): wired count underflow @%s:%d"
	PFStringMetric *stringMetric = pfmetric_string_init("pmap %p (pte %p): wired count underflow @%s:%d");
	XPF_ASSERT(stringMetric);

	__block uint64_t wired_count_underflow_stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		wired_count_underflow_stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(wired_count_underflow_stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(wired_count_underflow_stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pte_update_wiredcnt = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pte_update_wiredcnt = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	printf("pte_update_wiredcnt found? 0x%llx\n", pte_update_wiredcnt);
	
	// Find second adrp; first is vm_first_phys, second is pv_head_table
	uint32_t inst[] = {
		0x90000000, // adrp xN, #0x...
		0xf9400000, // ldr xN, [xN, #0x...]
	};
	uint32_t mask[] = {
		0x9F000000,
		0xFFC00000,
	};
	
	PFPatternMetric *metric = pfmetric_pattern_init(inst, mask, sizeof(inst), sizeof(uint32_t));
	__block uint64_t adrpAddr = 0;
	pfmetric_run_in_range(gXPF.kernelTextSection, pte_update_wiredcnt, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});

	pfmetric_run_in_range(gXPF.kernelTextSection, adrpAddr+8, -1, metric, ^(uint64_t vmaddr, bool *stop){
		adrpAddr = vmaddr;
		*stop = true;
	});
	uint64_t ret = pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelTextSection, adrpAddr+4);
	printf("pv_head_table found? 0x%llx\n", ret);
	return ret;
}

static uint64_t xpf_find_pv_head_table(void)
{
	uint64_t pmap_enter_pv = xpf_item_resolve("kernelSymbol.pmap_enter_pv");
	XPF_ASSERT(pmap_enter_pv);

	uint32_t ldrAnyInst = 0, ldrAnyMask = 0;
	arm64_gen_ldr_imm(0, LDR_STR_TYPE_UNSIGNED, ARM64_REG_ANY, ARM64_REG_ANY, OPT_UINT64_NONE, &ldrAnyInst, &ldrAnyMask);

	uint64_t ref = pfsec_find_next_inst(gXPF.kernelPPLTextSection, pmap_enter_pv, 0, ldrAnyInst, ldrAnyMask);
	XPF_ASSERT(ref);
	return pfsec_arm64_resolve_adrp_ldr_str_add_reference_auto(gXPF.kernelPPLTextSection, ref);
}

static uint64_t xpf_sptm_find_pmap_enter_options_addr(void)
{
	// Find `pmap_enter_options_internal` by xref "pmap_enter_options(): attempt to add executable mapping to kernel_pmap @%s:%d"
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_enter_options(): attempt to add executable mapping to kernel_pmap @%s:%d");
	XPF_ASSERT(stringMetric);

	__block uint64_t stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_enter_options_addr = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_enter_options_addr = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	printf("pmap_enter_options_addr found? 0x%llx\n", pmap_enter_options_addr);
	return pmap_enter_options_addr;
}

static uint64_t xpf_find_pmap_enter_options_addr(void)
{
	uint64_t pmap_enter_options_ppl = xpf_item_resolve("kernelSymbol.pmap_enter_options_ppl");
	XPF_ASSERT(pmap_enter_options_ppl);

	__block uint64_t pmap_enter_options_addr = 0;

	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_enter_options_ppl, XREF_TYPE_MASK_CALL);
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		// Find an Xref, that within the the previous 25 instructions...
		if (pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 25, 0x12000000, 0x7F800000) && // Has an AND
			pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 25, 0x32000000, 0x7F800000) && // Has an ORR
		   !pfsec_find_prev_inst(gXPF.kernelTextSection, vmaddr, 25, 0x53000000, 0x7F800000)) { // Has no LSL
			pmap_enter_options_addr = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
			*stop = true;
		}
	});
	pfmetric_free(xrefMetric);

	return pmap_enter_options_addr;
}

static uint64_t xpf_sptm_find_pmap_remove_options(void)
{
    // Find `pmap_remove_options` by xref "pmap_remove_options_internal"
	PFStringMetric *stringMetric = pfmetric_string_init("pmap_remove_options_internal");
	XPF_ASSERT(stringMetric);

	__block uint64_t stringAddr = 0;
	pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t vmaddr, bool *stop){
		stringAddr = vmaddr;
		*stop = true;
	});
	pfmetric_free(stringMetric);
	XPF_ASSERT(stringAddr);

	PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddr, XREF_TYPE_MASK_REFERENCE);
	__block uint64_t pmap_remove_options = 0;
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		pmap_remove_options = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
		*stop = true;
	});
	pfmetric_free(xrefMetric);
	printf("pmap_remove_options found? 0x%llx\n", pmap_remove_options);
	return pmap_remove_options;
}

static uint64_t xpf_find_pmap_remove_options(void)
{
    uint64_t pmap_remove_options_ppl = xpf_item_resolve("kernelSymbol.pmap_remove_options_ppl");
	XPF_ASSERT(pmap_remove_options_ppl);

	__block uint64_t pmap_remove_options = 0;

	PFXrefMetric *xrefMetric = pfmetric_xref_init(pmap_remove_options_ppl, XREF_TYPE_MASK_CALL);
	pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t vmaddr, bool *stop) {
		if (pfsec_read32(gXPF.kernelTextSection, vmaddr - 4) != 0x52802003) {
			pmap_remove_options = pfsec_find_function_start(gXPF.kernelTextSection, vmaddr);
			*stop = true;
		}
	});
	pfmetric_free(xrefMetric);

	return pmap_remove_options;
}

void xpf_ppl_init(void)
{
	if (gXPF.kernelIsArm64e) {
		xpf_item_register("kernelSymbol.ppl_enter", xpf_find_ppl_enter, NULL);
		xpf_item_register("kernelSymbol.ppl_bootstrap_dispatch", xpf_find_ppl_bootstrap_dispatch, NULL);
		xpf_item_register("kernelSymbol.ppl_dispatch_section", xpf_find_ppl_dispatch_section, NULL);
		xpf_item_register("kernelSymbol.ppl_handler_table", xpf_find_ppl_handler_table, NULL);
		xpf_item_register("kernelSymbol.pmap_enter_options_internal", xpf_find_ppl_routine, (void *)(uint32_t)10);
		xpf_item_register("kernelSymbol.pmap_enter_options_ppl", xpf_find_ppl_dispatch_func, (void *)(uint32_t)10);
		xpf_item_register("kernelSymbol.pmap_remove_options_ppl", xpf_find_ppl_dispatch_func, (void *)(uint32_t)23);
		xpf_item_register("kernelSymbol.pmap_lookup_in_loaded_trust_caches_internal", xpf_find_ppl_routine, (void *)(uint32_t)41);
		xpf_item_register("kernelSymbol.pmap_pin_kernel_pages", xpf_find_pmap_pin_kernel_pages, NULL);
		xpf_item_register("kernelSymbol.pmap_enter_pv", xpf_find_pmap_enter_pv, NULL);


		if(gXPF.isSPTMDevice) {
			xpf_item_register("kernelSymbol.pmap_enter_options_addr", xpf_sptm_find_pmap_enter_options_addr, NULL);
			xpf_item_register("kernelSymbol.pmap_remove_options", xpf_sptm_find_pmap_remove_options, NULL);
			xpf_item_register("kernelSymbol.phys_attribute_clear_with_flush_range", xpf_find_phys_attribute_clear_with_flush_range, NULL);
			xpf_item_register("kernelSymbol.vm_first_phys", xpf_find_phys_attribute_clear_with_flush_range_reference, (void *)(uint32_t)0);
			xpf_item_register("kernelSymbol.vm_last_phys", xpf_find_phys_attribute_clear_with_flush_range_reference, (void *)(uint32_t)1);
			xpf_item_register("kernelSymbol.pp_attr_table", xpf_find_phys_attribute_clear_with_flush_range_reference, (void *)(uint32_t)2);
			xpf_item_register("kernelSymbol.pv_head_table", xpf_sptm_find_pv_head_table, NULL);
		}
		else {
			xpf_item_register("kernelSymbol.pmap_enter_options_addr", xpf_find_pmap_enter_options_addr, NULL);
			xpf_item_register("kernelSymbol.pmap_remove_options", xpf_find_pmap_remove_options, NULL);
			xpf_item_register("kernelSymbol.vm_first_phys", xpf_find_pmap_pin_kernel_pages_reference, (void *)(uint32_t)0);
			xpf_item_register("kernelSymbol.vm_last_phys", xpf_find_pmap_pin_kernel_pages_reference, (void *)(uint32_t)1);
			xpf_item_register("kernelSymbol.pp_attr_table", xpf_find_pmap_pin_kernel_pages_reference, (void *)(uint32_t)2);
			xpf_item_register("kernelSymbol.pv_head_table", xpf_find_pv_head_table, NULL);
		}
		

		if (strcmp(gXPF.darwinVersion, "22.0.0") >= 0) {
			// iOS >=16
			xpf_item_register("kernelSymbol.pmap_query_trust_cache_safe", xpf_find_pmap_query_trust_cache_safe, NULL);
			if(gXPF.isSPTMDevice) {
				xpf_item_register("kernelSymbol.load_static_trust_cache", xpf_find_load_static_trust_cache, NULL);
				xpf_item_register("kernelSymbol.trust_cache_rt", xpf_find_sptm_trust_cache_rt, NULL);
			}
			else {
				xpf_item_register("kernelSymbol.trust_cache_rt", xpf_find_ppl_trust_cache_rt, NULL);
			}
		}
		else {
			// iOS <=15
			xpf_item_register("kernelSymbol.pmap_image4_trust_caches", xpf_find_pmap_image4_trust_caches, NULL);
		}
	}
}