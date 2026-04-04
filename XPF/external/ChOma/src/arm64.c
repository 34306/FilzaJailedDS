#include "arm64.h"
#include "Util.h"
#include <stdio.h>

#define ADRP_PAGE_SIZE 0x1000
#define ADRP_PAGE_MASK 0x0fff

uint8_t arm64_reg_type_get_width(arm64_register_type type)
{
    switch (type) {
        case ARM64_REG_TYPE_X:
        return 8;
        case ARM64_REG_TYPE_W:
        return 4;

        case ARM64_REG_TYPE_Q:
        return 16;
        case ARM64_REG_TYPE_D:
        return 8;
        case ARM64_REG_TYPE_S:
        return 4;
        case ARM64_REG_TYPE_H:
        return 2;
        case ARM64_REG_TYPE_B:
        return 1;
    }
}

const char *arm64_reg_type_get_string(arm64_register_type type)
{
    switch (type) {
        case ARM64_REG_TYPE_X:
        return "x";
        case ARM64_REG_TYPE_W:
        return "w";

        case ARM64_REG_TYPE_Q:
        return "q";
        case ARM64_REG_TYPE_D:
        return "d";
        case ARM64_REG_TYPE_S:
        return "s";
        case ARM64_REG_TYPE_H:
        return "h";
        case ARM64_REG_TYPE_B:
        return "b";
    }
    return "";
}

const char *arm64_reg_get_type_string(arm64_register reg)
{
    return arm64_reg_type_get_string(ARM64_REG_GET_TYPE(reg));
}

int arm64_gen_b_l(optional_bool optIsBl, optional_uint64_t optOrigin, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut)
{
    bool isBl = false;
    if (OPT_BOOL_IS_SET(optIsBl)) {
        isBl = OPT_BOOL_GET_VAL(optIsBl);
    }

    uint64_t origin = 0;
    uint64_t target = 0;
    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        *maskOut = 0xffffffff;
        origin = OPT_UINT64_GET_VAL(optOrigin);
        target = OPT_UINT64_GET_VAL(optTarget);
    }
    else {
        if (!OPT_BOOL_IS_SET(optIsBl)) {
            *maskOut = 0x7c000000;
        }
        else {
            *maskOut = 0xfc000000;
        }
    }

    int64_t offset = ((int64_t)target - (int64_t)origin) / 4;
    *bytesOut = (isBl ? 0x94000000 : 0x14000000) | (uint32_t)(offset & 0x3ffffff);
    return 0;
}

int arm64_dec_b_l(uint32_t inst, uint64_t origin, uint64_t *targetOut, bool *isBlOut)
{
    if ((inst & 0xfc000000) == 0x14000000) {
        if (isBlOut) *isBlOut = false;
    }
    else if ((inst & 0xfc000000) == 0x94000000) {
        if (isBlOut) *isBlOut = true;
    }
    else {
        return -1;
    }

    int64_t offset = sxt64((inst & 0x3ffffff), 26);
    if (targetOut) *targetOut = origin + (offset * 4);
    return 0;
}

int arm64_gen_b_c_cond(optional_bool optIsBc, optional_uint64_t optOrigin, optional_uint64_t optTarget, arm64_cond optCond, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t inst = 0x54000000;
    uint32_t mask = 0xff000000;

    if (OPT_BOOL_IS_SET(optIsBc)) {
        mask |= (1 << 4);
        inst |= (OPT_BOOL_GET_VAL(optIsBc) << 4);
    }

    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        uint64_t origin = OPT_UINT64_GET_VAL(optOrigin);
        uint64_t target = OPT_UINT64_GET_VAL(optTarget);
        int64_t offset = (int64_t)target - (int64_t)origin;
        if (offset < -0x100000 || offset > 0x100000) return -1; // +/-1MB max
        inst |= ((offset / 4) << 5);
        mask |= (0x7ffff << 5);
    }

    if (ARM64_COND_IS_SET(optCond)) {
        mask |= 0xf;
        inst |= ARM64_COND_GET_VAL(optCond);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_b_c_cond(uint32_t inst, uint64_t origin, uint64_t *targetOut, arm64_cond *condOut, bool *isBcOut)
{
    if ((inst & 0xff000000) != 0x54000000) return -1;

    if (targetOut) {
        int64_t offset = sxt64(((inst >> 5) & 0x7ffff), 19);
        *targetOut = origin + (offset * 4);
    }

    if (condOut) {
        *condOut = ARM64_COND(inst & 0xf);
    }

    if (isBcOut) {
        *isBcOut = inst & (1 << 4);
    }

    return 0;
}

int arm64_gen_adr_p(optional_bool optIsAdrp, optional_uint64_t optOrigin, optional_uint64_t optTarget, arm64_register reg, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(reg)) return -1;

    bool isAdrp = false;

    uint32_t inst = (1 << 28);
    uint32_t mask = 0x1f000000;

    if (OPT_BOOL_IS_SET(optIsAdrp)) {
        mask |= (1 << 31);
        isAdrp = OPT_BOOL_GET_VAL(optIsAdrp);
        if (isAdrp) {
            inst |= (1 << 31);
        }
    }

    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        mask |= 0x60ffffe0;
        
        uint64_t origin = OPT_UINT64_GET_VAL(optOrigin);
        uint64_t target = OPT_UINT64_GET_VAL(optTarget);
        if (isAdrp) {
            origin &= ~ADRP_PAGE_MASK;
            target &= ~ADRP_PAGE_MASK;
        }
        int64_t offset = ((int64_t)target - (int64_t)origin);
        if (isAdrp) {
            offset = (offset >> 12);
        }

        // +- 1MB
        if (offset > 0x100000 || offset < -0x100000) {
            // Offset too big
            return -1;
        }

        uint64_t unsignedOffset = offset & 0x1FFFFF;
        inst |= ((unsignedOffset &  0x3) << 29);
        inst |= ((unsignedOffset & ~0x3) << 3);
    }

    if (!ARM64_REG_IS_ANY(reg)) {
        if (ARM64_REG_IS_W(reg)) return -1;
        inst |= ARM64_REG_GET_NUM(reg);;
        mask |= 0x1F;
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_adr_p(uint32_t inst, uint64_t origin, uint64_t *targetOut, arm64_register *registerOut, bool *isAdrpOut)
{
    bool isAdrp = false;
    if ((inst & 0x9f000000) == 0x90000000) {
        isAdrp = true;
    }
    else if ((inst & 0x9f000000) == 0x10000000) {
        isAdrp = false;
    }
    else {
        return -1;
    }

    if (targetOut) {
        uint64_t offset = ((inst >> 29) & 0x3) | ((inst >> 3) & 0x1ffffc);
        int64_t signedOffset = 0;
        if (isAdrp) {
            offset = (offset << 12);
            origin &= ~ADRP_PAGE_MASK;
            signedOffset = sxt64(offset, 33);
        }
        else {
            signedOffset = sxt64(offset, 21);
        }
        *targetOut = origin + signedOffset;
    }

    if (registerOut) *registerOut = ARM64_REG_X(inst & 0x1f);
    if (isAdrpOut) *isAdrpOut = isAdrp;
    return 0;
}

int arm64_gen_mov_imm(char type, arm64_register destinationReg, optional_uint64_t optImm, optional_uint64_t optShift, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(destinationReg)) return -1;

    uint32_t inst = 0x12800000;
    uint32_t mask = 0x7f800000; // Note this mask includes the type as it's not optional

    switch (type) {
        case 'k': {
            inst |= (1 << 30) | (1 << 29);
            break;
        }

        case 'n': {
            break;
        }

        case 'z': {
            inst |= (1 << 30);
            break;
        }

        default: {
            return -1;
        }
    }

    if (!ARM64_REG_IS_ANY(destinationReg)) {
        mask |= (1 << 31);
        if (ARM64_REG_IS_W(destinationReg)) {
            if (OPT_UINT64_IS_SET(optShift)) {
                uint64_t shift = OPT_UINT64_GET_VAL(optShift);
                if (shift != 0 && shift != 16) return -1;
            }
        }
        else {
            inst |= (1 << 31);
            if (OPT_UINT64_IS_SET(optShift)) {
                uint64_t shift = OPT_UINT64_GET_VAL(optShift);
                if (shift != 0 && shift != 16 && shift != 32 && shift != 48) return -1;
            }
        }

        mask |= 0x1f;
        inst |= ARM64_REG_GET_NUM(destinationReg);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm);
        if (imm > UINT16_MAX) return -1;
        mask |= 0x1fffe0;
        inst |= ((uint32_t)imm << 5);
    }

    if (OPT_UINT64_IS_SET(optShift)) {
        uint64_t shift = OPT_UINT64_GET_VAL(optShift);
        inst |= ((shift / 16) & 0b11) << 21;
        mask |= (0b11 << 21);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_mov_imm(uint32_t inst, arm64_register *destinationRegOut, uint64_t *immOut, uint64_t *shiftOut, char *typeOut)
{
    if ((inst & 0x1f800000) != 0x12800000) return -1;

    char type = 0;
    uint8_t opc = ((inst >> 29) & 0b11);
    switch (opc) {
        case 0b11: {
            type = 'k';
            break;
        }
        case 0b00: {
            type = 'n';
            break;
        }
        case 0b10: {
            type = 'z';
            break;
        }
        default: {
            return -1;
        }
    } 

    if (destinationRegOut) {
        bool is64 = inst & (1 << 31);
        *destinationRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1f);
    }
    if (immOut) {
        *immOut = (inst >> 5) & 0xffff;
    }
    if (shiftOut) {
        *shiftOut = ((inst >> 21) & 0b11) * 16;
    }
    if (typeOut) {
        *typeOut = type;
    }

    return 0;
}

int arm64_gen_mov_reg(arm64_register destinationReg, arm64_register sourceReg, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t inst = 0x2a0003e0;
    uint32_t mask = 0x7fe0ffe0;

    if (!ARM64_REG_IS_ANY(destinationReg) && !ARM64_REG_IS_ANY(sourceReg)) {
        if (ARM64_REG_IS_W(destinationReg) != ARM64_REG_IS_W(sourceReg)) return -1;
    }

    if (!ARM64_REG_IS_ANY(destinationReg)) {
        mask |= (1 << 31);
        inst |= (ARM64_REG_IS_X(destinationReg) << 31);

        inst |= (ARM64_REG_GET_NUM(destinationReg));
        mask |= 0x1f;
    }

    if (!ARM64_REG_IS_ANY(sourceReg)) {
        mask |= (1 << 31);
        inst |= (ARM64_REG_IS_X(sourceReg) << 31);

        inst |= (ARM64_REG_GET_NUM(sourceReg) << 16);
        mask |= (0x1f << 16);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;

    return 0;
}

int arm64_dec_mov_reg(uint32_t inst, arm64_register *destinationRegOut, arm64_register *sourceRegOut)
{
    if ((inst & 0x7fe0ffe0) != 0x2a0003e0) return -1;

    bool is64 = inst & (1 << 31);
    if (destinationRegOut) *destinationRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1f);
    if (sourceRegOut) *sourceRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, (inst >> 16) & 0x1f);

    return 0;
}

int arm64_gen_add_imm(arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(destinationReg)) return -1;
    if (ARM64_REG_IS_ANY_VECTOR(sourceReg)) return -1;

    if (!ARM64_REG_IS_ANY(destinationReg) && !ARM64_REG_IS_ANY(sourceReg)) {
        // if both regs are set and have a mismatching width, abort
        if (ARM64_REG_IS_W(destinationReg) != ARM64_REG_IS_W(sourceReg)) return -1;
    }

    uint32_t inst = 0x11000000;
    uint32_t mask = 0x7f800000;

    // if one is set and 32 bit, include 32 bit in mask and set it in inst
    if (!ARM64_REG_IS_ANY(destinationReg)) {
        mask |= (1 << 31);
        inst |= ((uint32_t)(ARM64_REG_IS_X(destinationReg)) << 31);
    }
    else if (!ARM64_REG_IS_ANY(sourceReg)) {
        mask |= (1 << 31);
        inst |= ((uint32_t)(ARM64_REG_IS_X(sourceReg)) << 31);
    }

    if (!ARM64_REG_IS_ANY(destinationReg)) {
        mask |= 0x1F;
        inst |= (uint32_t)(ARM64_REG_GET_NUM(destinationReg));
    }
    if (!ARM64_REG_IS_ANY(sourceReg)) {
        mask |= (0x1F << 5);
        inst |= ((uint32_t)(ARM64_REG_GET_NUM(destinationReg)) << 5);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm);
        if (imm & ~0xFFF) return -1;
        mask |= (0xFFF << 10);
        inst |= (imm << 10);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_add_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *sourceRegOut, uint16_t *immOut)
{
    if ((inst & 0x7f800000) != 0x11000000) return -1;
    bool is64 = (inst & 0x80000000);
    bool shift = (inst & 0x400000);

    if (destinationRegOut) {
        *destinationRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1F);
    }
    if (sourceRegOut) {
        *sourceRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, (inst >> 5) & 0x1F);
    }

    if (immOut) {
        uint16_t imm = ((inst >> 10) & 0xFFF);
        if (shift) {
            imm = (imm << 12);
        }
        *immOut = imm;
    }

    return 0;
}

int arm64_gen_sub_imm(arm64_register destinationReg, arm64_register sourceReg, optional_uint64_t optImm, optional_bool optS, uint32_t *bytesOut, uint32_t *maskOut) {
  if (ARM64_REG_IS_ANY_VECTOR(destinationReg)) return -1;
  if (ARM64_REG_IS_ANY_VECTOR(sourceReg)) return -1;

  if (!ARM64_REG_IS_ANY(destinationReg) && !ARM64_REG_IS_ANY(sourceReg)) {
    // if both regs are set and have a mismatching width, abort
    if (ARM64_REG_IS_W(destinationReg) != ARM64_REG_IS_W(sourceReg)) return -1;
  }

  uint32_t inst = 0x51000000;
  uint32_t mask = 0x7f800000;
  if(OPT_BOOL_IS_SET(optS)) {
    bool s = OPT_BOOL_GET_VAL(optS);
    if(s) {
      inst = 0x71000000;
      mask |= (1 << 29);
      inst |= (1 << 29);
    }
  }

  // if one is set and 32 bit, include 32 bit in mask and set it in inst
  if (!ARM64_REG_IS_ANY(destinationReg)) {
    mask |= (1 << 31);
    inst |= ((uint32_t)(ARM64_REG_IS_X(destinationReg)) << 31);
  }
  else if (!ARM64_REG_IS_ANY(sourceReg)) {
    mask |= (1 << 31);
    inst |= ((uint32_t)(ARM64_REG_IS_X(sourceReg)) << 31);
  }

  if (!ARM64_REG_IS_ANY(destinationReg)) {
    mask |= 0x1F;
    inst |= (uint32_t)(ARM64_REG_GET_NUM(destinationReg));
  }
  if (!ARM64_REG_IS_ANY(sourceReg)) {
    mask |= (0x1F << 5);
    inst |= ((uint32_t)(ARM64_REG_GET_NUM(destinationReg)) << 5);
  }

  if (OPT_UINT64_IS_SET(optImm)) {
    uint64_t imm = OPT_UINT64_GET_VAL(optImm);
    if (imm & ~0xFFF) return -1;
    mask |= (0xFFF << 10);
    inst |= (imm << 10);
  }

  if (bytesOut) *bytesOut = inst;
  if (maskOut) *maskOut = mask;
  return 0;
}

int arm64_dec_sub_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *sourceRegOut, uint16_t *immOut, bool *sOut) {
  if ((inst & 0x7f800000) != 0x51000000) {
    if ((inst & 0x7f800000) != 0x71000000) {
      return -1;
    }
  }
  bool is64 = (inst & 0x80000000);
  bool isS = (inst & 0x20000000);
  bool shift = (inst & 0x400000);

  if (destinationRegOut) {
    *destinationRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1F);
  }
  if (sourceRegOut) {
    *sourceRegOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, (inst >> 5) & 0x1F);
  }

  if (immOut) {
    uint16_t imm = ((inst >> 10) & 0xFFF);
    if (shift) {
      imm = (imm << 12);
    }
    *immOut = imm;
  }

  if (sOut) {
    *sOut = isS;
  }

  return 0;
}

uint8_t arm64_str_ldr_type_width(arm64_register_type registerType, char ldrStrType)
{
    switch (ldrStrType) {
        case 'b': return 1;
        case 'h': return 2;
        default: return arm64_reg_type_get_width(registerType);
    }
}

static int _arm64_gen_str_ldr_imm(uint32_t inst, uint32_t mask, char type, arm64_ldr_str_type instType, arm64_register sourceDestinationReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(addrReg)) return -1;

    if (!ARM64_REG_IS_ANY(sourceDestinationReg)) {
        if (ARM64_REG_IS_ANY_VECTOR(sourceDestinationReg)) {
            mask |= (1 << 26);
            inst |= (1 << 26);
        }
        else {
            mask |= (1 << 23) | (1 << 26);
            //inst |= (0 << 23) | (0 << 26);

            inst |= ARM64_REG_GET_NUM(sourceDestinationReg);
            mask |= 0x1f;

            bool isVector = ARM64_REG_IS_VECTOR(sourceDestinationReg);
            if (isVector && type != 0) return -1;
            mask |= (1 << 23) | (1 << 26) | (0b11 << 30);
            inst |= (isVector << 26);            

            uint8_t size = 0b00;

            arm64_register_type regType = ARM64_REG_GET_TYPE(sourceDestinationReg);

            if (isVector) {
                switch (regType) {
                    case ARM64_REG_TYPE_Q:
                    size = 0b00;
                    inst |= (1 << 23);
                    break;
                    case ARM64_REG_TYPE_D:
                    size = 0b11;
                    break;
                    case ARM64_REG_TYPE_S:
                    size = 0b10;
                    break;
                    case ARM64_REG_TYPE_H:
                    size = 0b01;
                    break;
                    case ARM64_REG_TYPE_B:
                    size = 0b00;
                    break;
                    default:
                    break;
                }
            }
            else {
                if (regType == ARM64_REG_TYPE_X) {
                    size = 0b11;
                }
                else if (regType == ARM64_REG_TYPE_W) {
                    size = 0b10;
                }
            }
            inst |= (size << 30);
            mask |= (0b11 << 30);
        }
    }

    if (type != 0) {
        mask |= (1 << 23) | (1 << 26);
        //inst |= (0 << 23) | (0 << 26);

        uint8_t size = 0b00;
        if (type == 'h') {
            size = 0b01;
        }
        else if (type == 'b') {
            size = 0b00;
        }

        inst &= ~(0b11 << 30);
        inst |= (size << 30);
        mask |= (0b11 << 30);
    }

    if (instType != LDR_STR_TYPE_ANY) {
        mask |= (1 << 24);
        if (instType == LDR_STR_TYPE_PRE_INDEX || instType == LDR_STR_TYPE_POST_INDEX) {
            // Bit 10: Mask out LDUR / STUR
            // Bit 11: post index or not?
            mask |= (1 << 10) | (1 << 11);
            inst |= (1 << 10) | ((instType == LDR_STR_TYPE_PRE_INDEX) << 11);
        }
        else if(instType == LDR_STR_TYPE_UNSIGNED) {
            inst |= (1 << 24);
        }
    }

    if (!ARM64_REG_IS_ANY(addrReg)) {
        if (!ARM64_REG_IS_X(addrReg)) return -1;
        inst |= ((uint32_t)(ARM64_REG_GET_NUM(addrReg)) << 5);
        mask |= (0x1f << 5);
    }

    if (OPT_UINT64_IS_SET(optImm)) {
        uint64_t imm = OPT_UINT64_GET_VAL(optImm) / arm64_str_ldr_type_width(ARM64_REG_GET_TYPE(sourceDestinationReg), type);
        if (imm & ~0xfff) return -1;
        inst |= (imm << 10);
        mask |= (0xfff << 10);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

static int _arm64_dec_str_ldr_imm(uint32_t inst, arm64_register *sourceDestinationRegOut, arm64_register *addrRegOut, uint64_t *immOut, char *typeOut, arm64_ldr_str_type *instTypeOut)
{
    bool isVector = inst & (1 << 26);

    bool isUnsigned = inst & (1 << 24);
    if (!isUnsigned) {
        bool isUnscaled = !(inst & (1 << 10));
        if (isUnscaled) return -1;
    }

    uint8_t size = (inst >> 30);
    char instructionType = 0;
    arm64_register_type registerType = 0;
    if (isVector) {
        switch (size) {
            case 0b00:
            if (inst & (1 << 23)) {
                registerType = ARM64_REG_TYPE_Q;
            }
            else {
                registerType = ARM64_REG_TYPE_B;
            }
            break;
            case 0b01:
            registerType = ARM64_REG_TYPE_H;
            break;
            case 0b10:
            registerType = ARM64_REG_TYPE_S;
            break;
            case 0b11:
            registerType = ARM64_REG_TYPE_D;
        }
    }
    else {
        switch (size) {
            case 0b00:
            registerType = ARM64_REG_TYPE_W;
            instructionType = 'b';
            break;
            case 0b01:
            registerType = ARM64_REG_TYPE_W;
            instructionType = 'h';
            break;
            case 0b10:
            registerType = ARM64_REG_TYPE_W;
            break;
            case 0b11:
            registerType = ARM64_REG_TYPE_X;
            break;
        }
    }

    if (sourceDestinationRegOut) {
        *sourceDestinationRegOut = ARM64_REG(registerType, (inst & 0x1f));
    }

    if (typeOut) {
        *typeOut = instructionType;
    }

    if (addrRegOut) {
        *addrRegOut = ARM64_REG_X((inst >> 5) & 0x1f);
    }

    if (immOut) {
        if (isUnsigned) {
            uint64_t imm = ((inst >> 10) & 0xfff) * arm64_str_ldr_type_width(registerType, instructionType);
            *immOut = imm;
        }
        else {
            uint64_t imm = ((inst >> 12) & 0x1ff);
            *immOut = sxt64(imm, 9);
        }
    }

    if (instTypeOut) {
        if (isUnsigned) {
            *instTypeOut = LDR_STR_TYPE_UNSIGNED;
        }
        else {
            bool isPreIndex = inst & (1 << 11);
            *instTypeOut = isPreIndex ? LDR_STR_TYPE_PRE_INDEX : LDR_STR_TYPE_POST_INDEX;
        }
    }

    return 0;
}

int arm64_gen_ldr_imm(char type, arm64_ldr_str_type instType, arm64_register destinationReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    return _arm64_gen_str_ldr_imm(0x38400000, 0x3a400000, type, instType, destinationReg, addrReg, optImm, bytesOut, maskOut);
}

int arm64_dec_ldr_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *addrRegOut, uint64_t *immOut, char *typeOut, arm64_ldr_str_type *instTypeOut)
{
    if ((inst & 0x3a400000) != 0x38400000) return -1;
    return _arm64_dec_str_ldr_imm(inst, destinationRegOut, addrRegOut, immOut, typeOut, instTypeOut);
}

int arm64_gen_ldrs_imm(char type, arm64_ldr_str_type instType, arm64_register destinationReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    return _arm64_gen_str_ldr_imm(0x38800000, 0x3ac00000, type, instType, destinationReg, addrReg, optImm, bytesOut, maskOut);
}

int arm64_dec_ldrs_imm(uint32_t inst, arm64_register *destinationRegOut, arm64_register *addrRegOut, uint64_t *immOut, char *typeOut, arm64_ldr_str_type *instTypeOut)
{
    if ((inst & 0x3ac00000) != 0x38800000) return -1;
	return _arm64_dec_str_ldr_imm(inst, destinationRegOut, addrRegOut, immOut, typeOut, instTypeOut);
}

int arm64_gen_str_imm(char type, arm64_ldr_str_type instType, arm64_register sourceReg, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    return _arm64_gen_str_ldr_imm(0x38000000, 0x3a400000, type, instType, sourceReg, addrReg, optImm, bytesOut, maskOut);
}

int arm64_dec_str_imm(uint32_t inst, arm64_register *sourceRegOut, arm64_register *addrRegOut, uint64_t *immOut, char *typeOut, arm64_ldr_str_type *instTypeOut)
{
    if ((inst & 0x3a400000) != 0x38000000) return -1;
    return _arm64_dec_str_ldr_imm(inst, sourceRegOut, addrRegOut, immOut, typeOut, instTypeOut);
}

int arm64_gen_ldr_lit(arm64_register destinationReg, optional_uint64_t optOrigin, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(destinationReg)) return -1;

    uint32_t inst = 0x18000000;
    uint32_t mask = 0xbf000000;

    if (!ARM64_REG_IS_ANY(destinationReg)) {
        mask |= (1 << 30);
        inst |= (ARM64_REG_IS_X(destinationReg) << 30);

        mask |= 0x1f;
        inst |= ARM64_REG_GET_NUM(destinationReg);
    }

    if (OPT_UINT64_IS_SET(optOrigin) && OPT_UINT64_IS_SET(optTarget)) {
        uint64_t origin = OPT_UINT64_GET_VAL(optOrigin);
        uint64_t target = OPT_UINT64_GET_VAL(optTarget);
        mask |= (0x7ffff << 5);
        inst |= (((target - origin) / 4) & 0x7ffff) << 5;
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;

    return 0;
}

int arm64_dec_ldr_lit(uint32_t inst, uint64_t origin, uint64_t *targetOut, arm64_register *destinationReg)
{
    if ((inst & 0xbf000000) != 0x18000000) return -1;

    if (destinationReg) {
        *destinationReg = ARM64_REG((inst & (1 << 30)) ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1f);
    }

    if (targetOut) {
        uint64_t imm = (inst >> 5) & 0x7ffff;
        *targetOut = origin + (sxt64(imm, 19) * 4);
    }

    return 0;
}

int arm64_gen_ldp(arm64_ldp_stp_type instType, arm64_register destinationReg1, arm64_register destinationReg2, arm64_register addrReg, optional_uint64_t optImm, uint32_t *bytesOut, uint32_t *maskOut)
{
    uint32_t inst = 0x28400000;
    uint32_t mask = 0x7e400000;

    if (!ARM64_REG_IS_ANY(destinationReg1) && !ARM64_REG_IS_ANY(destinationReg2)) {
        if (ARM64_REG_IS_X(destinationReg1) != ARM64_REG_IS_X(destinationReg2)) {
            return -1;
        }
    }

    bool is64 = false;
    if (!ARM64_REG_IS_ANY(destinationReg1) || !ARM64_REG_IS_ANY(destinationReg2)) {
        if (!ARM64_REG_IS_ANY(destinationReg1)) {
            is64 = ARM64_REG_IS_X(destinationReg1);
        }
        else {
            is64 = ARM64_REG_IS_X(destinationReg2);
        }
        mask |=    (1 << 31);
        inst |= (is64 << 31);
    }

    if (ARM64_REG_IS_ANY(destinationReg1) && ARM64_REG_IS_ANY(destinationReg2) && OPT_UINT64_IS_SET(optImm)) {
        return -1;
    }

    if (instType != ARM64_LDP_STP_TYPE_ANY) {
        mask |= (0b11 << 23);
        switch (instType) {
            case ARM64_LDP_STP_TYPE_POST_INDEX:
            inst |= (0b01 << 23);
            break;
            case ARM64_LDP_STP_TYPE_PRE_INDEX:
            inst |= (0b11 << 23);
            break;
            case ARM64_LDP_STP_TYPE_SIGNED:
            inst |= (0b10 << 23);
            break;
            default:
            break;
        }
    }

    if (!ARM64_REG_IS_ANY(destinationReg1)) {
        mask |= 0x1f;
        inst |= ARM64_REG_GET_NUM(destinationReg1);
    }
    if (!ARM64_REG_IS_ANY(destinationReg2)) {
        mask |= 0x1f << 10;
        inst |= ARM64_REG_GET_NUM(destinationReg2) << 10;
    }
    if (!ARM64_REG_IS_ANY(addrReg)) {
        mask |= 0x1f << 5;
        inst |= ARM64_REG_GET_NUM(addrReg) << 5;
    }
    if (OPT_UINT64_IS_SET(optImm)) {
        mask |= 0b1111111 << 15;
        if (is64) {
            inst |= OPT_UINT64_GET_VAL(optImm) / 8;
        }
        else {
            inst |= OPT_UINT64_GET_VAL(optImm) / 4;
        }
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_gen_cb_n_z(optional_bool isCbnz, arm64_register reg, optional_uint64_t optTarget, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(reg)) return -1;

    uint32_t inst = 0x34000000;
    uint32_t mask = 0x7e000000;

    if (OPT_BOOL_IS_SET(isCbnz)) {
        mask |= (1 << 24);
        if (OPT_BOOL_GET_VAL(isCbnz)) {
            inst |= (1 << 24);
        }
    }

    if (!ARM64_REG_IS_ANY(reg)) {
        mask |= 0x1f | (1 << 31);
        inst |= (ARM64_REG_IS_X(reg) << 31);
        inst |= ARM64_REG_GET_NUM(reg);
    }

    if (OPT_UINT64_IS_SET(optTarget)) {
        uint64_t target = OPT_UINT64_GET_VAL(optTarget) / 4;
        if (target & ~0x7ffff) {
            return -1;
        }
        mask |= (0x7ffff << 5);
        inst |= (target << 5);
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_cb_n_z(uint32_t inst, uint64_t origin, bool *isCbnzOut, arm64_register *regOut, uint64_t *targetOut)
{
    if ((inst & 0x7e000000) != 0x34000000) return -1;

    if (isCbnzOut) {
        *isCbnzOut = ((inst >> 24) & 0x1);
    }
    if (regOut) {
        bool is64 = ((inst >> 31) & 0x1);
        uint16_t num = inst & 0x1f;
        *regOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, num);
    }
    if (targetOut) {
        *targetOut = origin + sxt64(((inst >> 5) & 0x7ffff) * 4, 19);
    }

    return 0;
}

int arm64_gen_tb_n_z(optional_bool isTbnz, arm64_register reg, optional_uint64_t optTarget, optional_uint64_t optBit, uint32_t *bytesOut, uint32_t *maskOut)
{
    if (ARM64_REG_IS_ANY_VECTOR(reg)) return -1;

    uint32_t inst = 0x36000000;
    uint32_t mask = 0x7e000000;

    if (OPT_BOOL_IS_SET(isTbnz)) {
        mask |= (1 << 25);
        inst |= (OPT_BOOL_GET_VAL(isTbnz)) << 25;
    }

    if (!ARM64_REG_IS_ANY(reg)) {
        mask |= 0x1f | (1 << 31);
        inst |= (ARM64_REG_IS_X(reg) << 31);
        inst |= ARM64_REG_GET_NUM(reg);
    }

    if (OPT_UINT64_IS_SET(optTarget)) {
        uint64_t target = OPT_UINT64_GET_VAL(optTarget) / 4;
        if (target & ~0x3fff) {
            return -1;
        }
        mask |= (0x3fff << 5);
        inst |= (target << 5);
    }

    if (OPT_UINT64_IS_SET(optBit)) {
        uint64_t bit = OPT_UINT64_GET_VAL(optBit);
        if (bit & ~0x1f) return -1;

        bool bitIs64 = (bit & (1 << 5));
        if (!ARM64_REG_IS_ANY(reg)) {
            if (ARM64_REG_IS_X(reg) != bitIs64) return -1;
        }

        mask |= (1 << 31) | (0xf << 19);
        inst |= (bitIs64 << 31) | (bit & 0xf) << 5;
    }

    if (bytesOut) *bytesOut = inst;
    if (maskOut) *maskOut = mask;
    return 0;
}

int arm64_dec_tb_n_z(uint32_t inst, uint64_t origin, bool *isTbnzOut, arm64_register *regOut, uint64_t *targetOut, uint64_t *bitOut)
{
    if ((inst & 0x7e000000) != 0x36000000) return -1;

    bool is64 = inst & (1 << 31);

    if (isTbnzOut) {
        *isTbnzOut = (inst >> 25);
    }

    if (regOut) {
        *regOut = ARM64_REG(is64 ? ARM64_REG_TYPE_X : ARM64_REG_TYPE_W, inst & 0x1f);
    }

    if (targetOut) {
        *targetOut = origin + sxt64(((inst >> 5) & 0x3fff) * 4, 14);
    }

    if (bitOut) {
        *bitOut = (is64 << 5) | ((inst >> 19) & 0xf);
    }

    return 0;
}
