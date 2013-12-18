/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "dlx_internal.h"

#include "interface.h"
#include "trap_helper.h"

#include "util/macro.h"
#include "util/logging.h"

#include <stdlib.h>
#include <string.h>


#define DLX_START_ADDR       0x1000


#define OPERAND_D( I) ((((I) >> 0x13) & 0x7C) >> 2)
#define OPERAND_S1(I) ((((I) >> 0x0E) & 0x7C) >> 2)
#define OPERAND_S2(I) ((((I) >> 0x09) & 0x7C) >> 2)

#define OPERAND_UI(I) ((uint16_t)(I) & 0xFFFF)
#define OPERAND_SI(I) ((int16_t)(I) & 0xFFFF)
#define OPERAND_UJ(I) ((I) & 0x3FFFFFF)
#define OPERAND_SJ(I) (((I)& 0x2000000) ? (((I) & 0x3ffffff) | 0xFC000000) : ((I) & 0x3FFFFFF))

#define OP_RTYPE(  I, op1, op2, op3) (op1) = OPERAND_D(I); (op2) = OPERAND_S1(I); (op3) = OPERAND_S2(I);
#define OP_ITYPE_U(I, op1, op2, op3) (op1) = OPERAND_D(I); (op2) = OPERAND_S1(I); (op3) = OPERAND_UI(I);
#define OP_ITYPE_S(I, op1, op2, op3) (op1) = OPERAND_D(I); (op2) = OPERAND_S1(I); (op3) = OPERAND_SI(I);
#define OP_JTYPE_U(I, op1) (op1) = OPERAND_UJ(I)
#define OP_JTYPE_S(I, op1) (op1) = OPERAND_SJ(I)


// Load results of DiscoveryRAM and DeviceDescovery (1,3) from snapshops?
//#define DLX_LOAD_FROM_SNAPSHOT

/*
 *
 */

VM *dlx_initVM(struct bdplus_s *plus)
{
    VM *vm = calloc(1, sizeof(VM));
    if (!vm) {
        return NULL;
    }

    vm->size = DLX_MEMORY_SIZE;
    vm->addr = (uint8_t *)malloc(vm->size);
    if (!vm->addr) {
        X_FREE(vm);
        return NULL;
    }

    // Make sure memory is all zero
    memset(vm->addr, 0, vm->size);

    // Setup PC to the start
    dlx_setPC(vm, DLX_START_ADDR);

    vm->plus = plus;

    return vm;
}

void dlx_freeVM(VM **vm)
{
    if (vm && *vm) {
        free_sha_ctx(&(*vm)->sha_ctx_head, NULL);

        X_FREE((*vm)->addr);
        X_FREE((*vm));
    }
}

struct bdplus_s *dlx_getApp(VM *vm)
{
    return vm->plus;
}

uint8_t *dlx_getAddr(VM *vm)
{
    return vm->addr;
}

uint32_t dlx_getAddrSize(VM *vm)
{
    return vm->size;
}

/*
 *
 */

uint32_t dlx_setPC(VM *vm, unsigned int PC)
{
    uint32_t old;

    old = vm->PC;

    DEBUG(DBG_BDPLUS,"[dlx] setPC (%p, %08X -> %08X)\n", vm, old, PC);

    vm->PC = PC;

    if (!vm->code_start)
        vm->code_start = PC;

    return old;

}


uint32_t dlx_getPC(VM *vm)
{

    DEBUG(DBG_BDPLUS,"[dlx] getPC (%p): %08X\n", vm, vm->PC);
    return vm->PC;

}


int32_t dlx_setWD(VM *vm, int32_t WD)
{
    int32_t old;

    old = vm->WD;

    DEBUG(DBG_BDPLUS,"[dlx] setWD (%p, %08X -> %08X)\n", vm, old, WD);

    vm->WD = WD;
    return old;

}


int32_t dlx_getWD(VM *vm)
{

    DEBUG(DBG_BDPLUS,"[dlx] getWD (%p): %08X\n", vm, vm->WD);
    return vm->WD;

}

uint32_t dlx_setIF(VM *vm, uint32_t IF)
{
    uint32_t old;

    old = vm->IF;

    DEBUG(DBG_BDPLUS,"[dlx] setIF (%p, %08X -> %08X)\n", vm, old, IF);

    vm->IF = IF;
    return old;

}


uint32_t dlx_getIF(VM *vm)
{

    DEBUG(DBG_BDPLUS,"[dlx] getIF (%p): %08X\n", vm, vm->IF);
    return vm->IF;

}



uint32_t dlx_getStart(VM *vm)
{
    return vm->code_start;
}




// Format	Bits
// 	        31-26   25-21   20-16      15-11     10-6     5-0
// R-type     0x0     Rs1     Rs2         Rd   unused  opcode
// I-type  opcode     Rs1      Rd      |------immediate-----|
// J-type  opcode   |-------------------value---------------|
//
// Return code:
//  0 Instruction execution ok (STEP_I)
//  1 Trap
//  2 Break
// -1 Unknown opcode
// -2 PC trace failed
// -3 WD trace failed
// -4 IF trace failed
int32_t dlx_run(VM *vm, int32_t flags)
{
    uint32_t I, C, d, s1, s2, U_Iimm, U_Jimm;
    int16_t S_Iimm;
    int32_t S_Jimm;

    if (!vm || !vm->addr) return -1;

    // Clear last-trap holder. Just for dlx_last_trap() calls.
    vm->trap = 0;

    if (flags != BD_STEP_I) {
        DEBUG(DBG_DLX,"[dlx] running VM %p\n", vm);
    }

    do {

        vm->PC &= ADDR_MASK4;
        I = FETCH4(&vm->addr[vm->PC]);


        // INSTF magic to confuse everything.
        I ^= vm->IF;


        vm->PC += 4;
        vm->PC &= ADDR_MASK4;

        vm->num_instructions++;

        C  = I >> 0x1A;                   // command

        switch(C) {

        case 0x00: // NOP
        case 0x3B: // NOP
        case 0x3C: // NOP
        case 0x3D: // NOP
        case 0x3E: // NOP
        case 0x3F: // NOP
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): NOP\n", vm->PC-4, C);
            vm->WD-=1;
            break;

        case 0x01: // ADD   | R-type | Rd = Rs1 + Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): ADD (R%-2d = R%-2d + R%-2d): %d = %d + %d\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]+vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] + vm->R[s2];
            vm->WD-=1;
            break;

        case 0x02: // SUB   | R-type | Rd = Rs1 - Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SUB (R%-2d = R%-2d - R%-2d): %08X = %08X - %08X\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]-vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] - vm->R[s2];
            vm->WD-=1;
            break;

        case 0x03: // MUL   | R-type | Rd = Rs1 * Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): MUL (R%-2d = R%-2d * R%-2d): %08X = %08X * %08X\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]*vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] * vm->R[s2];
            vm->WD-=4;
            break;

        case 0x04: // DIV   | R-type | Rd = signed(Rs1) / signed(Rs2)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): DIV (R%-2d = R%-2d / R%-2d): %08X = %08X / %08X\n"
                   , vm->PC-4, C,
                  d,s1,s2,(vm->R[s2] ? (int32_t)vm->R[s1]/(int32_t)vm->R[s2] : 0),vm->R[s1],vm->R[s2]);
            if (vm->R[s2])
                vm->R[d] = (int32_t)vm->R[s1] / (int32_t)vm->R[s2];
            else
                vm->R[d] = 0;  // Division by 0?
            vm->WD-=16;
            break;

        case 0x05: // DIVU  | R-type | Rd = unsigned(Rs1) / unsigned(Rs2)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): DIVU(R%-2d = R%-2d / R%-2d): %08X = %08X / %08X\n"
                   , vm->PC-4, C,
                  d,s1,s2,(vm->R[s2] ? vm->R[s1]/vm->R[s2] : 0),vm->R[s1],vm->R[s2]);
            if (vm->R[s2])
                vm->R[d] = vm->R[s1] / vm->R[s2];
            else
                vm->R[d] = 0;
            vm->WD-=16;
            break;

        case 0x06: // SLL   | R-type | Rd = Rs1 << (Rs2 & 0x1F)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLL (R%-2d = R%-2d << R%-2d): %08X = %08X << %d\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]<<(vm->R[s2]&0x1F),vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] << (vm->R[s2]&0x1F);
            vm->WD-=1;
            break;

        case 0x07: // SRL   | R-type | Rd = Rs1 >> (Rs2 & 0x1F)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SRL (R%-2d = R%-2d >> R%-2d): %08X = %08X >> %d\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]>>(vm->R[s2]&0x1F),vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] >> (vm->R[s2]&0x1F);
            vm->WD-=1;
            break;

        case 0x08: // SRA   | R-type | SRL and SRA perform identically if Rs1 is positive. If Rs1 is negative (bit 31 == 1), 1's are shifted in from the left for SRA and SRAI.
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SRA (R%-2d = R%-2d >> R%-2d): %08X = %08X >> %d\n"
                   , vm->PC-4, C,
                   d,s1,s2,(int32_t)vm->R[s1]>>(vm->R[s2]&0x1F),vm->R[s1],vm->R[s2]);
            vm->R[d] = (int32_t)vm->R[s1] >> (vm->R[s2]&0x1F);
            vm->WD-=1;
            break;

        case 0x09: // AND   | R-type | Rd = Rs1 & Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): AND (R%-2d = R%-2d & R%-2d): %08X = %08X & %08X\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]&vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] & vm->R[s2];
            vm->WD-=1;
            break;

        case 0x0A: // OR    | R-type | Rd = Rs1 | Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): OR  (R%-2d = R%-2d | R%-2d): %08X = %08X | %08X\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]|vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] | vm->R[s2];
            vm->WD-=1;
            break;

        case 0x0B: // XOR   | R-type | Rd = Rs1 ^ Rs2
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): XOR (R%-2d = R%-2d ^ R%-2d): %08X = %08X ^ %08X\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]^vm->R[s2],vm->R[s1],vm->R[s2]);
            vm->R[d] = vm->R[s1] ^ vm->R[s2];
            vm->WD-=1;
            break;

        case 0x0C: // SEQ   | R-type | Rd = (Rs1 == Rs2 ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SEQ (R%-2d = (R%-2d == R%-2d)): %08X = (%08X == %d)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]==vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] == vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x0D: // SNE   | R-type | Rd = (Rs1 != Rs2 ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SNE (R%-2d = (R%-2d != R%-2d)): %08X = (%08X != %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]!=vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] != vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x0E: // SLT   | R-type | Rd = (Rs1 < Rs2 ? 1 : 0) [signed]
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLT (R%-2d = (R%-2d < R%-2d)): %08X = (%08X < %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,(int32_t)vm->R[s1]<(int32_t)vm->R[s2] ? 1 : 0,
                   vm->R[s1], vm->R[s2]);
            vm->R[d] = (int32_t)vm->R[s1] < (int32_t)vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x0F: // SBT   | R-type | Rd = (Rs1 < Rs2 ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SBT (R%-2d = (R%-2d < R%-2d)): %08X = (%08X < %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]<vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] < vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x10: // SGT   | R-type | Rd = (Rs1 > Rs2 ? 1 : 0) [signed]
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SGT (R%-2d = (R%-2d > R%-2d)): %08X = (%08X < %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,(int32_t)vm->R[s1]>(int32_t)vm->R[s2] ? 1 : 0,
                   vm->R[s1], vm->R[s2]);
            vm->R[d] = (int32_t)vm->R[s1] > (int32_t)vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x11: // SAT   | R-type | Rd = (Rs1 > Rs2 ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SAT (R%-2d = (R%-2d > R%-2d)): %08X = (%08X > %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]>vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] > vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x12: // SLE   | R-type | Rd = (Rs1 <= Rs2 ? 1 : 0) [signed]
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLE (R%-2d = (R%-2d <= R%-2d)): %08X = (%08X <= %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,(int32_t)vm->R[s1]<=(int32_t)vm->R[s2] ? 1 : 0,
                   vm->R[s1], vm->R[s2]);
            vm->R[d] = (int32_t)vm->R[s1] <= (int32_t)vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x13: // SBE   | R-type | Rd =(unsigned(Rs1) <= unsigned(Rs2) ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SBE (R%-2d = (R%-2d <= R%-2d)): %08X = (%08X <= %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]<=vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] <= vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x14: // SGE   | R-type | Rd = (Rs1 >= Rs2 ? 1 : 0) [signed]
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SGE (R%-2d = (R%-2d >= R%-2d)): %08X = (%08X >= %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,(int32_t)vm->R[s1]>=(int32_t)vm->R[s2] ? 1 : 0,
                   vm->R[s1], vm->R[s2]);
            vm->R[d] = (int32_t)vm->R[s1] >= (int32_t)vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x15: // SAE   | R-type | Rd =(unsigned(Rs1) >= unsigned(Rs2) ? 1 : 0)
            OP_RTYPE(I, d, s1, s2);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SAE (R%-2d = (R%-2d >= R%-2d)): %08X = (%08X >= %08X)\n"
                   , vm->PC-4, C,
                   d,s1,s2,vm->R[s1]>=vm->R[s2] ? 1 : 0, vm->R[s1], vm->R[s2]);
            vm->R[d] = vm->R[s1] >= vm->R[s2] ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x16: // JR    | I-type | PC = Rs1
            s1 = OPERAND_S1(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): JR  (PC = R%-2d): PC=%08X\n"
                   , vm->PC-4, C,
                   s1,vm->R[s1] & ADDR_MASK4);
            vm->PC = vm->R[s1] & ADDR_MASK4;
            vm->WD-=2;
            break;

        case 0x17: // JALR  | I-type | R31 = PC + 4 ; PC = Rs1
            s1 = OPERAND_S1(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): JALR(R31 = PC; PC = R%-2d): PC=%08X\n"
                   , vm->PC-4, C,
                   s1,vm->R[s1]);
            vm->R[31] = vm->PC;
            vm->PC = vm->R[s1] & ADDR_MASK4;
            vm->WD-=3;
            break;

        case 0x18: // ADDIE | I-type | Rd = Rs1 + extend(immediate)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X):ADDIE(R%-2d = R%-2d + %04X): %d = %d + %d\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,vm->R[s1]+S_Iimm,vm->R[s1],S_Iimm);
            vm->R[d] = vm->R[s1] + S_Iimm;
            vm->WD-=1;
            break;

        case 0x19: // ADDI  | I-type | Rd = Rs1 + immediate
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): ADDI(R%-2d = R%-2d + %04X): %d = %d + %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]+U_Iimm,vm->R[s1],U_Iimm);
            vm->R[d] = vm->R[s1] + U_Iimm;
            vm->WD-=1;
            break;

        case 0x1A: // SUBIE | I-type | Rd = Rs1 - extended(immediate)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X):SUBIE(R%-2d = R%-2d - %04X): %08X = %08X - %d\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,
                   vm->R[s1] - S_Iimm,
                   vm->R[s1], S_Iimm);
            vm->R[d] = vm->R[s1] - S_Iimm;
            vm->WD-=1;
            break;

        case 0x1B: // SUBI  | I-type | Rd = Rs1 - immediate
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SUBI(R%-2d = R%-2d - %04X): %08X = %08X - %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,
                   vm->R[s1] - U_Iimm,
                   vm->R[s1], U_Iimm);
            vm->R[d] = vm->R[s1] - U_Iimm;
            vm->WD-=1;
            break;

        case 0x1C: // SLLI  | I-type | Rd = Rs1 << (immediate & 0x1F)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLLI(R%-2d = R%-2d << %02X): %08X = %08X << %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm&0x1F,vm->R[s1]<<(U_Iimm&0x1F),vm->R[s1],U_Iimm&0x1F);
            vm->R[d] = vm->R[s1] << (U_Iimm&0x1F);
            vm->WD-=1;
            break;

        case 0x1D: // SRLI  | I-type | Rd = Rs1 >> (immediate & 0x1F)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SRLI(R%-2d = R%-2d >> %02X): %08X = %08X >> %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm&0x1F,vm->R[s1]>>(U_Iimm&0x1F),vm->R[s1],U_Iimm&0x1F);
            vm->R[d] = vm->R[s1] >> (U_Iimm&0x1F);
            vm->WD-=1;
            break;

        case 0x1E: //  SRAI  | I-type | as SRLI & sign extend
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SRLI(R%-2d = R%-2d >> %04X): %08X = %08X >> %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,(int32_t)vm->R[s1]>>(U_Iimm&0x1F),vm->R[s1],U_Iimm);
            vm->R[d] = (int32_t)vm->R[s1] >> (U_Iimm&0x1F);
            vm->WD-=1;
            break;

        case 0x1F: // ANDI  | I-type | Rd = Rs1 & immediate
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): ANDI(R%-2d = R%-2d & %04X): %08X = %08X & %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]&U_Iimm,vm->R[s1],U_Iimm);
            vm->R[d] = vm->R[s1] & U_Iimm;
            vm->WD-=1;
            break;

        case 0x20: // ORI   | I-type | Rd = Rs1 | immediate
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): ORI (R%-2d = R%-2d | %04X): %08X = %08X | %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]|U_Iimm,vm->R[s1],U_Iimm);
            vm->R[d] = vm->R[s1] | U_Iimm;
            vm->WD-=1;
            break;

        case 0x21: // XORI  | I-type | Rd = Rs1 ^ immediate
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): XORI(R%-2d = R%-2d ^ %04X): %08X = %08X ^ %d\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]^U_Iimm,vm->R[s1],U_Iimm);
            vm->R[d] = vm->R[s1] ^ U_Iimm;
            vm->WD-=1;
            break;

        case 0x22: // SEQI  | I-type | Rd = (Rs1 == extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SEQI(R%-2d = (R%-2d == %04X)): %08X = (%08X == %d)\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,vm->R[s1]==(uint32_t)(int32_t)S_Iimm ? 1 : 0, vm->R[s1], S_Iimm);
            vm->R[d] = (vm->R[s1] == (uint32_t)(int32_t)S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x23: // SNEI  | I-type | Rd = (Rs1 != extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SNEI(R%-2d = (R%-2d != %04X)): %08X = (%08X != %d)\n"
                   , vm->PC-4, C,
                  d,s1,S_Iimm,(int32_t)vm->R[s1]!=(int32_t)S_Iimm ? 1 : 0, vm->R[s1], S_Iimm);
            vm->R[d] = (vm->R[s1] != (uint32_t)(int32_t)S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x24: // SLI   | I-type | Rd = (Rs1 < extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLI (R%-2d = (R%-2d < %04X)): %08X = (%08X < %d)\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,(int32_t)vm->R[s1]<S_Iimm ? 1 : 0, vm->R[s1], S_Iimm);
            vm->R[d] = ((int32_t)vm->R[s1] < S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x25: // SBI   | I-type | Rd = (Rs1 < extend(immediate) ? 1 : 0)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SBI (R%-2d = (R%-2d < %04X)): %08X = (%08X < %d)\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]<U_Iimm ? 1 : 0, vm->R[s1], U_Iimm);
            vm->R[d] = (vm->R[s1] < U_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x26: // SGI   | I-type | Rd = (Rs1 > extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SGI (R%-2d = (R%-2d > %04X)): %08X = (%08X > %d)\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,(int32_t)vm->R[s1]>S_Iimm ? 1 : 0, vm->R[s1], S_Iimm);
            vm->R[d] = ((int32_t)vm->R[s1] > S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x27: // SAI   | I-type | Rd = (Rs1 > extend(immediate) ? 1 : 0)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SAI (R%-2d = (R%-2d > %04X)): %08X = (%08X > %d)\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]>U_Iimm ? 1 : 0, vm->R[s1], U_Iimm);
            vm->R[d] = (vm->R[s1] > U_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x28: // SLEI  | I-type | Rd = (Rs1 <= extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SLEI(R%-2d = (R%-2d <= %04X)): %08X = (%08X <= %d)\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,(int32_t)vm->R[s1]<=S_Iimm ? 1 :0, vm->R[s1], S_Iimm);
            vm->R[d] = ((int32_t)vm->R[s1] <= S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x29: // SBEI  | I-type | Rd = (Rs1 <= unsigned(immediate) ? 1 : 0)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SBEI(R%-2d = (R%-2d <= %04X)): %08X = (%08X <= %d)\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]<=U_Iimm ? 1 : 0, vm->R[s1], U_Iimm);
            vm->R[d] = (vm->R[s1] <= U_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x2A: // SGEI  | I-type | Rd = (Rs1 >= extend(immediate) ? 1 : 0)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SGEI (R%-2d = (R%-2d >= %04X)): %08X = (%08X >= %d)\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,(int32_t)vm->R[s1]>=S_Iimm ? 1 :0, vm->R[s1], S_Iimm);
            vm->R[d] = ((int32_t)vm->R[s1] >= S_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x2B: // SAEI  | I-type | Rd = (Rs1 >= extend(immediate) ? 1 : 0)
            OP_ITYPE_U(I, d, s1, U_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SAEI(R%-2d = (R%-2d >= %04X)): %08X = (%08X >= %d)\n"
                   , vm->PC-4, C,
                   d,s1,U_Iimm,vm->R[s1]>=U_Iimm ? 1 : 0, vm->R[s1], U_Iimm);
            vm->R[d] = (vm->R[s1] >= U_Iimm) ? 1 : 0;
            vm->WD-=1;
            break;

        case 0x2C: // J      | J-type | PC += extend(value)
            OP_JTYPE_S(I, S_Jimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): J   (PC += %07X): %08X = %08X + %d\n"
                   , vm->PC-4, C,
                   S_Jimm, (vm->PC+S_Jimm)&ADDR_MASK4, vm->PC, S_Jimm);

            vm->PC = (vm->PC + S_Jimm) & ADDR_MASK4;

            //if (S_Jimm == -4) return -1;
            vm->WD-=2;
            break;

        case 0x2D: // JAL   | J-type | R31 = PC + 4 ; PC += extend(value)
            OP_JTYPE_S(I, S_Jimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): JAL (R31 = %08X ; PC += %04X): %08X = PC + %d\n"
                   , vm->PC-4, C,
                   vm->PC,
                   S_Jimm,
                   vm->PC + S_Jimm,
                   S_Jimm);
            vm->R[31] = vm->PC;
            vm->PC = (vm->PC + S_Jimm) & ADDR_MASK4;
            vm->WD-=3;
            break;

        case 0x2E: // BEQZ  | I-type | PC += (Rs1 == 0 ? extend(immediate) : 0)
            s1 = OPERAND_S1(I);
            S_Iimm = OPERAND_SI(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): BEQZ(PC += %04X if !R%-2d): %08X = PC + %d if !%d\n"
                   , vm->PC-4, C,
                   S_Iimm,
                   s1,
                   vm->PC + (!vm->R[s1] ? S_Iimm : 0),
                   S_Iimm,
                   vm->R[s1]);
            vm->PC = (vm->PC + (!vm->R[s1] ? S_Iimm : 0)) & ADDR_MASK4;
            vm->WD-=2;
            break;

        case 0x2F: // BNEZ  | I-type | PC += (Rs1 != 0 ? extend(immediate) : 0)
            s1 = OPERAND_S1(I);
            S_Iimm = OPERAND_SI(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): BNEZ(PC += %04X if R%-2d): %08X += %d if %d\n"
                   , vm->PC-4, C,
                   S_Iimm, s1, vm->PC, vm->R[s1] ? S_Iimm : 0, vm->R[s1]);

            vm->PC = (vm->PC + (vm->R[s1] ? S_Iimm : 0)) & ADDR_MASK4;
            vm->WD-=2;
            break;

        case 0x30: // LHI   | I-type | Rd = immediate << 16
            d = OPERAND_D(I);
            U_Iimm = OPERAND_UI(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LHI (R%-2d = %04X << 16): %08X = %08X << 16\n"
                   , vm->PC-4, C,
                   d, U_Iimm, U_Iimm << 16, U_Iimm);

            vm->R[d] = U_Iimm << 16;
            vm->WD-=1;
            break;

        case 0x31: // LBE   | I-type | Rd = extend(MEM[Rs1 + extend(immediate)] && 0xFF)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LBE (R%-2d = [R%-2d + %04X]c): %08X = [%08X + %d]\n"
                   , vm->PC-4, C,
                   d, s1, S_Iimm,
                   (int8_t)(vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK1 ]&0xff),
                   vm->R[s1], S_Iimm);

            vm->R[d] = (int8_t)(vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK1 ]&0xff);
            vm->WD-=4;
            break;

        case 0x32: // LB    | I-type | Rd = MEM[Rs1 + extend(immediate)]
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LB  (R%-2d = [R%-2d + %04X]c): %08X = %08X + %d\n"
                   , vm->PC-4, C,
                   d, s1, S_Iimm, vm->addr[ ( vm->R[s1] + S_Iimm) & ADDR_MASK1 ]&0xff,
                   vm->R[s1], S_Iimm);

            vm->R[d] = vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK1 ]&0xff;
            vm->WD-=4;
            break;

        case 0x33: // LWE   | I-type | Rd = extend(MEM[Rs1 + extend(immediate)] && 0xFFFF) (?)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LWE (R%-2d = [R%-2d + %04X]s): %08X = %08X + %d\n"
                   , vm->PC-4, C,
                   d, s1, S_Iimm, FETCHS2( &vm->addr[ vm->R[s1] + S_Iimm ] ),
                   vm->R[s1], S_Iimm);

            vm->R[d] = FETCHS2(&vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK2 ]);
            vm->WD-=4;
            break;

        case 0x34: // LW    | I-type | Rd = MEM[Rs1 + extend(immediate)] && 0xFFFF)
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LW  (R%-2d = [R%-2d + %04X]s): %08X = %08X + %d\n"
                   , vm->PC-4, C,
                   d, s1, S_Iimm, FETCHU2( &vm->addr[ vm->R[s1] + S_Iimm ] ),
                   vm->R[s1], S_Iimm);

            vm->R[d] = FETCHU2(&vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK2 ]);
            vm->WD-=4;
            break;

        case 0x35: // LDW   | I-type | Rd = MEM[Rs1 + extend(immediate)]
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): LDW (R%-2d = [R%-2d + %02X]l): %08X = %08X + %d\n"
                   , vm->PC-4, C,
                   d,s1,S_Iimm,
                   FETCH4( &vm->addr[ ( vm->R[s1] + S_Iimm ) & ADDR_MASK4 ] ),
                   vm->R[s1], S_Iimm);

            vm->R[d] = FETCH4( &vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK4 ] );
            vm->WD-=2;
            break;

        case 0x36: // SB    | I-type | MEM[Rs1 + extend(immediate)]c = (u_char) Rd
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SB  ([R%-2d + %04X]c = R%-2d): [ %08X + %d ] = %02X\n"
                   , vm->PC-4, C,
                   s1, S_Iimm, d,
                   vm->R[s1], S_Iimm, vm->R[d] & 0xFF);

            vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK1 ] = vm->R[d]&0xFF;
            vm->WD-=4;
            break;

        case 0x37: // SW    | I-type | MEM[Rs1 + extend(immediate)]s = (uint16) Rd
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SW  ([R%-2d + %04X]s = R%-2d): [ %08X + %d ] = %04X\n"
                   , vm->PC-4, C,
                   s1, S_Iimm, d,
                   vm->R[s1], S_Iimm, vm->R[d] & 0xFFFF);

            STORE2(&vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK2 ], vm->R[d]);
            vm->WD-=4;
            break;

        case 0x38: // SDW   | I-type | MEM[Rs1 + extend(immediate)] = (uint32) Rd
            OP_ITYPE_S(I, d, s1, S_Iimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): SDW ([R%-2d + %02X] = R%-2d): %08X = %08X\n"
                   , vm->PC-4, C,
                   s1,S_Iimm,d,
                   (vm->R[s1] + S_Iimm) & ADDR_MASK4,
                   vm->R[d]);

            STORE4(&vm->addr[ (vm->R[s1] + S_Iimm) & ADDR_MASK4 ], vm->R[d]);
            vm->WD-=2;
            break;

        case 0x39: // TRAP  | J-type | trap[immediate]
            OP_JTYPE_U(I, U_Jimm);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): TRAP([%02X]): TRAP %d\n"
                   , vm->PC-4, C,
                   U_Jimm, U_Jimm);

            vm->trap = U_Jimm;

            //vm->WD=0x7fffffff;
            // TRAP resets WD, trap might also set it, like trap_Finished().
            if (vm->event_processing)
                dlx_setWD(vm, 0x7FFFFFFF);

            // Call the above layer to deal with the trap.
            interface_trap(vm, U_Jimm);

            vm->num_traps++;

            if ((vm->WD <= 0) &&
                !vm->event_processing) {

                DEBUG(DBG_DLX, "[dlx] trap expired WD %08X. WD reset\n", vm->WD);
                dlx_setWD(vm, 0xFA0); // 4000
            }

            return 1;          // Return TRAP reached.
            break;

        case 0x3A: // INSTF | I-type | IF = Rs1
            s1 = OPERAND_S1(I);
            DEBUG(DBG_DLX,"[dlx] %08X (I=%02X): INSTF(IF = R%-2d): IF = %08X\n"
                   , vm->PC-4, C,
                   s1,
                   vm->R[s1]);

            vm->IF = vm->R[s1];
            vm->WD-=6;
            break;

        default:
            DEBUG(DBG_DLX,"[dlx] %08X fetch %08X (I=%02X); UNKNOWN\n", vm->PC, I, C);
            return -1;
        }

        // According to DLX specifications, R0 is always 0, and read-only
        if (vm->R[0]) DEBUG(DBG_DLX,"[dlx] WARNING R0 (%08X) not 0!\n", vm->R[0]);
        vm->R[0] = 0;

        if (vm->WD <= 0) {
            DEBUG(DBG_DLX,"[dlx] BREAK! PC=%08X. WD=%08X (old R28 %08X, event %d)\n",
                   vm->PC, vm->WD, vm->R[28], vm->event_processing);

            // What do we actually do on breaks?

            vm->num_breaks++;

            if (vm->event_processing) {
                vm->R[28] = dlx_getPC(vm);
            }
            dlx_setWD(vm, 0xFA0); // 4000

            return 2; // Reached BREAK
        }

        // If we run per STEP_I, this runs once
        // If we run per trap, we loop until trap's return

    } while(flags == BD_STEP_TRAP); // do until trap etc


    return 0;
}


