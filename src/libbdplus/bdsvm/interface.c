/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
 * Copyright (C) 2013       VideoLAN
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

#include "interface.h"

#include "dlx_internal.h"
#include "slot_data.h"
#include "event.h"
#include "segment.h"
#include "slot.h"
#include "trap.h"

#include "libbdplus/internal.h"

#include "util/logging.h"
#include "util/macro.h"

// Load results of DiscoveryRAM and DeviceDescovery (1,3) from snapshops?
//#define DLX_LOAD_FROM_SNAPSHOT





/*
 * Handle a trap for a VM. This translates between VM to trap calls. Note that
 * trap calls do not have any knowledge of VM and its insides.
 */
void interface_trap(VM *vm, uint32_t trap)
{
    bdplus_t *plus = vm->plus;
    uint32_t result = 0;
    uint8_t *SP; // Not really a Stack Pointer, but all traps use R29
    uint32_t fsize;
    // Temporary variable holders for parameter checking
    uint32_t src, dst, slot, key, len, PC, fname_len;
    uint32_t Region, RegionLen, SearchData, SearchDataLen;
    uint64_t src64;

    if (!plus || !vm->addr) return; // assert?

    DEBUG(DBG_BDPLUS,"[interface] ** #%06u TRAP %08x (%d) return PC=%08X: event %d (current %04x)\n", vm->num_traps, trap, trap, vm->PC-4, vm->event_processing, vm->event_current);

    SP = &vm->addr[ vm->R[29] & ADDR_MASK4 ];

    switch(trap) {

        // All calls below to &vm.addr, needs to have & ADDR_MASK4 added.

        // 000010 = void TRAP_Finished();
    case 0x010: // Trap_Finished
        result = TRAP_Finished();

        // Finished called, WD=0x4000 to sit in idle-loop
        //dlx_setPC(vm, vm->R[28]);
#if 1
        DEBUG(DBG_BDPLUS,"[interface] trap_Finished. PC=%08X R28=%08X: EVENT %04X\n",
              vm->PC, vm->R[28],
              vm->event_current);
#else
        DEBUG(DBG_DLX,"[interface] trap_Finished. PC=%08X R28=%08X:", vm->PC, vm->R[28]);
        for (result = 0; result < 16; result++)
            DEBUG(DBG_DLX,"%02X ", vm->addr[result]);

        DEBUG(DBG_DLX,"\n");
        for (result = 0; result < 16; result++)
            DEBUG(DBG_DLX,"%02X ", vm->addr[0x10+result]);
        DEBUG(DBG_DLX,"\n");
#endif

        // If Finished is in reply to ComputeSP, we received a new
        // decode-key.
        if (vm->event_current == EVENT_ComputeSP) {
            segment_decrypt(bdplus_getConvTable(plus),
                            &vm->addr[ 0x10 ],
                            &vm->addr[ 0x20 ]);
        }

#if 0
        /* table is saved in bdplus.c */
        // If we Finished from a Shutdown, we are completely done.
        if (vm->event_current == EVENT_Shutdown) {
            segment_save(bdplus_getConvTable(plus));
        }
#endif

        if (vm->event_processing) {
            dlx_setPC(vm, vm->R[28] & ADDR_MASK4);
            dlx_setWD(vm, 0xFA0); // 4000 decimal
        }

        // Enter IDLE mode
        vm->event_processing = 0;
        vm->event_current = 0x88888888; // :)

        // trap_Finish() does not set R1, so we quit here.
        return;
        break;


        // 000020 trap_ConversionTable(uint32_t len, uint32_t *src);
    case 0x020: // TRAP_ConversionTable

        len = FETCH4( SP   );
        src = FETCH4( SP+4 );

        DEBUG(DBG_BDPLUS,"[interface] trap_ConversionTable(%08X, *%08X)\n",  len, src);

        if ( VALIDATE_ADDRESS_ALIGN(src, len) )
            result = STATUS_INVALID_PARAMETER;
        else if ( len > 0x100000 )
            result = STATUS_NOT_SUPPORTED;
        else
            result =
                TRAP_FixUpTableSend(len);

        // Save the table to VM
        if (len) {
            conv_table_t *old_ct = bdplus_getConvTable(plus);
            conv_table_t *ct = NULL;

            // Decode it into C structures.
            segment_setTable(&ct,
                             &vm->addr[ src & ADDR_MASK4 ],
                             len);

            // Assign it, or merge it.
            if (!old_ct) {
                bdplus_setConvTable(plus, ct);
            } else {
                segment_mergeTables(old_ct, ct);
                segment_freeTable(&ct);
            }

        }

        break;

        // 000110 = UINT32 TRAP_Aes(UINT8 *dst, UINT8 *src, UINT32 len, UINT8 *key, UINT32 opOrKeyID);
    case 0x110: // TRAP_Aes
        dst = FETCH4( SP   );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );
        key = FETCH4( SP+12);

        DEBUG(DBG_BDPLUS,"[interface] Aes(*%08X, *%08X, %08X, *%08X, %08X\n", dst, src, len, key, FETCH4(SP+16));

        // Check the event-id.
        // This trap will fail if we are not in processing mode.

        DEBUG(DBG_BDPLUS,"[interface] TRAP_Aes: processing %d and event %08X\n", vm->event_processing, vm->event_current);

        if ((vm->event_current != 0x0000) &&
            (vm->event_current != 0x0010) &&
            (vm->event_current != 0x0110)) {
            DEBUG(DBG_BDPLUS,"[interface] TRAP_Aes refused due to event-ID %08X\n", vm->event_current);
            result = STATUS_INTERNAL_ERROR;
        } else
            //        if (vm->num_traps == 10179) {
            //result = STATUS_INTERNAL_ERROR;
            //} else
            if (
            VALIDATE_ADDRESS(dst, 16 * len) ||
            VALIDATE_ADDRESS(src, 16 * len) ||
            VALIDATE_ADDRESS(key, 16) ||
            ((dst + (16 * len) > src) && (dst < src + (16 * len)) && (dst != src))
            //            || ((dst + (16 * len) > key) && (dst < key + (16 * len)) && (dst != key))

            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_Aes(
                         bdplus_getConfig(plus),
                         &vm->addr[ dst & ADDR_MASK1 ],  // dst
                         &vm->addr[ src & ADDR_MASK1 ],  // src
                         len,
                         &vm->addr[ key & ADDR_MASK1 ],  // key
                         (uint32_t) FETCH4( SP+16 ),     // id
                         bdplus_getMediaKey(plus)
                         );

        break;

        // 000120 = UINT32 TRAP_PrivateKey(UINT32 keyID, UINT8 *dst, UINT8 *src, UINT32 srcLen, UINT32 controlWord);
    case 0x120: // TRAP_PrivateKey
        dst = FETCH4( SP+4 );
        src = FETCH4( SP+8 );
        len = FETCH4( SP+12 );

        DEBUG(DBG_BDPLUS,"[interface] PrivateKey(%08X, *%08X, *%08X, %08X, %08X)\n",
               FETCH4( SP   ), dst, src, len, FETCH4( SP+16));

        // Check the event-id.
        if ((vm->event_current != 0x0000) &&
            (vm->event_current != 0x0010) &&
            (vm->event_current != 0x0110)) {
            DEBUG(DBG_BDPLUS,"[interface] TRAP_PrivateKey refused due to event-ID %08X\n",
                   vm->event_current);
            result = STATUS_INTERNAL_ERROR;
        } else
        if (
            VALIDATE_ADDRESS(dst, 40) ||
            VALIDATE_ADDRESS(src, len) ||
            (dst < src)
            )
            result = STATUS_INVALID_PARAMETER;
        else result =
                 TRAP_PrivateKey(
                                 bdplus_getConfig(plus),
                                 (uint32_t) FETCH4( SP   ),      // KeyID
                                 &vm->addr[ dst & ADDR_MASK1 ],  // dst
                                 &vm->addr[ src & ADDR_MASK1 ],  // src
                                 len,                            // srclen
                                 (uint32_t) FETCH4( SP+16)       // controlWord
                                 );

#ifdef DLX_LOAD_FROM_SNAPSHOT
        // No convtab at all
        if (result == STATUS_OK) {
            // Load the memory changes from snapshots.
            dlx_loadfrom_snapshot(vm, dst & ADDR_MASK1, 40);
        }
#endif

        break;

        // 000130 = UINT32 TRAP_Random(UINT8 *dst, UINT32 len);
    case 0x130: // TRAP_Random
        dst = FETCH4( SP   );
        len = FETCH4( SP+4 );
        DEBUG(DBG_BDPLUS,"[interface] TRAP_Random(%08X, %08X)\n", dst, len);
        if (
            VALIDATE_ADDRESS(dst, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_Random(
                            &vm->addr[ dst & ADDR_MASK1 ],  // dst
                            len
                            );


#ifdef DLX_LOAD_FROM_SNAPSHOT

        if (result == STATUS_OK) {
            // Load the memory changes from snapshots.
            dlx_loadfrom_snapshot(vm, dst & ADDR_MASK1, len);
        }
#endif

        break;

        // 000140=UINT32 TRAP_Sha(UINT8 *dst,UINT8 *src,UINT32 len, UINT32 op);
    case 0x140: // TRAP_Sha
        dst = FETCH4( SP );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] Sha1(%08X, %08X, %08X, %08X\n", dst, src, len, FETCH4( SP+12));

        if (
            VALIDATE_ADDRESS(src, len) ||
            VALIDATE_ADDRESS_ALIGN(dst, 0x200) ||
            (dst + 0x200 > src && dst < src + len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_Sha1(
                          &vm->sha_ctx_head,
                          &vm->addr[ dst & ADDR_MASK4 ],  // dst
                          &vm->addr[ src & ADDR_MASK1 ],  // src
                          len,                            // len
                          FETCH4( SP+12)       // op
                          );

        break;


        // 000210= UINT32 TRAP_AddWithCarry(UINT32 *dst,UINT32 *src,UINT32 len);
    case 0x210: // TRAP_AddWithCarry
        dst = FETCH4( SP   );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] AddWithCarry(%08X, %08X, %08X)\n", dst, src, len);

        if (
            VALIDATE_ADDRESS_ALIGN(dst, 4 * len) ||
            VALIDATE_ADDRESS_ALIGN(src, 4 * len) ||
            (src < (dst + 4 * len) && (src + 4 * len) > dst && (src != dst))
            )
            result = STATUS_INVALID_PARAMETER;
        else if (len == 0)
            result = STATUS_OK;
        else
            result =
                TRAP_AddWithCarry(
                                  (uint32_t *)
                                  &vm->addr[ dst & ADDR_MASK4],//dst
                                  (uint32_t *)
                                  &vm->addr[ src & ADDR_MASK4],//src
                                  (uint32_t) len               //len
                                  );
        break;

        //000220=UINT32 TRAP_MultiplyWithRipple(UINT32 *dst,UINT32 *src,
        //                                     UINT32 len, UINT32 multiplicand);
    case 0x220: // TRAP_MultiplyWithRipple
        dst = FETCH4( SP   );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] MultiplyWithCarry(*%08X, *%08X, %08X, %08X)\n", dst, src, len, FETCH4(SP+12));

        if (
            VALIDATE_ADDRESS_ALIGN(dst, 4 * len + 4) ||
            VALIDATE_ADDRESS_ALIGN(src, 4 * len) ||
            (dst + 4 * len + 4 > src && dst < src + 4 * len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_MultiplyWithCarry(
                                        (uint32_t *)
                                        &vm->addr[ dst & ADDR_MASK4],//dst
                                        (uint32_t *)
                                        &vm->addr[ src & ADDR_MASK4],//src
                                        len,                         //len
                                        FETCH4( SP+12)       // op
                                        );
        break;


        // 000230 = UINT32 TRAP_XorBlock(UINT32 *dst, UINT32 *src, UINT32 len);
    case 0x230: // TRAP_XorBlock
        dst = FETCH4( SP   );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] XorBlock(%08X, %08X, %08X)\n", dst, src, len);

        if (
            VALIDATE_ADDRESS_ALIGN(dst, 4 * len) ||
            VALIDATE_ADDRESS_ALIGN(src, 4 * len) ||
            ((dst + (4 * len) > src) && (dst < src + (4*len)))
            )
            result = STATUS_INVALID_PARAMETER;
        else if (!len)
            result = STATUS_OK;
        else
            result =
                TRAP_XorBlock(
                              (uint32_t *)&vm->addr[ dst & ADDR_MASK4 ],// dst
                              (uint32_t *)&vm->addr[ src & ADDR_MASK4 ],// src
                              len
                              );
        break;

        // 000310 = UINT32 TRAP_Memmove(UINT8 *dst, UINT8 *src, UINT32 len);
    case 0x310: // TRAP_Memmove
        dst = FETCH4( SP   );
        src = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] Memmove(%08X, %08X, %08X)\n", dst, src, len);

        if (
            VALIDATE_ADDRESS(dst, len) ||
            VALIDATE_ADDRESS(src, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else if (
                 (src == dst) ||
                 (len == 0)
                 )
            result = STATUS_OK;
        else
            result =
                TRAP_Memmove(
                             (uint8_t *)&vm->addr[ dst & ADDR_MASK1 ],  // dst
                             (uint8_t *)&vm->addr[ src & ADDR_MASK1 ],  // src
                             len
                             );
        break;

        // 000320 = UINT32 TRAP_MemSearch(UINT8 *Region, UINT32 RegionLen,
        //                                UINT8 *SearchData,
        //                                UINT32 SearchDataLen, UINT32 *Dst);
    case 0x320: // TRAP_MemSearch
        Region        = FETCH4( SP    );
        RegionLen     = FETCH4( SP+4  );
        SearchData    = FETCH4( SP+8  );
        SearchDataLen = FETCH4( SP+12 );
        dst           = FETCH4( SP+16 );

        DEBUG(DBG_BDPLUS,"[interface] MemSearch(*%08X, %08X, *%08X, %08X, %08X\n", Region, RegionLen, SearchData, SearchDataLen, dst);
        // Set fsize to Region start, then trap_MemSearch will +i the location
        // of found string. Or set it to 00 as needed.
        fsize = Region;
        if (
            VALIDATE_ADDRESS(Region, RegionLen) ||
            VALIDATE_ADDRESS(SearchData, SearchDataLen) ||
            VALIDATE_ADDRESS_ALIGN(dst, 4)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_MemSearch(
                               &vm->addr[ Region & ADDR_MASK1 ], // region
                               RegionLen,                  // regionlen
                               &vm->addr[ SearchData & ADDR_MASK1 ],
                               SearchDataLen,
                               &fsize                      // *Dst
                               );
        // fsize has VM memory address, so translate to virtual address
        if (result == STATUS_OK) {
            DEBUG(DBG_BDPLUS,"[interface] MemSearch: storing %08X in *dst\n", fsize);
            STORE4(&vm->addr[dst & ADDR_MASK4],fsize);
        }
        break;


        // 000330 = UINT32 TRAP_Memset(UINT8 *dst, UINT8 fillvalue, UINT32 len);
    case 0x330: // TRAP_Memset(UINT8 *dst, UINT8 fillvalue, UINT32 len);
        dst = FETCH4( SP   );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] Memset(%08X, %08X)\n", dst, len);
        if (
            VALIDATE_ADDRESS(dst, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else if (len == 0)
            result = STATUS_OK; // ?
        else
            result =
                TRAP_Memset(
                            &vm->addr[ dst & ADDR_MASK1 ],  // dst
                            (uint8_t) FETCH4( SP+4  )&0xFF,          // fill
                            len
                            );
        break;

        //uint32_t trap_SlutAttach(uint32_t slot, uint32_t codeLen,
        //               uint32_t PC, uint32_t IF, uint8_t *CodeEntry,
        //               uint8_t *PCp)
        // 000410 = UINT32 TRAP-SlotAttach(UINT32 slot, UINT32 codeLen);
    case 0x410:
        // Reset status. Reset before or after invalid parameter test?
        bdplus_resetSlotStatus(plus);

        PC = vm->PC - 4;
        len = FETCH4( SP+4 );

        DEBUG(DBG_BDPLUS,"[interface] SlotAttach(%08X, %u, %08X, %08X)\n", FETCH4( SP   ), len, vm->code_start, PC);

        // [interface] SlotAttach(00000000, 20, 00001000, 00026244) :800001


        if (
            VALIDATE_ADDRESS_ALIGN(PC, 4 * len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                slot_SlotAttach(vm,
                                (uint32_t)FETCH4( SP   ),         // slot
                                len,                              // codeLen
                                (uint8_t *)&vm->addr[ vm->code_start],
                                (uint8_t *)&vm->addr[ PC ]        // *PC
                                );
        break;

        // 000420 = UINT32 TRAP-SlotRead(UINT8 *dst, UINT32 slot);
    case 0x420:
        // Tests with addresses should be done un-masked, as confirmed by
        // snapshots.
        dst  = FETCH4( SP   );
        slot = FETCH4( SP+4 );
        DEBUG(DBG_BDPLUS,"[interface] SlotRead(%08X, %d)\n", dst,
               slot );

        if (slot == 0xFFFFFFFF)
            len = 0x0C;
        else
            len = sizeof(slot_t);

        if (
            VALIDATE_ADDRESS(dst, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                slot_SlotRead(vm,
                              &vm->addr[ dst & ADDR_MASK4 ],
                              slot
                              );


#ifdef DLX_LOAD_FROM_SNAPSHOT_NOSLOTREAD
        if (result == STATUS_OK) {
            // Load the memory changes from snapshots.
            dlx_loadfrom_snapshot(vm, dst & ADDR_MASK4, len);
        }
#endif



        break;

        // 000430 = UINT32 TRAP_SlotWrite(UINT8 *newContents);
    case 0x430:
        src  = FETCH4( SP   );

        if (
            VALIDATE_ADDRESS(src, sizeof(slot_t))
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                slot_SlotWrite(vm,
                               &vm->addr[ src & ADDR_MASK4 ]     // src
                               );
        break;


        // 000510=UINT32 TRAP_ApplicationLayer(UINT32 dev, UINT32 opID, UINT8 *buf);
    case 0x510:
        src  = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] ApplicationLayer(%08X, %08X, *%08X)\n",
               FETCH4( SP   ), FETCH4( SP+4 ), src);

        if ((vm->event_current == 0x0000) ||
            (vm->event_current == 0x0010) ||
            (vm->event_current == 0x0110)) {
            DEBUG(DBG_BDPLUS,"[interface] TRAP_ApplicationLayer refused due to event-ID %08X\n",
                   vm->event_current);
            result = STATUS_INTERNAL_ERROR;
        } else
        if (
            VALIDATE_ADDRESS_ALIGN(src, 4)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_ApplicationLayer(
                                      bdplus_getConfig(plus),
                                      FETCH4( SP   ),
                                      FETCH4( SP+4 ),
                                      (uint32_t*)&vm->addr[ src & ADDR_MASK4 ]
                                     );


#ifdef DLX_LOAD_FROM_SNAPSHOT
        // Without this I get type3
        if (result == STATUS_OK) {
            // Load the memory changes from snapshots.
            dlx_loadfrom_snapshot(vm, src & ADDR_MASK4, 4);
        }
#endif


        break;



        // 000520=UINT32 TRAP_Discovery(UINT32 dev, UINT32 qID, UINT8 *buf, UINT32 *len);
    case 0x520: // TRAP_DeviceDiscovery
        len   = FETCH4( SP+12  );
        fsize = FETCH4(&vm->addr[ len & ADDR_MASK4 ] );
        dst   =  FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] Discovery: %08X, %08X, %08X, %d\n",
               FETCH4( SP   ),  FETCH4( SP +4  ), dst, fsize);

        // [interface] Discovery: 00000001, 00000003, 0002EC68, 60
        // should be 8000001
        if (
            VALIDATE_ADDRESS_ALIGN(len, 4) ||
            VALIDATE_ADDRESS_ALIGN(dst, fsize)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                  TRAP_Discovery(
                                 bdplus_getConfig(plus),
                                 FETCH4( SP   ),     // dev
                                 FETCH4( SP+4 ),     // qID
                                 &vm->addr[ dst & ADDR_MASK4 ], // buf
                                 &fsize,                        // *len
                                 bdplus_getVolumeID(plus)
                                );

        if (result == STATUS_OK) {
            STORE4(&vm->addr[ len & ADDR_MASK4],fsize);
        }

#if 1
        // We know 1,3 will differ, due to the time, but want to make sure
        // that the other modes compare identical. So, during debugging,
        // we make 1,3 be its own trap
        if ((FETCH4(SP) == 1) &&
            (FETCH4(SP+4) == 3))
            vm->trap = 0x521;
#endif

#ifdef DLX_LOAD_FROM_SNAPSHOT
        // type 3
        if ((vm->trap == 0x521) &&
            (result == STATUS_OK)) {
            // Load the memory changes from snapshots.
            dlx_loadfrom_snapshot(vm, dst & ADDR_MASK4, 60);

            // Lets fiddle with the time!
            //vm->addr[ (dst & ADDR_MASK4) + 7 ] |= 1; // minisecs
#if 0
            printf("Time: %02X%02X %02X %02X %02X%02X %02X %02X\n",
                   vm->addr[ (dst & ADDR_MASK4) + 0 ],
                   vm->addr[ (dst & ADDR_MASK4) + 1 ],
                   vm->addr[ (dst & ADDR_MASK4) + 2 ],
                   vm->addr[ (dst & ADDR_MASK4) + 3 ],
                   vm->addr[ (dst & ADDR_MASK4) + 4 ],
                   vm->addr[ (dst & ADDR_MASK4) + 5 ],
                   vm->addr[ (dst & ADDR_MASK4) + 6 ],
                   vm->addr[ (dst & ADDR_MASK4) + 7 ]);
#endif
        }

#endif



        break;


        // 000530=UINT32 TRAP_DiscoveryRAM(UINT32 src, UINT32 dst, UINT32 len);
    case 0x530: // TRAP_DiscoveryRAM(UINT32 src, UINT32 dst, UINT32 len);
        src = FETCH4( SP   );
        dst = FETCH4( SP+4 );
        len = FETCH4( SP+8 );

        DEBUG(DBG_BDPLUS,"[interface] DiscoveryRAM(*%08x, *%08X, %08X)\n", src, dst, len);
        //[interface] DiscoveryRAM(001a94f0, 003DFCA0, 33C1CBF6)
        //[interface] DiscoveryRAM(001a94f0, 003DFCA0, 33C1CBF6)

        src64 = (uint64_t) src;

        //[interface] DiscoveryRAM(*c0100000, *003DEBCB, 00000001)
        // should be 80000001
        if ( len > 0x100000 )
            result = STATUS_NOT_SUPPORTED;
        else if (
                 VALIDATE_ADDRESS(dst, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else if ( !len )
            result = STATUS_OK;
        else if (
                 VALIDATE_ADDRESS_REAL(src64, (uint64_t)len) ||
                 ( src64 + (uint64_t)len > UINT64_C(0x100000000) ) ||
                 ( src >= 0x400000 ) ||
                 ( src+len >= 0x400000 )  // Why is this one current?
                 )
            result = STATUS_INVALID_PARAMETER;
        else
            result =
                TRAP_DiscoveryRAM(
                                  bdplus_getConfig(plus),
                                  src, // src is NOT VM space, but real map
                                  &vm->addr[ dst & ADDR_MASK1 ],  // dst
                                  len
                                  );

#ifdef DLX_LOAD_FROM_SNAPSHOT
        // Load the bytes of DiscoveryRAM from snapshot?
        if (result == STATUS_OK) {
            VM *poo;
            char buffer[1024];
            int i;

            poo  = bdplus_VM_new(DLX_MEMORY_SIZE);
            snprintf(buffer, sizeof(buffer), "post_trap_snapshots/post_trap_mem_%06u.bin", vm->num_traps);

            DEBUG(DBG_BDPLUS,"[bdtest] fudging with '%s'\n", buffer);

            dlx_loadcore(poo, 0x0, buffer, 0 /*DLX_LOAD_SWAP*/);

            DEBUG(DBG_BDPLUS,"Mine: ");
            for (i = 0; i < len; i++) {
                if (!(i % 16)) DEBUG(DBG_BDPLUS,"\n");
                DEBUG(DBG_BDPLUS,"%02X ", vm->addr[ (dst & ADDR_MASK1) + i ]);
            }
            DEBUG(DBG_BDPLUS,"\nTheirs: ");
            for (i = 0; i < len; i++) {
                if (!(i % 16)) DEBUG(DBG_BDPLUS,"\n");
                DEBUG(DBG_BDPLUS,"%02X ", poo->addr[ (dst & ADDR_MASK1) + i ]);
            }
            DEBUG(DBG_BDPLUS,"\nReturn\n");

            memcpy(&vm->addr[ dst & ADDR_MASK1 ],
                   &poo->addr[ dst & ADDR_MASK1 ],
                   len);
            bdplus_VM_free(poo);
        }
#endif

        break;

        // 000540 = UINT32 TRAP_LoadContentCode(UINT8 *ContentCode, UINT32 block, UINT32 offset, UINT32 *len, UINT8 *dst)
    case 0x540: // LoadContentCode
        src       = FETCH4( SP   ); // FileName
        fname_len = FETCH4( SP+4 ); // FileName
        len       = FETCH4( SP+12  );
        fsize     = FETCH4(&vm->addr[ len & ADDR_MASK4 ] );

        DEBUG(DBG_BDPLUS,"[interface] LoadContentCode(%08X-%08X): %d\n", FETCH4( SP+16 ), FETCH4( SP+16 ) + fsize, fsize);
        DEBUG(DBG_BDPLUS,"[interface] vm translated memory (%p-%p): %d\n", &vm->addr[FETCH4( SP+16 )], &vm->addr[FETCH4( SP+16 ) + fsize],
               fsize);

        if (FETCH4( SP+16 ) + fsize >= vm->size)
            DEBUG(DBG_BDPLUS,"[interface] Warning, load would wrap memory\n");


        // Why is "dst" not checked?
        if ((vm->event_current != 0x0000) &&
            (vm->event_current != 0x0010) &&
            (vm->event_current != 0x0110)) {
            DEBUG(DBG_BDPLUS,"[interface] TRAP_LoadContentCode refused due to event-ID %08X\n",  vm->event_current);
            result = STATUS_INTERNAL_ERROR;
        } else
        if (
            VALIDATE_ADDRESS_ALIGN(len, 4) ||
            VALIDATE_ADDRESS(src, 5)
            )
            result = STATUS_INVALID_PARAMETER;
        else {
            result =
                TRAP_LoadContentCode(
                                     bdplus_getDevicePath(plus),
                                     &vm->addr[ src & ADDR_MASK1 ],// ContentCode
                                     FETCH4( SP+4  ),  // block
                                     FETCH4( SP+8  ),  // offset
                                     &fsize,           // *len
                                     &vm->addr[ FETCH4( SP+16 ) & ADDR_MASK1] //dst
                                     );
        }

        if (result == STATUS_OK) {
            STORE4(&vm->addr[ len & ADDR_MASK4],fsize);
        }
        break;

        // 000550=UINT32 TRAP_MediaCheck(UINT8 *FileName,UINT32 FileNmLen, UINT32 FileOffsetHigh, UINT32 FileOffsetLow, UINT32 *len, UINT8 *dst);
    case 0x550: // MediaCheck
        src       = FETCH4( SP   );  // FileName
        fname_len = FETCH4( SP+4 );
        len       = FETCH4( SP+16 );
        dst       = FETCH4( SP+20 );
        fsize     = FETCH4(&vm->addr[ len & ADDR_MASK4 ] );

        DEBUG(DBG_BDPLUS,"TRAP_MediaCheck(%08X, %u, %u, %08X, %08X)\n",
               src,  // fname
               fname_len,
               fsize,                        // *len
               dst,
               len
               );
        if ((vm->event_current != 0x0000)) {
            DEBUG(DBG_BDPLUS,"[interface] TRAP_MediaCheck refused due to event-ID %08X\n",
                   vm->event_current);
            result = STATUS_INTERNAL_ERROR;
        } else
        if (
            VALIDATE_ADDRESS(len, 4) ||
            VALIDATE_ADDRESS_ALIGN(len, 4)
            )
            result = STATUS_INVALID_PARAMETER;
        else if (
                 (fsize > 0x200000)
                 )
            result = STATUS_NOT_SUPPORTED;
        else if (
                 (fsize & 0x1FF) != 0 ||
                 VALIDATE_ADDRESS(dst,SHA_DIGEST_LENGTH*(fsize/SHA_BLOCK_SIZE)) ||
                 VALIDATE_ADDRESS(src, fname_len) ||
                 fname_len == 0 ||
                 fname_len > 0x400
                 )
            result = STATUS_INVALID_PARAMETER;
        else {
            result =
                TRAP_MediaCheck(
                                bdplus_getDevicePath(plus),
                                &vm->addr[ src & ADDR_MASK1 ],// fname
                                fname_len,
                                FETCH4( SP+8  ),               // OffsHigh
                                FETCH4( SP+12 ),               // OffsLow
                                &fsize,                        // *len
                                &vm->addr[ dst & ADDR_MASK1 ]  // dst
                               );
        }


        if (result == STATUS_OK) {
            DEBUG(DBG_BDPLUS,"Storing %08X at %08X\n", fsize, len);
            STORE4(&vm->addr[ len & ADDR_MASK4],fsize);
        }
        break;

        // 008010 = UINT32 TRAP_DebugLog(UINT8 *txt, UINT32 len);
    case 0x8010: // DebugLog
        src   = FETCH4( SP   );  // txt
        len   = FETCH4( SP+4 );  // len
        if (
            VALIDATE_ADDRESS(src, len)
            )
            result = STATUS_INVALID_PARAMETER;
        else
            result = TRAP_DebugLog(
                                   &vm->addr[src & ADDR_MASK1],
                                   len
                                  );
        break;

    default:
        DEBUG(DBG_BDPLUS, "[interface] unknown trap %08X:%d.\n", trap, trap);
        result = STATUS_NOT_SUPPORTED;
    }

    DEBUG(DBG_BDPLUS,"[interface] TRAP return: R1 = %08X\n", result);
    vm->R[1] = result;

    // Decrease WD if not in event_processing
    if ((result != STATUS_INTERNAL_ERROR) &&
        !vm->event_processing) {
        int32_t tWD;

        tWD = dlx_getWD(vm);

        DEBUG(DBG_BDPLUS,"[interface] I want to decrease %08X by 0x140 to %08X (result %08X, processing %u, event %08X)\n",
               tWD, tWD - 0x140,
               result, vm->event_processing, vm->event_current);
#if 1
        if ((int32_t)tWD >= 0x140)
            tWD -= 0x140;
        else
            tWD = 0;

        dlx_setWD(vm, tWD);
#endif
    }

}


