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

#include "slot.h"
#include "slot_data.h"

#include "dlx.h"
#include "trap.h"

#include "libbdplus/internal.h"

#include "util/logging.h"
#include "util/macro.h"

#include <string.h>
#include <stdlib.h>
#include <gcrypt.h>

/*
  This procedure call is used to request privileged access to a
  specified slot. Prior to granting such access, the code making the
  request is authenticated. The procedure's input parameters identify
  the slot number and the code length. The procedure determines the
  starting address of the code to be granted access (e.g., the address
  in the content's memory following the instruction invoking the
  SlotAttach operation). Using the address and the specified length,
  the procedure then computes a cryptographic hash (e.g., using SHA-1)
  of the code. If the hash result does not match the value of the
  authorization hash stored in the slot then slot zero is attached and
  an error is returned. Otherwise, the requested slot number becomes
  the slot that is currently attached.  As a special case, the calling
  code can specify a slot number of (-1) to request that a new slot be
  allocated. Then the player selects a slot to overwrite (as described
  below), clears it out (e.g., by setting creator media ID to the
  current media ID, zeroing the other slot fields, and incrementing
  write counter) and attaches to the slot. If the interpreter supports
  interrupts or other capabilities that could cause the unexpected
  execution of potentially-untrusted code, these should be disabled to
  avoid the introduction of malicious code while a slot is
  attached. The return value is the attached slot number, or an error
  code if the operation failed (e.g., because of a code hash mismatch)
*/

uint32_t slot_SlotAttach(VM *vm,
                         uint32_t slot, uint32_t codeLen,
                         uint8_t *codeStart, uint8_t *PCp)
{
    uint32_t PC, IF, hash_len;
    uint8_t *hash = NULL;
    uint8_t digest1[SHA_DIGEST_LENGTH], digest2[SHA_DIGEST_LENGTH];

    BD_DEBUG(DBG_BDPLUS,"[slot] trap_SlotAttach(%d)\n", slot);

    PC = dlx_getPC(vm) - 4; // Pull back 4
    IF = dlx_getIF(vm);

    if ( slot >= BDPLUS_NUM_SLOTS )
        return STATUS_INVALID_PARAMETER;

    if (slot == 0xFFFFFFFF)
        return bdplus_new_slot(dlx_getApp(vm));

    // Use 16 bytes from code_start,
    // Use codeLen*4 bytes from PC
    // Use IF

    hash_len=sizeof(uint32_t) * (1 + 1 + 4 + codeLen);//PC+IF+codeStart+codeLen

    // Allocate area to hold the hash data, since codeLen is dynamic.
    hash = (uint8_t *) malloc( hash_len );

    if (!hash) return STATUS_INTERNAL_ERROR;

    // Assign the values
    STORE4(&hash[0],  PC);
    STORE4(&hash[4],  IF);
    memcpy(&hash[8],  codeStart, 16);
    memcpy(&hash[24], PCp, codeLen * sizeof(uint32_t) );

    // Hash that buffer
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest1, hash, hash_len);

    // Hash that hash again
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest2, digest1, sizeof(digest1));

    // Release buffer
    X_FREE(hash);

    if (bdplus_slot_authenticate(dlx_getApp(vm), slot, (char *)digest2)) {
        return STATUS_OK;
    }

    return STATUS_INVALID_PARAMETER;
}


uint32_t slot_SlotRead(VM *vm,
                       uint8_t *dst, uint32_t slot)
{

    BD_DEBUG(DBG_BDPLUS,"[slot] trap_SlotRead(%d)\n", slot);

    if (slot == 0xFFFFFFFF) { // Status?

        bdplus_getAttachStatus(dlx_getApp(vm), dst);

        return STATUS_OK;
    }

    if ( slot >= BDPLUS_NUM_SLOTS )
        return STATUS_INVALID_PARAMETER;

    BD_DEBUG(DBG_BDPLUS,"[slot] shoving slot %d to memory %p\n", slot, dst);

    bdplus_getSlot(dlx_getApp(vm), slot, (slot_t *)dst);

    return STATUS_OK;
}


uint32_t slot_SlotWrite(VM *vm,
                        uint8_t *src)
{
    slot_t newslot;
    uint32_t counter;
    slot_t *newContents = (slot_t *)src;

    BD_DEBUG(DBG_BDPLUS,"[slot] trap_SlotWrite()\n");

    bdplus_getSlot(dlx_getApp(vm), 0xFFFFFFFF, &newslot);

    memcpy(newslot.mMediaID, newContents->mMediaID, sizeof(newslot.mMediaID));
    memcpy(newslot.privateData,
           newContents->privateData, sizeof(newslot.privateData));
    memcpy(newslot.authHash, newContents->authHash, sizeof(newslot.authHash));
    memcpy(newslot.payload,  newContents->payload,  sizeof(newslot.payload));

    // Update sequence counter
    counter = FETCH4(newslot.sequence_counter);
    counter++;
    STORE4(newslot.sequence_counter, counter);

    bdplus_slot_write(dlx_getApp(vm), &newslot);

    return STATUS_OK;
}


