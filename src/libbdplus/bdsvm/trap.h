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

#ifndef TRAP_H_INCLUDED
#define TRAP_H_INCLUDED

#include <stdint.h>

#include "util/attributes.h"

struct bdplus_config_s;
struct sha_s;

#define STATUS_OK                    0x00000000
#define STATUS_INVALID_PARAMETER     0x80000001
#define STATUS_NOT_SUPPORTED         0x80000002
#define STATUS_INTERNAL_ERROR        0x80FFFFFF

#define SHA_UPDATE  0x00000000
#define SHA_INIT    0x00000001
#define SHA_FINAL   0x00000002
#define SHA_BLOCK   0x00000003

#define SHA_BLOCK_SIZE 0x200
#define SHA_DIGEST_LENGTH 20

#ifndef MIN
#define MIN(X, Y) ((X) <= (Y) ? (X) : (Y))
#endif

BD_PRIVATE uint32_t  TRAP_Finished          ( void );
BD_PRIVATE uint32_t  TRAP_FixUpTableSend    ( uint32_t );

BD_PRIVATE uint32_t  TRAP_Aes               ( struct bdplus_config_s *, uint8_t *,  uint8_t *, uint32_t,
                                              const uint8_t *, uint32_t, const uint8_t * );
BD_PRIVATE uint32_t  TRAP_PrivateKey        ( struct bdplus_config_s *, uint32_t,  uint8_t *, uint8_t *, uint32_t,  uint32_t );
BD_PRIVATE uint32_t  TRAP_Random            ( uint8_t *, uint32_t );
BD_PRIVATE uint32_t  TRAP_Sha1              ( struct sha_s **, uint8_t *,  uint8_t *, uint32_t, uint32_t );

BD_PRIVATE uint32_t  TRAP_AddWithCarry      ( uint32_t *, uint32_t *, uint32_t );
BD_PRIVATE uint32_t  TRAP_MultiplyWithCarry ( uint32_t *, uint32_t *, uint32_t, uint32_t );
BD_PRIVATE uint32_t  TRAP_XorBlock          ( uint32_t *, uint32_t *, uint32_t );

BD_PRIVATE uint32_t  TRAP_Memmove           ( uint8_t *,  uint8_t *, uint32_t );
BD_PRIVATE uint32_t  TRAP_MemSearch         ( uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t * );
BD_PRIVATE uint32_t  TRAP_Memset            ( uint8_t *,  uint8_t, uint32_t );

// trap slot* is in slot.c

BD_PRIVATE uint32_t  TRAP_ApplicationLayer  ( struct bdplus_config_s *, uint32_t, uint32_t, uint32_t * );
BD_PRIVATE uint32_t  TRAP_Discovery         ( struct bdplus_config_s *, uint32_t, uint32_t, uint8_t *, uint32_t *, uint8_t * );
BD_PRIVATE uint32_t  TRAP_DiscoveryRAM      ( struct bdplus_config_s *, uint32_t, uint8_t *, uint32_t ); // NS!
BD_PRIVATE uint32_t  TRAP_LoadContentCode   ( struct bdplus_config_s *, uint8_t *, uint32_t, uint32_t, uint32_t *, uint8_t * );
BD_PRIVATE uint32_t  TRAP_MediaCheck        ( struct bdplus_config_s *, uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t *, uint8_t * );
BD_PRIVATE uint32_t  TRAP_RunNative         ( );
BD_PRIVATE uint32_t  TRAP_000570            ( /* ? nop/vendor specific?*/ );

BD_PRIVATE uint32_t  TRAP_DebugLog          ( uint8_t *, uint32_t );
BD_PRIVATE uint32_t  TRAP_008020            ( );
BD_PRIVATE uint32_t  TRAP_008030            ( );

#endif
