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

#ifndef INTERNAL_H_INCLUDED
#define INTERNAL_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>

#ifndef BDPLUS_H_INCLUDED
typedef struct bdplus_s bdplus_t;
#endif

/*
 *
 */

struct conv_table_s;
struct bdplus_config_s;
struct slot_s;

BD_PRIVATE uint8_t                *bdplus_getVolumeID( bdplus_t *plus );
BD_PRIVATE uint8_t                *bdplus_getMediaKey( bdplus_t *plus );
BD_PRIVATE void                    bdplus_setConvTable( bdplus_t *plus, struct conv_table_s * );
BD_PRIVATE struct conv_table_s    *bdplus_getConvTable ( bdplus_t *plus );
BD_PRIVATE struct bdplus_config_s *bdplus_getConfig    ( bdplus_t *plus );
BD_PRIVATE const char             *bdplus_getDevicePath( bdplus_t *plus );
BD_PRIVATE char                   *bdplus_disc_cache_file( bdplus_t *plus, const char *file );

BD_PRIVATE void     bdplus_getSlot           ( bdplus_t *plus, uint32_t slot, struct slot_s *dst );
BD_PRIVATE void     bdplus_getAttachStatus   ( bdplus_t *plus, uint8_t *dst );
BD_PRIVATE void     bdplus_resetSlotStatus   ( bdplus_t *plus );
BD_PRIVATE uint32_t bdplus_slot_authenticate ( bdplus_t *plus, uint32_t slot, char *digest );
BD_PRIVATE uint32_t bdplus_new_slot          ( bdplus_t *plus );
BD_PRIVATE void     bdplus_slot_write        ( bdplus_t *plus, struct slot_s *slot );

#endif
