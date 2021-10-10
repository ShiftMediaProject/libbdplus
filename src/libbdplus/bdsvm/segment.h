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

#ifndef SEGMENT_H_INCLUDED
#define SEGMENT_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>
#include <stdio.h>


typedef struct conv_table_s conv_table_t;

#ifndef BDPLUS_H_INCLUDED
typedef struct bdplus_st_s bdplus_st_t;
#endif

BD_PRIVATE uint32_t     segment_numTables ( conv_table_t * );
BD_PRIVATE uint32_t     segment_numEntries ( conv_table_t * );

BD_PRIVATE int32_t      segment_setTable    ( conv_table_t **, uint8_t *, uint32_t );
BD_PRIVATE int32_t      segment_freeTable   ( conv_table_t ** );
BD_PRIVATE uint32_t     segment_mergeTables ( conv_table_t *, conv_table_t * );
BD_PRIVATE int32_t      segment_activateTable ( conv_table_t * );

BD_PRIVATE int32_t      segment_nextSegment ( conv_table_t *, uint32_t *, uint32_t * );
BD_PRIVATE int32_t      segment_setSegment  ( conv_table_t *, uint32_t, uint32_t );
BD_PRIVATE int32_t      segment_decrypt     ( conv_table_t *, uint8_t *, uint8_t * );

BD_PRIVATE int32_t      segment_save        ( conv_table_t *, FILE * );
BD_PRIVATE int32_t      segment_load        ( conv_table_t **,FILE * );

BD_PRIVATE bdplus_st_t *segment_set_m2ts    ( conv_table_t *, uint32_t );
BD_PRIVATE int32_t      segment_patchfile   ( conv_table_t *, uint32_t , FILE * );
BD_PRIVATE int32_t      segment_patchseek   ( bdplus_st_t *, uint64_t );
BD_PRIVATE int32_t      segment_patch       ( bdplus_st_t *, int32_t, uint8_t * );
BD_PRIVATE void         segment_close_m2ts  ( bdplus_st_t * );

#endif

