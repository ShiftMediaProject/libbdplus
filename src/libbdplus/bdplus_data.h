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

#ifndef BDPLUS_DATA_H_INCLUDED
#define BDPLUS_DATA_H_INCLUDED

#include "util/attributes.h"

#include "internal.h"

#include "bdsvm/slot_data.h"

#include <stdint.h>

/*
 *
 */

struct conv_table_s;
struct bdplus_config_s;
struct VM_s;

struct bdplus_s {
    char *device_path;

    struct VM_s *vm;

    slot_t   slots[BDPLUS_NUM_SLOTS];
    uint32_t attached_slot;
    uint32_t free_slot;
    uint8_t  attachedStatus[2];

    uint8_t  volumeID[BLURAY_VOLUMEID_LEN]; // This should probably be moved out,API?
    uint8_t  mediaKey[BLURAY_VOLUMEID_LEN]; // This should probably be moved out,API?

    struct conv_table_s *conv_tab;

    struct bdplus_config_s *config;

    struct bd_mutex_s  *mutex;

    uint8_t   loaded;
    uint8_t   started;

    /* BD+ content code version */
    int gen;
    int date;
};


BD_PRIVATE int      crypto_init( void );

BD_PRIVATE int32_t  bdplus_load_svm   ( bdplus_t *plus, const char *fname );
BD_PRIVATE int32_t  bdplus_load_slots ( bdplus_t *plus, const char *fname );
BD_PRIVATE int32_t  bdplus_save_slots ( bdplus_t *plus, const char *fname );

BD_PRIVATE int32_t  bdplus_run_init   ( struct VM_s *vm );
BD_PRIVATE int32_t  bdplus_run_idle   ( struct VM_s *vm );
BD_PRIVATE int32_t  bdplus_run_convtab( bdplus_t *plus, uint32_t num_titles );
BD_PRIVATE int32_t  bdplus_run_title  ( bdplus_t *plus, uint32_t title );
BD_PRIVATE int32_t  bdplus_run_m2ts   ( bdplus_t *plus, uint32_t m2ts );
BD_PRIVATE int32_t  bdplus_run_shutdown(bdplus_t *plus );

BD_PRIVATE int32_t  bdplus_run_event210(struct VM_s *vm, uint32_t param);

#endif
