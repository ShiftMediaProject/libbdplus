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

#ifndef SLOT_DATA_H_INCLUDED
#define SLOT_DATA_H_INCLUDED

#include <stdint.h>

#define BDPLUS_NUM_SLOTS 500
#define BLURAY_VOLUMEID_LEN 16


// 256 bytes.
struct slot_s {
    uint8_t cMediaID[16];        // 00-0F Creator Media ID
    uint8_t mMediaID[16];        // 10-1F Last Update Media ID

    uint8_t privateData[16];     // 20-2F

    uint8_t authHash[20];        // 40-43

    uint8_t youguess[4];         // 44-47

    uint8_t sequence_counter[4]; // 48-4B

    uint8_t payload[180];        // 4C-FF
};

typedef struct slot_s slot_t;


#endif
