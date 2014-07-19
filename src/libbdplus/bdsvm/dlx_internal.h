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

#ifndef DLX_INTERNAL_H_INCLUDED
#define DLX_INTERNAL_H_INCLUDED

#include "util/attributes.h"

#include "dlx.h"

#include <stdint.h>
#include <stdio.h>

#define ADDR_MASK1 0x3FFFFF
#define ADDR_MASK2 0x3FFFFE
#define ADDR_MASK4 0x3FFFFC

#define DLX_MEMORY_SIZE    0x400000

/*
 * The DLX VM Structure
 */

#include <stdio.h>

struct bdplus_s;
struct sha_s;

struct VM_s {

    uint8_t *addr;             // VM's memory area.
    uint32_t size;             // Allocated size, probably 0x400000

    uint32_t PC;               // Program Counter

    uint32_t R[32];            // R0 is always 0, and read only.
                               // R31 is used by some instructions
    uint32_t IF;               // Intruction Filter
    int32_t  WD;               // Watchdog timer

    uint32_t code_start;       // Generally 0x1000. Set by first call to setPC
    uint32_t event_processing; // Set when we are processing events, clear on idle
    uint32_t event_current;    // value of the current event.

    // Just statistics
    uint32_t num_breaks;
    uint32_t trap;
    uint32_t num_traps;
    uint32_t num_instructions;

    // Trace file handles, if used..
    FILE *trace_PC;
    FILE *trace_WD;
    FILE *trace_IF;

    // for traps
    struct bdplus_s *plus;
    struct sha_s    *sha_ctx_head;
};

BD_PRIVATE uint32_t     dlx_setPC            ( VM *, uint32_t );
BD_PRIVATE int32_t      dlx_setWD            ( VM *, int32_t );
BD_PRIVATE uint32_t     dlx_setIF            ( VM *, uint32_t );
BD_PRIVATE uint32_t     dlx_getStart         ( VM * );

#endif
