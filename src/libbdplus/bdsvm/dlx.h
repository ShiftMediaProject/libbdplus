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

#ifndef DLX_H_INCLUDED
#define DLX_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>

#define BD_STEP_I     1  // Step one instruction
#define BD_STEP_TRAP  2  // Step until next trap


typedef struct VM_s VM;

struct bdplus_s;

BD_PRIVATE VM *             dlx_initVM           ( struct bdplus_s * );
BD_PRIVATE void             dlx_freeVM           ( VM ** );
BD_PRIVATE struct bdplus_s *dlx_getApp       ( VM * );

BD_PRIVATE uint32_t     dlx_getPC            ( VM * );
BD_PRIVATE int32_t      dlx_getWD            ( VM * );
BD_PRIVATE uint32_t     dlx_getIF            ( VM * );
BD_PRIVATE uint8_t *    dlx_getAddr          ( VM * );
BD_PRIVATE uint32_t     dlx_getAddrSize      ( VM * );
BD_PRIVATE int32_t      dlx_run              ( VM *, int32_t );
BD_PRIVATE uint32_t     dlx_num_breaks       ( VM * );
BD_PRIVATE uint32_t     dlx_num_traps        ( VM * );
BD_PRIVATE uint32_t     dlx_num_instructions ( VM * );

#endif
