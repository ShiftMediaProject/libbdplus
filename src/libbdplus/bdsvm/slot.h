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

#ifndef SLOT_H_INCLUDED
#define SLOT_H_INCLUDED

#include <stdint.h>

#include "util/attributes.h"

struct VM_s;

BD_PRIVATE uint32_t  slot_SlotAttach        ( struct VM_s *, uint32_t, uint32_t,
                                              uint8_t *, uint8_t * );
BD_PRIVATE uint32_t  slot_SlotRead          ( struct VM_s *, uint8_t *, uint32_t );
BD_PRIVATE uint32_t  slot_SlotWrite         ( struct VM_s *, uint8_t * );

#endif
