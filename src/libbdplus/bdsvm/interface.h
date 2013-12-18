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

#ifndef INTERFACE_H_INCLUDED
#define INTERFACE_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>

#define VALIDATE_ADDRESS(      p, len) ((p) >= DLX_MEMORY_SIZE || (p) + (len) > DLX_MEMORY_SIZE || (p) + (len) < (p))
#define VALIDATE_ADDRESS_ALIGN(p, len) (VALIDATE_ADDRESS(p, len) || ((p) & 0x03) != 0)

#define VALIDATE_ADDRESS_REAL( p, len) ((p) + (len-1) < (p))


struct VM_s;

BD_PRIVATE void         interface_trap   ( struct VM_s *, uint32_t trap );


#endif
