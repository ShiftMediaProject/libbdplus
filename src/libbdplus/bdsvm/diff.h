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

#ifndef DIFF_H_INCLUDED
#define DIFF_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>

// Due to legacy reasons, the old java Debugger initially stored everything
// as little-endian, which was later corrected. Due to this, we define
// a way to be backward compatible. It is unlikely new developers wants to use
// this.
#define BDPLUS_LOAD_SWAP 1


BD_PRIVATE int32_t  diff_loadcore   ( uint8_t *, uint32_t, char *, uint32_t, uint32_t );

BD_PRIVATE uint32_t diff_hashdb_load( uint8_t *, uint8_t *, uint64_t, uint32_t *, uint8_t *);

#endif
