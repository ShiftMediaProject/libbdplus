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

#ifndef EVENT_H_INCLUDED
#define EVENT_H_INCLUDED

#include <stdint.h>

#include "util/attributes.h"

#define EVENT_Start            0x00000000
#define EVENT_Shutdown         0x00000010
#define EVENT_PlaybackFile     0x00000110
#define EVENT_ApplicationLayer 0x00000210
#define EVENT_ComputeSP        0x00000220


struct VM_s;

BD_PRIVATE void bdplus_send_event(struct VM_s *vm, uint32_t eventID, uint32_t arg1,
                                  uint32_t table, uint32_t segment);

#endif
