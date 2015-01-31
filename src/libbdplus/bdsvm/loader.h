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

#ifndef LOADER_H_INCLUDED
#define LOADER_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>

struct VM_s;
struct bdplus_file;

BD_PRIVATE int32_t loader_load_svm (struct bdplus_file *fp, const char *fname, struct VM_s *vm, int *p_gen, int *p_date);

#endif
