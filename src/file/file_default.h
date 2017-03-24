/*
 * This file is part of libbdplus
 * Copyright (C) 2015  VideoLAN
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

#ifndef FILE_DEFAULT_H_
#define FILE_DEFAULT_H_

#include "util/attributes.h"

struct bdplus_file;
BD_PRIVATE struct bdplus_file *file_open_default(void *root_path, const char *file_name);

#endif /* FILE_DEFAULT_H_ */
