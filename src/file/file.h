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

#ifndef FILE_H_
#define FILE_H_

#include "filesystem.h"

#ifdef _WIN32
# define DIR_SEP "\\"
# define DIR_SEP_CHAR '\\'
#else
# define DIR_SEP "/"
# define DIR_SEP_CHAR '/'
#endif

/*
 * file access
 */

#define file_close(X)    X->close(X)
#define file_seek(X,Y,Z) X->seek(X,Y,Z)
#define file_read(X,Y,Z) X->read(X,Y,Z)

#define file_open(cfg, fname) (cfg->fopen(cfg->fopen_handle, fname))

#endif /* FILE_H_ */
