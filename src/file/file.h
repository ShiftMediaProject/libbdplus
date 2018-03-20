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

#include "util/attributes.h"

#include "filesystem.h"

#include <stdint.h>
#include <stddef.h>

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

static inline void file_close(BDPLUS_FILE_H *fp)
{
    fp->close(fp);
}

static inline BD_USED int64_t file_seek(BDPLUS_FILE_H *fp, int64_t offset, int32_t origin)
{
    return fp->seek(fp, offset, origin);
}

static inline BD_USED size_t file_read(BDPLUS_FILE_H *fp, uint8_t *buf, size_t size)
{
    return (size_t)fp->read(fp, buf, (int64_t)size);
}

#define file_open(cfg, fname) (cfg->fopen(cfg->fopen_handle, fname))

#endif /* FILE_H_ */
