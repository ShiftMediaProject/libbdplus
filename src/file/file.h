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

typedef BDPLUS_FILE_H BD_FILE_H;
typedef BDPLUS_FILE_OPEN BD_FILE_OPEN;

/*
 * file access
 */

static inline void file_close(BD_FILE_H *fp)
{
    fp->close(fp);
}

static inline int64_t file_tell(BD_FILE_H *fp)
{
    return fp->tell(fp);
}

static inline BD_USED int64_t file_seek(BD_FILE_H *fp, int64_t offset, int32_t origin)
{
    return fp->seek(fp, offset, origin);
}

static inline BD_USED size_t file_read(BD_FILE_H *fp, uint8_t *buf, size_t size)
{
    return (size_t)fp->read(fp, buf, (int64_t)size);
}

#define file_open(cfg, fname) (cfg->fopen(cfg->fopen_handle, fname))

BD_PRIVATE int64_t file_size(BD_FILE_H *fp);

BD_PRIVATE BDPLUS_FILE_OPEN file_open_default(void);

/*
 * directory access
 */

typedef struct
{
    char    d_name[256];
} BD_DIRENT;

typedef struct bdplus_dir_s BD_DIR_H;
struct bdplus_dir_s
{
    void* internal;
    void (*close)(BD_DIR_H *dir);
    int (*read)(BD_DIR_H *dir, BD_DIRENT *entry);
};

typedef BD_DIR_H* (*BD_DIR_OPEN) (const char* dirname);

#define dir_close(X) X->close(X)
#define dir_read(X,Y) X->read(X,Y)

BD_PRIVATE BD_DIR_OPEN dir_open_default(void);

/*
 * local filesystem
 */

BD_PRIVATE int file_path_exists(const char *path);
BD_PRIVATE int file_mkdir(const char *dir);
BD_PRIVATE int file_mkdirs(const char *path);

#endif /* FILE_H_ */
