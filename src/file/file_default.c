/*
 * This file is part of libaacs
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_default.h"

#include "file.h"

#include "util/macro.h"
#include "util/strutl.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(__MINGW32__)
/* fseeko64() prototypes from stdio.h */
#   undef __STRICT_ANSI__
#   define fseeko fseeko64
#endif

static void _file_close(BDPLUS_FILE_H *file)
{
    if (file) {
        fclose((FILE *)file->internal);
        X_FREE(file);
    }
}

static int64_t _file_seek(BDPLUS_FILE_H *file, int64_t offset, int32_t origin)
{
    return fseeko((FILE *)file->internal, offset, origin);
}

static int64_t _file_read(BDPLUS_FILE_H *file, uint8_t *buf, int64_t size)
{
    return fread(buf, 1, size, (FILE *)file->internal);
}

BDPLUS_FILE_H *file_open_default(void *handle, const char* file_name)
{
    const char    *device_root = handle;
    char          *file_path;
    BDPLUS_FILE_H *file;
    FILE          *fp;

    file_path = str_printf("%s"DIR_SEP"%s", device_root, file_name);
    fp = fopen(file_path, "rb");
    X_FREE(file_path);

    if (!fp) {
        return NULL;
    }

    file = calloc(1, sizeof(BDPLUS_FILE_H));
    file->internal = fp;
    file->close    = _file_close;
    file->seek     = _file_seek;
    file->read     = _file_read;

    return file;
}
