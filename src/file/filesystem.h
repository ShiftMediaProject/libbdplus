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

#ifndef BDPLUS_FILESYSTEM_H_
#define BDPLUS_FILESYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifndef BD_PUBLIC
#  define BD_PUBLIC
#endif

/* Keep this compatible with libaacs ! */
typedef struct bdplus_file BDPLUS_FILE_H;
struct bdplus_file
{
    void    *internal;

    void    (*close) (BDPLUS_FILE_H *file);
    int64_t (*seek)  (BDPLUS_FILE_H *file, int64_t offset, int32_t origin);
    int64_t (*tell)  (BDPLUS_FILE_H *file);
    int     (*eof)   (BDPLUS_FILE_H *file);
    int64_t (*read)  (BDPLUS_FILE_H *file, uint8_t *buf, int64_t size);
    int64_t (*write) (BDPLUS_FILE_H *file, const uint8_t *buf, int64_t size);
};

/**
 *
 *  Function that will be used to open a file
 *
 *  NOTE: file name is relative to disc root directory !
 *
 * @param handle application-specific handle
 * @param filename file to open
 * @return pointer to BDPLUS_FILE_H, NULL if error
 */
typedef BDPLUS_FILE_H* (*BDPLUS_FILE_OPEN)(void *handle, const char *filename);

/**
 *
 *  Register function pointer that will be used to open a file
 *
 * @param bdplus bdplus instance
 * @param handle handle that will be passed to file open function
 * @param p function pointer
 */
struct bdplus_s;

BD_PUBLIC
void bdplus_set_fopen(struct bdplus_s *bdplus, void *handle, BDPLUS_FILE_OPEN p);

#ifdef __cplusplus
}
#endif

#endif /* BDPLUS_FILESYSTEM_H_ */
