/*
 * This file is part of libbdplus
 * Copyright (C) 2013  VideoLAN
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "configfile.h"

#include "file.h"
#include "dirs.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BDPLUS_DIR "bdplus"


#define MIN_FILE_SIZE 1
#define MAX_FILE_SIZE 0xffffff


char *file_get_cache_dir(void)
{
    char *cache = file_get_cache_home();
    char *dir;

    if (!cache) {
        return NULL;
    }

    dir = str_printf("%s/%s/", cache, BDPLUS_DIR);
    X_FREE(cache);
    file_mkdirs(dir);

    return dir;
}

static char *_probe_config_dir(const char *base, const char *vm, const char *file)
{
    char *dir = str_printf("%s/%s/%s/%s", base, BDPLUS_DIR, vm, file);
    BDPLUS_FILE_H *fp;

    if (!dir) {
        return NULL;
    }

    fp = file_open_default()(NULL, dir);

    if (fp) {
        file_close(fp);
        *(strrchr(dir, '/') + 1) = 0;
        BD_DEBUG(DBG_BDPLUS, "Found VM config from %s\n", dir);
        return dir;
    }

    BD_DEBUG(DBG_BDPLUS, "VM config not found from  %s\n", dir);
    free(dir);
    return NULL;
}

char *file_get_config_dir(const char *file)
{
    char *dir = NULL;
    const char *vm;
    char *config_home;
    const char *base;

    vm = getenv("BDPLUS_VM_ID");
    if (!vm) {
        vm = "vm0";
    }

    /* try home directory */
    config_home = file_get_config_home();
    if (!config_home) {
        return NULL;
    }
    dir = _probe_config_dir(config_home, vm, file);
    X_FREE(config_home);
    if (dir) {
        return dir;
    }

    /* try system config dirs */
    base = file_get_config_system(NULL);
    while (base) {
        dir = _probe_config_dir(base, vm, file);
        if (dir) {
            return dir;
        }
        base = file_get_config_system(base);
    }

    return NULL;
}

static char *_load_fp(BDPLUS_FILE_H *fp, uint32_t *p_size)
{
    char *data = NULL;
    int64_t size, read_size;

    size = file_size(fp);

    if (size < MIN_FILE_SIZE || size > MAX_FILE_SIZE) {
        BD_DEBUG(DBG_FILE, "Invalid file size\n");
        return NULL;
    }

    data      = malloc(size + 1);
    if (!data) {
        BD_DEBUG(DBG_FILE, "Out of memory\n");
        return NULL;
    }

    read_size = file_read(fp, (void *)data, size);

    if (read_size != size) {
        BD_DEBUG(DBG_FILE, "Error reading file\n");
        free(data);
        return NULL;
    }

    data[size] = 0;

    if (p_size) {
        *p_size = size;
    }

    return data;
}

char *file_load(const char *path, uint32_t *p_size)
{
    char *mem;
    BDPLUS_FILE_H *fp;

    if (!path) {
        return NULL;
    }

    fp = file_open_default()(NULL, path);

    if (!fp) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Error loading %s\n", path);
        return NULL;
    }

    mem = _load_fp(fp, p_size);

    file_close(fp);

    return mem;
}
