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

#include "dirs.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
# define mkdir(p,m) win32_mkdir(p)
#endif


#define BDPLUS_DIR "bdplus"


#define MIN_FILE_SIZE 1
#define MAX_FILE_SIZE 0xffffff


int file_mkpath(const char *path)
{
    struct stat s;
    int result = 1;
    char *dir = str_printf("%s", path);
    char *end = dir;

    while (*end == '/')
        end++;

    while ((end = strchr(end, '/'))) {
        *end = 0;

        if (stat(dir, &s) != 0 || !S_ISDIR(s.st_mode)) {
            BD_DEBUG(DBG_FILE, "Creating directory %s\n", dir);

            if (mkdir(dir, S_IRWXU|S_IRWXG|S_IRWXO) == -1) {
                BD_DEBUG(DBG_FILE | DBG_CRIT, "Error creating directory %s\n", dir);
                result = 0;
                break;
            }
        }

        *end++ = '/';
    }

    free(dir);

    return result;
}

char *file_get_cache_dir(void)
{
    char *cache = file_get_cache_home();
    char *dir;

    dir = str_printf("%s/%s", cache ? cache : "/tmp/", BDPLUS_DIR);
    X_FREE(cache);
    file_mkpath(dir);

    return dir;
}

static char *_probe_config_dir(const char *base, const char *vm, const char *file)
{
    char *dir = str_printf("%s/%s/%s/%s", base, BDPLUS_DIR, vm, file);
    FILE *fp  = fopen(dir, "r");

    if (fp) {
        fclose(fp);
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

static char *_load_fp(FILE *fp, uint32_t *p_size)
{
    char *data = NULL;
    long file_size, read_size;

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < MIN_FILE_SIZE || file_size > MAX_FILE_SIZE) {
        BD_DEBUG(DBG_FILE, "Invalid file size\n");
        return NULL;
    }

    data      = malloc(file_size + 1);
    read_size = fread(data, 1, file_size, fp);

    if (read_size != file_size) {
        BD_DEBUG(DBG_FILE, "Error reading file\n");
        free(data);
        return NULL;
    }

    data[file_size] = 0;

    if (p_size) {
        *p_size = file_size;
    }

    return data;
}

char *file_load(const char *path, uint32_t *p_size)
{
    char *mem;
    FILE *fp;

    fp = fopen(path, "rb");

    if (!fp) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Error loading %s\n", path);
        return NULL;
    }

    mem = _load_fp(fp, p_size);

    fclose(fp);

    return mem;
}
