/*
 * This file is part of libbdplus
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "bdplus_config.h"

#include "file/configfile.h"
#include "util/logging.h"
#include "util/strutl.h"
#include "util/macro.h"

#include <stdlib.h>
#include <string.h>


#define MEMORY_MAP_FILE     "memory.map"
#define AES_KEYS_FILE       "aes_keys.bin"
#define CERTIFICATES_FILE   "certificates.bin"
#define ECDSA_KEYS_FILE     "ecdsa_keys.txt"
#define DEV_DISCOVERY_FILE  "device_discovery_%d.bin"

static int _load_aes_keys(bdplus_aes_key_t *aes_keys, const char *base)
{
    char *path = str_printf("%s/" AES_KEYS_FILE, base);
    uint8_t *keys;
    uint32_t size = 0;
    uint32_t num_keys, ii;

    if (!path) {
        return -1;
    }

    keys = (uint8_t *)file_load(path, &size);
    X_FREE(path);

    num_keys = size / 16;
    if (num_keys > MAX_AES_KEYS) {
        num_keys = MAX_AES_KEYS;
    }
    if (num_keys * 16 != size) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Invalid AES key file size\n");
    }

    for (ii = 0; ii < num_keys; ii++) {
        memcpy(aes_keys[ii].key, keys + 16*ii, 16);
    }

    X_FREE(keys);
    return num_keys > 6 ? (int)num_keys : -1;
}

static int _load_ecdsa_keys(bdplus_ecdsa_key_t *ecdsa_keys, const char *base)
{
    const char *p;
    char *path = str_printf("%s/" ECDSA_KEYS_FILE, base);
    char *cfg;
    int   num_ecdsa_keys = 0;

    if (!path) {
        return -1;
    }

    cfg = file_load(path, NULL);
    X_FREE(path);

    /* parse keys */
    p = cfg;
    while (*p) {
        char key_d[41], key_Qx[41], key_Qy[41];

        p = str_skip_white(p);
        if (*p == '#') {
            /* comment */
        }
        else if (3 == sscanf(p, "%40s %40s %40s", key_d, key_Qx, key_Qy)) {
            if (num_ecdsa_keys >= MAX_ECDSA_KEYS) {
                BD_DEBUG(DBG_FILE | DBG_CRIT, "Too many ECDSA keys\n");
                break;
            }
            memcpy(ecdsa_keys[num_ecdsa_keys].d,  key_d, 40);
            memcpy(ecdsa_keys[num_ecdsa_keys].Qx, key_Qx, 40);
            memcpy(ecdsa_keys[num_ecdsa_keys].Qy, key_Qy, 40);
            num_ecdsa_keys++;
        }
        else {
            BD_DEBUG(DBG_FILE | DBG_CRIT, "invalid line in config file: %4.4s...\n", p);
        }
        p = str_next_line(p);
    }

    X_FREE(cfg);
    return num_ecdsa_keys > 0 ? 0 : -1;
}

static int _load_ram(bdplus_ram_t **p, const char *base, uint32_t address, const char *file)
{
    bdplus_ram_t *ram;

    if (!*p) {
        *p = calloc(1, sizeof(bdplus_ram_t));
        if (!*p) {
            return 0;
        }
    }
    ram = *p;

    void *tmp = ram->area;
    ram->area = realloc(ram->area, (ram->num_area + 1) * sizeof(*ram->area));
    if (!ram->area) {
        X_FREE(tmp);
        BD_DEBUG(DBG_CRIT, "out of memory\n");
        return 0;
    }

    memset(&ram->area[ram->num_area], 0, sizeof(ram->area[ram->num_area]));
    ram->area[ram->num_area].start_address = address;

    if (!strcmp(file, "PSR")) {
        ram->area[ram->num_area].type = MEM_TYPE_PSR;
        BD_DEBUG(DBG_BDPLUS, "mapped PSR register file to 0x%x\n", address);

    } else if (!strcmp(file, "GPR")) {
        ram->area[ram->num_area].type = MEM_TYPE_PSR;
        BD_DEBUG(DBG_BDPLUS, "mapped GPR register file to 0x%x\n", address);

    } else {
        /* load from file */
        char *path = str_printf("%s/%s", base, file);
        if (!path) {
            return 0;
        }

        ram->area[ram->num_area].memory = file_load(path, &ram->area[ram->num_area].size);
        ram->area[ram->num_area].mem    = ram->area[ram->num_area].memory;
        X_FREE(path);

        if (!ram->area[ram->num_area].mem) {
            return 0;
        }

        BD_DEBUG(DBG_BDPLUS, "mapped %d bytes from %s to 0x%x\n",
              ram->area[ram->num_area].size, file, address);
    }

    ram->num_area++;

    return 1;
}

static void _ram_free(bdplus_ram_t **pp)
{
    if (pp && *pp) {
        unsigned int ii;
        for (ii = 0; ii < (*pp)->num_area; ii++) {
            X_FREE((*pp)->area[ii].memory);
        }
        X_FREE((*pp)->area);
        X_FREE(*pp);
    }
}

static int _load_dev_discovery(bdplus_dev_t *dev, const char *base)
{
    unsigned ii;

    for (ii = 0; ii < MAX_DEV_DISCOVERY; ii++) {
        char *path = str_printf("%s/" DEV_DISCOVERY_FILE, base, ii + 1);
        if (!path) {
            break;
        }
        dev[ii].mem = (uint8_t *)file_load(path, &dev[ii].size);
        X_FREE(path);
        if (!dev[ii].mem) {
            break;
        }
    }

    return ii >= 5 ? 0 : -1;
}


static void _dev_free(bdplus_dev_t **pp)
{
    if (pp && *pp) {
        unsigned ii;
        for (ii = 0; ii < MAX_DEV_DISCOVERY; ii++) {
            X_FREE((*pp)[ii].mem);
        }

        X_FREE(*pp);
    }
}

static int _load_memory(bdplus_ram_t **ram, const char *base)
{
    const char *p;
    char *path;
    char *cfg = NULL;

    path = str_printf("%s/" MEMORY_MAP_FILE, base);
    if (path) {
        cfg = file_load(path, NULL);
        X_FREE(path);
    }

    if (!cfg) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Error loading memory map file '"MEMORY_MAP_FILE"'\n");
        return -1;
    }

    /* parse memory map file */

    p = cfg;
    while (*p) {
        uint32_t address;
        char name[64];

        p = str_skip_white(p);

        if (*p == '#') {
            /* comment */
        }
        else if (2 == sscanf(p, "%x %63s", &address, name)) {
            name[sizeof(name) - 1] = 0;
            _load_ram(ram, base, address, name);
        }
        else {
            BD_DEBUG(DBG_FILE | DBG_CRIT, "invalid line in config file: %4.4s...\n", p);
        }
        p = str_next_line(p);
    }

    X_FREE(cfg);
    return 0;
}

void bdplus_config_free(bdplus_config_t **p_config)
{
    if (*p_config) {
        _ram_free(&(*p_config)->ram);
        _dev_free(&(*p_config)->dev);
        X_FREE((*p_config)->aes_keys);
        X_FREE((*p_config)->ecdsa_keys);

        X_FREE(*p_config);
    }
}

int bdplus_config_load(const char *config_path,
                       bdplus_config_t **p_config)
{
    bdplus_config_free(p_config);
    bdplus_config_t *config = *p_config = calloc(1, sizeof(bdplus_config_t));
    if (!config) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "out of memory\n");
        return -1;
    }

    char *base = NULL;
    if (!config_path) {
        base = file_get_config_dir(MEMORY_MAP_FILE);
        config_path = base;
        if (!base) {
            BD_DEBUG(DBG_FILE | DBG_CRIT, "VM configuration not found\n");
            return -1;
        }
    }

    config->aes_keys   = calloc(MAX_AES_KEYS,      sizeof(bdplus_aes_key_t));
    config->ecdsa_keys = calloc(MAX_ECDSA_KEYS,    sizeof(bdplus_ecdsa_key_t));
    config->dev        = calloc(MAX_DEV_DISCOVERY, sizeof(bdplus_dev_t));

    if (!config->aes_keys || !config->ecdsa_keys || !config->dev) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "out of memory\n");
        X_FREE(base);
        return -1;
    }

    config->num_aes_keys = _load_aes_keys(config->aes_keys, config_path);
    if (config->num_aes_keys < 0) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Player AES keys not found\n");
    }
    if (_load_ecdsa_keys(config->ecdsa_keys, config_path) < 0) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Player ECDSA keys not found\n");
    }
    if (_load_dev_discovery(config->dev, config_path) < 0) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Player device discovery signatures not found\n");
    }
    if (_load_memory(&config->ram, config_path) < 0) {
        BD_DEBUG(DBG_FILE | DBG_CRIT, "Player memory loading failed\n");
    }

    X_FREE(base);

    return 0;
}

static bdplus_ram_area_t *_find_mem(bdplus_ram_t *p, uint32_t mask)
{
    if (p) {
        unsigned int ii;
        for (ii = 0; ii < p->num_area; ii++) {
            if (p->area[ii].type & mask) {
                return &p->area[ii];
            }
        }
    }
    return NULL;
}

void bdplus_config_mmap(bdplus_ram_t *ram, uint32_t type, void *mem, uint32_t size)
{
    bdplus_ram_area_t *p;

    if (!mem) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: config not read\n");
        return;
    }

    if (((intptr_t)mem) & 3) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: register file %d not aligned\n", type);
        return;
    }

    p = _find_mem(ram, type);
    if (!p) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: register file %d not mapped in config\n", type);
        return;
    }

    p->type = type;
    p->mem = mem;
    p->size = size;
}

