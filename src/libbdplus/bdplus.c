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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "util/attributes.h" /* included before bdplus.h (define BD_PUBLIC for win32 dll exports) */
#include "bdplus.h"

#include "bdplus_data.h"
#include "bdplus_config.h"
#include "bdplus-version.h"

#include "bdsvm/segment.h"

#include "util/logging.h"
#include "util/macro.h"
#include "util/mutex.h"
#include "util/strutl.h"
#include "file/configfile.h"
#include "file/file.h"

#include <string.h>
#include <stdlib.h>

/*
 * Privileged       |   Unprivileged/Guest VM
 *    bluray.c     ->   dlx_run
 *    interface    <-   dlx_trap
 *    interface    ->   trap_xxx() call.
 *                  |
 */

void bdplus_get_version(int *major, int *minor, int *micro)
{
  *major = BDPLUS_VERSION_MAJOR;
  *minor = BDPLUS_VERSION_MINOR;
  *micro = BDPLUS_VERSION_MICRO;
}

static int _load_svm(bdplus_t *plus)
{
    if (!plus->config->fopen) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "No device path or filesystem access function provided\n");
        return -1;
    }

    BD_DEBUG(DBG_BDPLUS, "[bdplus] loading BDSVM/00000.svm...\n");
    if (bdplus_load_svm(plus, "BDSVM/00000.svm")) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Error loading BDSVM/00000.svm\n");
        return -1;
    }

    plus->loaded = 1;
    return 0;
}

int32_t bdplus_get_code_gen(bdplus_t *plus)
{
    if (!plus) return -1;
    if (!plus->loaded && _load_svm(plus) < 0) return -1;

    return plus->gen;
}

int32_t bdplus_get_code_date(bdplus_t *plus)
{
    if (!plus) return -1;
    if (!plus->loaded && _load_svm(plus) < 0) return -1;

    return plus->date;
}


static char *_slots_file(void)
{
    char *base = file_get_cache_dir();
    char *result = NULL;
    if (base) {
        result = str_printf("%s/slots.bin", base);
        X_FREE(base);
    }
    return result;
}

static void _load_slots(bdplus_t *plus)
{
    char *file_name = _slots_file();
    if (file_name) {
        bdplus_load_slots(plus, file_name);
        X_FREE(file_name);
    }
}

static void _save_slots(bdplus_t *plus)
{
    char *file_name = _slots_file();
    if (file_name) {
        file_mkdirs(file_name);
        bdplus_save_slots(plus, file_name);
        X_FREE(file_name);
    }
}

bdplus_t *bdplus_init(const char *path, const char *config_path, const uint8_t *vid)
{
    bdplus_t *plus = NULL;

    // Change to TEAM BLUH-RAY, DOOM9 FORUMS.
    BD_DEBUG(DBG_BDPLUS, "[bdplus] initialising...\n");

    /* Ensure libgcrypt is initialized before doing anything else */
    BD_DEBUG(DBG_BDPLUS, "Initializing libgcrypt...\n");
    if (!crypto_init())
    {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "Failed to initialize libgcrypt\n");
        return NULL;
    }

    // Initialize the PSRs and GPRs
    // deprecated by r433
    // libbluray_register_init();

    // Get us a new container.
    plus = malloc(sizeof(*plus));
    if (!plus) return NULL;

    memset(plus, 0, sizeof(*plus)); // I just don't like calloc, strange..

    if (bdplus_config_load(config_path, &plus->config) < 0) {
        X_FREE(plus);
        return NULL;
    }

    plus->free_slot = BDPLUS_NUM_SLOTS-1;

    // What is this really?
    plus->attachedStatus[0] = 0;
    plus->attachedStatus[1] = 7;

    if (path) {
        plus->device_path = str_dup(path);
        if (!plus->device_path) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "out of memory\n");
            bdplus_free(plus);
            return NULL;
        }
        plus->config->fopen_handle = plus->device_path;
        plus->config->fopen        = file_open_default();
    }

    plus->mutex     = calloc(1, sizeof(BD_MUTEX));
    if (!plus->mutex) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "out of memory\n");
        bdplus_free(plus);
        return NULL;
    }
    bd_mutex_init(plus->mutex);

    if (plus->config->fopen) {
        if (_load_svm(plus) < 0) {
            bdplus_free(plus);
            return NULL;
        }
    }

    BD_DEBUG(DBG_BDPLUS, "[bdplus] loading flash.bin...\n");
    _load_slots(plus);

    memcpy(plus->volumeID, vid, sizeof(plus->volumeID));

    BD_DEBUG(DBG_BDPLUS, "[bdplus] created and returning bdplus_t %p\n", plus);

    return plus;
}

void bdplus_set_fopen(bdplus_t *plus, void *handle, BDPLUS_FILE_OPEN p)
{
    if (plus) {
        plus->config->fopen_handle = handle;
        plus->config->fopen        = p;
    }
}

void bdplus_set_mk(bdplus_t *plus, const uint8_t *mk)
{
    if (plus && mk) {
        memcpy(plus->mediaKey, mk, sizeof(plus->mediaKey));
    }
}

int32_t bdplus_start(bdplus_t *plus)
{
    int32_t result = 0;

    if (!plus) return -1;

    if (!plus->loaded && !_load_svm(plus)) {
        return -1;
    }

    bd_mutex_lock(plus->mutex);

    BD_DEBUG(DBG_BDPLUS, "[bdplus] running VM for conv_table...\n");
    // FIXME: Run this as separate thread?
    result = bdplus_run_init(plus->vm);

    plus->started = 1;

    bd_mutex_unlock(plus->mutex);

    return result;
}


void bdplus_free(bdplus_t *plus)
{
    BD_DEBUG(DBG_BDPLUS, "[bdplus] releasing %p..\n", plus);

    if (!plus) {
        return;
    }

    if (plus->mutex) {
        bd_mutex_lock(plus->mutex);
    }

    if (plus->started) {
        bdplus_run_shutdown(plus);
    }

    _save_slots(plus);

    // Technically, we should run the VM with EVENT_Shutdown, until
    // TRAP_Finished. In case it wants to save state etc.
    // FIXME

    if (plus->conv_tab) {
        char *file = bdplus_disc_cache_file(plus, "convtab.bin");
        FILE *fp = NULL;
        if (file) {
            fp = fopen(file, "wb");
            X_FREE(file);
        }
        if (fp) {
            segment_save(plus->conv_tab, fp);
            fclose(fp);
        }
        segment_freeTable(&plus->conv_tab);
    }

    X_FREE(plus->device_path);

    bdplus_config_free(&plus->config);

    if (plus->mutex) {
        bd_mutex_unlock(plus->mutex);
        bd_mutex_destroy(plus->mutex);
        X_FREE(plus->mutex);
    }

    X_FREE(plus);
}

bdplus_st_t *bdplus_m2ts(bdplus_t *plus, uint32_t m2ts)
{
    BD_DEBUG(DBG_BDPLUS, "[bdplus] set_m2ts %p -> %u\n", plus, m2ts);

    if (!plus) return NULL;

    bd_mutex_lock(plus->mutex);

    if (!plus->conv_tab) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] bdplus_m2ts(%05u.m2ts): no conversion table\n", m2ts);
        bd_mutex_unlock(plus->mutex);
        return NULL;
    }

    bdplus_run_m2ts(plus, m2ts);

    bdplus_st_t *st = segment_set_m2ts(plus->conv_tab, m2ts);

    bd_mutex_unlock(plus->mutex);

    return st;
}


void bdplus_m2ts_close(bdplus_st_t *st)
{
    free(st);
}

void bdplus_mmap(bdplus_t *plus, uint32_t id, void *mem )
{
    if (!plus || !plus->config || !plus->config->ram) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: memory not initialized\n");
        return;
    }

    if (plus->started) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap ignored: VM already running\n");
        return;
    }

    switch (id) {
        case MMAP_ID_PSR:
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: PSR register file at %p\n", mem);
            bdplus_config_mmap(plus->config->ram, MEM_TYPE_PSR, mem, 128 * sizeof(uint32_t));
            break;

        case MMAP_ID_GPR:
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: GPR register file at %p\n", mem);
            bdplus_config_mmap(plus->config->ram, MEM_TYPE_GPR, mem, 4096 * sizeof(uint32_t));
            break;

        default:
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] mmap: unknown region id %d\n", id);
            break;
    }
}

void bdplus_psr             ( bdplus_t *plus,
                              void *regs,
                              uint32_t (*psr_read) (void *, int),
                              int      (*psr_write)(void *, int, uint32_t) )
{
    if (!plus || !plus->config) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] set psr: no config loaded\n");
        return;
    }

    if (plus->started) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] set psr ignored: VM already running\n");
        return;
    }

    if (!regs || !psr_read || !psr_write) {
        plus->config->regs      = NULL;
        plus->config->psr_read  = NULL;
        plus->config->psr_write = NULL;
    }

    plus->config->regs      = regs;
    plus->config->psr_read  = psr_read;
    plus->config->psr_write = psr_write;
}


static int32_t _bdplus_event(bdplus_t *plus, uint32_t event, uint32_t param1, uint32_t param2)
{
    if (!plus) return -1;

    if (!plus->loaded && _load_svm(plus) < 0) {
        return -1;
    }

    if (event == BDPLUS_EVENT_START) {
        return bdplus_start(plus);
    }

    if (event == BDPLUS_RUN_CONVTAB) {
        /* this event is used when disc is played without menus. */
        /* try to emulate player to get converson table. */
        BD_DEBUG(DBG_BDPLUS, "[bdplus] received CONVERSION TABLE event\n");

        unsigned int num_titles = param2;

        bdplus_run_init(plus->vm);
        return bdplus_run_convtab(plus, num_titles);
    }


    if (!plus->started) {
        return -1;
    }

    if (event == BDPLUS_EVENT_TITLE) {
        if (plus->conv_tab && param1 == 0xffff) {
            BD_DEBUG(DBG_BDPLUS, "[bdplus] ignoring FirstPlay title event (conversion table exists)\n");
            return 0;
        }
        BD_DEBUG(DBG_BDPLUS, "[bdplus] received TITLE event: %d\n", param1);
        return bdplus_run_title(plus, param1);
    }

    if (event == BDPLUS_EVENT_APPLICATION) {
        /* actual communication between BD+ and HDMV/BD-J uses registers PSR102-PSR104. */
        /* This event is just a notification that register has been written to. */
        BD_DEBUG(DBG_BDPLUS, "[bdplus] received APPLICATION LAYER event\n");
        return bdplus_run_event210(plus->vm, param1);
    }

    fprintf(stderr, "BD+: unknown event %x 0x%08x,%08X\n", event, param1, param2);
    return -1;
}

int32_t bdplus_event(bdplus_t *plus, uint32_t event, uint32_t param1, uint32_t param2)
{
      int32_t ret = 0;

      if (!plus) return -1;

      bd_mutex_lock(plus->mutex);

      ret = _bdplus_event(plus, event, param1, param2);

      bd_mutex_unlock(plus->mutex);

      return ret;
 }

int32_t bdplus_seek(bdplus_st_t *st, uint64_t offset)
{
    if (!st) return -1;
    return segment_patchseek(st, offset);
}

int32_t bdplus_fixup(bdplus_st_t *st, int len, uint8_t *buffer)
{
    if (!st) return -1;
    return segment_patch(st, len, buffer);
}







