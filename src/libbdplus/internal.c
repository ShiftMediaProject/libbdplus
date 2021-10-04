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

#include "internal.h"
#include "bdplus_data.h"
#include "bdplus_config.h"

#include "bdsvm/dlx.h"
#include "bdsvm/event.h"
#include "bdsvm/loader.h"
#include "bdsvm/segment.h"

#include "file/configfile.h"
#include "file/dirs.h"
#include "file/file.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gcrypt.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

/* Use pthread in libgcrypt */
#ifdef HAVE_PTHREAD_H
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

/* Initializes libgcrypt */
int crypto_init()
{
    static int crypto_init_check = 0;

  if (!crypto_init_check)
  {
    crypto_init_check = 1;
#ifdef HAVE_PTHREAD_H
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
    if (!gcry_check_version(GCRYPT_VERSION))
    {
      crypto_init_check = 0;
    }
  }

  return crypto_init_check;
}

static char *_cache_scanpath(const char *cachepath, const char *mk_str)
{
    char             *result = NULL;
    char             *fullpath = NULL;
    BD_DIR_H         *dir;
    BD_DIRENT         ent, entlower;
    long unsigned int i;
    size_t            len;

    if(!cachepath)
        return NULL;

    /* open and scan cachepath for mk_str[.bin] */
    BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Scanning %s for cached conversion table...\n", cachepath);
    fullpath = str_printf("%s%s%s", cachepath, DIR_SEP, "convtab");
    if (fullpath) {
        dir = dir_open_default()(fullpath);

        if (dir) {
            while (!result && !dir_read(dir, &ent)) {
                len = strlen(ent.d_name);
                /* skip if filename is shorter than 32 chars (ie. 32 hexdigits plus .bin) */
                if (len < 36)
                    continue;

                /* create lower-case copy of the filename for comparison */
                for (i = 0; i < len; i++) {
                    entlower.d_name[i] = tolower(ent.d_name[i]);
                }

                /* check if (lowercase) filename contains the MK and ends with .bin, create
                   result with original-case filename if it matches */
                if (!memcmp(entlower.d_name, mk_str, 32) && !memcmp(entlower.d_name + len - 4, ".bin", 4))
                    result = str_printf("%s%s%s", fullpath, DIR_SEP, ent.d_name);
            }
            dir_close(dir);
        }
        X_FREE(fullpath);
    }

    return result;
}

char *bdplus_disc_findcachefile(bdplus_t *plus)
{
    char       *cache_home = file_get_cache_dir();
    char       *config_home = file_get_config_home();
    const char *sysbase = NULL;
    char       *syspath = NULL;
    char       *home_convtab = NULL;
    char       *result = NULL;
    char        mk_str[33];

    str_print_hex(mk_str, plus->mediaKey, 16);

    /* Scan home config convtab dir (ie. bdplus/convtab/ */
    if (config_home) {
        home_convtab = str_printf("%s%s%s", config_home, DIR_SEP, BDPLUS_DIR);
        if (home_convtab)
            result = _cache_scanpath(home_convtab, mk_str);

        X_FREE(home_convtab);
    }

    /* Scan home cache dir */
    if (!result && cache_home)
        result = _cache_scanpath(cache_home, mk_str);

    /* Scan system config dirs (no convtab in cache and home conf dirs) */
    if (!result) {
        sysbase = file_get_config_system(NULL);
        while (sysbase) {
            syspath = str_printf("%s%s%s", sysbase, DIR_SEP, BDPLUS_DIR);
            if (syspath)
                result = _cache_scanpath(syspath, mk_str);

            X_FREE(syspath);

            /* stop iterator if cached convtab was found */
            if (result)
                break;

            sysbase = file_get_config_system(sysbase);
        }
    }

    if (result)
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Found cached conversion table at %s\n", result);
    else
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] No cached conversion table found\n");

    X_FREE(config_home);
    X_FREE(cache_home);

    return result;
}

char *bdplus_disc_cache_file(bdplus_t *plus, const char *file)
{
    char *base = file_get_cache_dir();
    char vid_str[33];
    char *result;
    str_print_hex(vid_str, plus->volumeID, 16);
    result = str_printf("%s/%s/%s", base ? base : "/tmp/", vid_str, file);
    X_FREE(base);
    file_mkdirs(result);
    return result;
}

int32_t bdplus_load_svm(bdplus_t *plus, const char *fname)
{
    BDPLUS_FILE_H *fp;

    dlx_freeVM(&plus->vm);
    plus->vm = dlx_initVM(plus);
    if (!plus->vm) {
        return -1;
    }

    fp = file_open(plus->config, fname);
    if (!fp) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Error opening %s\n", fname);
        return -1;
    }

    return loader_load_svm(fp, fname, plus->vm, &plus->gen, &plus->date);
}


int32_t bdplus_load_slots(bdplus_t *plus, const char *fname)
{
    FILE *fd;
    int32_t i, p=0;

    fd = fopen(fname, "rb");
    if (!fd) return errno;

    for (i = 0 ; i < BDPLUS_NUM_SLOTS; i++)
        p+=fread(&plus->slots[i], sizeof(plus->slots[i]), 1, fd);
    fclose(fd);

    BD_DEBUG(DBG_BDPLUS,"[bdplus] Loaded bdplus %p slots with '%s' %d : size %zd\n",
          plus, fname,p,
          sizeof(slot_t));

    return 0;
}



int32_t bdplus_save_slots(bdplus_t *plus, const char *fname)
{
    FILE *fd;
    int32_t i, p=0;

    fd = fopen(fname, "wb");
    if (!fd) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "Error opening %s for writing\n", fname);
        return errno;
    }

    for (i = 0 ; i < BDPLUS_NUM_SLOTS; i++)
        p+=fwrite(&plus->slots[i], sizeof(plus->slots[i]), 1, fd);
    fclose(fd);

    BD_DEBUG(DBG_BDPLUS,"[bdplus] Saved bdplus %p slots with '%s' %d : size %zd\n",
          plus, fname,p,
          sizeof(slot_t));

    return 0;
}





// Unprotected access API, see slot.c
// Use slot -1 to get the attached slot, if any.
void bdplus_getSlot(bdplus_t *plus, uint32_t slot, slot_t *dst)
{
    BD_DEBUG(DBG_BDPLUS,"[bdplus] getSlot(%d)\n", slot);

    if (slot == 0xFFFFFFFF)
        slot = plus->attached_slot;

    if (slot >= BDPLUS_NUM_SLOTS) return;

    memcpy(dst, &plus->slots[ slot ], sizeof(slot_t));

    //if (slot && (slot != vm->attached_slot)) {
    if ((slot != plus->attached_slot)) {
        BD_DEBUG(DBG_BDPLUS,"[bdplus] clearing authHash since it is not authorised\n");
        memset(&dst->authHash, 0, sizeof(dst->authHash));
    }
}


void bdplus_getAttachStatus(bdplus_t *plus, uint8_t *dst)
{
    BD_DEBUG(DBG_BDPLUS,"[bdplus] attachedStatus %d %d %d\n",
           plus->attached_slot, plus->attachedStatus[0], plus->attachedStatus[1]);
    STORE4( dst   , plus->attached_slot);
    STORE4(&dst[4], (uint32_t)plus->attachedStatus[0]);
    STORE4(&dst[8], (uint32_t)plus->attachedStatus[1]);
}


void bdplus_resetSlotStatus(bdplus_t *plus)
{
    plus->attached_slot = 0;
    plus->attachedStatus[0] = 0;
}

uint32_t bdplus_slot_authenticate(bdplus_t *plus, uint32_t slot, char *digest)
{
    if (slot >= BDPLUS_NUM_SLOTS) return 0;

    if (!memcmp(&plus->slots[ slot ].authHash,
                digest,
                sizeof(plus->slots[ slot ].authHash))) {
        plus->attached_slot = slot;
        BD_DEBUG(DBG_BDPLUS,"[bdplus] slot %d authentication successful. \n", slot);
        return 1;
    }

    BD_DEBUG(DBG_BDPLUS,"[bdplus] slot %d authentication failed \n", slot);

    plus->attached_slot = 0;

    return 0;
}



uint32_t bdplus_new_slot(bdplus_t *plus)
{
    slot_t *newContent;
    uint8_t *MediaID = bdplus_getVolumeID(plus);

    // select a new slot to allocate/overwrite
    plus->attached_slot = plus->free_slot;
    plus->free_slot--;
    newContent = &plus->slots[ plus->attached_slot ];

    // Clear it
    memset(newContent, 0, sizeof(*newContent));

    memcpy(&newContent->cMediaID, MediaID, sizeof(newContent->cMediaID));
    memcpy(&newContent->mMediaID, MediaID, sizeof(newContent->mMediaID));

    // Last Update Sequence Counter is ignored and set to 0 here

    // update the slot attachment information
    if ( plus->attachedStatus[1] > 2 )
        plus->attachedStatus[1]--;

    plus->attachedStatus[0] = plus->attachedStatus[1];

    return plus->attached_slot;
}


void bdplus_slot_write(bdplus_t *plus, slot_t *slot)
{

    BD_DEBUG(DBG_BDPLUS,"[bdplus] dlx_slot_write: %d\n", plus->attached_slot);
    memcpy(&plus->slots[ plus->attached_slot ], slot, sizeof(slot_t));
}


uint8_t *bdplus_getVolumeID(bdplus_t *plus)
{
    return plus->volumeID;
}

uint8_t *bdplus_getMediaKey(bdplus_t *plus)
{
    return plus->mediaKey;
}

struct bdplus_config_s *bdplus_getConfig(bdplus_t *plus)
{
    return plus->config;
}

void bdplus_setConvTable(bdplus_t *plus, conv_table_t *conv_tab)
{
    if (plus->conv_tab) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] set_convTable(): old table dropped !\n");
        segment_freeTable(&plus->conv_tab);
    }
    plus->conv_tab = conv_tab;
}

conv_table_t *bdplus_getConvTable(bdplus_t *plus)
{
    return plus->conv_tab;
}


/*
 *
 * Run the VM until we have produced a conv_table (which can be multiple
 * conv_tables that are merged).
 *
 */
int32_t bdplus_run_convtab(bdplus_t *plus)
{
    int32_t keep_running, ret;
    uint32_t current_break = 0;
    VM *vm = plus->vm;

    BD_DEBUG(DBG_BDPLUS,"RUNNING VM FOR CONV_TABLE...\n");

    // Start event processing
    bdplus_send_event(vm, EVENT_Start, 0x00000000, 0x00000000,0 );

    keep_running = 1;
    while (keep_running) {

        ret = dlx_run(vm, BD_STEP_TRAP);

        if (ret < 0) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "run_convtab(): DLX execution error\n");
            break; // DLX execution error.
        }

        // deal with breaks
        if (ret == 2) {
            // BREAK
#if 0
            BD_DEBUG(DBG_BDPLUS,"[bdplus] break reached, PC=%08X: WD=%08X\n",
                   dlx_getPC(vm)-4, dlx_getWD(vm));
#endif

            current_break++;

            // Generic table retrieval.

            switch(current_break) {
            case 0:
            case 1:
            case 2:
                break; // Do nothing

            case 3:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110
                                  0x00000000, 0x0000FFFF, 0x0000000 );
                break;// 64 20 DD 44 58 01 00 00 B8 01 FF FC B6 D8 61 31


                // This sequence was recorded somewhere
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x3B:
            case 0x3C:
            case 0x3D:
            case 0x3E:
            case 0x3F:
            case 0x40:
                bdplus_send_event(vm, EVENT_ApplicationLayer,
                               0x00000000, 0x00000001,0 );
                break;


                // Start playback
            case 0x42:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110, FileNumber
                                  0x00000000, 2,0 );
                break;
                // 0x43: we tend to get conv_tab around here.

            case 0x65:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110, FileNumber
                                  0x00000000, 4,0 );
                break;

            case 0xF6:
            case 0x158:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110, FileNumber
                                  0x00000000, 0,0 );
                break;


            case 0x19E:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110, FileNumber
                                  0x00000000, 1,0 );
                break;

            case 0x276:
                bdplus_send_event(vm, EVENT_ApplicationLayer,
                                  0x00000000, 0x00000004,1 );
                break;

#if 0
                // We don't actually shut down yet.
            case 0x277:
                bdplus_send_event(vm, EVENT_Shutdown,
                                  0x00000000, 0x00000000,0 );
                break;
#endif

            case 0x280:
                keep_running = 0;
                break;

            default:
#if 0
                if (!vm->event_processing && plus->conv_tab) {
                    printf("events finished, and we have a table\n");
                    keep_running = 0;
                }
#endif
                break;

            }

        } // ret == 2, is break

    } // while bdplus_run

    BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"CONV_TABLE %p: numTables %u\n",
          plus->conv_tab,
          segment_numTables(plus->conv_tab));


    if (plus->conv_tab) return 1;

    return 0;

}

/*
 *
 */

int32_t bdplus_run_idle(VM *vm)
{
    int32_t keep_running, ret;
    uint32_t current_break = 0;

    BD_DEBUG(DBG_BDPLUS, "RUNNING VM (IDLE)...\n");

    keep_running = 1;
    while (keep_running) {

        ret = dlx_run(vm, BD_STEP_TRAP);

        if (ret < 0) return ret; // DLX execution error.

        // deal with breaks
        if (ret == 2) {
            // BREAK
            BD_DEBUG(DBG_BDPLUS,"[bdplus] break reached, PC=%08X: WD=%08X\n",
                   dlx_getPC(vm)-4, dlx_getWD(vm));

            current_break++;

            switch(current_break) {
            case 0: /* never 0 */
            case 1:
            case 2:
            case 3:
              /* idle code. Sometimes it may run traps ? */
              break;
            case 4:
              keep_running = 0;
              break;
            default:
              break;
            }

        } // ret == 2, is break

    } // while bdplus_run

    return 0;
}

int32_t bdplus_run_init(VM *vm)
{
    BD_DEBUG(DBG_BDPLUS, "RUNNING VM (INIT)...\n");

    if (!vm) return 0;

    // Start event processing
    bdplus_send_event(vm, EVENT_Start, 0x00000000, 0x00000000,0 );

    return bdplus_run_idle(vm);
}


int32_t bdplus_run_shutdown(bdplus_t *plus)
{
    int32_t result;

    BD_DEBUG(DBG_BDPLUS, "RUNNING VM (SHUTDOWN)...\n");

    if (!plus || !plus->vm) return 0;

    // Start event processing
    bdplus_send_event(plus->vm, EVENT_Shutdown, 0x00000000, 0x00000000,0 );

    result = bdplus_run_idle(plus->vm);

    dlx_freeVM(&plus->vm);

    return result;
}


/*
 *
 * Run the VM in an attempt to decode all the segment keys for a title.
 *
 */
int32_t bdplus_run_m2ts(bdplus_t *plus, uint32_t m2ts)
{
    int32_t keep_running, ret;
    uint32_t current_break = 0, table, segment;
    VM *vm;

    if (!plus || !plus->vm || !plus->conv_tab) return 0;

    // Set the title we want for nextSegment()
    if (segment_setSegment(plus->conv_tab, m2ts, 0) < 0) {
        // no table found
        return 1;
    }

    /* empty table ? */
    int entries = segment_numEntries(plus->conv_tab);
    if (entries < 1) {
        BD_DEBUG(DBG_BDPLUS, "conversion table is empty\n");
        return 1;
    }

    BD_DEBUG(DBG_BDPLUS, "RUNNING VM TO DECRYPT %05u.m2ts\n", m2ts);

    vm = plus->vm;
    keep_running = 1;
    while (keep_running) {

        ret = dlx_run(vm, BD_STEP_TRAP);

        if (ret < 0) break; // DLX execution error.

        // deal with breaks
        if (ret == 2) {
            // BREAK
            BD_DEBUG(DBG_BDPLUS,"[bdplus] break reached, PC=%08X: WD=%08X\n",
                   dlx_getPC(vm)-4, dlx_getWD(vm));

            current_break++;

            switch(current_break) {
            case 0:
            case 1:
            case 2:
                break; // Do nothing

                // Until finished.
            default:
                while(1) {
                    // nextSegment will return all titles, and all
                    // segments, so we will skip all titles that is
                    // not for this one (FIXME: Change segment to return for
                    // just one title.)
                    if (!segment_nextSegment(plus->conv_tab,
                                             &table,
                                             &segment)) {
                        BD_DEBUG(DBG_BDPLUS, "[bdplus] finished all segment keys for %05u.m2ts\n", m2ts);
                        keep_running = 0;
                        break; // Looped.
                    }

                    if (table != m2ts) {
                        BD_DEBUG(DBG_BDPLUS, "[bdplus] different title\n");
                        keep_running = 0;
                        break;
                    }

                    BD_DEBUG(DBG_BDPLUS, "[bdplus] posting event for segment keys %d/%d\n", table, segment);

                    bdplus_send_event(vm, EVENT_ComputeSP,
                                      0x00000000, table, segment);
                    // Lets have a break between segment keys:
                    current_break = 1;


                    // We found one, break out here.
                    break;
                } // while titles
                break;

            } // switch break

        } // ret == 2, is break

    } // while bdplus_run

    if (plus->conv_tab) return 1;

    return 0;

}

int32_t bdplus_run_title(bdplus_t *plus, uint32_t title)
{
    int32_t keep_running, ret;
    uint32_t current_break = 0;
    VM *vm;

    if (!plus || !plus->vm) return 0;

    BD_DEBUG(DBG_BDPLUS, "RUNNING VM (TITLE)...\n");

    vm = plus->vm;
    keep_running = 1;
    while (keep_running) {

        ret = dlx_run(vm, BD_STEP_TRAP);

        if (ret < 0) break; // DLX execution error.

        // deal with breaks
        if (ret == 2) {
            // BREAK
            BD_DEBUG(DBG_BDPLUS,"[bdplus] break reached, PC=%08X: WD=%08X\n",
                   dlx_getPC(vm)-4, dlx_getWD(vm));

            current_break++;

            switch(current_break) {
            case 0: /* never 0 */
            case 1:
            case 2:
              /* idle code. Sometimes it may run traps ? */
              break;
            case 3:
                bdplus_send_event(vm, EVENT_PlaybackFile,  // 110
                                  0x00000000, title, 0x0000000 );
                break;
            case 4: /* run idle code */
            case 5:
            case 6:
              break;
            case 30:
              keep_running = 0;
              break;
            default:
              break;
            }

        } // ret == 2, is break

    } // while bdplus_run

    BD_DEBUG(DBG_BDPLUS, "CONV_TABLE %p: numTables %u\n",
          plus->conv_tab,
          segment_numTables(plus->conv_tab));

    if (plus->conv_tab) return 1;

    return 0;

}


int32_t bdplus_run_event210(VM *vm, uint32_t param)
{
    if (!vm) return 0;

    BD_DEBUG(DBG_BDPLUS,"RUNNING VM PSR CHANGE %u\n", param);

    bdplus_send_event(vm, EVENT_ApplicationLayer,
                      0,1,0);//0,0,param);//param, param&0xffff,0 );

    return bdplus_run_idle(vm);
}
