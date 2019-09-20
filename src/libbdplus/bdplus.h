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

#ifndef BDPLUS_H_INCLUDED
#define BDPLUS_H_INCLUDED

#include <stdint.h>

#ifndef BD_PUBLIC
#  define BD_PUBLIC
#endif

/* opaque types */

typedef struct bdplus_s bdplus_t;
typedef struct bdplus_st_s bdplus_st_t;

/* Memory region types for bdplus_mmap() */

#define MMAP_ID_PSR  0
#define MMAP_ID_GPR  1

/* Events from application to bdplus */

#define BDPLUS_EVENT_START        0x00000000
#define BDPLUS_EVENT_TITLE        0x00000110
#define BDPLUS_EVENT_APPLICATION  0x00000210
#define BDPLUS_RUN_CONVTAB        0xffffffff /* get conversion table when disc is played without menus */


/*
 * Get the bdplus library version number.
 *
 */
BD_PUBLIC
void bdplus_get_version(int *major, int *minor, int *micro);


/*
 * Initialise the bdplus library.
 *
 * @param  path         Path to BD disc root
 * @param  config_path  Path to BD+ configuration (optional)
 * @param  vid          BD disc Volume ID
 * @return bdplus handle, NULL on error
 */
BD_PUBLIC
bdplus_t *bdplus_init(const char *path, const char *config_path, const uint8_t *vid);

/* get BD+ content code generation */
BD_PUBLIC
int32_t bdplus_get_code_gen(bdplus_t *plus);

/* get BD+ content code release date */
BD_PUBLIC
int32_t bdplus_get_code_date(bdplus_t *plus);

BD_PUBLIC
int32_t bdplus_is_cached(bdplus_t *plus);


/*
 * Release the bdplus library.
 *
 * @param  bdplus handle
 */
BD_PUBLIC
void bdplus_free(bdplus_t *);


/*
 * Map player memory region.
 *
 * @param  id   Memory region type
 * @param  mem  Memory region address
 */
BD_PUBLIC
void bdplus_mmap(bdplus_t *, uint32_t id, void *mem);

/*
 * Set media key
 *
 * @param  mk  BD disc Media Key
 */
BD_PUBLIC
void bdplus_set_mk(bdplus_t *, const uint8_t *mk);


/*
 * Register PSR handler functions.
 *
 * @param  regs  Application-specific handle for psr_read/psr_write
 * @param  psr_read   Function used to read from PSR
 * @param  psr_write  Function used to write to PSR
 */
BD_PUBLIC
void bdplus_psr(bdplus_t *,
                void *regs,
                uint32_t (*psr_read) (void *regs, int reg),
                int      (*psr_write)(void *regs, int reg, uint32_t value));


/*
 * Start the bdplus VM
 */
BD_PUBLIC
int32_t bdplus_start(bdplus_t *);


/*
 * Send event to the bdplus VM.
 *
 * @param  event  event type (BDPLUS_EVENT_*)
 */
BD_PUBLIC
int32_t bdplus_event(bdplus_t *, uint32_t event, uint32_t param1, uint32_t param2);


/*
 * Stream interface
 */


/*
 * Select m2ts file for playback.
 *
 * @param  m2ts  m2ts file number
 * @return stream handle, NULL on error
 */
BD_PUBLIC
bdplus_st_t *bdplus_m2ts(bdplus_t *, uint32_t m2ts);


/*
 * Close stream handle.
 */
BD_PUBLIC
void bdplus_m2ts_close(bdplus_st_t *);


/*
 * Notify stream seek.
 *
 * @param  offset  new byte offset of the stream.
 */
BD_PUBLIC
int32_t bdplus_seek(bdplus_st_t *, uint64_t offset);

/*
 * Patch stream buffer.
 *
 * @param  len  buffer length
 * @param  buffer  stream data
 * @return Number of patches performed for the buffer (statistics).
 */
BD_PUBLIC
int32_t bdplus_fixup(bdplus_st_t *, int len, uint8_t *buffer);



#endif  /* BDPLUS_H_INCLUDED */
