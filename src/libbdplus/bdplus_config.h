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

#ifndef BDPLUS_CONFIG_H_INCLUDED
#define BDPLUS_CONFIG_H_INCLUDED

#include "util/attributes.h"

#include <stdint.h>


#define MEM_TYPE_PSR            (1<<1)
#define MEM_TYPE_GPR            (2<<1)

typedef struct {
  /* mapped memory region for DiscoveryRAM trap */
  uint32_t       start_address;
  uint32_t       size;
  const uint8_t *mem;

  /* housekeeping */
  uint8_t        type;   /* allow shadowing of preloaded data with live data */
  void          *memory; /* preloaded data, should be freed at shutdown */
} bdplus_ram_area_t;

typedef struct bdplus_ram_s {
  unsigned           num_area;
  bdplus_ram_area_t *area;
} bdplus_ram_t;


typedef struct bdplus_dev_s {
  uint32_t   size;
  uint8_t   *mem;
} bdplus_dev_t;

#define MAX_DEV_DISCOVERY 5


typedef struct bdplus_ecdsa_key_s {
    char d[41];
    char Qx[41];
    char Qy[41];
} bdplus_ecdsa_key_t;

#define MAX_ECDSA_KEYS 4


typedef struct bdplus_aes_key_s {
    char key[16];
} bdplus_aes_key_t;

#define MAX_AES_KEYS 10


typedef struct bdplus_config_s {
    bdplus_ram_t       *ram; /* mapped player memory */
    bdplus_dev_t       *dev;
    bdplus_ecdsa_key_t *ecdsa_keys;
    bdplus_aes_key_t   *aes_keys;

    int                 num_aes_keys;

    void *regs;
    uint32_t (*psr_read) (void *, int);
    int      (*psr_write)(void *, int, uint32_t);

} bdplus_config_t;

BD_PRIVATE int  bdplus_config_load(const char *config_path /* optional */,
                                   bdplus_config_t **config);
BD_PRIVATE void bdplus_config_mmap(bdplus_ram_t *ram, uint32_t type, void *mem, uint32_t size);
BD_PRIVATE void bdplus_config_free(bdplus_config_t **config);


#endif
