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

#ifndef TRAP_HELPER_H
#define TRAP_HELPER_H

#include "util/attributes.h"

#include "sha1.h"

#include <stdint.h>
#include <gcrypt.h>

typedef struct sha_s {
  void *prev, *next;
  uint8_t *dst; // initialize from caller

  /* TODO: context should be mapped to VM address space */
  SHA1_CTX sha;
} sha_t;

BD_PRIVATE sha_t *get_sha_ctx  (sha_t **head, uint8_t *);
BD_PRIVATE int    free_sha_ctx (sha_t **head, sha_t *);

#endif
