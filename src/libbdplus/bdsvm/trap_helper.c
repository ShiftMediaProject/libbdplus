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

#include "trap_helper.h"

#include <stdlib.h>
#include <string.h>

static sha_t *_new_sha_ctx(uint8_t *dst)
{
  sha_t *ctx = malloc(sizeof(sha_t));
  memset(ctx, 0, sizeof(sha_t));
  ctx->dst = dst;
  return ctx;
}

/*
  Search for a context matching key 'dst'.
  If one does not exist, allocate memory for it
  and add it to the linked list ctx_head.
 */
sha_t *get_sha_ctx(sha_t **ctx_head, uint8_t *dst) {
  sha_t *ctx_curr, *ctx_new;

  /* empty list ? */
  if (!*ctx_head) {
    *ctx_head = _new_sha_ctx(dst);
    return *ctx_head;
  }

  /* if the list has members, search it */
  for (ctx_curr = *ctx_head; ctx_curr; ctx_curr = ctx_curr->next) {
    if (ctx_curr->dst == dst) return ctx_curr;
    if (!ctx_curr->next) break;
  }

  /* if the dst in question isn't found, allocate space for it */
  ctx_new = _new_sha_ctx(dst);
  ctx_curr->next = ctx_new;
  ctx_new->prev = ctx_curr;
  return ctx_new;
}

/*
  Remove the passed member from the linked list;
  free sha
 */
int free_sha_ctx(sha_t **ctx_head, sha_t *sha) {
  sha_t *tmp1, *tmp2;

  /* free all */
  if (!sha) {
    while (*ctx_head) {
      sha = *ctx_head;
      *ctx_head = sha->next;
      free(sha);
    }
    return 0;
  }

  if (!sha->prev && !sha->next) {
    /* we're at the list head and there is only one member */
    free(sha);
    *ctx_head = NULL;
  } else if (!sha->prev && sha->next) {
    /* we're at the list head and there are additional members */
    *ctx_head = sha->next;
    (*ctx_head)->prev = NULL;
    free(sha);
  } else if (sha->prev && sha->next) {
    /* we're somewhere in the middle of the list */
    tmp1 = sha->prev;
    tmp2 = sha->next;
    tmp1->next = tmp2;
    tmp2->prev = tmp1;
    free(sha);
  }
  else {
    /* we're at the end of the list */
    tmp1 = sha->prev;
    tmp1->next = NULL;
    free(sha);
  }
  return 0;
}

/* END: trap_Sha */
