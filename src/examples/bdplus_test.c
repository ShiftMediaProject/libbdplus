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

#include "libbdplus/bdplus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBAACS
#include <libaacs/aacs.h>
#endif

static uint8_t _hex_byte(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    else {
        fprintf(stderr, "invalid char in hex string: 0x%02X (%c)\n", c, c);
        exit(1);
    }

    return 0;
}

static void _libaacs_get_vid(uint8_t *vid, uint8_t *mk, const char *root)
{
#ifndef HAVE_LIBAACS
    fprintf(stderr, "libaacs support not enabled. Please provide VID in command line.\n");
    exit(1);
#else
    AACS *aacs = aacs_open(root, NULL);
    unsigned ii;

    if (!aacs) {
        fprintf(stderr, "aacs_open() failed. Please provide VID in command line.\n");
        exit(1);
    }

    const uint8_t *aacs_vid = aacs_get_vid(aacs);
    if (!aacs_vid) {
        fprintf(stderr, "aacs_get_vid() failed. Please provide VID in command line.\n");
        aacs_close(aacs);
        exit(1);
    }
    memcpy(vid, aacs_vid, 16);

    const uint8_t *aacs_mk = aacs_get_mk(aacs);
    if (!aacs_mk) {
        fprintf(stderr, "aacs_get_mk() failed.\n");
        aacs_close(aacs);
        exit(1);
    }
    memcpy(mk, aacs_mk, 16);

    aacs_close(aacs);

    printf("got vid from libaacs: ");
    for (ii = 0; ii < 16; ii++) {
        printf("%02X", vid[ii]);
    }
    printf("\n");
#endif
}

int main(int argc, char **argv)
{
    uint8_t vid[16], mk[16] = {0};
    unsigned ii;

    if (argc < 2) {
        fprintf(stderr, "%s /path/tobluray [VID]\r\n", argv[0]);
        fprintf(stderr, "Where we expect to find /path/tobluray/BDSVM/\r\n");
        exit(1);
    }

    if (argc < 3) {
      _libaacs_get_vid(vid, mk, argv[1]);
    } else {
        for (ii = 0; ii < 16; ii++) {
            vid[ii] = (_hex_byte(argv[2][2*ii]) << 4) | _hex_byte(argv[2][2*ii + 1]);
        }
    }

    printf("Opening bdplus ...\n");

    bdplus_t *bd = bdplus_init(argv[1], NULL, vid);

    if (!bd) {
        fprintf(stderr, "bdplus_init() failed\n");
        exit(1);
    }

    int dd = bdplus_get_code_date(bd);
    printf("BD+ content code generation %d (released %d-%02d-%02d)\n\n",
           bdplus_get_code_gen(bd), dd >> 16, (dd >> 8) & 0xff, dd & 0xff);

    bdplus_set_mk(bd, mk);
    if (bdplus_start(bd) < 0) {
        fprintf(stderr, "bdplus_start() failed\n");
    }

    /* Try to get conversion table without actually playing the disc. */
    bdplus_event(bd, BDPLUS_RUN_CONVTAB, 32, 0);

    for (ii = 0; ii < 32; ii++) {
        bdplus_event(bd, BDPLUS_EVENT_TITLE, ii, 0);
    }

    for (ii = 0; ii < 32; ii++) {
        bdplus_st_t *st = bdplus_m2ts(bd, ii);
        if (st) {
            printf("BD+ active for %05d.m2ts\n", ii);
            bdplus_m2ts_close(st);
        }
    }

    printf("Cleaning up...\n");

    bdplus_free(bd);

    exit(0);
}

