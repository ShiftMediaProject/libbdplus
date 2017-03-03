/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
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

#include "diff.h"
#include "dlx.h"
#include "trap.h"

#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <gcrypt.h>

/*
 * DiffArchive File Format:
 *
 * All values are LE!
 *
 *    len | name     | description
 * -------+----------+------------
 *     4  | size     | size of contained files. all files have same size.
 *     4  | count    | number of contained files
 * count *
 *     4  | diffcnt  | total number of diff-segments for this file
 * diffcnt *
 *     4  | start    | start of diff
 *     4  | length   | length of diff
 * length | data     | raw data that differs from previous file
 *
 */


#if 0
int32_t diff_isarchive(char *fname)
{
    int32_t len;

    if (!fname || !*fname) return 0;

    len = strlen(fname);

    if ((len > 15) &&
        (!str_match(fname, ".*diffarchive\\.bin$", 1)))
        return 1;

    return 0;
}
#endif


int32_t diff_loadcore(uint8_t *addr, uint32_t vmsize, char *fname,
                      uint32_t trap, uint32_t flags)
{
    FILE *fd;
    uint32_t currtrap = 0;
    uint32_t currdiff = 0;
    uint32_t size, count, diffcnt, start, length;

    fd = fopen(fname, "rb");
    if (!fd) return errno;

    BD_DEBUG(DBG_BDPLUS,"[diff] opened '%s' to find trap %d...\n", fname, trap);

    if (fread(&size, sizeof(size), 1, fd) != 1) goto fail;
    if (fread(&count, sizeof(count), 1, fd) != 1) goto fail;

    // Now BE
    size  = FETCH4((uint8_t*)&size);
    count = FETCH4((uint8_t*)&count);

    BD_DEBUG(DBG_BDPLUS,"[diff] Memory size is %08X, num diff-files %08X\n", size, count);

    if (trap >= count) {
        fclose(fd);
        return -1;
    }
    if (size > vmsize) {
        fclose(fd);
        return -2; // Safety
    }

    // Clear the area first.
    memset(addr, 0, vmsize);

    // Process diffs from the start to the image we want.
    for (currtrap = 0; currtrap <= trap; currtrap++) {
        if (fread(&diffcnt, sizeof(diffcnt), 1, fd) != 1) goto fail;
        diffcnt = FETCH4((uint8_t*)&diffcnt);
        BD_DEBUG(DBG_BDPLUS,"       trap %08X has %d diffs\n", currtrap, diffcnt);
        for (currdiff = 0; currdiff < diffcnt; currdiff++) {
            if (fread(&start,  sizeof(diffcnt), 1, fd) != 1) goto fail;
            if (fread(&length, sizeof(diffcnt), 1, fd) != 1) goto fail;
            // Read in the bytes.
            start  = FETCH4((uint8_t*)&start);
            length = FETCH4((uint8_t*)&length);

            if (fread(&addr[ start ], length, 1, fd) != 1) goto fail;
        } // currdiff

    } // currtrap

    fclose(fd);

    // Little endian load?
    // Swap the whole area.
    if (flags & BDPLUS_LOAD_SWAP) {
        uint32_t i;
        uint8_t u1,u2,u3,u4;
        for (i = 0; i < vmsize; i+=4 ) {
            u1 = addr[i];
            u2 = addr[i+1];
            u3 = addr[i+2];
            u4 = addr[i+3];
            addr[i+3] = u1;
            addr[i+2] = u2;
            addr[i+1] = u3;
            addr[i]   = u4;
        }
    }

    return 0;

 fail:
    BD_DEBUG(DBG_BDPLUS,"[diff] archive failed at reading trap %08X diff %08X\n",
           currtrap, currdiff);
    fclose(fd);
    return -1;

}



struct sha_hdr_s {
    uint8_t digest[SHA_DIGEST_LENGTH];
    uint32_t next;
    uint32_t len;
};

uint32_t diff_hashdb_load(uint8_t *hashname, uint8_t *fname, uint64_t offset,
                          uint32_t *len, uint8_t *dst)
{
    uint8_t *namehash;
    uint8_t digest[SHA_DIGEST_LENGTH];
    FILE *fd;
    struct sha_hdr_s sha_hdr;
    uint32_t shalen;

    BD_DEBUG(DBG_BDPLUS,"[diff] Attempting to open '%s' looking for '%s'\n",
          hashname, fname);

    fd = fopen((char *)hashname, "rb");
    if (!fd) return STATUS_INVALID_PARAMETER;


    shalen = sizeof(offset) + sizeof(*len) + strlen((char *)fname) + 1;
    namehash = (uint8_t *)malloc( shalen );
    if (!namehash) {
        fclose(fd);
        return STATUS_INTERNAL_ERROR;
    }

    // SHA[64bit-offset, 32bit-len, filename]
    STORE8(&namehash[0], offset);
    STORE4(&namehash[sizeof(offset)], *len);
    strcpy((char *)&namehash[sizeof(offset)+sizeof(*len)],
           (char *)fname);

    char str[512];
    BD_DEBUG(DBG_BDPLUS,"[diff] namehash: %s\n",
          str_print_hex(str, namehash, shalen));

    // Hash it.
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest, namehash, shalen - 1);

    memset(str, 0, sizeof(str));
    BD_DEBUG(DBG_BDPLUS,"[diff] find hashdb: %s\n",
          str_print_hex(str, digest, sizeof(digest)));

    while(fread(&sha_hdr, sizeof(sha_hdr), 1, fd) == 1) {

        memset(str, 0, sizeof(str));
        BD_DEBUG(DBG_BDPLUS,"[diff] read hashdb: %s\n",
              str_print_hex(str, sha_hdr.digest, sizeof(digest)));

        sha_hdr.next = FETCH4((uint8_t *)&sha_hdr.next);

        if (!memcmp(digest, sha_hdr.digest, sizeof(digest))) {
            // Found the digest we are looking for
            sha_hdr.len = FETCH4((uint8_t *)&sha_hdr.len);
            BD_DEBUG(DBG_BDPLUS,"[diff] found digest, reading %08X (%u) bytes...\n",
                   sha_hdr.next - (uint32_t)sizeof(sha_hdr.len),
                   sha_hdr.next - (uint32_t)sizeof(sha_hdr.len));

            // Read in all digests, perhaps error checking?
            if (!fread(dst, sha_hdr.next - sizeof(sha_hdr.len), 1, fd)) {
                BD_DEBUG(DBG_BDPLUS,"[diff] Short read on hash_db.bin!\n");
            }
            // Update new len
            *len = sha_hdr.len;
            fclose(fd);
            return STATUS_OK;
        } // if digest match

        // Seek past this entry, "next" number of bytes from "next" position,
        // but we read "next" AND "len".
        fseek(fd, sha_hdr.next - sizeof(sha_hdr.len), SEEK_CUR);

    } // while fread

    fclose(fd);

    *len = 0;
    return STATUS_INVALID_PARAMETER;
}



