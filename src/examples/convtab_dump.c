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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

// endian safe fetch
#define FETCH4(X) (uint32_t)(((X)[0]<<24)|(X)[1]<<16|(X)[2]<<8|(X)[3])
#define FETCHU2(X) (uint32_t)((uint16_t)(((X)[0]<<8)|(X)[1]))

// raw table
#define MAX_TAB_SIZE 64*1024*1024
uint8_t tab[MAX_TAB_SIZE];
uint32_t index[0xffff];

static size_t _read_tab(const char *file)
{
    FILE *fp = fopen(file, "rb");
    size_t len;

    if (!fp) {
        perror("fopen(): ");
        return 0;
    }

    memset(tab, 0, MAX_TAB_SIZE);

    len = fread(tab, 1, MAX_TAB_SIZE, fp);
    if (len < 1) {
        perror("fread(): ");
    }

    fclose(fp);

    printf("Read %zd bytes from %s\n", len, file);

    return len;
}

int main(int argc, char **argv)
{
    uint32_t numTables, table;
    uint32_t ptr = 0;
    uint32_t offset = 0;

    if (argc < 2) {
        fprintf(stderr, "%s /path/to/conv_tab.bin\n", argv[0]);
        exit(1);
    }

    if (_read_tab(argv[1]) < 1) {
        fprintf(stderr, "Error reading %s\n", argv[0]);
        exit(1);
    }

    numTables = FETCHU2(&tab[ptr]);
    ptr += 2;

    printf("%d tables:\n", numTables);


    for (table = 0; table < numTables; table++) {
        uint32_t tableID, numSegments, segment;

        tableID = FETCH4(&tab[ptr]);
        ptr += 4;
        numSegments = FETCHU2(&tab[ptr]);
        ptr += 2;

        printf("Table %d: %05d.m2ts (%d segments)\n", table, tableID, numSegments);

        for (segment = 0; segment < numSegments; segment++) {
            uint32_t numEntries, entry;

            offset = FETCH4(&tab[ptr + (segment * 4) ]);

            numEntries = FETCH4(&tab[offset]);
            offset += 4;

            printf("  Segment %d: %d entries\n", segment, numEntries);

            // read index table
            for (entry = 0; entry < numEntries; entry++) {
                index[entry] = FETCH4(&tab[offset]);
                offset += 4;
            }

            // read data
            for (entry = 0; entry < numEntries; entry++) {

                uint8_t  flags = tab[ offset ];
                offset += 1;

                uint32_t tmp = FETCH4(&tab[offset]); // only fetch 3bytes, 24 bits.
                offset += 3;
                tmp &= 0xFFFFFF00;

                uint32_t patch0_address_adjust = (tmp & 0xFFF00000) >> 20;
                uint32_t patch1_address_adjust = (tmp & 0x000FFF00) >> 8;

                uint32_t patch0_buffer_offset = tab[offset++];
                uint32_t patch1_buffer_offset = tab[offset++];
                uint8_t  patch0[5], patch1[5];

                memcpy(patch0, &tab[ offset ], sizeof(patch0));
                offset += 5;
                memcpy(patch1, &tab[ offset ], sizeof(patch1));
                offset += 5;

                uint64_t off0 = (( (uint64_t)index[entry] +
                                   (uint64_t)patch0_address_adjust) *
                                 (uint64_t)0xC0 +
                                 (uint64_t)patch0_buffer_offset);

                uint64_t off1 = (( (uint64_t)index[entry] +
                                   (uint64_t)patch0_address_adjust +
                                   (uint64_t)patch1_address_adjust) *
                                 (uint64_t)0xC0 +
                                 (uint64_t)patch1_buffer_offset);

                printf("  Entry %d: flags 0x%x (%d)\n", entry, flags, flags>>6);
                printf("    %08X %08X:  %02X %02X %02X %02X %02X\n",
                       (uint32_t)(off0 >> 32), (uint32_t)(off0 & 0xffffffff),
                       patch0[0], patch0[1], patch0[2], patch0[3], patch0[4]);
                printf("    %08X %08X:  %02X %02X %02X %02X %02X\n",
                       (uint32_t)(off1 >> 32), (uint32_t)(off1 & 0xffffffff),
                       patch1[0], patch1[1], patch1[2], patch1[3], patch1[4]);
            } // for entry

        } // for segment

        ptr = offset;

    } // for table

    return 0;
}
