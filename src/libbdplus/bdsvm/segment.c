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

#if defined(__MINGW32__)
/* ftello64() and fseeko64() prototypes from stdio.h */
#   undef __STRICT_ANSI__
#endif

#include "segment.h"

#include "event.h"

#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"
#include "file/file.h"

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#if defined(__MINGW32__)
#  define fseeko fseeko64
#endif

/*
 *
 */

/*
  CONV_TABLE_STRUCTURE
+-----------+-----------+-----------+---------+
|31-------24|23-------16|15--------8|7-------0|
                        |-  Number of tables -|
+-----------+-----------+-----------+---------+
|-            table ID                       -|
                        |- number of segments-|
+-----------+-----------+-----------+---------+
|-    Segment offset 1                       -|
|-    Segment offset 2                       -|
|-    Segment offset ..N                     -|
+-----------+-----------+-----------+---------+
|-      Segment 1 number of entries           |
+-----------+-----------+-----------+---------+
|-      Segment 1 Entry 1 index value        -|
|-      Segment 1 Entry 1 table entry 0-3    -|
|-      Segment 1 Entry 1 table entry 4-7    -|
|-      Segment 1 Entry 1 table entry 8-11   -|
|-      Segment 1 Entry 1 table entry 12-15  -|
+-----------+-----------+-----------+---------+
|-      Segment 1 Entry 2 index value        -|
|-      Segment 1 Entry 2 table entry 0-3    -|
|-      Segment 1 Entry 2 table entry 4-7    -|
|-      Segment 1 Entry 2 table entry 8-11   -|
|-      Segment 1 Entry 2 table entry 12-15  -|
+-----------+-----------+-----------+---------+
   ...  Segment 1 Entry N  ....
+-----------+-----------+-----------+---------+
|-      Segment 2 number of entries           |
+-----------+-----------+-----------+---------+
|-      Segment 2 Entry 1 index value        -|

*/


// is 4+16 bytes in memory. Bigger here.
struct entry_s {
    uint32_t index;

    uint8_t flags;
    uint16_t patch0_address_adjust; // 12 bits
    uint16_t patch1_address_adjust; // 12 bits
    uint8_t patch0_buffer_offset;
    uint8_t patch1_buffer_offset;
    uint8_t patch0[5];
    uint8_t patch1[5];

    uint8_t active;
};
typedef struct entry_s entry_t;

struct segment_s {
    uint32_t encrypted;
  //uint32_t offset;
    uint32_t numEntries;
    entry_t *Entries;

    // Technically, we don't need to hold on to these two
    uint8_t mask[8];
    uint8_t key[16];
};
typedef struct segment_s segment_t;

struct subtable_s {
    uint32_t tableID;
    uint32_t numSegments;
    segment_t *Segments;

    // Extra variables.
    uint32_t merge; // Only used during merging
};
typedef struct subtable_s subtable_t;

struct conv_table_s {
    uint16_t numTables;
    subtable_t *Tables;

    uint32_t current_table;     // When iterating
    uint32_t current_segment;   // - "" -

    /* Table type. Redundant, but simplifies things ... */
    enum { ct_full = 0, ct_segment_masks = 1, ct_derivation_data = 2 } type;
};

/*
 *
 */

struct bdplus_st_s {
    conv_table_t *table;

    // The following is used for streaming, to be more
    // efficient and record offset.
    uint32_t stream_table;
    uint32_t stream_segment;
    uint32_t stream_entry;
    uint64_t stream_offset;

    uint64_t next_patch_offset; /* optimize patching */

    /* Process fixups from stream ? */
    uint8_t  process_stream;
};

/*
 *
 */

static int64_t _entry_offset0(const entry_t *e)
{
    return (((uint64_t)e->index +
             (uint64_t)e->patch0_address_adjust) *
            (uint64_t)0xC0 +
            (uint64_t)e->patch0_buffer_offset);
}

static int64_t _entry_offset1(const entry_t *e)
{
    return (( (uint64_t)e->index +
              (uint64_t)e->patch0_address_adjust +
              (uint64_t)e->patch1_address_adjust) *
            (uint64_t)0xC0 +
            (uint64_t)e->patch1_buffer_offset);
}

static int _is_invalid_entry(const entry_t *e, const entry_t *prev)
{
    unsigned invalid = 0;

    /*
      Do some basic sanity checks for conversion table entry.
      Note: Following checks are incomplete. The idea is to catch tables with
      random or encrypted data. This works quite well because of there are
      thousands of entries in the table.

      Checks could be improved a lot if we parse also .clpi file and the stream.
    */

    if ((e->flags >> 6) == 3) {
        BD_DEBUG(DBG_BDPLUS, "[segment] invalid flags in entry.\n");
        return 1;
    }

    /* Check only unconditionally applied entries. */
    /* Inactive entries are most likely filled with random data to secure the key. */
    if ((e->flags >> 6) == 1) {
        if (e->patch0_buffer_offset < 8 || e->patch0_buffer_offset > 187 ||
            e->patch1_buffer_offset < 8 || e->patch1_buffer_offset > 187) {

            /* - too easy to reconstruct, would compromize segment key */
            /* - ATC is used to control buffering and disk spinning at _lower_ layers */
            /* - not user-visible, useless for watermarking. */
            BD_DEBUG(DBG_BDPLUS, "[segment] invalid patch buffer offsets in entry.\n");
            invalid = 1;
        }
        if (_entry_offset0(e) >= _entry_offset1(e) ||
            ( prev && (prev->flags >> 6) == 1 &&
              _entry_offset0(e) < _entry_offset1(prev))) {

            /* tables are always sorted */
            BD_DEBUG(DBG_BDPLUS, "[segment] invalid offset in entry.\n");
            invalid = 1;
        }
    }

    return invalid;
}

/*
 *
 */

static int  _findTableIndex(conv_table_t *ct, unsigned m2ts)
{
    unsigned ii;
    for (ii = 0; ii < ct->numTables; ii++) {
        if (ct->Tables[ii].tableID == m2ts) {
            return ii;
        }
    }
    return -1;
}


uint32_t segment_numTables(conv_table_t *ct)
{
    return ct ? ct->numTables : 0;
}

uint32_t segment_numEntries(conv_table_t *ct)
{
    uint32_t entries = 0;

    if (ct && ct->current_table < ct->numTables) {
        subtable_t *subtable = &ct->Tables[ ct->current_table ];
        unsigned ii;
        for (ii = 0; ii < subtable->numSegments; ii++) {
            entries += subtable->Segments[ii].numEntries;
        }
    }

    return entries;
}

static int32_t segment_validateTable(conv_table_t *ct)
{
    uint32_t table, currseg, currentry;
    int errors = 0;

    for (table = 0; table < ct->numTables; table++) {
        subtable_t *subtable = &ct->Tables[ table ];
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {
            segment_t *segment = &subtable->Segments[ currseg ];
            for (currentry = 0; currentry < segment->numEntries; currentry++) {
                entry_t *entry = &segment->Entries[ currentry ];
                errors += _is_invalid_entry(entry, currentry == 0 ? NULL : (entry - 1));
            }
        }
    }
    return errors;
}

static void *_arrayGrow(void *mem, size_t elem_size, size_t n_old, size_t n_add)
{
    void *new_mem = realloc(mem, elem_size * (n_old + n_add));
    if (!new_mem) {
        free(mem);
        return NULL;
    }
    memset((uint8_t*)new_mem + elem_size * n_old, 0, elem_size * n_add);
    return new_mem;
}


int32_t segment_setTable(conv_table_t **conv_tab, uint8_t *Table, uint32_t len)
{
    uint32_t table, currseg, currentry;
    uint32_t tmp;
    conv_table_t *ct;
    subtable_t *subtable;
    segment_t *segment;
    entry_t *entry;
    uint32_t ptr = 0;
    uint32_t offset = 0;
    uint32_t encrypted_segments = 0;

    if (!Table || len < 2) return -1;
    if (len > 0x400000) return -1; /* VM memory size */


    BD_DEBUG(DBG_BDPLUS,"[segment] Starting decode of conv_tab.bin: %p (%d)\n", Table, len);

    if (*conv_tab) {
        BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[segment] ERROR: Table already exists.\n");
        return -1;
    }

    ct = (conv_table_t *) calloc(1, sizeof(*ct));
    if (!ct) return -2;


    // Update the number of tables we received
    ct->numTables = FETCHU2(&Table[ptr]);
    ptr += 2;

    // Let nextSegment() initialise these, So that we can ignore
    // any prior calls to trap_Finished().
    ct->current_table   = 0xffffffff;
    ct->current_segment = 0xffffffff;

    ct->Tables = (subtable_t *) calloc(ct->numTables, sizeof(subtable_t));
    if (!ct->Tables) goto error;


    BD_DEBUG(DBG_BDPLUS,"[segment] num tables %d\n", ct->numTables);

    for (table = 0; table < ct->numTables; table++) {

        if (len < 6 || ptr > len - 6)
            goto error;

        // Assign pointer so we don't need to keep dereferencing
        subtable = &ct->Tables[ table ];

        subtable->tableID = FETCH4(&Table[ptr]);
        ptr += 4;

        // Here, we might increase the number of segments.

        subtable->numSegments = FETCHU2(&Table[ptr]);
        ptr += 2;

        // Don't allocate if no (new) segments
        if (!subtable->numSegments) continue;

        BD_DEBUG(DBG_BDPLUS,"[segment] Table %d ID %08X, %u segments\n",
               table, subtable->tableID, subtable->numSegments);

        subtable->Segments = (segment_t *) calloc(subtable->numSegments, sizeof(segment_t));
        if (!subtable->Segments) goto error;

        // Loop on all segments
        for (currseg = 0;
             currseg < subtable->numSegments;
             currseg++) {

            if (ptr + currseg * 4 > len - 4)
                goto error;

            segment = &subtable->Segments[ currseg ];

            offset = FETCH4(&Table[ptr + (currseg * 4) ]);
            //segment->offset = offset;  // not really used

            if (offset > len - 4)
                goto error;

            segment->numEntries = FETCH4(&Table[offset]);
            offset += 4;

            // Don't allocate if no entries
            if (!segment->numEntries) continue;

            BD_DEBUG(DBG_BDPLUS,"   Segment %d offset %08X -> %d entries\n",
                   currseg, offset-4, segment->numEntries);

            segment->Entries = (entry_t *) calloc(segment->numEntries, sizeof(entry_t));
            if (!segment->Entries) goto error;

            // If we have non-zero entries, assume they are encrypted
            segment->encrypted = 1;
            encrypted_segments++;

            // First read in the index table
            for (currentry = 0; currentry < segment->numEntries; currentry++) {

                if (offset > len - 4)
                    goto error;

                entry = &segment->Entries[ currentry ];

                entry->index = FETCH4(&Table[offset]);
                offset += 4;
            }

            // Now read in the data.
            for (currentry = 0; currentry < segment->numEntries; currentry++) {
                entry = &segment->Entries[ currentry ];

                if (len < 16 || offset > len - 16)
                    goto error;

                entry->flags = Table[ offset ];
                offset += 1;

                tmp = FETCH4(&Table[offset]); // only fetch 3bytes, 24 bits.
                offset += 3;
                tmp &= 0xFFFFFF00;

                entry->patch0_address_adjust = (tmp & 0xFFF00000) >> 20;
                entry->patch1_address_adjust = (tmp & 0x000FFF00) >> 8;

                entry->patch0_buffer_offset = Table[offset++];
                entry->patch1_buffer_offset = Table[offset++];
                memcpy(entry->patch0, &Table[ offset ], sizeof(entry->patch0));
                offset += 5;
                memcpy(entry->patch1, &Table[ offset ], sizeof(entry->patch1));
                offset += 5;

            } // for currentry


        } // for currseg

        // offset should point at the very end of the last entry, which
        // should be the next table
        BD_DEBUG(DBG_BDPLUS,"[segment] Table done. Setting ptr to %08X\n", offset);
        ptr = offset;
    } // for table

    BD_DEBUG(DBG_BDPLUS,"[segments] Done parsing. %d segments need decrypting.\n",
           encrypted_segments);

    *conv_tab = ct;
    return ct->numTables;

 error:
    BD_DEBUG(DBG_BDPLUS|DBG_CRIT,"[segments] Conversion table parsing failed.\n");
    segment_freeTable(&ct);
    return -1;
}

static int32_t segment_setMasks(conv_table_t **conv_tab, uint8_t *Table, size_t len)
{
    conv_table_t *ct;
    uint32_t ptr = 0;
    unsigned rec_size = 16;

    if (!Table || !len) return -1;

    BD_DEBUG(DBG_BDPLUS,"[segment] Starting decode of segment_masks.bin: %p (%zu)\n", Table, len);

    // If we do not already have a conv_tab, allocate it.
    if (!*conv_tab) {
        *conv_tab = (conv_table_t *) calloc(1, sizeof(*ct));
        if (!*conv_tab) return -2;
        (*conv_tab)->type = ct_segment_masks;
    } else if ((*conv_tab)->type != ct_segment_masks) {
        return -1;
    }

    ct = *conv_tab;

    if (!memcmp(Table, "SEGK", 4)) {
        if (!memcmp(Table, "SEGK0200", 8)) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] segment mask file with FM_ID (version %8.8s)\n", Table);
            rec_size += 8;
        }
        else if (memcmp(Table, "SEGK0100", 8)) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] unsupported segment mask file version %8.8s\n", Table);
            return -1;
        }
        Table += 8;
    } else {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] no header found from segment mask file\n");
        //return -1;
    }

    while (ptr + 4 + 2 + rec_size <= len) {
        subtable_t *subtable;
        segment_t  *segment;
        uint32_t    tableID, subtableID;
        int         table;

        tableID = FETCH4(&Table[ptr]);
        ptr += 4;
        subtableID = (Table[ptr] << 8) | Table[ptr + 1];
        ptr += 2;

        /* find sutable or allocate new */
        table = _findTableIndex(ct, tableID);
        if (table < 0) {
            ct->Tables = _arrayGrow(ct->Tables, sizeof(subtable_t), ct->numTables, 1);
            if (!ct->Tables)
                return segment_freeTable(conv_tab);
            table = ct->numTables;
            ct->numTables++;
        }
        subtable = &ct->Tables[ table ];
        subtable->tableID = tableID;

        /* find segment or allocate new */
        if (subtable->numSegments <= subtableID) {
            int diff = subtableID + 1 - subtable->numSegments;
            subtable->Segments = _arrayGrow(subtable->Segments, sizeof(segment_t), subtable->numSegments, diff);
            if (!subtable->Segments)
                return segment_freeTable(conv_tab);
            subtable->numSegments = subtableID + 1;
        }
        segment = &subtable->Segments[ subtableID ];

        BD_DEBUG(DBG_BDPLUS,"[segment] Table %d ID %08X, %u segments\n",
                 table, subtable->tableID, subtable->numSegments);

        segment->encrypted = 1;

        memcpy(segment->key, &Table[ptr], 16);
        ptr += 16;
        if (rec_size >= 16+8) {
            memcpy(segment->mask, &Table[ptr], 8);
            ptr += 8;
        } else {
            /* not available, enable all */
            memset(segment->mask, 0xff, sizeof(segment->mask));
        }
    }

    return ct->numTables;
}

int32_t segment_freeTable(conv_table_t **Table)
{
    uint32_t table, currseg;
    conv_table_t *ct;
    subtable_t *subtable;
    segment_t *segment;

    BD_DEBUG(DBG_BDPLUS,"[segment] freeing conv_tab.bin\n");

    ct = *Table;

    if (ct->Tables)
    for (table = 0; table < ct->numTables; table++) {

        // Assign pointer so we don't need to keep dereferencing
        subtable = &ct->Tables[ table ];

        if (subtable->Segments)
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {

            segment = &subtable->Segments[ currseg ];

            X_FREE(segment->Entries);
            segment->numEntries = 0;

        } // Segments

        X_FREE(subtable->Segments);
        subtable->numSegments = 0;

    } // tables

    X_FREE(ct->Tables);
    ct->numTables = 0;

    X_FREE(ct);

    *Table = NULL;

    return 0;

}


//
// This takes a tableID, and assigned current_table to the correct
// table with said ID.
//
int32_t segment_setSegment(conv_table_t *conv_tab,
                           uint32_t tableID, uint32_t segment)
{
    uint32_t table;

    if (!conv_tab) return 1;

    for (table = 0;
         table < conv_tab->numTables;
         table++) {
        if (conv_tab->Tables[ table ].tableID == tableID) {
            conv_tab->current_table   = table;
            break;
        }
    }

    if (table >= conv_tab->numTables) {
        BD_DEBUG(DBG_BDPLUS,"[segment] failed to locate tableID %u.\n", tableID);
        table = 0;
        //return 1; // Function should probably signal failures.
    }

    BD_DEBUG(DBG_BDPLUS,"[segment] Set to table %u (tableID %u) and segment %u\n",
           table, conv_tab->Tables[ table ].tableID,
           segment);

    //(*conv_tab)->current_table   = tableID;
    conv_tab->current_table   = table;
    conv_tab->current_segment = segment;

    return 0;
}

int32_t segment_nextSegment(conv_table_t *conv_tab,
                            uint32_t *ret_table, uint32_t *ret_segment)
{
    uint32_t table, segment;

    if (conv_tab->current_table == 0xFFFFFFFF)
        conv_tab->current_table = 0;
    if (conv_tab->current_segment == 0xFFFFFFFF)
        conv_tab->current_segment = 0;

    // Find next encrypted segment, looping all titles, and segments.
    for (table = conv_tab->current_table;
         table < conv_tab->numTables;
         table++) {

        for (segment = conv_tab->current_segment;
             segment < conv_tab->Tables[ table ].numSegments;
             segment++) {

            if (conv_tab->Tables[ table ].Segments[ segment ].encrypted) {

                conv_tab->current_table   = table;
                conv_tab->current_segment = segment;

                BD_DEBUG(DBG_BDPLUS,"[segment] next set to table %d segment %d (tableID %u)\n",
                       table, segment,
                       conv_tab->Tables[ table ].tableID);

                // All exposed variables count from "1".
                // We should probably return tableID, not table index.
                //*ret_table = table;
                *ret_table   = conv_tab->Tables[ table ].tableID;
                *ret_segment = segment;
                return 1;
            } // if encrypted


        } // for segments

        conv_tab->current_segment = 0;

    } // for tables

    conv_tab->current_table = 0;

    return 0;

}

//
// Merge 2 conv_tabs into 1. Currently, this assumes that conv_tab will always
// hold complete tableID tables. So if we already have a tableID, it is skipped.
// This may need to be updated in future, to handle more segments, and entries
// added to existing tableIDs. However, there have been no example of such
// tables so far.
//
uint32_t segment_mergeTables(conv_table_t *set1, conv_table_t *set2)
{
    uint32_t numMergeTables, ctable, i;

    BD_DEBUG(DBG_BDPLUS,"[segment] Merging tables.. \n");

    // Count the number of "new" tableIDs in set2.
    numMergeTables = 0;

    for (ctable = 0; ctable < set2->numTables; ctable++) {
        // See if it exists already, if so, skip it.
        for (i = 0; i < set1->numTables; i++) {
            if (set2->Tables[ ctable ].tableID ==
                set1->Tables[ i ].tableID) {
                if (set1->Tables[i].numSegments !=
                    set2->Tables[ctable].numSegments) {
                    BD_DEBUG(DBG_BDPLUS,"[segment] Warning, skipping tableID but differenting numSegments\n");
                } // if numSegments
                break;
            } // tableID == tableID

        } // for set1

        if (i >= set1->numTables) { // Exhausted set1? It is new.
            numMergeTables++;
            set2->Tables[ ctable ].merge = 1;
        } // tableID

    } // for set2

    BD_DEBUG(DBG_BDPLUS,"[segment] Received %u new tableIDs to merge.\n",
           numMergeTables);
    if (!numMergeTables) return 0;

    // Grow the list to hold the new tables.
    void *tmp = set1->Tables;
    set1->Tables = (subtable_t *) realloc(set1->Tables,
                                          (set1->numTables + numMergeTables) *
                                          sizeof(subtable_t));
    if (!set1->Tables) {
        X_FREE(tmp);
        set1->numTables = 0;
        BD_DEBUG(DBG_BDPLUS,"[segment] Out of memory.\n");
        return 0;
    }

    // Clear the new nodes
    memset(&set1->Tables[ set1->numTables ], 0,
           numMergeTables * sizeof(subtable_t));

    // Merge the tables. For now, we destroy set2, but we could do this
    // by cloning the table. Perhaps in future versions...

    for (ctable = 0, i = set1->numTables;
         ctable < set2->numTables;
         ctable++, i++) {

        if (!set2->Tables[ ctable ].merge) continue;

        BD_DEBUG(DBG_BDPLUS,"[segment] merging tableID %08X, numSegments %u\n",
               set2->Tables[ ctable ].tableID,
               set2->Tables[ ctable ].numSegments);

        memcpy( &set1->Tables[ i ],
                &set2->Tables[ ctable ],
                sizeof(set1->Tables[ i ]));

        // Since we naughtily stole the node, and ptrs, zero the original
        // so it doesn't go and free anything.
        memset( &set2->Tables[ ctable ],
                0,
                sizeof(set2->Tables[ ctable ]));

    }

    set1->numTables += numMergeTables;

    BD_DEBUG(DBG_BDPLUS,"[segment] Merge complete. New total tables %u.\n",
           set1->numTables);

    return numMergeTables;
}


//
// Activates a table. This is usefull if a cached convtab.bin file is being used.
// Sets all segements as decrypted and all entries as active
int32_t segment_activateTable(conv_table_t *conv_tab)
{
    uint32_t table, currseg, currentry;
    subtable_t *subtable = NULL;
    segment_t *segment = NULL;
    entry_t *entry = NULL;

    BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] activating conv_tab.bin\n");

    for (table = 0; table < conv_tab->numTables; table++) {

        // Assign pointer so we don't need to keep dereferencing
        subtable = &conv_tab->Tables[ table ];

        //set all segments as decrypted
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {
            segment = &subtable->Segments[ currseg ];
            segment->encrypted = 0;

            //set all entries as active
            for (currentry = 0; currentry < segment->numEntries; currentry++) {
                entry = &segment->Entries[ currentry ];
                entry->active = 1;
            }
        }
    }
    return 0;
}


//
// VM has received a segment key, and mask for a subtable&segment pair.
// The key is 16 bytes of XOR data to use, and mask is 8 bytes, where byte
// 7 has bits 0-7, and byte 0 has 56-63 bits.
//
int32_t segment_decrypt(conv_table_t *conv_tab, uint8_t *key, uint8_t *mask)
{
    static const uint8_t empty[32] = {0};
    uint32_t i;
    segment_t *segment;
    uint32_t currentry, tmp;
    uint32_t removed = 0;
    entry_t *entry;
    uint8_t bits = 0;

    if (!conv_tab) return 0;
    if (conv_tab->current_table == 0xFFFFFFFF) return 0;
    if (conv_tab->current_segment == 0xFFFFFFFF) return 0;

    if (!memcmp(key, empty, 16)) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] WARNING: receiverd empty segment key\n");
    }


    char str[128];
    BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] Key %2u, %3u: %s\n", conv_tab->current_table,
          conv_tab->current_segment,
          str_print_hex(str, key, 16));
    BD_DEBUG(DBG_BDPLUS," mask: %s\n", str_print_hex(str, mask, 8));
    BD_DEBUG(DBG_BDPLUS,"Q: %s\n", str_print_hex(str, mask, 39));

    if ( conv_tab->current_table >=  conv_tab->numTables) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] decrypt, current_table (%d) >= numTables! help?!\n",
              conv_tab->numTables);
        return 0;
    }

    segment = &conv_tab->Tables[ conv_tab->current_table ].Segments[ conv_tab->current_segment ];

    // If already decrypted, don't XOR again
    if (!segment->encrypted) {

        if (!memcmp(segment->key, key, sizeof(segment->key))) {
            /* key not changed */
            return 0;
        }

        if (memcmp(segment->key, empty, 16)) {
            /* old key was not empty */
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] WARNING: Segment already decrypted with different key\n");
            return 0;
        }

        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] Old key was empty, decrypting again with new key\n");
    }

    memcpy(segment->key,   key, sizeof(segment->key));
    memcpy(segment->mask, mask, sizeof(segment->mask));

    // mark it not encrypted so that nextSegment do not spin forever
    segment->encrypted = 0;

    for (currentry = 0;
         currentry < segment->numEntries;
         currentry++) {

        entry = &segment->Entries[ currentry ];

        // XOR that sucker.
        entry->flags ^= key[0];

        tmp = FETCH4(&key[1]); // only fetch 3bytes, 24 bits.
        tmp &= 0xFFFFFF00;

        entry->patch0_address_adjust ^= (tmp & 0xFFF00000) >> 20;
        entry->patch1_address_adjust ^= (tmp & 0x000FFF00) >> 8;

        entry->patch0_buffer_offset ^= key[4];
        entry->patch1_buffer_offset ^= key[5];

        for (i=0; i < sizeof(entry->patch0); i++) {
            entry->patch0[i] ^= key[ 6 + i ];
            entry->patch1[i] ^= key[ 11 + i ];
        }

    }

    // After decrypting the whole segment, re-parse it to remove any
    // repair descriptors that are "fakes".
    unsigned logged_flag3 = 0, invalid_entries = 0;
    for (currentry = 0;
         currentry < segment->numEntries;
         currentry++) {

        entry = &segment->Entries[ currentry ];

        // Check the flag field, if it is type 2 (%10xxxxxx) then we
        // need to use the "mask" field to determine if it should be
        // applied of not.
        switch((entry->flags>>6) & 0x3) {

        case 0:
            /* No transform */
            //BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] entry type 0. Don't know what to do\n");
            entry->active = 0;
            break;

        case 1: // Type 1, always active.
            /* Transform */
            entry->active = 1;
            break;

        case 2: // Type 2, index mask[] to check if active
            /* Forensic */
            bits = entry->flags & 0x3f; // 6 bits, 0-63

            // If set true, it is active, so process next..
            // Fix me "7", sizeof(mask)?
            if (((mask[ 7-(bits >> 3) ] & (1<<(bits & 0x07))))) {
                entry->active = 1;
                continue;
            }

            // Bit was not set, so it is in-active, and should be removed...
            BD_DEBUG(DBG_BDPLUS,"[segment] removing entry %3u (flags %02X: bits %u => byte %u, set %02X to false)\n",
                   currentry, entry->flags & 0xC0,
                   bits,7-(bits >> 3), 1<<(bits&0x07));

            entry->active = 0;

#if 0
            removed++;
            // Decrease the number of entries, and copy over the remaining
            // entry nodes after this.
            for (i = (int32_t)currentry;
                 i < (int32_t)(segment->numEntries-1);
                 i++) {
                memcpy(&segment->Entries[ i ],
                       &segment->Entries[ i+1 ],
                       sizeof(segment->Entries[ i ]));
            }

            segment->numEntries--;
            // Also decreate for counter, so the new "this" gets processed.
            currentry--;
#endif

            bits = 0; // Just clearing for debug print.
            break;

        case 3:
            /* Reserved. Table or mask is invalid ? */
            if (logged_flag3 < 2)
                BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] entry type 3. Don't know what to do\n");
            else
                BD_DEBUG(DBG_BDPLUS,"[segment] entry type 3. Don't know what to do\n");
            logged_flag3++;
            entry->active = 0;
            break;

        default:
            BD_DEBUG(DBG_BDPLUS,"[segment] I can't get here.\n");
            break;

        } // switch flags

        /* deactivate invalid entries */
        if (_is_invalid_entry(entry, currentry == 0 ? NULL : entry - 1)) {
            entry->active = 0;
            invalid_entries++;
        }

    } // for entries

    if (invalid_entries) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] broken table %05d, %d (deactivated %u invalid entries, %u entries left). Mask %02x%02x0x%02x...\n",
                 conv_tab->Tables[ conv_tab->current_table ].tableID, conv_tab->current_segment,
                 invalid_entries, segment->numEntries - invalid_entries,
                 segment->key[0], segment->key[1], segment->key[2]);
    }

    if (removed)
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] cleaned out %u entries.\n", removed);

    return 1;
}


static int segment_sortby_tableid(const void *a1, const void *a2)
{
    const subtable_t *e1 = (const subtable_t *) a1;
    const subtable_t *e2 = (const subtable_t *) a2;

    if (e1->tableID < e2->tableID) return -1;
    if (e1->tableID > e2->tableID) return  1;
    return 0;
}


int32_t segment_load(conv_table_t **conv_tab, BD_FILE_H *fp)
{
    int64_t fileLen;
    int64_t len;
    uint8_t *buffer = NULL;

    BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[segment] loading cached convTable file\n");

    fileLen = file_size(fp);
    if (fileLen < 2 || fileLen > 0x400000)
        return -1;

    buffer = (uint8_t *)malloc(fileLen);
    if (!buffer)
        return -1;

    len = file_read(fp, buffer, fileLen);

    // Save the table to VM
    if (len == fileLen) {
        // Decode the table into C structures.
        if (fileLen > 8 && !memcmp(buffer, "SEGK0", 5))
            segment_setMasks(conv_tab, buffer, fileLen);
        else
            segment_setTable(conv_tab, buffer, fileLen);
    }

    X_FREE(buffer);

    if (*conv_tab) {
        int errors = segment_validateTable(*conv_tab);
        if (errors == 0) {
            return 1;
        }
        BD_DEBUG(DBG_BDPLUS|DBG_CRIT, "[bdplus] dropping broken cached conversion table (%d invalid entries).\n", errors);
        segment_freeTable(conv_tab);
    }
    return 0;
}


int32_t segment_save(conv_table_t *ct, FILE *fd)
{
    uint16_t u16;
    uint32_t u32;
    uint32_t table, currseg, currentry;
    subtable_t *subtable;
    segment_t *segment;
    entry_t *entry;
    uint8_t tmp[4]; // Hold 3 byte value in right endianess
    uint32_t offset;
    size_t rval;

    if (!ct) return -1;

    BD_DEBUG(DBG_BDPLUS,"[segment] saving convTable\n");

    // Sort based on tableID ?
    qsort(ct->Tables,             // Base
          ct->numTables,          // nmemb
          sizeof(ct->Tables[0]),  // size
          segment_sortby_tableid);// compar

    // Write number of tables
    STORE2((uint8_t *)&u16, ct->numTables);
    rval = fwrite(&u16, sizeof(u16), 1, fd);
    if(rval != 1)
        goto fail;

    // We use "offset" to keep track of where we are, and were we WILL write
    // entries, for the index-offset-array we write at the start of each
    // segment.
    offset = sizeof(ct->numTables);

    for (table = 0; table < ct->numTables; table++) {

        subtable = &ct->Tables[ table ];

        BD_DEBUG(DBG_BDPLUS,"[segment] Saving table %u tableID %08X, numSegments %u\n",
               table, subtable->tableID, subtable->numSegments);

        STORE4((uint8_t *)&u32, subtable->tableID);
        rval = fwrite(&u32, sizeof(u32), 1, fd);
        if (rval != 1)
            goto fail;
        offset += 4;

        STORE2((uint8_t *)&u16, subtable->numSegments);
        rval = fwrite(&u16, sizeof(u16), 1, fd);
        if (rval != 1)
            goto fail;
        offset += 2;

        offset += subtable->numSegments * sizeof(uint32_t);

        // Write out segment index list
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {
            segment = &subtable->Segments[ currseg ];

            //BD_DEBUG(DBG_BDPLUS,"[segment] segment offset %08X computed %08X\n",
            //       segment->offset, offset);
            //STORE4((uint8_t *)&u32, segment->offset);
            STORE4((uint8_t *)&u32, offset);
            rval = fwrite(&u32, sizeof(u32), 1, fd);
            if (rval != 1)
                goto fail;

            // Increase offset based on size of entries.
            offset += sizeof(segment->numEntries);
            offset += segment->numEntries * sizeof(entry->index);
            // Size of entry, in case we have added information
            // in the structure, or packing differences with compilers.
            offset += segment->numEntries * 16;
        }

        // write out segments
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {

            segment = &subtable->Segments[ currseg ];

            // seek to make sure we are at the right offset?
            //BD_DEBUG(DBG_BDPLUS,"[segment] save offset(%08X)\n", segment->offset);

            // This code is broken after merging tables.
            //            if (segment->offset)
            //    fseek(fd, segment->offset, SEEK_SET);

            STORE4((uint8_t *)&u32, segment->numEntries);
            rval = fwrite(&u32, sizeof(u32), 1, fd);
            if (rval != 1)
                goto fail;

            // Write out entry index list
            for (currentry = 0; currentry < segment->numEntries; currentry++) {

                entry = &segment->Entries[ currentry ];

                STORE4((uint8_t *)&u32, entry->index);
                rval = fwrite(&u32, sizeof(u32), 1, fd);
                if (rval != 1)
                    goto fail;
            }

            // Write out entries
            for (currentry = 0; currentry < segment->numEntries; currentry++) {

                entry = &segment->Entries[ currentry ];

                rval = fwrite(&entry->flags, 1, 1, fd);
                if (rval != 1)
                    goto fail;

                u32 = entry->patch0_address_adjust << 20;
                u32 |= (entry->patch1_address_adjust << 8);
                STORE4(tmp, u32);
                rval = fwrite(tmp, 3, 1, fd);
                if (rval != 1)
                    goto fail;

                rval = fwrite(&entry->patch0_buffer_offset, 1, 1, fd);
                if (rval != 1)
                    goto fail;
                rval = fwrite(&entry->patch1_buffer_offset, 1, 1, fd);
                if (rval != 1)
                    goto fail;

                rval = fwrite(&entry->patch0, sizeof(entry->patch0), 1, fd);
                if (rval != 1)
                    goto fail;
                rval = fwrite(&entry->patch1, sizeof(entry->patch1), 1, fd);
                if (rval != 1)
                    goto fail;

            } // entries

        } // segments

    } // tables

    return 0;
 fail:
    BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] Saving segment failed\n");
    return -1;
}













/*

The first indexing value in the table is:
0x9900A.
The first entry is:
4A 1A A0 53 64 B1 AA 2D 40 8E 4A 4D EF 4B 6B E5

(0x9900A+0x1AA)*0xC0       + 0x64 = 0x72D4764      // offset in the big file where the first 5 bytes are put to
(0x9900A+0x1AA+0x053)*0xC0 + 0xB1 = 0x72D85F1      // offset in the big file where the second 5 bytes are put to

-----

The second indexing value in the table is:
0x99C85.
The second entry is:
8F 20 C0 11 AA 98 B6 F7 76 EC CB 7E 61 A3 C6 C1

(0x99C85+0x20C)*0xC0       + 0xAA = 0x736ED6A      // offset in the big file where the third 5 bytes are put to
(0x99C85+0x20C+0x011)*0xC0 + 0x98 = 0x736FA18      // offset in the big file where the fourth 5 bytes are put to

*/

int32_t segment_patchfile(conv_table_t *ct, uint32_t table, FILE *fd)
{
    subtable_t *subtable;
    segment_t *segment;
    entry_t *entry;
    uint32_t currentry, currseg;
    uint64_t offset;
    int32_t firsttime = 10;

    BD_DEBUG(DBG_BDPLUS,"segment: direct patch title %d started.\n", table);

    subtable = &ct->Tables[ table ];

    for (currseg = 0; currseg < subtable->numSegments; currseg++) {

        segment = &subtable->Segments[ currseg ];

        for (currentry = 0; currentry < segment->numEntries; currentry++) {

            entry = &segment->Entries[ currentry ];

            // Skip any entries that are in-active.
            if (!entry->active) continue;

#if 1
            if (firsttime) {
                BD_DEBUG(DBG_BDPLUS,"[segment] index   %04X\n", entry->index);
                BD_DEBUG(DBG_BDPLUS,"[segment] flags   %02X\n", entry->flags);
                BD_DEBUG(DBG_BDPLUS,"[segment] adjust0 %04X\n", entry->patch0_address_adjust);
                BD_DEBUG(DBG_BDPLUS,"[segment] adjust1 %04X\n", entry->patch1_address_adjust);
                BD_DEBUG(DBG_BDPLUS,"[segment] offset0 %02X\n", entry->patch0_buffer_offset);
                BD_DEBUG(DBG_BDPLUS,"[segment] offset1 %02X\n", entry->patch1_buffer_offset);
                BD_DEBUG(DBG_BDPLUS,"[segment] patch0  %02X%02X%02X%02X%02X\n",
                       entry->patch0[0],entry->patch0[1],entry->patch0[2],
                       entry->patch0[3],entry->patch0[4]);
                BD_DEBUG(DBG_BDPLUS,"[segment] patch1  %02X%02X%02X%02X%02X\n",
                       entry->patch1[0],entry->patch1[1],entry->patch1[2],
                       entry->patch1[3],entry->patch1[4]);
            }
#endif

            // PATCH 0

            offset = _entry_offset0(entry);

            if (firsttime) {
                BD_DEBUG(DBG_BDPLUS,"[segment] would seek to %016"PRIx64" to write patch0\n",
                       offset);
            }

            if (fseeko(fd, offset, SEEK_SET)) {
                printf("Seek to offset %"PRIx64" failed. Stopping at table %d, segment %d, entry %d.\n",
                       offset, table, currseg, currentry);
                return -1;
            }
            if (fwrite(entry->patch0, sizeof(entry->patch0), 1, fd) != 1) {
                printf("Write at offset %"PRIx64" failed. Stopping at table %d, segment %d, entry %d.\n",
                       offset, table, currseg, currentry);
                return -1;
            }


            // PATCH 1

            offset = _entry_offset1(entry);

            if (firsttime) {
                BD_DEBUG(DBG_BDPLUS,"[segment] would seek to %016"PRIx64" to write patch1\n",
                       offset);
            }

            if (fseeko(fd, offset, SEEK_SET)) {
                printf("Seek to offset %"PRIx64" failed. Stopping at table %d, segment %d, entry %d.\n",
                       offset, table, currseg, currentry);
                return -1;
            }
            if (fwrite(entry->patch1, sizeof(entry->patch1), 1, fd) != 1) {
                printf("Write at offset %"PRIx64" failed. Stopping at table %d, segment %d, entry %d.\n",
                       offset, table, currseg, currentry);
                return -1;
            }

            if (firsttime)firsttime--;

        } // for entries

    } // for segments

    return 0;
}


void segment_close_m2ts(bdplus_st_t *st)
{
    free(st);
}

bdplus_st_t *segment_set_m2ts(conv_table_t *ct, uint32_t m2ts)
{
    int table = -1;

    BD_DEBUG(DBG_BDPLUS, "set_m2ts(%05u.m2ts)\n", m2ts);

    if (!ct || !ct->numTables) {
        BD_DEBUG(DBG_CRIT, "set_m2ts(%05u.m2ts): no tables !\n", m2ts);
        return NULL;
    }

    unsigned ii;
    for (ii = 0; ii < ct->numTables; ii++) {
        if (ct->Tables[ii].tableID == m2ts) {
            table = ii;
            break;
        }
    }

    if (table < 0) {
        BD_DEBUG(DBG_BDPLUS, "no conversion table %05u.m2ts\n", m2ts);
        return NULL;
    }

    BD_DEBUG(DBG_BDPLUS, "using table index %d for %05u.m2ts\n", table, m2ts);

    if (ct->type == ct_segment_masks) {
        unsigned missing_masks = 0;
        const uint8_t empty_mask[16] = {0};
        for (ii = 0; ii < ct->Tables[table].numSegments; ii++) {
            ct->Tables[table].Segments[ii].numEntries = 0;
            X_FREE(ct->Tables[table].Segments[ii].Entries);
            ct->Tables[table].Segments[ii].encrypted = 1;
            missing_masks += !memcmp(ct->Tables[table].Segments[ii].key, empty_mask, 16);
        }
        if (missing_masks) {
            /* it is quite typical to have empty first segment. => not fatal if one or two masks are missing. */
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "conversion table for %05d.m2ts does not have all masks (%d/%d are missing)\n",
                     m2ts, missing_masks, ct->Tables[table].numSegments);
        }
    } else {
    /* empty table -> no patching needed */
    int segments = 0;
    for (ii = 0; ii < ct->Tables[table].numSegments; ii++) {
        segments += ct->Tables[table].Segments[ii].numEntries;
    }
    if (segments < 1) {
        BD_DEBUG(DBG_BDPLUS, "conversion table is empty\n");
        return NULL;
    }

    /* table not decrypted ? */
    if (ct->Tables[table].Segments[0].encrypted) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "conversion table for %05d.m2ts is still encrypted\n", m2ts);
        return NULL;
    }
    }

    // Changing table, or seeking elsewhere, means zero the segment and
    // entry so we have to find them again.

    bdplus_st_t *st = calloc(1, sizeof(*st));
    if (!st) {
        BD_DEBUG(DBG_CRIT, "out of memory\n");
        return NULL;
    }
    st->process_stream = (ct->type != ct_full);
    st->stream_table = table;
    st->table = ct;
    BD_DEBUG(DBG_BDPLUS,"[segment] settable(%05u.m2ts): %p\n", m2ts, st);

    return st;
}

int32_t segment_patchseek(bdplus_st_t *ct, uint64_t offset)
{
    if (ct->process_stream) {
        /* flush cache */
        unsigned    currseg;
        subtable_t *subtable = &ct->table->Tables[ ct->stream_table ];
        for (currseg = 0; currseg < subtable->numSegments; currseg++) {
            X_FREE(subtable->Segments[ currseg ].Entries);
            subtable->Segments[ currseg ].numEntries = 0;
        }
    }

    // Changing table, or seeking elsewhere, means zero the segment and
    // entry so we have to find them again.
    ct->stream_segment = 0;
    ct->stream_entry = 0;

    ct->stream_offset = offset;
    ct->next_patch_offset = 0;

    BD_DEBUG(DBG_BDPLUS,"[segment] seek: %016"PRIx64"\n", offset);

    if (ct->process_stream) {
        /* data (offset) must be aligned */
        if ((offset % 192) != 0) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] segment_patchseek() error: unaligned seek in mode1\n");
            return -1;
        }
    }

    return 0;
}

//#define DUMP_0x89
#ifdef DUMP_0x89
static void _dump_0x89(unsigned spn, const uint8_t *d, const uint8_t *mask)
{
    fprintf(stderr, "@%-12u  | ", spn);
    for (int i = 0; i < d[1]; i++)
        fprintf(stderr, "%02x ", d[2+i]);
    fprintf(stderr, "| next @%d (+%d)\n", spn + (d[d[1]]<<8) + d[d[1]+1], (d[d[1]]<<8) + d[d[1]+1]);
    fprintf(stderr, "          MASK | %4u |%02x %02x %02x %02x ...\n", (d[2] << 8) | d[3], mask[0], mask[1], mask[2], mask[3]);

     /* no mask -> no point to continue */
    const uint8_t empty_mask[16] = {0};
    if (!memcmp(mask, empty_mask, 16))
        return;

    if (((d[4] ^ mask[0]) >> 6) == 0 || ((d[4] ^ mask[0]) >> 6) == 3)
        fprintf(stderr, "            F%d |       ", (d[4] ^ mask[0]) >> 6);
    else
        fprintf(stderr, "      %s |       ", ((d[4] ^ mask[0]) >> 6) == 2 ? "FORENSIC" : "   PATCH");

    if (((d[4] ^ mask[0]) >> 6) != 0) {
        /* dump content */
        const uint8_t *p = d + 4;
        for (int i = 0; i < d[1] - 4; i++)
            fprintf(stderr, "%02x ", p[i] ^ mask[i]);
        uint32_t t = (FETCH4(&p[1]) ^ FETCH4(&mask[1]));
        fprintf(stderr, "      | BP: %d %d  O: %d %d", p[4] ^ mask[4], p[5] ^ mask[5], t>>20, (t>>8)&0xfff);
    }
    fprintf(stderr, "\n");
}
#endif

static int ts_parse_desc_0x89(bdplus_st_t *ct, const unsigned spn, const unsigned spn0, const uint8_t *d)
{
    subtable_t    *st = &ct->table->Tables[ ct->stream_table ];
    segment_t     *segment;
    const uint8_t *mask;
    unsigned       sp_id = (d[2] << 8) | d[3];
    const uint8_t  empty_mask[16] = {0};

    if (sp_id >= st->numSegments) {
        /* broken table or stream */
        return 0;
    }

    mask = st->Segments[sp_id].key;
#ifdef DUMP_0x89
    _dump_0x89(spn, d, mask);
#endif

    /* TODO: if mask missing, call VM for computeSP */
    if (!memcmp(mask, empty_mask, 16)) {
        return 0;
    }

    /* skip fuzzing entries (random data) */
    if (((d[4] ^ mask[0]) >> 6) == 0)
        return 0;
    /* sanity check flags */
    if (((d[4] ^ mask[0]) >> 6) == 3) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] found invalid flags value. incorrect mask ?\n");
        return 0;
    }

    /* avoid polluting tables with incomplete lists */
    if (sp_id > 0) {
        X_FREE(st->Segments[sp_id - 1].Entries);
        st->Segments[sp_id - 1].numEntries = 0;
    }

    segment = &st->Segments[ sp_id ];

    /* check Forensic Mark ID */
    if (((d[4] ^ mask[0]) >> 6) == 2) {
        unsigned fm_id_pos = (d[4] ^ mask[0]) & 0x3f;
        unsigned fm_id_bit = segment->mask[ 7 - (fm_id_pos >> 3) ] & (1 << (fm_id_pos & 0x07));
        BD_DEBUG(DBG_BDPLUS, "[segment] %s type 2 patch (FM_ID_bit_pos = %d, FM_ID_bit = %d)\n",
                 fm_id_bit ? "activated" : "deactivated", fm_id_pos, !!fm_id_bit);
        if (fm_id_bit == 0) {
            return 0;
        }
    }

#define E1_CACHE_SIZE 50  /* there must be some upper bound in the specs (?) */
    /* keep ordered list of next patches */
    if (segment->Entries == NULL) {
        segment->Entries = calloc(E1_CACHE_SIZE, sizeof(st->Segments[sp_id].Entries[0]));
        segment->numEntries = 0;
        if (!segment->Entries)
            return 0;
    }
    /* drop past entries */
    while (segment->numEntries > 0 &&
           segment->Entries[0].index + segment->Entries[0].patch0_address_adjust + segment->Entries[0].patch1_address_adjust < spn0 - 1) {
        segment->numEntries--;
        if (segment->numEntries > 0)
            memmove(&segment->Entries[0], &segment->Entries[1], segment->numEntries * sizeof(segment->Entries[0]));
    }
    if (segment->numEntries >= E1_CACHE_SIZE - 1) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] stream entry cache overflow\n");
        return 0;
    }

    /* inject entry to the table for segment_patch() */
    entry_t entry = {
        spn, d[4] ^ mask[0], ((d[5] ^ mask[1]) << 4) | ((d[6] ^ mask[2]) >> 4),
        (((d[6] ^ mask[2]) & 0x0f) << 8) | ( d[7] ^ mask[3]), d[8] ^ mask[4], d[9] ^ mask[5],
        {d[10] ^ mask[6],  d[11] ^ mask[7],  d[12] ^ mask[8],  d[13] ^ mask[9],  d[14] ^ mask[10], },
        {d[15] ^ mask[11], d[16] ^ mask[12], d[17] ^ mask[13], d[18] ^ mask[14], d[19] ^ mask[15], }, 1,
    };
    memcpy(&segment->Entries[segment->numEntries], &entry, sizeof(entry));
    segment->numEntries++;

    ct->stream_segment = sp_id;
    ct->stream_entry = 0;
    ct->next_patch_offset = 0;

    BD_DEBUG(DBG_BDPLUS, "[segment] injected patch for segment %u, SPN %u (queue %d patches).\n",
             sp_id, entry.index + entry.patch0_address_adjust, segment->numEntries);

    return 1;
}

//
// Given a buffer and its size in bytes. Using the "offset" the buffer
// starts at, work out if any patch Entries lie inside that offset, and
// modify buffer as required.
//
int32_t segment_patch(bdplus_st_t *ct, int len, uint8_t *buffer)
{
    uint64_t end_offset, start_offset, offset0, offset1, diff;
    subtable_t *subtable;
    segment_t *segment;
    entry_t *entry;
    uint32_t currentry, currseg;
    int32_t patches=0;

    BD_DEBUG(DBG_BDPLUS,
          "[segment] read(len %d): %016"PRIx64"\n",
          len, ct->stream_offset);

    // While stream_segment[stream_entry] is less than the end of the buffer
    // possible apply it
    // and iterate to the next one.


    start_offset = ct->stream_offset;
    end_offset = ct->stream_offset + (uint64_t) len;
    ct->stream_offset += (uint64_t) len;

    if (ct->process_stream) {
        const uint8_t *p;
        if (buffer[4] != 0x47) {
            BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[segment] segment_patch() input error: unaligned data in stream fixup mode\n");
            return -1;
        }

        for (p = buffer; p < buffer + len; p += 192) {
            if (p[5] == 0x41 && p[6] == 0x00 && !(p[7] & 0x20) && p[4] == 0x47 && p[21] == 0x89 && p[22] == 0x14) {
                ts_parse_desc_0x89(ct, ((start_offset + p - buffer) / 192), start_offset / 192, p + 21);
            }
        }
    }

    if (ct->next_patch_offset > end_offset) {
        return 0;
    }

    subtable = &ct->table->Tables[ ct->stream_table ];

    for (currseg = ct->stream_segment;
         currseg < subtable->numSegments;
         currseg++, ct->stream_segment++ ) {

        segment = &subtable->Segments[ currseg ];

        for (currentry = ct->stream_entry;
             currentry < segment->numEntries;
             currentry++, ct->stream_entry++ ) {

            entry = &segment->Entries[ currentry ];

            // Skip any entries that are in-active.
            if (!entry->active) continue;
            offset0 = _entry_offset0(entry);

            // If this Entry is beyond this buffer, stop here, we need
            // more data.
            if (offset0 > end_offset) {
                ct->next_patch_offset = offset0;
                return patches;
            }

            offset1 = _entry_offset1(entry);

            // While this Entry (patch1) is (completely) before this
            // buffer, skip to the next
            if (offset1+(uint64_t)sizeof(entry->patch1) <= start_offset)
                continue;

            // Ok, it is possible this Entry patch0, or patch1, lands
            // Inside this buffer, so lets process it.

            // Check patch0, really we do patch0 -4 >= offset, at least
            // one byte is inside. But since patch0 could be "0", we can
            // not do -4.
            // So we go +4 on offset, and do the same test.
            // AND if patch is < end_offset.

            // Consider patch0
            if (offset0 < start_offset) {
                // patch0 goes over the start of buffer.
                diff = (start_offset - offset0);
                if (diff < (uint64_t) sizeof(entry->patch0)) {
                    memcpy(buffer, &entry->patch0[ diff ],
                           sizeof(entry->patch0) - (size_t)diff);
                    patches++;
                } // 0-4 bytes

            } else { // greater-or-equal

                diff = (end_offset - offset0);

                if (diff < (uint64_t) sizeof(entry->patch0)) {
                    // Stradling the end
                    memcpy(&buffer[ len - diff ], entry->patch0, (size_t)diff);
                    patches++;
                } else {
                    // Entirely inside
                    memcpy(&buffer[ len - diff ], entry->patch0,
                           sizeof(entry->patch0));
                    patches++;
                }
            }


            // If this Entry is beyond this buffer, stop here, we need
            // more data.
            if (offset1 > end_offset)
                return patches;

            // Consider patch1
            if (offset1 < start_offset) {
                // patch1 goes over the start of buffer.
                diff = (start_offset - offset1);
                if (diff < (uint64_t) sizeof(entry->patch1)) {
                    memcpy(buffer, &entry->patch1[ diff ],
                           sizeof(entry->patch1) - (size_t)diff);
                    patches++;
                } // 0-4 bytes

            } else { // greater-or-equal

                diff = (end_offset - offset1);

                if (diff < (uint64_t) sizeof(entry->patch1)) {
                    // Stradling the end
                    memcpy(&buffer[ len - diff ], entry->patch1, (size_t)diff);
                    patches++;
                } else {
                    // Entirely inside
                    memcpy(&buffer[ len - diff ], entry->patch1,
                           sizeof(entry->patch1));
                    patches++;
                }

            }

        } // currentry

        ct->stream_entry = 0;

    } // curseg

    // If we set stream_segment to 0 here, we will forever scan the list.
    // So we leave it high
    //ct->stream_segment = 0;

    // We've run out of entries..
    return patches;
}

