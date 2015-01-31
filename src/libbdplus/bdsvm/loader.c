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

#include "loader.h"

#include "dlx.h"

#include "file/file.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <string.h>


static int _code_version_check(uint8_t *hdr, int *p_gen, int *p_date)
{
    // known BD+ content code generations
    static const uint16_t gentbl[][3] = {
      //
      // Year,Month,Day           Manufacturer  First title              Notes
      //
      { 2007,  6,  8 },  // gen  1: CRI         "The Day After Tomorrow" First BD+. Content watermarking.
      { 2007, 12, 20 },  // gen  2:             "Mrs Doubtfire"          TRAP_MediaCheck (checks if content is encrypted with AACS).
      { 2008,  4, 14 },  // gen  3: Macrovision "Jumper"                 Useless FUEs, TRAP_DebugLog, BD-J <-> BD+ handshake.
      { 2008,  8, 22 },  // gen  4:             "Futurama: Benders Game" MK.enc (encrypted java code).
      { 2009,  2,  2 },  // gen  5:             "Slumdog Millionaire"    Variable handshake return codes.
      { 2009,  3, 31 },  // gen  6:             "Valkyrie"               MK.enc --> 77773.jar
      { 2009,  8, 18 },  // gen  7:             "Ice Age 3"              00003.svm
      { 2010,  3,  6 },  // gen  8:             "Avatar"                 Native code. Permanent handshake during playback.
      { 2010,  9,  3 },  // gen  9:             "Knight and Day"         00004.svm, 00005.svm. New native code.
      { 2011,  2, 28 },  // gen 10:             "Rabbit Hole"
      { 2011,  6,  1 },  // gen 11:             "Star Wars"
      { 2011, 11, 16 },  // gen 12/13: Irdeto   "Contagion"
      { 2011, 11, 16 },  // -,,-
      { 2012,  8,  7 },  // gen 14:             "Prometheus"
      { 2013,  1, 25 },  // gen 15:             "Parental Guidance"
      { 2013,  4, 30 },  // gen 16:             "Stoker"                StreetLock.
    };

    unsigned int year  = hdr[0x0d] << 8 | hdr[0x0e];
    unsigned int month = hdr[0x0f];
    unsigned int day   = hdr[0x10];
    unsigned int gen;

    for (gen = 0; gen < sizeof(gentbl) / sizeof(gentbl[0]); gen++) {
        if ( year < gentbl[gen][0] ||
            (year == gentbl[gen][0] && month <  gentbl[gen][1]) ||
            (year == gentbl[gen][0] && month == gentbl[gen][1] && day < gentbl[gen][2])) {
            break;
        }
    }

    BD_DEBUG(DBG_BDPLUS, "[bdplus] BD+ code created: %04d-%02d-%02d (BD+ generation %d)\n", year, month, day, gen);

    if (p_gen) {
        *p_gen = gen;
    }
    if (p_date) {
        *p_date = (hdr[0x0d] << 24) | (hdr[0x0e] << 16) | (hdr[0x0f] << 8) | hdr[0x10];
    }

    if (gen > 3) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] WARNING: BD+ generation %d not tested / supported\n", gen);
        return -1;
    }

    return 0;
}

int32_t loader_load_svm(BDPLUS_FILE_H *fp, const char *fname, VM *vm, int *p_gen, int *p_date)
{
    uint32_t len;
    uint8_t *addr = dlx_getAddr(vm);

    // Read BD SVM header
    if (file_read(fp, addr, 0x18) != 0x18) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Error reading header from %s\n", fname);
        return -1;
    }

    if (memcmp(addr, "BDSVM_CC", 8)) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[bdplus] %s failed signature match\n", fname);
    }

    _code_version_check(addr, p_gen, p_date);

    // Pull out length
    len = FETCH4(&addr[0x14]);

    BD_DEBUG(DBG_BDPLUS,"[bdplus] svm size %08X (%u)\n", len, len);

    if (len >= dlx_getAddrSize(vm)) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT,"[bdplus] Section too long (%d) in %s\n", len, fname);
        return -1;
    }

    // read length data
    if (file_read(fp, addr, len) != len) {
        BD_DEBUG(DBG_BDPLUS | DBG_CRIT, "[bdplus] Error reading section from %s\n", fname);
        return -1;
    }

    file_close(fp);

    BD_DEBUG(DBG_BDPLUS,"[bdplus] loaded core '%s'\n", fname);

    // clear first 0x1000 bytes
    memset(addr, 0, 0x1000);

    return 0;
}
