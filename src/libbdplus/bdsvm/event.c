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

#include "event.h"

#include "dlx_internal.h"

#include "util/logging.h"
#include "util/macro.h"

#include <string.h>
#include <stdlib.h>
#include <gcrypt.h>

void bdplus_send_event(VM *vm, uint32_t eventID, uint32_t arg1,
                       uint32_t table, uint32_t segment)
{

    BD_DEBUG(DBG_BDPLUS_EVENT,"[bdplus] ** posting EVENT %X (%08X, %d, %d)\n", eventID,
          arg1, table, segment);

    if (!vm || !vm->addr) return;

    STORE4( &vm->addr[ 0x0 ], eventID );
    STORE4( &vm->addr[ 0x4 ], arg1    );
    STORE4( &vm->addr[ 0x8 ], table   );
    if (eventID == EVENT_ComputeSP) {

        STORE4( &vm->addr[ 0xC ], segment );
        STORE4( &vm->addr[ 0x20 ], 0 ); // Set by Jumper, clearing MASK?
        STORE4( &vm->addr[ 0x24 ], 0 ); // Set by Jumper
#if 0
        /* this should be set already ... */
        if (plus->conv_tab)
            segment_setSegment(plus->conv_tab, table, segment);
#endif
    }

    // Remember break location?
    // send_event sets R28, but it MUST be clear to start.

    // If we are Starting, don7t touch R28, since they must all be 0 at start.
    if (eventID != EVENT_Start)
        vm->R[28] = dlx_getPC(vm);

    dlx_setPC(vm, 0x1000);
    dlx_setWD(vm, 0x7FFFFFFF);
    vm->event_processing = 1;
    vm->event_current = eventID;
}
